//! Native-source durability and consumer acceptance have separate identities.
use crate::{
    auth::{self, Headers, SignedRequest, Target},
    native,
    ports::PortError,
    CommandResult, Provider, Result,
};
use async_trait::async_trait;
use llull_buzz_wire::{
    digest, hash, id, parse, sha256, Command, Evidence, Execution, Fault, Resource, MAX_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{types::Json, Row};
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intake {
    pub event_id: String,
    pub community_id: String,
    pub channel_id: String,
    pub content_sha256: String,
    pub evidence: Vec<Evidence>,
}
impl Intake {
    fn validate(&self) -> Result<()> {
        hash(&self.event_id)?;
        hash(&self.content_sha256)?;
        id(&self.community_id)?;
        id(&self.channel_id)?;
        if self.evidence.len() > 32 {
            return Err(Fault::TooLarge.into());
        }
        let mut sources = BTreeSet::new();
        for e in &self.evidence {
            id(&e.source_id)?;
            hash(&e.sha256)?;
            id(&e.media_type)?;
            id(&e.release_ref)?;
            if e.size_bytes > 26_214_400 || !sources.insert(&e.source_id) {
                return Err(Fault::Invalid.into());
            }
        }
        Ok(())
    }
}

/// Trusted fixed-origin native retrieval, never a URL selected by a wire payload.
#[async_trait]
pub trait NativeEventSource: Send + Sync {
    async fn event(
        &self,
        community: &str,
        channel: &str,
        event: &str,
    ) -> std::result::Result<Vec<u8>, PortError>;
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedEvidence {
    pub source_id: Uuid,
    pub intake: Intake,
    pub native_event: Value,
    pub enrollment_id: String,
    pub enrollment_revision: u64,
    pub source_bytes_sha256: String,
    pub consumer_receipt: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationReceipt {
    source_id: Uuid,
    durable_receipt_id: String,
}

impl Provider {
    pub async fn intake<S: NativeEventSource>(
        &self,
        body: &[u8],
        headers: Headers<'_>,
        source: &S,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "intake" {
            return Err(Fault::Unavailable.into());
        }
        let intake: Intake = c.payload()?;
        intake.validate()?;
        if c.resource.reference != intake.event_id || c.resource.revision != "1" {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/conversation-intakes",
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        if intake.community_id != registration.community_id {
            return Err(Fault::Denied.into());
        }
        let fingerprint = digest(&intake)?;
        let existing=sqlx::query("SELECT source_id,module_id,context_domain,intake_sha256,event_bytes,event_sha256 FROM native_inputs WHERE consumer_id=$1 AND community_id=$2 AND event_id=$3")
            .bind(&c.consumer_id).bind(&intake.community_id).bind(&intake.event_id).fetch_optional(&mut *tx).await?;
        let bytes = if let Some(row) = &existing {
            if row.try_get::<String, _>("module_id")? != claims.module_id
                || row.try_get::<String, _>("context_domain")? != claims.context_domain
                || row.try_get::<String, _>("intake_sha256")? != fingerprint
            {
                return Err(Fault::Conflict.into());
            }
            let bytes: Vec<u8> = row.try_get("event_bytes")?;
            if sha256(&bytes) != row.try_get::<String, _>("event_sha256")? {
                return Err(Fault::Unknown.into());
            }
            bytes
        } else {
            // Keep current authority and initial source acceptance serialized.
            // Retried intake uses the retained original even if its origin is down.
            tokio::time::timeout(
                Duration::from_secs(5),
                source.event(&intake.community_id, &intake.channel_id, &intake.event_id),
            )
            .await
            .map_err(|_| Fault::Unknown)?
            .map_err(|_| Fault::Unknown)?
        };
        if bytes.len() > MAX_BYTES {
            return Err(Fault::TooLarge.into());
        }
        let event = native::event(&bytes)?;
        if event.id.to_hex() != intake.event_id
            || native::tag(&event, "h")? != intake.channel_id
            || sha256(event.content.as_bytes()) != intake.content_sha256
            || event.kind.as_u16() as u32 != buzz_core::kind::KIND_STREAM_MESSAGE
            || event.created_at.as_secs() > Self::now(&mut tx).await?.timestamp() as u64 + 30
        {
            return Err(Fault::Denied.into());
        }
        // Every declared attachment must be present in the original signed imeta.
        // No URL is dereferenced here; original bytes have their own media gate.
        if event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().is_some_and(|f| f == "imeta"))
            .count()
            != intake.evidence.len()
        {
            return Err(Fault::Denied.into());
        }
        for evidence in &intake.evidence {
            let matches = event
                .tags
                .iter()
                .filter(|t| {
                    let fields = t.as_slice();
                    fields.first().is_some_and(|f| f == "imeta")
                        && fields.contains(&format!("x {}", evidence.sha256))
                        && fields.contains(&format!("m {}", evidence.media_type))
                        && fields.contains(&format!("size {}", evidence.size_bytes))
                })
                .count();
            if matches != 1 {
                return Err(Fault::Denied.into());
            }
        }
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        let source_id = if let Some(row) = existing {
            if row.try_get::<String, _>("module_id")? != claims.module_id
                || row.try_get::<String, _>("context_domain")? != claims.context_domain
                || row.try_get::<String, _>("intake_sha256")? != fingerprint
            {
                return Err(Fault::Conflict.into());
            }
            row.try_get::<Uuid, _>("source_id")?
        } else {
            let (enrollment,revision):(String,i64)=sqlx::query_as("SELECT enrollment_id,revision FROM enrollments WHERE consumer_id=$1 AND module_id=$2 AND native_key=$3 AND active AND NOT key_retired")
                .bind(&c.consumer_id).bind(&claims.module_id).bind(event.pubkey.to_hex()).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
            let source_id = Uuid::new_v4();
            sqlx::query("INSERT INTO native_inputs(source_id,consumer_id,community_id,event_id,module_id,context_domain,channel_id,enrollment_id,enrollment_revision,intake,intake_sha256,event_bytes,event_sha256,retain_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,clock_timestamp()+($14::bigint * interval '1 day'))")
                .bind(source_id).bind(&c.consumer_id).bind(&intake.community_id).bind(&intake.event_id).bind(&claims.module_id).bind(&claims.context_domain).bind(&intake.channel_id).bind(enrollment).bind(revision).bind(Json(&intake)).bind(fingerprint).bind(&bytes).bind(sha256(&bytes)).bind(registration.retention.audit_days as i64).execute(&mut *tx).await?;
            source_id
        };
        let registered:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM intake_registrations WHERE consumer_id=$1 AND source_id=$2)").bind(&c.consumer_id).bind(source_id).fetch_one(&mut *tx).await?;
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result=Self::remember(&mut tx,(&c,&claims),source_id.to_string(),Execution::Completed,1,json!({"source_id":source_id,"event_id":intake.event_id,"bytes_durable":true,"consumer_registration":if registered {"registered"} else {"pending"},"attachment_bytes_durable":intake.evidence.is_empty()})).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn evidence(
        &self,
        consumer: &str,
        source: &str,
        headers: Headers<'_>,
    ) -> Result<RetainedEvidence> {
        id(consumer)?;
        let source_id = Uuid::parse_str(source).map_err(|_| Fault::Invalid)?;
        if source_id.to_string() != source {
            return Err(Fault::Invalid.into());
        }
        let resource = Resource {
            namespace: consumer.into(),
            reference: source.into(),
            revision: "1".into(),
        };
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &SignedRequest {
                    headers: &headers,
                    body: b"",
                },
                auth::EVIDENCE,
                &format!("/integration/v1/evidence/{source}"),
                "GET",
                &Target {
                    consumer,
                    intent: source,
                    operation: "read-evidence",
                    resource: &resource,
                    fingerprint: &sha256(b""),
                    root: None,
                },
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        let row=sqlx::query("SELECT n.*,r.durable_receipt_id FROM native_inputs n LEFT JOIN intake_registrations r USING(consumer_id,source_id) WHERE n.consumer_id=$1 AND n.source_id=$2 AND n.module_id=$3 AND n.context_domain=$4")
            .bind(consumer).bind(source_id).bind(&claims.module_id).bind(&claims.context_domain).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        let bytes: Vec<u8> = row.try_get("event_bytes")?;
        let expected: String = row.try_get("event_sha256")?;
        if sha256(&bytes) != expected {
            return Err(Fault::Unknown.into());
        }
        native::event(&bytes)?;
        let value = RetainedEvidence {
            source_id,
            intake: row.try_get::<Json<Intake>, _>("intake")?.0,
            native_event: parse(&bytes)?,
            enrollment_id: row.try_get("enrollment_id")?,
            enrollment_revision: row.try_get::<i64, _>("enrollment_revision")? as u64,
            source_bytes_sha256: expected,
            consumer_receipt: row.try_get("durable_receipt_id")?,
        };
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn register_intake(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "register-intake" {
            return Err(Fault::Unavailable.into());
        }
        let receipt: RegistrationReceipt = c.payload()?;
        id(&receipt.durable_receipt_id)?;
        if c.resource.reference != receipt.source_id.to_string() || c.resource.revision != "1" {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/intake-registrations",
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let allowed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_inputs WHERE consumer_id=$1 AND source_id=$2 AND module_id=$3 AND context_domain=$4)")
            .bind(&c.consumer_id).bind(receipt.source_id).bind(&claims.module_id).bind(&claims.context_domain).fetch_one(&mut *tx).await?;
        if !allowed {
            return Err(Fault::Denied.into());
        }
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        let existing:Option<(Uuid,String)>=sqlx::query_as("SELECT source_id,durable_receipt_id FROM intake_registrations WHERE consumer_id=$1 AND (source_id=$2 OR durable_receipt_id=$3)")
            .bind(&c.consumer_id).bind(receipt.source_id).bind(&receipt.durable_receipt_id).fetch_optional(&mut *tx).await?;
        if let Some((source, prior)) = existing {
            if source != receipt.source_id || prior != receipt.durable_receipt_id {
                return Err(Fault::Conflict.into());
            }
        } else {
            sqlx::query("INSERT INTO intake_registrations(consumer_id,source_id,durable_receipt_id) VALUES($1,$2,$3)")
                .bind(&c.consumer_id).bind(receipt.source_id).bind(&receipt.durable_receipt_id).execute(&mut *tx).await?;
        }
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result=Self::remember(&mut tx,(&c,&claims),receipt.source_id.to_string(),Execution::Completed,1,json!({"source_id":receipt.source_id,"consumer_registration":"registered","durable_receipt_id":receipt.durable_receipt_id})).await?;
        tx.commit().await?;
        Ok(result)
    }
}
