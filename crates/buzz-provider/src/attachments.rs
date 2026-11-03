//! Retain and read exact attachment bytes under the existing intake/authority scope.
//! Native Blossom publication mediation is a distinct, still unavailable surface.
use crate::{
    auth::{self, Headers, SignedRequest, Target},
    native,
    ports::PortError,
    CommandResult, Intake, Provider, Result,
};
use async_trait::async_trait;
use llull_buzz_wire::{digest, hash, id, sha256, Command, Evidence, Execution, Fault, Resource};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{types::Json, Row};
use std::time::Duration;
use uuid::Uuid;

pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Trusted fixed private origin only. Signed imeta URLs are never fetch targets.
#[async_trait]
pub trait NativeAttachmentSource: Send + Sync {
    fn attachment_owner(&self) -> &str;
    async fn attachment(
        &self,
        community: &str,
        evidence: &Evidence,
    ) -> std::result::Result<Vec<u8>, PortError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainAttachment {
    pub source_id: Uuid,
    pub evidence: Evidence,
}

fn current(
    claims: &auth::Claims,
    retained_until: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    claims.fresh(now.timestamp())?;
    if retained_until <= now {
        return Err(Fault::Denied.into());
    }
    Ok(())
}

pub(crate) fn validate_bytes(evidence: &Evidence, bytes: &[u8]) -> Result<()> {
    hash(&evidence.sha256)?;
    if evidence.size_bytes > MAX_ATTACHMENT_BYTES as u64 || bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(Fault::TooLarge.into());
    }
    if bytes.len() as u64 != evidence.size_bytes || sha256(bytes) != evidence.sha256 {
        return Err(Fault::Unknown.into());
    }
    Ok(())
}

impl Provider {
    pub async fn retain_attachment<S: NativeAttachmentSource>(
        &self,
        body: &[u8],
        headers: Headers<'_>,
        source: &S,
    ) -> Result<CommandResult> {
        let command: Command = Self::decode(body)?;
        if command.operation != "retain-attachment" {
            return Err(Fault::Unavailable.into());
        }
        let request: RetainAttachment = command.payload()?;
        let evidence = &request.evidence;
        hash(&evidence.sha256)?;
        id(&evidence.source_id)?;
        id(&evidence.release_ref)?;
        id(&evidence.media_type)?;
        id(source.attachment_owner())?;
        if evidence.size_bytes > MAX_ATTACHMENT_BYTES as u64 {
            return Err(Fault::TooLarge.into());
        }
        if command.resource.reference != format!("{}/{}", request.source_id, evidence.sha256)
            || command.resource.revision != "1"
        {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &command,
                &SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/attachment-retentions",
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let row = sqlx::query("SELECT intake,intake_sha256,event_bytes,event_sha256,retain_until FROM native_inputs WHERE consumer_id=$1 AND source_id=$2 AND module_id=$3 AND context_domain=$4 AND retain_until>clock_timestamp()")
            .bind(&command.consumer_id).bind(request.source_id).bind(&claims.module_id)
            .bind(&claims.context_domain).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        let retained_until = row.try_get::<chrono::DateTime<chrono::Utc>, _>("retain_until")?;
        let intake = row.try_get::<Json<Intake>, _>("intake")?.0;
        let event: Vec<u8> = row.try_get("event_bytes")?;
        if digest(&intake)? != row.try_get::<String, _>("intake_sha256")?
            || sha256(&event) != row.try_get::<String, _>("event_sha256")?
            || native::event(&event)?.id.to_hex() != intake.event_id
        {
            return Err(Fault::Unknown.into());
        }
        if intake.community_id != registration.community_id
            || !intake.evidence.iter().any(|item| item == evidence)
        {
            return Err(Fault::Denied.into());
        }
        // Scope is checked before even an immutable original command receipt is read.
        if let Some(result) = Self::replay(&mut tx, &command).await? {
            current(&claims, retained_until, Self::now(&mut tx).await?)?;
            tx.commit().await?;
            return Ok(result);
        }
        let retained = sqlx::query("SELECT evidence,bytes,origin_owner FROM native_attachments WHERE consumer_id=$1 AND source_id=$2 AND evidence_source_id=$3")
            .bind(&command.consumer_id).bind(request.source_id).bind(&evidence.source_id)
            .fetch_optional(&mut *tx).await?;
        if let Some(retained) = retained {
            if retained.try_get::<Json<Evidence>, _>("evidence")?.0 != *evidence
                || retained.try_get::<String, _>("origin_owner")? != source.attachment_owner()
            {
                return Err(Fault::Conflict.into());
            }
            validate_bytes(evidence, &retained.try_get::<Vec<u8>, _>("bytes")?)?;
        } else {
            // The bounded read has no remote write effect. Expiry/DB failure rolls
            // back the new bytes and command together; retries cannot duplicate rows.
            let bytes = tokio::time::timeout(
                Duration::from_secs(5),
                source.attachment(&intake.community_id, evidence),
            )
            .await
            .map_err(|_| Fault::Unknown)?
            .map_err(|_| Fault::Unknown)?;
            validate_bytes(evidence, &bytes)?;
            current(&claims, retained_until, Self::now(&mut tx).await?)?;
            sqlx::query("INSERT INTO native_attachments(consumer_id,source_id,evidence_source_id,evidence,byte_sha256,byte_length,bytes,origin_owner) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(&command.consumer_id).bind(request.source_id).bind(&evidence.source_id)
                .bind(Json(evidence)).bind(&evidence.sha256).bind(evidence.size_bytes as i64)
                .bind(bytes).bind(source.attachment_owner()).execute(&mut *tx).await?;
        }
        current(&claims, retained_until, Self::now(&mut tx).await?)?;
        let result = Self::remember(
            &mut tx,
            (&command, &claims),
            request.source_id.to_string(),
            Execution::Completed,
            1,
            json!({"source_id":request.source_id,
                "evidence_source_id":evidence.source_id,"sha256":evidence.sha256,
                "bytes":evidence.size_bytes,"attachment_bytes_durable":true,
                "consumer_registration":"unchanged"}),
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn attachment_bytes(
        &self,
        consumer: &str,
        source: &str,
        digest: &str,
        headers: Headers<'_>,
    ) -> Result<Vec<u8>> {
        id(consumer)?;
        hash(digest)?;
        let source_id = Uuid::parse_str(source).map_err(|_| Fault::Invalid)?;
        if source_id.to_string() != source {
            return Err(Fault::Invalid.into());
        }
        let resource = Resource {
            namespace: consumer.into(),
            reference: format!("{source}/{digest}"),
            revision: "1".into(),
        };
        let path = format!("/integration/v1/evidence/{source}/attachments/{digest}");
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &SignedRequest {
                    headers: &headers,
                    body: b"",
                },
                auth::EVIDENCE,
                &path,
                "GET",
                &Target {
                    consumer,
                    intent: source,
                    operation: "read-attachment",
                    resource: &resource,
                    fingerprint: &sha256(b""),
                    root: None,
                },
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        let row = sqlx::query("SELECT a.evidence,a.bytes,n.retain_until FROM native_attachments a JOIN native_inputs n USING(consumer_id,source_id) WHERE a.consumer_id=$1 AND a.source_id=$2 AND a.byte_sha256=$3 AND n.module_id=$4 AND n.context_domain=$5 AND n.retain_until>clock_timestamp() LIMIT 1")
            .bind(consumer).bind(source_id).bind(digest).bind(&claims.module_id).bind(&claims.context_domain)
            .fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        let retained_until = row.try_get::<chrono::DateTime<chrono::Utc>, _>("retain_until")?;
        let evidence = row.try_get::<Json<Evidence>, _>("evidence")?.0;
        let bytes = row.try_get::<Vec<u8>, _>("bytes")?;
        if evidence.sha256 != digest {
            return Err(Fault::Unknown.into());
        }
        validate_bytes(&evidence, &bytes)?;
        current(&claims, retained_until, Self::now(&mut tx).await?)?;
        tx.commit().await?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bytes_need_exact_digest_size_and_profile_bound() {
        let mut evidence = Evidence {
            source_id: "attachment".into(),
            sha256: sha256(b"original"),
            media_type: "image/png".into(),
            size_bytes: 8,
            release_ref: "release".into(),
        };
        assert!(validate_bytes(&evidence, b"original").is_ok());
        assert!(validate_bytes(&evidence, b"changed!").is_err());
        assert!(validate_bytes(&evidence, b"original-extra").is_err());
        evidence.size_bytes = MAX_ATTACHMENT_BYTES as u64 + 1;
        assert!(validate_bytes(&evidence, b"original").is_err());
    }
}
