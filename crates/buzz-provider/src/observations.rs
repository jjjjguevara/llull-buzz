//! Content-minimal scoped observation journal with authenticated reconnect cursors.
use crate::{
    auth::{self, Claims, Headers, SignedRequest, Target},
    db::Tx,
    CommandResult, Provider, Result,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use llull_buzz_wire::{id, parse, sha256, Command, Execution, Fault, Resource, PROFILE};
use serde::{Deserialize, Serialize};
use sqlx::{types::Json, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationQuery {
    pub cursor: Option<String>,
    pub limit: Option<u16>,
}
impl ObservationQuery {
    /// Canonical URL spelling is signed by NIP-98, including the query string.
    pub fn path(&self) -> llull_buzz_wire::Result<String> {
        if self.limit.is_some_and(|n| n == 0 || n > 100)
            || self
                .cursor
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 2048)
        {
            return Err(Fault::Invalid);
        }
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(cursor) = &self.cursor {
            query.append_pair("cursor", cursor);
        }
        if let Some(limit) = self.limit {
            query.append_pair("limit", &limit.to_string());
        }
        let query = query.finish();
        Ok(format!(
            "/integration/v1/observations{}{}",
            if query.is_empty() { "" } else { "?" },
            query
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub sequence: u64,
    pub operation: String,
    pub operation_id: String,
    pub resource: Resource,
    pub execution: Execution,
    pub revision: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationPage {
    pub observations: Vec<Observation>,
    pub cursor: String,
    pub committed_high_water: u64,
    pub recovery_epoch: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgment {
    cursor: String,
    durable_receipt_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    profile: String,
    consumer: String,
    module: String,
    context: String,
    epoch: u64,
    after: u64,
    through: u64,
    exp: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorHeader {
    alg: String,
    typ: String,
    kid: String,
}

impl Provider {
    async fn insert_observation(
        tx: &mut Tx,
        consumer: &str,
        module: &str,
        context: &str,
        mut event: Observation,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO observation_counters(consumer_id) VALUES($1) ON CONFLICT DO NOTHING",
        )
        .bind(consumer)
        .execute(&mut **tx)
        .await?;
        let sequence:i64=sqlx::query_scalar("UPDATE observation_counters SET next_sequence=next_sequence+1 WHERE consumer_id=$1 RETURNING next_sequence")
            .bind(consumer).fetch_one(&mut **tx).await?;
        event.sequence = sequence as u64;
        sqlx::query("INSERT INTO observations(consumer_id,sequence,module_id,context_domain,record) VALUES($1,$2,$3,$4,$5)")
            .bind(consumer).bind(sequence).bind(module).bind(context)
            .bind(Json(&event)).execute(&mut **tx).await?;
        Ok(())
    }

    pub(crate) async fn journal(
        tx: &mut Tx,
        c: &Command,
        claims: &Claims,
        response: &CommandResult,
    ) -> Result<()> {
        if matches!(
            c.operation.as_str(),
            "ack-observations" | "create-snapshot" | "ack-snapshot"
        ) {
            return Ok(());
        }
        let event = Observation {
            sequence: 0,
            operation: c.operation.clone(),
            operation_id: response.receipt.operation_id.clone(),
            resource: c.resource.clone(),
            execution: response.receipt.execution,
            revision: response.receipt.revision,
        };
        Self::insert_observation(
            tx,
            &c.consumer_id,
            &claims.module_id,
            &claims.context_domain,
            event,
        )
        .await
    }

    /// System-side effect transitions use the original attempt identity and
    /// root scope. They are inserted atomically with the attempt state change.
    pub(crate) async fn journal_effect_transition(
        tx: &mut Tx,
        consumer: &str,
        module: &str,
        context: &str,
        attempt_id: Uuid,
        execution: Execution,
        revision: u64,
    ) -> Result<()> {
        let event = Observation {
            sequence: 0,
            operation: "effect-outcome".into(),
            operation_id: attempt_id.to_string(),
            resource: Resource {
                namespace: consumer.into(),
                reference: attempt_id.to_string(),
                revision: "1".into(),
            },
            execution,
            revision,
        };
        Self::insert_observation(tx, consumer, module, context, event).await
    }

    async fn decode_cursor(
        tx: &mut Tx,
        token: &str,
        consumer: &str,
        claims: &Claims,
    ) -> Result<Cursor> {
        if token.len() > 2048 {
            return Err(Fault::Invalid.into());
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Fault::Denied.into());
        }
        let header: CursorHeader = parse(
            &URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|_| Fault::Denied)?,
        )?;
        if header.alg != "HS256" || header.typ != "bz-observation-cursor+jwt" {
            return Err(Fault::Denied.into());
        }
        let key_id = Uuid::parse_str(&header.kid).map_err(|_| Fault::Denied)?;
        let key:Vec<u8>=sqlx::query_scalar("SELECT secret FROM observation_keys WHERE key_id=$1 AND (active OR verify_until>clock_timestamp())")
            .bind(key_id).fetch_optional(&mut **tx).await?.ok_or(Fault::Denied)?;
        let _: Cursor = parse(
            &URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|_| Fault::Denied)?,
        )?;
        let mut policy = Validation::new(Algorithm::HS256);
        policy.validate_exp = false;
        policy.validate_aud = false;
        let cursor =
            jsonwebtoken::decode::<Cursor>(token, &DecodingKey::from_secret(&key), &policy)
                .map_err(|_| Fault::Denied)?
                .claims;
        if cursor.consumer != consumer
            || cursor.profile != PROFILE
            || cursor.module != claims.module_id
            || cursor.context != claims.context_domain
            || cursor.after > cursor.through
            || cursor.through > llull_buzz_wire::MAX_SAFE_INTEGER as u64
        {
            return Err(Fault::Denied.into());
        }
        if cursor.epoch != claims.recovery_epoch || cursor.exp <= Self::now(tx).await?.timestamp() {
            return Err(Fault::Gap.into());
        }
        Ok(cursor)
    }

    async fn encode_cursor(tx: &mut Tx, cursor: &Cursor) -> Result<String> {
        let row = sqlx::query("SELECT key_id,secret FROM observation_keys WHERE active")
            .fetch_one(&mut **tx)
            .await?;
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("bz-observation-cursor+jwt".into());
        header.kid = Some(row.try_get::<Uuid, _>("key_id")?.to_string());
        let key: Vec<u8> = row.try_get("secret")?;
        jsonwebtoken::encode(&header, cursor, &EncodingKey::from_secret(&key))
            .map_err(|_| Fault::Unavailable.into())
    }

    pub async fn observations(
        &self,
        consumer: &str,
        query: ObservationQuery,
        headers: Headers<'_>,
    ) -> Result<ObservationPage> {
        id(consumer)?;
        let path = query.path()?;
        let mut tx = self.begin().await?;
        let resource = Resource {
            namespace: consumer.into(),
            reference: "observations".into(),
            revision: "1".into(),
        };
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &SignedRequest {
                    headers: &headers,
                    body: b"",
                },
                auth::INVOCATION,
                &path,
                "GET",
                &Target {
                    consumer,
                    intent: "observations",
                    operation: "observe",
                    resource: &resource,
                    fingerprint: &sha256(b""),
                    root: None,
                },
            )
            .await?;
        // Consumer observation delivery is service-owned. Native human reads use
        // their artifact gates; a consumer subscription cannot impersonate them.
        self.service_scope(&registration, &claims)?;
        let offset = Self::observation_offset(&mut tx, consumer, &claims).await?;
        let after = if let Some(cursor) = &query.cursor {
            Self::decode_cursor(&mut tx, cursor, consumer, &claims)
                .await?
                .through
        } else {
            offset
        };
        let (high_water, retained): (i64, i64) = sqlx::query_as(
            "SELECT next_sequence,retained_after FROM observation_counters WHERE consumer_id=$1",
        )
        .bind(consumer)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or((0, 0));
        if after < (retained as u64) {
            return Err(Fault::Gap.into());
        }
        if after > high_water as u64 {
            return Err(Fault::Conflict.into());
        }
        let limit = query.limit.unwrap_or(100) as i64;
        let rows:Vec<Json<Observation>>=sqlx::query_scalar("SELECT record FROM observations WHERE consumer_id=$1 AND module_id=$2 AND context_domain=$3 AND sequence>$4 AND sequence<=$5 ORDER BY sequence LIMIT $6")
            .bind(consumer).bind(&claims.module_id).bind(&claims.context_domain).bind(after as i64)
            .bind(high_water).bind(limit+1).fetch_all(&mut *tx).await?;
        let has_more = rows.len() > limit as usize;
        let observations: Vec<_> = rows.into_iter().take(limit as usize).map(|v| v.0).collect();
        let through = if has_more {
            observations.last().ok_or(Fault::Conflict)?.sequence
        } else {
            high_water as u64
        };
        let now = Self::now(&mut tx).await?.timestamp();
        let cursor = Self::encode_cursor(
            &mut tx,
            &Cursor {
                profile: PROFILE.into(),
                consumer: consumer.into(),
                module: claims.module_id.clone(),
                context: claims.context_domain.clone(),
                epoch: self.external_epoch,
                after,
                through,
                exp: now + 86_400,
            },
        )
        .await?;
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        tx.commit().await?;
        Ok(ObservationPage {
            observations,
            cursor,
            committed_high_water: high_water as u64,
            recovery_epoch: self.external_epoch,
        })
    }

    pub(crate) async fn observation_offset(
        tx: &mut Tx,
        consumer: &str,
        claims: &Claims,
    ) -> Result<u64> {
        sqlx::query("INSERT INTO observation_offsets(consumer_id,module_id,context_domain,recovery_epoch) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(consumer).bind(&claims.module_id).bind(&claims.context_domain).bind(claims.recovery_epoch as i64).execute(&mut **tx).await?;
        let offset:i64=sqlx::query_scalar("SELECT acknowledged FROM observation_offsets WHERE consumer_id=$1 AND module_id=$2 AND context_domain=$3 AND recovery_epoch=$4 FOR UPDATE")
            .bind(consumer).bind(&claims.module_id).bind(&claims.context_domain).bind(claims.recovery_epoch as i64).fetch_one(&mut **tx).await?;
        Ok(offset as u64)
    }

    pub async fn ack_observations(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "ack-observations" {
            return Err(Fault::Unavailable.into());
        }
        if c.resource.reference != "observations" || c.resource.revision != "1" {
            return Err(Fault::Conflict.into());
        }
        let ack: Acknowledgment = c.payload()?;
        id(&ack.durable_receipt_id)?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/observation-acks",
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let cursor = Self::decode_cursor(&mut tx, &ack.cursor, &c.consumer_id, &claims).await?;
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        let digest = sha256(ack.cursor.as_bytes());
        let existing:Option<String>=sqlx::query_scalar("SELECT durable_receipt_id FROM observation_receipts WHERE consumer_id=$1 AND cursor_sha256=$2")
            .bind(&c.consumer_id).bind(&digest).fetch_optional(&mut *tx).await?;
        match existing {
            Some(receipt) if receipt != ack.durable_receipt_id => {
                return Err(Fault::Conflict.into())
            }
            Some(_) => (),
            None => {
                let reused: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM observation_receipts WHERE consumer_id=$1 AND durable_receipt_id=$2)")
                    .bind(&c.consumer_id).bind(&ack.durable_receipt_id).fetch_one(&mut *tx).await?;
                if reused {
                    return Err(Fault::Conflict.into());
                }
                let offset = Self::observation_offset(&mut tx, &c.consumer_id, &claims).await?;
                if offset != cursor.after {
                    return Err(Fault::Conflict.into());
                }
                sqlx::query("INSERT INTO observation_receipts(consumer_id,module_id,context_domain,recovery_epoch,cursor_sha256,durable_receipt_id,acknowledged) VALUES($1,$2,$3,$4,$5,$6,$7)")
                    .bind(&c.consumer_id).bind(&claims.module_id).bind(&claims.context_domain).bind(claims.recovery_epoch as i64)
                    .bind(digest).bind(&ack.durable_receipt_id).bind(cursor.through as i64).execute(&mut *tx).await?;
                sqlx::query("UPDATE observation_offsets SET acknowledged=$5 WHERE consumer_id=$1 AND module_id=$2 AND context_domain=$3 AND recovery_epoch=$4")
                    .bind(&c.consumer_id).bind(&claims.module_id).bind(&claims.context_domain).bind(claims.recovery_epoch as i64)
                    .bind(cursor.through as i64).execute(&mut *tx).await?;
            }
        }
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result=Self::remember(&mut tx,(&c,&claims),ack.durable_receipt_id.clone(),Execution::Completed,1,
            serde_json::json!({"acknowledged":cursor.through,"durable_receipt_id":ack.durable_receipt_id,"purged":false})).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Trusted operator-only rotation. Old keys verify outstanding 24-hour cursors.
    pub async fn rotate_observation_key(&self) -> Result<Uuid> {
        let mut tx = self.begin().await?;
        sqlx::query("UPDATE observation_keys SET active=false,verify_until=clock_timestamp()+interval '1 day' WHERE active").execute(&mut *tx).await?;
        let key:Uuid=sqlx::query_scalar("INSERT INTO observation_keys(key_id,secret,active) VALUES(gen_random_uuid(),decode(replace(gen_random_uuid()::text||gen_random_uuid()::text,'-',''),'hex'),true) RETURNING key_id")
            .fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(key)
    }
}
