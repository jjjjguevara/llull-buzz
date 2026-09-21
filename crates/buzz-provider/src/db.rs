use crate::auth::{self, Claims, Headers, Registration, Target};
use buzz_auth::Nip98ReplayGuard;
use chrono::{DateTime, Utc};
use llull_buzz_wire::{digest, Admission, Command, Execution, Fault, Receipt, CONTRACT, PROFILE};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};
use std::{future::Future, pin::Pin};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error(transparent)]
    Admission(#[from] Fault),
    #[error("provider persistence unavailable")]
    Storage(#[from] sqlx::Error),
    #[error("provider migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
}
pub type Result<T> = std::result::Result<T, ProviderError>;
pub(crate) type Tx = Transaction<'static, Postgres>;

#[derive(Clone)]
pub struct Provider {
    pub(crate) pool: PgPool,
    public_origin: String,
    pub(crate) external_epoch: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResult {
    pub receipt: Receipt,
    pub result: serde_json::Value,
    pub replayed: bool,
}
impl Provider {
    pub fn new(pool: PgPool, public_origin: &str, external_epoch: u64) -> Result<Self> {
        if external_epoch == 0 || external_epoch > llull_buzz_wire::MAX_SAFE_INTEGER as u64 {
            return Err(Fault::Invalid.into());
        }
        auth::https_origin(public_origin)?;
        Ok(Self {
            pool,
            public_origin: public_origin.trim_end_matches('/').into(),
            external_epoch,
        })
    }
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        Ok(())
    }
    /// Operator-only bootstrap/update interface. Not exposed by the HTTP router or MCP.
    /// Callers hold deployment-admin authority, independently of consumer credentials.
    pub async fn register(
        &self,
        registration: Registration,
        expected_digest: Option<&str>,
    ) -> Result<String> {
        registration.validate()?;
        let fingerprint = digest(&registration)?;
        let mut tx = self.begin().await?;
        let existing = sqlx::query("SELECT registration_sha256, revision FROM consumer_registry WHERE consumer_id = $1 FOR UPDATE")
            .bind(&registration.consumer_id).fetch_optional(&mut *tx).await?;
        match existing {
            None => {
                if expected_digest.is_some() || registration.revision != 1 {
                    return Err(Fault::Conflict.into());
                }
                sqlx::query("INSERT INTO consumer_registry(consumer_id, revision, registration, registration_sha256) VALUES ($1,$2,$3,$4)")
                    .bind(&registration.consumer_id).bind(registration.revision as i64)
                    .bind(sqlx::types::Json(&registration)).bind(&fingerprint).execute(&mut *tx).await?;
            }
            Some(row) => {
                let old: String = row.try_get("registration_sha256")?;
                let revision: i64 = row.try_get("revision")?;
                if expected_digest != Some(old.as_str())
                    || registration.revision != revision as u64 + 1
                {
                    return Err(Fault::Conflict.into());
                }
                sqlx::query("UPDATE consumer_registry SET revision=$2, registration=$3, registration_sha256=$4 WHERE consumer_id=$1")
                    .bind(&registration.consumer_id).bind(registration.revision as i64).bind(sqlx::types::Json(&registration)).bind(&fingerprint).execute(&mut *tx).await?;
                self.fence_consumer(&mut tx, &registration.consumer_id)
                    .await?;
            }
        }
        sqlx::query("INSERT INTO registration_history(consumer_id,revision,active,registration) SELECT consumer_id,revision,active,registration FROM consumer_registry WHERE consumer_id=$1")
            .bind(&registration.consumer_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(fingerprint)
    }
    /// Operator-only service deactivation/reactivation with optimistic policy identity.
    /// Reactivation requires a newly registered revision, not re-use of old assertions.
    pub async fn set_service_active(
        &self,
        consumer: &str,
        active: bool,
        expected_digest: &str,
    ) -> Result<()> {
        let mut tx = self.begin().await?;
        let row=sqlx::query("SELECT registration,registration_sha256,active FROM consumer_registry WHERE consumer_id=$1 FOR UPDATE")
            .bind(consumer).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        if row.try_get::<String, _>("registration_sha256")? != expected_digest
            || row.try_get::<bool, _>("active")? == active
        {
            return Err(Fault::Conflict.into());
        }
        let mut config = row
            .try_get::<sqlx::types::Json<Registration>, _>("registration")?
            .0;
        config.revision = config.revision.checked_add(1).ok_or(Fault::Exhausted)?;
        config.authority_epoch = config
            .authority_epoch
            .checked_add(1)
            .ok_or(Fault::Exhausted)?;
        config.validate()?;
        sqlx::query("UPDATE consumer_registry SET active=$2,revision=$3,registration=$4,registration_sha256=$5 WHERE consumer_id=$1")
            .bind(consumer).bind(active).bind(config.revision as i64).bind(sqlx::types::Json(&config)).bind(digest(&config)?).execute(&mut *tx).await?;
        self.fence_consumer(&mut tx, consumer).await?;
        sqlx::query("INSERT INTO registration_history(consumer_id,revision,active,registration) SELECT consumer_id,revision,active,registration FROM consumer_registry WHERE consumer_id=$1")
            .bind(consumer).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn begin(&self) -> Result<Tx> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '10s'")
            .execute(&mut *tx)
            .await?;
        // Initial four-root deployment: one ordered admission lock avoids lock-order
        // races across enrollment, capacity, reservations and restore. This is not a
        // throughput claim. Do not remove it without equivalent concurrency tests.
        sqlx::query("SELECT recovery_epoch FROM provider_control WHERE singleton=1 FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
        Ok(tx)
    }
    pub(crate) async fn now(tx: &mut Tx) -> Result<DateTime<Utc>> {
        Ok(sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **tx)
            .await?)
    }
    pub(crate) async fn epoch(tx: &mut Tx) -> Result<u64> {
        let epoch: i64 =
            sqlx::query_scalar("SELECT recovery_epoch FROM provider_control WHERE singleton=1")
                .fetch_one(&mut **tx)
                .await?;
        Ok(epoch as u64)
    }
    pub(crate) async fn authorize(
        &self,
        tx: &mut Tx,
        headers: &Headers<'_>,
        purpose: &str,
        path: &str,
        method: &str,
        body: &[u8],
        target: &Target<'_>,
    ) -> Result<(Registration, Claims)> {
        if !path.starts_with('/') || path.contains('?') || path.contains('#') {
            return Err(Fault::Invalid.into());
        }
        let row = sqlx::query(
            "SELECT registration, active FROM consumer_registry WHERE consumer_id=$1 FOR UPDATE",
        )
        .bind(target.consumer)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Fault::Denied)?;
        if !row.try_get::<bool, _>("active")? {
            return Err(Fault::Denied.into());
        }
        let registration: Registration = row
            .try_get::<sqlx::types::Json<Registration>, _>("registration")?
            .0;
        let now = Self::now(tx).await?;
        let verified = auth::verify(
            &registration,
            headers,
            purpose,
            &format!("{}{path}", self.public_origin),
            method,
            body,
            target,
            now.timestamp(),
        )?;
        if verified.claims.recovery_epoch != Self::epoch(tx).await?
            || verified.claims.recovery_epoch != self.external_epoch
        {
            return Err(Fault::Denied.into());
        }
        {
            let guard = TransactionReplayGuard {
                connection: Mutex::new(&mut **tx),
            };
            let scope = digest(&(target.consumer, &registration.community_id))?;
            let fresh = guard
                .try_mark_in_scope(&scope, &verified.native_event_id, 120)
                .await
                .map_err(|_| Fault::Denied)?;
            if !fresh {
                return Err(Fault::Denied.into());
            }
        }
        let inserted = sqlx::query("INSERT INTO assertion_replays(consumer_id,issuer,jti,expires_at) VALUES ($1,$2,$3,to_timestamp($4::double precision)) ON CONFLICT DO NOTHING")
            .bind(target.consumer).bind(&verified.claims.iss).bind(&verified.claims.jti).bind(verified.claims.exp as f64).execute(&mut **tx).await?;
        if inserted.rows_affected() != 1 {
            return Err(Fault::Denied.into());
        }
        sqlx::query("INSERT INTO admission_evidence(consumer_id,issuer,jti,purpose,request_sha256,target_path,method,native_event_id,native_authorization,invocation_jws,registration_snapshot,claims) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
            .bind(target.consumer).bind(&verified.claims.iss).bind(&verified.claims.jti).bind(purpose).bind(target.fingerprint).bind(path).bind(method)
            .bind(verified.native_event_id.to_hex()).bind(headers.authorization).bind(headers.invocation)
            .bind(sqlx::types::Json(&registration)).bind(sqlx::types::Json(&verified.claims)).execute(&mut **tx).await?;
        verified.claims.fresh(Self::now(tx).await?.timestamp())?;
        Ok((registration, verified.claims))
    }
    pub(crate) async fn authorize_command(
        &self,
        tx: &mut Tx,
        c: &Command,
        headers: &Headers<'_>,
        path: &str,
        body: &[u8],
        root: Option<&str>,
        purpose: &str,
    ) -> Result<(Registration, Claims)> {
        c.validate()?;
        let fingerprint = c.fingerprint()?;
        self.authorize(
            tx,
            headers,
            purpose,
            path,
            "POST",
            body,
            &Target {
                consumer: &c.consumer_id,
                intent: &c.intent_id,
                operation: &c.operation,
                resource: &c.resource,
                fingerprint: &fingerprint,
                root,
            },
        )
        .await
    }
    pub(crate) async fn replay(tx: &mut Tx, c: &Command) -> Result<Option<CommandResult>> {
        let row = sqlx::query("SELECT request_sha256,result FROM commands WHERE consumer_id=$1 AND operation=$2 AND intent_id=$3")
            .bind(&c.consumer_id).bind(&c.operation).bind(&c.intent_id).fetch_optional(&mut **tx).await?;
        match row {
            None => Ok(None),
            Some(row) => {
                if row.try_get::<String, _>("request_sha256")? != c.fingerprint()? {
                    return Err(Fault::Conflict.into());
                }
                let mut result: CommandResult = row
                    .try_get::<sqlx::types::Json<CommandResult>, _>("result")?
                    .0;
                result.replayed = true;
                Ok(Some(result))
            }
        }
    }
    pub(crate) async fn remember<T: Serialize>(
        tx: &mut Tx,
        c: &Command,
        operation_id: String,
        execution: Execution,
        revision: u64,
        result: T,
    ) -> Result<CommandResult> {
        let response = CommandResult {
            receipt: Receipt {
                contract: CONTRACT.into(),
                profile: PROFILE.into(),
                consumer_id: c.consumer_id.clone(),
                intent_id: c.intent_id.clone(),
                operation_id,
                request_sha256: c.fingerprint()?,
                admission: Admission::Accepted,
                execution,
                revision,
                effect_refs: vec![],
            },
            result: serde_json::to_value(result).map_err(|_| Fault::Invalid)?,
            replayed: false,
        };
        sqlx::query("INSERT INTO commands(consumer_id,operation,intent_id,request_sha256,result) VALUES ($1,$2,$3,$4,$5)")
            .bind(&c.consumer_id).bind(&c.operation).bind(&c.intent_id).bind(&response.receipt.request_sha256)
            .bind(sqlx::types::Json(&response)).execute(&mut **tx).await?;
        Ok(response)
    }
    pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        Ok(llull_buzz_wire::parse(bytes)?)
    }
}

/// The pinned upstream replay-guard trait, backed by the *same* provider transaction.
/// It is neither an in-process seen-set nor a second connection that could deadlock
/// a one-connection pool. Scope comes from trusted consumer/community registration.
struct TransactionReplayGuard<'c> {
    connection: Mutex<&'c mut PgConnection>,
}
impl Nip98ReplayGuard for TransactionReplayGuard<'_> {
    fn try_mark_in_scope<'a>(
        &'a self,
        scope: &'a str,
        event_id: &'a nostr::EventId,
        ttl_secs: u64,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<bool, buzz_auth::error::AuthError>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let ttl = ttl_secs.clamp(
                buzz_auth::DEFAULT_REPLAY_TTL_SECS,
                buzz_auth::MAX_REPLAY_TTL_SECS,
            ) as i64;
            let mut connection = self.connection.lock().await;
            let result = sqlx::query("INSERT INTO resource_replays(scope,event_id,expires_at) VALUES ($1,$2,clock_timestamp()+($3::bigint * interval '1 second')) ON CONFLICT(scope,event_id) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE resource_replays.expires_at <= clock_timestamp()")
                .bind(scope).bind(event_id.to_hex()).bind(ttl).execute(&mut **connection).await
                .map_err(|_| buzz_auth::error::AuthError::Internal("durable replay guard unavailable".into()))?;
            Ok(result.rows_affected() == 1)
        })
    }
}
