use crate::{
    auth::{self, Claims, Headers, Registration},
    db::{CommandResult, Provider, Result, Tx},
    native,
};
use chrono::{DateTime, Duration, Utc};
use llull_buzz_wire::{AccessChange, ChangeAccess, Command, Enroll, Execution, Fault, ProveKey};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Binding {
    pub enrollment_id: String,
    pub consumer_id: String,
    pub module_id: String,
    pub issuer: String,
    pub subject: String,
    pub native_key: String,
    pub revision: i64,
    pub authority_epoch: i64,
    pub active: bool,
    pub key_retired: bool,
    pub proof_event_id: String,
    pub proof_event: serde_json::Value,
    pub created_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentChallenge {
    pub enrollment_id: String,
    pub challenge: String,
    pub community_id: String,
    pub channel_id: String,
    pub bot_public_key: String,
    pub message_text: String,
    pub expires_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetireKey {
    enrollment_id: String,
    expected_revision: String,
}

impl Provider {
    pub async fn enroll(&self, body: &[u8], headers: Headers<'_>) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "enroll" {
            return Err(Fault::Unavailable.into());
        }
        let request: Enroll = c.payload()?;
        request.validate()?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &headers,
                "/integration/v1/enrollments",
                body,
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let now = Self::now(&mut tx).await?;
        let browser = claims.browser(true, now.timestamp())?;
        let module = registration
            .modules
            .get(&request.module_id)
            .ok_or(Fault::Denied)?;
        if request.community_id != registration.community_id
            || request.module_id != claims.module_id
            || request.issuer != browser.issuer
            || request.subject != browser.subject
            || request.browser_transaction_id != browser.transaction_id
            || !module.principal_issuers.contains(&request.issuer)
        {
            return Err(Fault::Denied.into());
        }
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        let enrollment_id = uuid::Uuid::new_v4().to_string();
        // Two independent OS-backed v4 UUIDs: 244 unpredictable bits, no custom RNG.
        let challenge = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let expiry = (now + Duration::seconds(300))
            .min(DateTime::from_timestamp(browser.expires_at, 0).ok_or(Fault::Denied)?);
        let response = EnrollmentChallenge {
            enrollment_id: enrollment_id.clone(),
            challenge: challenge.clone(),
            community_id: registration.community_id.clone(),
            channel_id: registration.enrollment_channel.clone(),
            bot_public_key: registration.enrollment_bot_key.clone(),
            message_text: native::enrollment_text(
                &c.consumer_id,
                &registration.community_id,
                &enrollment_id,
                &challenge,
            ),
            expires_at: expiry,
        };
        sqlx::query("INSERT INTO enrollment_challenges(enrollment_id,consumer_id,requested,challenge,request_sha256,issued_at,expires_at,recovery_epoch,registration_revision) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(&enrollment_id).bind(&c.consumer_id).bind(sqlx::types::Json(&request)).bind(&challenge).bind(c.fingerprint()?).bind(now).bind(expiry).bind(claims.recovery_epoch as i64).bind(registration.revision as i64).execute(&mut *tx).await?;
        let final_now = Self::now(&mut tx).await?.timestamp();
        claims.fresh(final_now)?;
        claims.browser(true, final_now)?;
        let result =
            Self::remember(&mut tx, &c, enrollment_id, Execution::Pending, 1, &response).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn prove_key(
        &self,
        enrollment_id: &str,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        llull_buzz_wire::id(enrollment_id)?;
        let c: Command = Self::decode(body)?;
        if c.operation != "prove-key" {
            return Err(Fault::Unavailable.into());
        }
        let request: ProveKey = c.payload()?;
        if c.resource.reference != enrollment_id
            || c.resource.revision != "1"
            || request.enrollment_id != enrollment_id
        {
            return Err(Fault::Conflict.into());
        }
        let proof = native::event(&llull_buzz_wire::canonical(&request.native_event)?)?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &headers,
                &format!(
                    "/integration/v1/enrollments/{}/proof",
                    crate::native::segment(enrollment_id)?
                ),
                body,
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let now = Self::now(&mut tx).await?;
        let browser = claims.browser(false, now.timestamp())?;
        let row = sqlx::query("SELECT requested,challenge,issued_at,expires_at,consumed_at,recovery_epoch,registration_revision FROM enrollment_challenges WHERE consumer_id=$1 AND enrollment_id=$2 FOR UPDATE")
            .bind(&c.consumer_id).bind(enrollment_id).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        if row.try_get::<i64, _>("recovery_epoch")? as u64 != claims.recovery_epoch
            || row.try_get::<i64, _>("registration_revision")? as u64 != registration.revision
        {
            return Err(Fault::Denied.into());
        }
        let fixed: Enroll = row.try_get::<sqlx::types::Json<Enroll>, _>("requested")?.0;
        if browser.issuer != fixed.issuer
            || browser.subject != fixed.subject
            || browser.transaction_id != fixed.browser_transaction_id
            || claims.module_id != fixed.module_id
            || fixed.community_id != registration.community_id
            || !registration
                .modules
                .get(&fixed.module_id)
                .ok_or(Fault::Denied)?
                .principal_issuers
                .contains(&fixed.issuer)
        {
            return Err(Fault::Denied.into());
        }
        // An identical, authenticated command replay returns the original record.
        // A different intent cannot consume the same challenge/event again.
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        if row
            .try_get::<Option<DateTime<Utc>>, _>("consumed_at")?
            .is_some()
        {
            return Err(Fault::Denied.into());
        }
        let challenge: String = row.try_get("challenge")?;
        native::verify_enrollment_proof(
            &proof,
            &fixed.intended_public_key,
            &registration.enrollment_bot_key,
            &registration.enrollment_channel,
            &native::enrollment_text(
                &c.consumer_id,
                &fixed.community_id,
                enrollment_id,
                &challenge,
            ),
            row.try_get::<DateTime<Utc>, _>("issued_at")?.timestamp(),
            row.try_get::<DateTime<Utc>, _>("expires_at")?.timestamp(),
            now.timestamp(),
        )?;
        let previous: Vec<Binding> = sqlx::query_as("SELECT * FROM enrollments WHERE consumer_id=$1 AND module_id=$2 AND (issuer=$3 AND subject=$4 OR native_key=$5) FOR UPDATE")
            .bind(&c.consumer_id).bind(&fixed.module_id).bind(&fixed.issuer).bind(&fixed.subject).bind(&fixed.intended_public_key).fetch_all(&mut *tx).await?;
        if previous
            .iter()
            .any(|b| !b.key_retired || b.native_key == fixed.intended_public_key)
        {
            return Err(Fault::Denied.into());
        }
        let epoch = previous
            .iter()
            .map(|b| b.authority_epoch)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Fault::Exhausted)?;
        if epoch > llull_buzz_wire::MAX_SAFE_INTEGER {
            return Err(Fault::Exhausted.into());
        }
        let binding = Binding {
            enrollment_id: enrollment_id.into(),
            consumer_id: c.consumer_id.clone(),
            module_id: fixed.module_id,
            issuer: fixed.issuer,
            subject: fixed.subject,
            native_key: fixed.intended_public_key,
            revision: 1,
            authority_epoch: epoch,
            active: true,
            key_retired: false,
            proof_event_id: proof.id.to_hex(),
            proof_event: request.native_event,
            created_at: now,
        };
        sqlx::query("INSERT INTO enrollments(enrollment_id,consumer_id,module_id,issuer,subject,native_key,revision,authority_epoch,active,key_retired,proof_event_id,proof_event,created_at) VALUES ($1,$2,$3,$4,$5,$6,1,$7,true,false,$8,$9,$10)")
            .bind(&binding.enrollment_id).bind(&binding.consumer_id).bind(&binding.module_id).bind(&binding.issuer).bind(&binding.subject).bind(&binding.native_key).bind(epoch).bind(&binding.proof_event_id).bind(&binding.proof_event).bind(now).execute(&mut *tx).await?;
        let consumed = sqlx::query("UPDATE enrollment_challenges SET consumed_at=clock_timestamp() WHERE enrollment_id=$1 AND consumer_id=$2 AND consumed_at IS NULL AND expires_at > clock_timestamp()")
            .bind(enrollment_id).bind(&c.consumer_id).execute(&mut *tx).await?;
        if consumed.rows_affected() != 1 {
            return Err(Fault::Denied.into());
        }
        Self::history(&mut tx, &binding, "intended-key-proven").await?;
        let final_now = Self::now(&mut tx).await?.timestamp();
        claims.fresh(final_now)?;
        claims.browser(false, final_now)?;
        let result = Self::remember(
            &mut tx,
            &c,
            enrollment_id.into(),
            Execution::Completed,
            1,
            &binding,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn change_access(&self, body: &[u8], headers: Headers<'_>) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "change-access" {
            return Err(Fault::Unavailable.into());
        }
        let change: ChangeAccess = c.payload()?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &headers,
                "/integration/v1/access-changes",
                body,
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let mut binding = Self::binding(&mut tx, &c.consumer_id, &change.enrollment_id).await?;
        if binding.module_id != claims.module_id {
            return Err(Fault::Denied.into());
        }
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        if change.expected_revision != binding.revision.to_string()
            || c.resource.revision != change.expected_revision
            || c.resource.reference != change.enrollment_id
            || binding.key_retired
        {
            return Err(Fault::Conflict.into());
        }
        let active = change.change == AccessChange::Restore;
        if binding.active == active {
            return Err(Fault::Conflict.into());
        }
        binding.active = active;
        self.update_binding(
            &mut tx,
            &mut binding,
            if active {
                "access-restored"
            } else {
                "access-revoked"
            },
        )
        .await?;
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result = Self::remember(
            &mut tx,
            &c,
            binding.enrollment_id.clone(),
            Execution::Completed,
            binding.revision as u64,
            &binding,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    /// Additive foundation operation. Explicit fresh browser authentication is
    /// required before permanently retiring a lost key; access restore cannot undo it.
    pub async fn retire_key(&self, body: &[u8], headers: Headers<'_>) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "retire-key" {
            return Err(Fault::Unavailable.into());
        }
        let retire: RetireKey = c.payload()?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &headers,
                "/integration/foundation/v1/key-retirements",
                body,
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let mut binding = Self::binding(&mut tx, &c.consumer_id, &retire.enrollment_id).await?;
        let browser = claims.browser(true, Self::now(&mut tx).await?.timestamp())?;
        if binding.module_id != claims.module_id
            || browser.issuer != binding.issuer
            || browser.subject != binding.subject
        {
            return Err(Fault::Denied.into());
        }
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        if retire.expected_revision != binding.revision.to_string()
            || c.resource.reference != binding.enrollment_id
            || c.resource.revision != retire.expected_revision
            || binding.key_retired
        {
            return Err(Fault::Conflict.into());
        }
        binding.active = false;
        binding.key_retired = true;
        self.update_binding(&mut tx, &mut binding, "key-retired")
            .await?;
        claims.browser(true, Self::now(&mut tx).await?.timestamp())?;
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result = Self::remember(
            &mut tx,
            &c,
            binding.enrollment_id.clone(),
            Execution::Completed,
            binding.revision as u64,
            &binding,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) fn service_scope(&self, registration: &Registration, claims: &Claims) -> Result<()> {
        if claims.enrollment_id.is_some()
            || claims.enrollment_revision.is_some()
            || claims.represented_principal.is_some()
            || claims.authority_epoch != registration.authority_epoch
        {
            return Err(Fault::Denied.into());
        }
        Ok(())
    }
    pub(crate) async fn binding(tx: &mut Tx, consumer: &str, enrollment: &str) -> Result<Binding> {
        Ok(sqlx::query_as(
            "SELECT * FROM enrollments WHERE consumer_id=$1 AND enrollment_id=$2 FOR UPDATE",
        )
        .bind(consumer)
        .bind(enrollment)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Fault::Denied)?)
    }
    pub(crate) async fn scope(
        &self,
        tx: &mut Tx,
        registration: &Registration,
        claims: &Claims,
    ) -> Result<Option<Binding>> {
        match (&claims.enrollment_id, claims.enrollment_revision) {
            (None, None) => {
                self.service_scope(registration, claims)?;
                Ok(None)
            }
            (Some(id), Some(revision)) => {
                let binding = Self::binding(tx, &claims.consumer_id, id).await?;
                if !binding.active
                    || binding.key_retired
                    || binding.module_id != claims.module_id
                    || binding.revision as u64 != revision
                    || binding.authority_epoch as u64 != claims.authority_epoch
                    || claims.represented_principal.as_deref() != Some(binding.subject.as_str())
                {
                    return Err(Fault::Denied.into());
                }
                Ok(Some(binding))
            }
            _ => Err(Fault::Denied.into()),
        }
    }
    async fn update_binding(&self, tx: &mut Tx, binding: &mut Binding, action: &str) -> Result<()> {
        if binding.revision >= llull_buzz_wire::MAX_SAFE_INTEGER
            || binding.authority_epoch >= llull_buzz_wire::MAX_SAFE_INTEGER
        {
            return Err(Fault::Exhausted.into());
        }
        binding.revision += 1;
        binding.authority_epoch += 1;
        sqlx::query("UPDATE enrollments SET revision=$2,authority_epoch=$3,active=$4,key_retired=$5 WHERE enrollment_id=$1")
            .bind(&binding.enrollment_id).bind(binding.revision).bind(binding.authority_epoch).bind(binding.active).bind(binding.key_retired).execute(&mut **tx).await?;
        Self::history(tx, binding, action).await?;
        self.fence_enrollment(tx, &binding.consumer_id, &binding.enrollment_id)
            .await?;
        Ok(())
    }
    async fn history(tx: &mut Tx, binding: &Binding, action: &str) -> Result<()> {
        sqlx::query("INSERT INTO enrollment_history(enrollment_id,revision,record,action) VALUES ($1,$2,$3,$4)")
            .bind(&binding.enrollment_id).bind(binding.revision).bind(sqlx::types::Json(binding)).bind(action).execute(&mut **tx).await?;
        Ok(())
    }
}
