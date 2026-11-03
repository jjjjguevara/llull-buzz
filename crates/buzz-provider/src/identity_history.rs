//! A separately authorized historical read, never a replay of enrollment admission.
use crate::{
    auth::{self, Claims, Headers},
    db::{CommandResult, Provider, Result},
    identity::Binding,
};
use llull_buzz_wire::{Command, Enroll, Fault, ProveKey, Resource};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityResultQuery {
    original_command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalIdentityResult {
    pub consumer_id: String,
    pub module_id: String,
    pub context_domain: String,
    pub operation: String,
    pub intent_id: String,
    pub request_sha256: String,
    pub resource: Resource,
    pub original_result: CommandResult,
    pub current_binding: Option<Binding>,
}

impl Provider {
    pub async fn identity_result(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<HistoricalIdentityResult> {
        let read: Command = Self::decode(body)?;
        if read.operation != "read-identity-result" {
            return Err(Fault::Unavailable.into());
        }
        let query: IdentityResultQuery = read.payload()?;
        let original = query.original_command;
        original.validate()?;
        if !matches!(original.operation.as_str(), "enroll" | "prove-key")
            || original.consumer_id != read.consumer_id
            || original.resource != read.resource
            || original.correlation_id != read.correlation_id
            || original.intent_id != read.causation_id
        {
            return Err(Fault::Denied.into());
        }
        let fingerprint = original.fingerprint()?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &read,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/identity-results",
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        if claims.delegation_id.is_some()
            || claims.root_task_id.is_some()
            || claims.grant_revision.is_some()
            || !claims.verdicts.is_empty()
            || claims.release.is_some()
        {
            return Err(Fault::Denied.into());
        }
        let browser = claims.browser(true, Self::now(&mut tx).await?.timestamp())?;
        // Both records are immutable and committed with the original command.
        // A journal/snapshot metadata observation is deliberately insufficient.
        let row = sqlx::query("SELECT request_sha256,result FROM commands WHERE consumer_id=$1 AND operation=$2 AND intent_id=$3")
            .bind(&original.consumer_id).bind(&original.operation).bind(&original.intent_id)
            .fetch_optional(&mut *tx).await?.ok_or(Fault::Unknown)?;
        if row.try_get::<String, _>("request_sha256")? != fingerprint {
            return Err(Fault::Conflict.into());
        }
        let result = row
            .try_get::<sqlx::types::Json<CommandResult>, _>("result")?
            .0;
        let admitted: Claims = sqlx::query_scalar::<_, sqlx::types::Json<Claims>>(
            "SELECT claims FROM admission_evidence WHERE consumer_id=$1 AND request_sha256=$2 AND purpose=$3 AND claims->>'intent_id'=$4 AND claims->>'operation'=$5 ORDER BY recorded_at, jti LIMIT 1")
            .bind(&original.consumer_id).bind(&fingerprint).bind(auth::INVOCATION)
            .bind(&original.intent_id).bind(&original.operation)
            .fetch_optional(&mut *tx).await?.ok_or(Fault::Unknown)?.0;
        if admitted.module_id != claims.module_id
            || admitted.context_domain != claims.context_domain
            || admitted.resource != original.resource
            || admitted.payload_sha256 != fingerprint
            || result.receipt.consumer_id != original.consumer_id
            || result.receipt.intent_id != original.intent_id
            || result.receipt.request_sha256 != fingerprint
        {
            return Err(Fault::Denied.into());
        }
        let enrollment_id = &result.receipt.operation_id;
        let fixed: Enroll = sqlx::query_scalar::<_, sqlx::types::Json<Enroll>>(
            "SELECT requested FROM enrollment_challenges WHERE consumer_id=$1 AND enrollment_id=$2",
        )
        .bind(&original.consumer_id)
        .bind(enrollment_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Fault::Unknown)?
        .0;
        fixed.validate()?;
        if browser.issuer != fixed.issuer
            || browser.subject != fixed.subject
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
        if original.operation == "enroll" {
            let requested: Enroll = original.payload()?;
            if llull_buzz_wire::digest(&requested)? != llull_buzz_wire::digest(&fixed)? {
                return Err(Fault::Denied.into());
            }
        } else {
            let proof: ProveKey = original.payload()?;
            if original.resource.reference != *enrollment_id
                || proof.enrollment_id != *enrollment_id
            {
                return Err(Fault::Denied.into());
            }
        }
        let binding: Option<Binding> = sqlx::query_as(
            "SELECT * FROM enrollments WHERE consumer_id=$1 AND enrollment_id=$2 FOR UPDATE",
        )
        .bind(&original.consumer_id)
        .bind(enrollment_id)
        .fetch_optional(&mut *tx)
        .await?;
        if original.operation == "prove-key" && binding.is_none() {
            return Err(Fault::Unknown.into());
        }
        if let Some(binding) = &binding {
            if !binding.active
                || binding.key_retired
                || binding.module_id != fixed.module_id
                || binding.issuer != fixed.issuer
                || binding.subject != fixed.subject
                || binding.native_key != fixed.intended_public_key
            {
                return Err(Fault::Denied.into());
            }
        }
        let response = HistoricalIdentityResult {
            consumer_id: original.consumer_id,
            module_id: admitted.module_id,
            context_domain: admitted.context_domain,
            operation: original.operation,
            intent_id: original.intent_id,
            request_sha256: fingerprint,
            resource: original.resource,
            original_result: result,
            current_binding: binding,
        };
        // Current authority expires independently of every original deadline.
        // No remember(), replay(), challenge consumption or binding mutation.
        let now = Self::now(&mut tx).await?.timestamp();
        claims.fresh(now)?;
        claims.browser(true, now)?;
        tx.commit().await?;
        Ok(response)
    }
}
