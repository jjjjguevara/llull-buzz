//! Durable model-budget reservation and signed gateway accounting DTOs. No model
//! transport or credentials exist here; independent gateway counting is required.
use crate::{
    auth::{self, Headers},
    Provider, Result,
};
use chrono::{DateTime, Utc};
use llull_buzz_wire::{Charge, Command, Execution, Fault};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pricing {
    pub revision: String,
    pub model_profile: String,
    pub checked_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// Worst-case rates, including applicable cache-write and reasoning premiums.
    pub input_usd_micros_per_million: u64,
    pub output_usd_micros_per_million: u64,
}
impl Pricing {
    pub fn validate(&self) -> llull_buzz_wire::Result<()> {
        llull_buzz_wire::id(&self.revision)?;
        if self.model_profile != "sonnet-5-adaptive-bounded-v1"
            || self.checked_at >= self.valid_until
            || self.input_usd_micros_per_million == 0
            || self.output_usd_micros_per_million == 0
            || self.input_usd_micros_per_million > 1_000_000_000
            || self.output_usd_micros_per_million > 1_000_000_000
        {
            return Err(Fault::Invalid);
        }
        Ok(())
    }
    pub(crate) fn cost(&self, input: u64, output: u64) -> llull_buzz_wire::Result<u64> {
        let total = (input as u128) * (self.input_usd_micros_per_million as u128)
            + (output as u128) * (self.output_usd_micros_per_million as u128);
        u64::try_from(total.div_ceil(1_000_000)).map_err(|_| Fault::Exhausted)
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelReservation {
    pub task_id: String,
    pub expected_generation: u64,
    pub worker_id: String,
    pub pricing_revision: String,
    pub prompt_sha256: String,
    pub input_upper_bound: u64,
    pub output_upper_bound: u64,
}

/// Signed only by the trusted gateway's broker after counting the exact vendor
/// request. For this extension, reservation.prompt_sha256 is the SHA-256 of that
/// complete canonical request, including tools/context/model/output settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginModelDispatch {
    pub reservation_id: uuid::Uuid,
    pub task_id: String,
    pub expected_generation: u64,
    pub worker_id: String,
    pub model_owner: String,
    pub request_sha256: String,
    pub counted_input_tokens: u64,
    pub output_upper_bound: u64,
}
impl BeginModelDispatch {
    pub(crate) fn validate(&self) -> llull_buzz_wire::Result<()> {
        for value in [&self.task_id, &self.worker_id, &self.model_owner] {
            llull_buzz_wire::id(value)?;
        }
        llull_buzz_wire::hash(&self.request_sha256)?;
        if !(1..=llull_buzz_wire::MAX_SAFE_INTEGER as u64).contains(&self.expected_generation)
            || !(1..=32_000).contains(&self.counted_input_tokens)
            || !(1..=16_000).contains(&self.output_upper_bound)
        {
            return Err(Fault::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub observed_usd_micros: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettleModelDispatch {
    pub reservation_id: uuid::Uuid,
    pub task_id: String,
    pub expected_generation: u64,
    pub model_owner: String,
    pub request_sha256: String,
    pub outcome_sha256: String,
    pub usage: ModelUsage,
}
impl SettleModelDispatch {
    pub(crate) fn validate(&self) -> llull_buzz_wire::Result<()> {
        llull_buzz_wire::id(&self.task_id)?;
        llull_buzz_wire::id(&self.model_owner)?;
        llull_buzz_wire::hash(&self.request_sha256)?;
        llull_buzz_wire::hash(&self.outcome_sha256)?;
        if !(1..=llull_buzz_wire::MAX_SAFE_INTEGER as u64).contains(&self.expected_generation)
            || [
                self.usage.input_tokens,
                self.usage.output_tokens,
                self.usage.observed_usd_micros,
            ]
            .iter()
            .any(|n| *n > llull_buzz_wire::MAX_SAFE_INTEGER as u64)
        {
            return Err(Fault::Invalid);
        }
        Ok(())
    }
}
impl Provider {
    pub async fn reserve_model_budget(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<crate::CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "reserve-model-budget" {
            return Err(Fault::Unavailable.into());
        }
        let r: ModelReservation = c.payload()?;
        llull_buzz_wire::hash(&r.prompt_sha256)?;
        if c.resource.reference != r.task_id
            || c.resource.revision != r.expected_generation.to_string()
        {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (root, mut state) = Self::root_for_task(&mut tx, &c.consumer_id, &r.task_id).await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/foundation/v1/model-reservations",
                Some(&root.manifest.root_task_id),
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        root.scope.new_work(&claims)?;
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        Self::model_profile_clear(&mut tx, &c.consumer_id).await?;
        let now = Self::now(&mut tx).await?;
        let pricing = registration.pricing.as_ref().ok_or(Fault::Unavailable)?;
        if pricing.revision != r.pricing_revision
            || pricing.model_profile != root.manifest.model_profile
            || pricing.checked_at > now
            || pricing.valid_until < root.manifest.expires_at
        {
            return Err(Fault::Denied.into());
        }
        let charge = Charge::Model {
            input_tokens: r.input_upper_bound,
            output_tokens: r.output_upper_bound,
            usd_micros: pricing.cost(r.input_upper_bound, r.output_upper_bound)?,
        };
        state.reserve(
            &r.worker_id,
            r.expected_generation,
            &root.manifest,
            &charge,
            now,
        )?;
        let reservation_id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO model_reservations(reservation_id,consumer_id,root_task_id,task_id,generation,intent_id,request_sha256,reservation,charge) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(reservation_id).bind(&c.consumer_id).bind(&root.manifest.root_task_id).bind(&r.task_id).bind(r.expected_generation as i64)
            .bind(&c.intent_id).bind(c.fingerprint()?).bind(sqlx::types::Json(&r)).bind(sqlx::types::Json(&charge)).execute(&mut *tx).await?;
        Self::save_state(&mut tx, &c.consumer_id, &root.manifest.root_task_id, &state).await?;
        let final_now = Self::now(&mut tx).await?;
        claims.fresh(final_now.timestamp())?;
        state.worker(
            &r.worker_id,
            r.expected_generation,
            &root.manifest,
            final_now,
        )?;
        let result=Self::remember(&mut tx,(&c, &claims),reservation_id.to_string(),Execution::Pending,state.revision,
            serde_json::json!({"reservation_id":reservation_id,"charge":charge,"model_dispatch":"unavailable","task_generation":state.generation})).await?;
        tx.commit().await?;
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cost_rounds_up_and_never_uses_caller_dollar_estimate() {
        let p = Pricing {
            revision: "synthetic".into(),
            model_profile: "sonnet-5-adaptive-bounded-v1".into(),
            checked_at: DateTime::from_timestamp(100, 0).unwrap(),
            valid_until: DateTime::from_timestamp(1000, 0).unwrap(),
            input_usd_micros_per_million: 3,
            output_usd_micros_per_million: 5,
        };
        assert_eq!(p.cost(1, 1).unwrap(), 1);
        assert_eq!(p.cost(1_000_000, 1_000_000).unwrap(), 8);
    }
}
