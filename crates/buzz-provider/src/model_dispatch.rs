//! Signed accounting boundary for the separately installed trusted model gateway.
//! Never mount its signing credentials in the agent or accept model-supplied counts.
//! This module performs no vendor call and does not activate a model profile.
use crate::{
    auth::{self, Headers},
    budget::{BeginModelDispatch, ModelReservation, Pricing, SettleModelDispatch},
    db::Tx,
    CommandResult, Provider, Result,
};
use chrono::{DateTime, Utc};
use llull_buzz_wire::{digest, Charge, Command, Execution, Fault};
use serde::{Deserialize, Serialize};
use sqlx::{types::Json, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDispatchView {
    pub reservation_id: Uuid,
    pub state: String,
    /// The gateway must bound its send and response wait by this deadline and
    /// independently recheck its current scope. Retrying cannot renew this value.
    pub dispatch_deadline: DateTime<Utc>,
    pub request: BeginModelDispatch,
    pub settlement: Option<SettleModelDispatch>,
}

impl Provider {
    pub(crate) async fn unresolved_models(tx: &mut Tx, consumer: &str, root: &str) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM model_dispatches WHERE consumer_id=$1 AND root_task_id=$2 AND state IN ('unknown','incident'))")
            .bind(consumer).bind(root).fetch_one(&mut **tx).await?)
    }

    pub(crate) async fn model_profile_clear(tx: &mut Tx, consumer: &str) -> Result<()> {
        let incident: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM model_dispatches WHERE consumer_id=$1 AND state='incident')")
            .bind(consumer).fetch_one(&mut **tx).await?;
        if incident {
            return Err(Fault::Denied.into());
        }
        Ok(())
    }

    async fn model_dispatch(
        tx: &mut Tx,
        consumer: &str,
        id: Uuid,
    ) -> Result<Option<ModelDispatchView>> {
        let row = sqlx::query("SELECT reservation_id,state,dispatch_deadline,request,settlement FROM model_dispatches WHERE reservation_id=$1 AND consumer_id=$2 FOR UPDATE")
            .bind(id).bind(consumer).fetch_optional(&mut **tx).await?;
        row.map(|row| {
            Ok(ModelDispatchView {
                reservation_id: row.try_get("reservation_id")?,
                state: row.try_get("state")?,
                dispatch_deadline: row.try_get("dispatch_deadline")?,
                request: row.try_get::<Json<BeginModelDispatch>, _>("request")?.0,
                settlement: row
                    .try_get::<Option<Json<SettleModelDispatch>>, _>("settlement")?
                    .map(|v| v.0),
            })
        })
        .transpose()
    }

    /// Persist uncertainty before the gateway can send. Only the first successful
    /// response permits one send. Every retry, including a new command intent,
    /// returns dispatch_permitted=false; a lost first response stays unknown.
    /// Counting and exact vendor request construction belong to the trusted proxy.
    pub async fn begin_model_dispatch(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let command: Command = Self::decode(body)?;
        if command.operation != "begin-model-dispatch" {
            return Err(Fault::Unavailable.into());
        }
        let request: BeginModelDispatch = command.payload()?;
        request.validate()?;
        if command.resource.reference != request.task_id
            || command.resource.revision != request.expected_generation.to_string()
        {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (root, state) =
            Self::root_for_task(&mut tx, &command.consumer_id, &request.task_id).await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &command,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/foundation/v1/model-dispatches",
                Some(&root.manifest.root_task_id),
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        root.scope.recovery(&claims)?;
        let replay = Self::replay(&mut tx, &command).await?;
        if let Some(existing) =
            Self::model_dispatch(&mut tx, &command.consumer_id, request.reservation_id).await?
        {
            if digest(&existing.request)? != digest(&request)? {
                return Err(Fault::Conflict.into());
            }
            let result = serde_json::json!({"dispatch_permitted":false,"dispatch":existing});
            let response = if let Some(mut response) = replay {
                response.result = result;
                response
            } else {
                Self::remember(
                    &mut tx,
                    (&command, &claims),
                    request.reservation_id.to_string(),
                    model_execution(&existing.state)?,
                    state.revision,
                    result,
                )
                .await?
            };
            claims.fresh(Self::now(&mut tx).await?.timestamp())?;
            tx.commit().await?;
            return Ok(response);
        }
        if replay.is_some() {
            return Err(Fault::Unknown.into());
        }
        root.scope.new_work(&claims)?;
        Self::model_profile_clear(&mut tx, &command.consumer_id).await?;
        let row = sqlx::query("SELECT reservation FROM model_reservations WHERE reservation_id=$1 AND consumer_id=$2 AND root_task_id=$3 AND task_id=$4 AND generation=$5")
            .bind(request.reservation_id).bind(&command.consumer_id).bind(&root.manifest.root_task_id)
            .bind(&request.task_id).bind(request.expected_generation as i64).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        let reservation = row.try_get::<Json<ModelReservation>, _>("reservation")?.0;
        if reservation.worker_id != request.worker_id
            || reservation.prompt_sha256 != request.request_sha256
            || request.counted_input_tokens > reservation.input_upper_bound
            || request.output_upper_bound != reservation.output_upper_bound
        {
            return Err(Fault::Denied.into());
        }
        let pricing = registration.pricing.as_ref().ok_or(Fault::Unavailable)?;
        let now = Self::now(&mut tx).await?;
        if pricing.revision != reservation.pricing_revision
            || pricing.model_profile != root.manifest.model_profile
            || pricing.checked_at > now
            || pricing.valid_until < root.manifest.expires_at
        {
            return Err(Fault::Denied.into());
        }
        claims.fresh(now.timestamp())?;
        state.worker(
            &request.worker_id,
            request.expected_generation,
            &root.manifest,
            now,
        )?;
        let dispatch_deadline = root
            .manifest
            .expires_at
            .min(state.worker.as_ref().ok_or(Fault::Denied)?.lease_until)
            .min(DateTime::from_timestamp(claims.exp, 0).ok_or(Fault::Invalid)?);
        sqlx::query("INSERT INTO model_dispatches(reservation_id,consumer_id,root_task_id,task_id,generation,request,pricing,state,dispatch_deadline) VALUES($1,$2,$3,$4,$5,$6,$7,'unknown',$8)")
            .bind(request.reservation_id).bind(&command.consumer_id).bind(&root.manifest.root_task_id).bind(&request.task_id)
            .bind(request.expected_generation as i64).bind(Json(&request)).bind(Json(pricing)).bind(dispatch_deadline).execute(&mut *tx).await?;
        let view = ModelDispatchView {
            reservation_id: request.reservation_id,
            state: "unknown".into(),
            dispatch_deadline,
            request,
            settlement: None,
        };
        let final_now = Self::now(&mut tx).await?;
        claims.fresh(final_now.timestamp())?;
        state.worker(
            &view.request.worker_id,
            view.request.expected_generation,
            &root.manifest,
            final_now,
        )?;
        let response = Self::remember(
            &mut tx,
            (&command, &claims),
            view.reservation_id.to_string(),
            Execution::EffectUnknown,
            state.revision,
            serde_json::json!({"dispatch_permitted":true,"dispatch":view}),
        )
        .await?;
        tx.commit().await?;
        Ok(response)
    }

    /// Retain exact observed usage without refunding the admitted maximum. Fresh
    /// recovery authority may record a late result after cancellation/expiry; it
    /// cannot revive a worker or authorize another vendor send.
    pub async fn settle_model_dispatch(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let command: Command = Self::decode(body)?;
        if command.operation != "settle-model-dispatch" {
            return Err(Fault::Unavailable.into());
        }
        let request: SettleModelDispatch = command.payload()?;
        request.validate()?;
        if command.resource.reference != request.task_id
            || command.resource.revision != request.expected_generation.to_string()
        {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (root, mut state) =
            Self::root_for_task(&mut tx, &command.consumer_id, &request.task_id).await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &command,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/foundation/v1/model-settlements",
                Some(&root.manifest.root_task_id),
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        root.scope.recovery(&claims)?;
        if let Some(response) = Self::replay(&mut tx, &command).await? {
            tx.commit().await?;
            return Ok(response);
        }
        let mut existing =
            Self::model_dispatch(&mut tx, &command.consumer_id, request.reservation_id)
                .await?
                .ok_or(Fault::Denied)?;
        if existing.request.task_id != request.task_id
            || existing.request.expected_generation != request.expected_generation
            || existing.request.model_owner != request.model_owner
            || existing.request.request_sha256 != request.request_sha256
        {
            return Err(Fault::Conflict.into());
        }
        if let Some(settled) = &existing.settlement {
            if digest(settled)? != digest(&request)? {
                return Err(Fault::Conflict.into());
            }
        } else {
            let row = sqlx::query("SELECT r.reservation,r.charge,d.pricing FROM model_reservations r JOIN model_dispatches d USING(reservation_id) WHERE reservation_id=$1")
                .bind(request.reservation_id).fetch_one(&mut *tx).await?;
            let reservation = row.try_get::<Json<ModelReservation>, _>("reservation")?.0;
            let pricing = row.try_get::<Json<Pricing>, _>("pricing")?.0;
            let Charge::Model { usd_micros, .. } = row.try_get::<Json<Charge>, _>("charge")?.0
            else {
                return Err(Fault::Unknown.into());
            };
            let incident = request.usage.input_tokens > reservation.input_upper_bound
                || request.usage.output_tokens > reservation.output_upper_bound
                || request.usage.observed_usd_micros > usd_micros
                || pricing
                    .cost(request.usage.input_tokens, request.usage.output_tokens)
                    .map_or(true, |cost| cost > usd_micros);
            existing.state = if incident { "incident" } else { "settled" }.into();
            sqlx::query("UPDATE model_dispatches SET state=$2,settlement=$3,settled_at=clock_timestamp() WHERE reservation_id=$1 AND state='unknown'")
                .bind(request.reservation_id).bind(&existing.state).bind(Json(&request)).execute(&mut *tx).await?;
            existing.settlement = Some(request.clone());
            if incident {
                self.fence_root(
                    &mut tx,
                    &command.consumer_id,
                    &root.manifest.root_task_id,
                    &mut state,
                )
                .await?;
            } else if state.phase == Execution::EffectUnknown {
                // Accounting can be the last original outcome learned after a
                // fence. Refresh only current recovery truth, as tool outcome
                // recovery does; no worker, budget, generation, or business
                // completion authority is restored by a known model result.
                let tools_unknown: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE consumer_id=$1 AND root_task_id=$2 AND state IN ('pending','effect-unknown'))")
                    .bind(&command.consumer_id).bind(&root.manifest.root_task_id)
                    .fetch_one(&mut *tx).await?;
                let unresolved = tools_unknown
                    || Self::unresolved_models(
                        &mut tx,
                        &command.consumer_id,
                        &root.manifest.root_task_id,
                    )
                    .await?;
                state.recovery_pending(unresolved)?;
                Self::save_state(
                    &mut tx,
                    &command.consumer_id,
                    &root.manifest.root_task_id,
                    &state,
                )
                .await?;
            }
        }
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let response = Self::remember(
            &mut tx,
            (&command, &claims),
            request.reservation_id.to_string(),
            model_execution(&existing.state)?,
            state.revision,
            serde_json::json!({"dispatch_permitted":false,"dispatch":existing}),
        )
        .await?;
        tx.commit().await?;
        Ok(response)
    }
}

fn model_execution(state: &str) -> Result<Execution> {
    match state {
        "unknown" | "incident" => Ok(Execution::EffectUnknown),
        "settled" => Ok(Execution::Completed),
        _ => Err(Fault::Unknown.into()),
    }
}
