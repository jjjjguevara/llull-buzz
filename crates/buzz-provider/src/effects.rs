use crate::{
    auth::{self, Claims, Headers, Target},
    db::{CommandResult, Provider, Result, Tx},
    ports::{ConsumerCommand, ConsumerPort, ConsumerResult, ConsumerStatus},
};
use llull_buzz_wire::{
    canonical, digest, parse, Charge, Command, Execution, Fault, Publication, TaskManifest,
    ToolCall,
};
use serde::{Deserialize, Serialize};
use sqlx::{types::Json, Row};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AttemptView {
    pub attempt_id: Uuid,
    pub consumer_id: String,
    pub root_task_id: String,
    pub task_id: String,
    pub generation: i64,
    pub effect_owner: String,
    pub effect_intent_id: String,
    pub action: String,
    pub request_sha256: String,
    pub state: String,
    pub result_ref: Option<String>,
}
/// Non-cloneable, private-field dispatch permit, minted only after a committed
/// reservation. The database remains authoritative even if this object is lost.
pub struct DispatchPermit<C: ConsumerCommand> {
    attempt: AttemptView,
    command: ToolCall<C>,
    body: Vec<u8>,
    claims: Claims,
    invocation: String,
    worker_id: String,
}
pub enum ToolAdmission<C: ConsumerCommand> {
    Dispatch(Box<DispatchPermit<C>>),
    Existing(Box<AttemptView>),
}
impl<C: ConsumerCommand> ToolAdmission<C> {
    pub fn reference(&self) -> &AttemptView {
        match self {
            Self::Dispatch(p) => &p.attempt,
            Self::Existing(a) => a,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverEffect {
    pub task_id: String,
    pub expected_generation: u64,
    pub attempt_id: Uuid,
    pub effect_owner: String,
    pub effect_intent_id: String,
    pub request_sha256: String,
}

impl Provider {
    pub async fn admit_tool<C: ConsumerCommand>(
        &self,
        worker_id: &str,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<ToolAdmission<C>> {
        let call: ToolCall<C> = Self::decode(body)?;
        let canonical_body = canonical(&call)?;
        // Detect a supposedly typed adapter that silently discarded unknown fields.
        let untyped: serde_json::Value = parse(body)?;
        if canonical_body != canonical(&untyped)? {
            return Err(Fault::Invalid.into());
        }
        call.resource.validate(&call.consumer_id)?;
        call.arguments.validate()?;
        for value in [
            &call.intent_id,
            &call.root_task_id,
            &call.task_id,
            &call.effect_owner,
            &call.effect_intent_id,
            worker_id,
        ] {
            llull_buzz_wire::id(value)?;
        }
        if call.schema_id != C::SCHEMA_ID
            || call.action != C::ACTION
            || call.schema_sha256 != digest(&C::schema())?
            || !C::SCHEMA_ID
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(Fault::Unavailable.into());
        }
        let fingerprint = digest(&call)?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                auth::INVOCATION,
                &format!(
                    "/integration/foundation/v1/tool-admissions/{}",
                    C::SCHEMA_ID
                ),
                "POST",
                &Target {
                    consumer: &call.consumer_id,
                    intent: &call.intent_id,
                    operation: &call.action,
                    resource: &call.resource,
                    fingerprint: &fingerprint,
                    root: Some(&call.root_task_id),
                },
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        let (root, mut state) =
            Self::root_for_task(&mut tx, &call.consumer_id, &call.task_id).await?;
        if root.manifest.root_task_id != call.root_task_id {
            return Err(Fault::Denied.into());
        }
        root.scope.new_work(&claims)?;
        let policy = registration
            .modules
            .get(&claims.module_id)
            .and_then(|m| m.tools.get(C::SCHEMA_ID))
            .ok_or(Fault::Unavailable)?;
        if policy.action != call.action
            || policy.schema_sha256 != call.schema_sha256
            || policy.effect_owner != call.effect_owner
            || (policy.requires_verdict && claims.verdicts.is_empty())
            || root
                .manifest
                .verdict_refs
                .iter()
                .any(|r| !claims.verdicts.iter().any(|v| &v.reference == r))
        {
            return Err(Fault::Denied.into());
        }
        let member:Json<TaskManifest>=sqlx::query_scalar("SELECT manifest FROM task_members WHERE consumer_id=$1 AND task_id=$2 AND root_task_id=$3")
            .bind(&call.consumer_id).bind(&call.task_id).bind(&call.root_task_id).fetch_one(&mut *tx).await?;
        if !member.0.tools.iter().any(|t| {
            t.schema_id == call.schema_id
                && t.schema_sha256 == call.schema_sha256
                && t.action == call.action
                && t.resources.contains(&call.resource)
        }) {
            return Err(Fault::Denied.into());
        }
        let now = Self::now(&mut tx).await?;
        state.worker(worker_id, call.generation, &root.manifest, now)?;
        let existing:Option<AttemptView>=sqlx::query_as("SELECT * FROM attempts WHERE consumer_id=$1 AND effect_owner=$2 AND effect_intent_id=$3 FOR UPDATE")
            .bind(&call.consumer_id).bind(&call.effect_owner).bind(&call.effect_intent_id).fetch_optional(&mut *tx).await?;
        if let Some(existing) = existing {
            if existing.request_sha256 != fingerprint {
                return Err(Fault::Conflict.into());
            }
            tx.commit().await?;
            return Ok(ToolAdmission::Existing(Box::new(existing)));
        }
        // An effect slot excludes caller-selected retry IDs AND resource revisions.
        // While uncertain, new content, a fresh root, or a new revision cannot
        // cause another mutation against the same owner/action/resource.
        let slot = digest(&(
            &call.effect_owner,
            &call.action,
            &call.resource.namespace,
            &call.resource.reference,
        ))?;
        let unresolved:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE consumer_id=$1 AND effect_owner=$2 AND slot_sha256=$3 AND state IN ('pending','effect-unknown'))")
            .bind(&call.consumer_id).bind(&call.effect_owner).bind(&slot).fetch_one(&mut *tx).await?;
        if unresolved {
            return Err(Fault::Unknown.into());
        }
        state.reserve(
            worker_id,
            call.generation,
            &root.manifest,
            &Charge::Tool,
            now,
        )?;
        let attempt = AttemptView {
            attempt_id: Uuid::new_v4(),
            consumer_id: call.consumer_id.clone(),
            root_task_id: call.root_task_id.clone(),
            task_id: call.task_id.clone(),
            generation: call.generation as i64,
            effect_owner: call.effect_owner.clone(),
            effect_intent_id: call.effect_intent_id.clone(),
            action: call.action.clone(),
            request_sha256: fingerprint,
            state: "pending".into(),
            result_ref: None,
        };
        sqlx::query("INSERT INTO attempts(attempt_id,consumer_id,root_task_id,task_id,generation,effect_owner,effect_intent_id,action,slot_sha256,request_sha256,request_bytes,charge,state) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending')")
            .bind(attempt.attempt_id).bind(&attempt.consumer_id).bind(&attempt.root_task_id).bind(&attempt.task_id).bind(attempt.generation)
            .bind(&attempt.effect_owner).bind(&attempt.effect_intent_id).bind(&attempt.action).bind(&slot).bind(&attempt.request_sha256)
            .bind(&canonical_body).bind(Json(&Charge::Tool)).execute(&mut *tx).await?;
        Self::save_state(&mut tx, &call.consumer_id, &call.root_task_id, &state).await?;
        let final_now = Self::now(&mut tx).await?;
        claims.fresh(final_now.timestamp())?;
        state.worker(worker_id, call.generation, &root.manifest, final_now)?;
        tx.commit().await?;
        Ok(ToolAdmission::Dispatch(Box::new(DispatchPermit {
            attempt,
            command: call,
            body: canonical_body,
            claims,
            invocation: headers.invocation.into(),
            worker_id: worker_id.into(),
        })))
    }
    pub async fn dispatch<C: ConsumerCommand, P: ConsumerPort<C>>(
        &self,
        permit: DispatchPermit<C>,
        port: &P,
    ) -> Result<AttemptView> {
        if port.owner() != permit.attempt.effect_owner {
            return Err(Fault::Denied.into());
        }
        let mut tx = self.begin().await?;
        let (root, state) = Self::root(
            &mut tx,
            &permit.attempt.consumer_id,
            &permit.attempt.root_task_id,
        )
        .await?;
        let row = sqlx::query(
            "SELECT registration,active FROM consumer_registry WHERE consumer_id=$1 FOR UPDATE",
        )
        .bind(&permit.attempt.consumer_id)
        .fetch_one(&mut *tx)
        .await?;
        let registration = row
            .try_get::<Json<auth::Registration>, _>("registration")?
            .0;
        let now = Self::now(&mut tx).await?;
        if !row.try_get::<bool, _>("active")?
            || registration.revision != permit.claims.registration_revision
            || Self::epoch(&mut tx).await? != permit.claims.recovery_epoch
            || self.external_epoch != permit.claims.recovery_epoch
        {
            return Err(Fault::Denied.into());
        }
        permit.claims.fresh(now.timestamp())?;
        self.scope(&mut tx, &registration, &permit.claims).await?;
        root.scope.new_work(&permit.claims)?;
        state.worker(
            &permit.worker_id,
            permit.command.generation,
            &root.manifest,
            now,
        )?;
        let attempt = Self::attempt(&mut tx, permit.attempt.attempt_id).await?;
        if attempt.state != "pending" || attempt.request_sha256 != permit.attempt.request_sha256 {
            return Err(Fault::Unknown.into());
        }
        let lease = state.worker.as_ref().ok_or(Fault::Denied)?.lease_until;
        let remaining_ms = root
            .manifest
            .expires_at
            .min(lease)
            .signed_duration_since(now)
            .num_milliseconds()
            .min((permit.claims.exp * 1000 - now.timestamp_millis()).max(0))
            .min(30_000);
        if remaining_ms <= 0 {
            return Err(Fault::Denied.into());
        }
        let timeout = Duration::from_millis(remaining_ms as u64);
        // Commit uncertainty BEFORE crossing the effect boundary. After this point,
        // neither a timeout nor a process crash is permission to execute again.
        let updated=sqlx::query("UPDATE attempts SET state='effect-unknown',dispatched_at=clock_timestamp() WHERE attempt_id=$1 AND state='pending' AND generation=$2")
            .bind(attempt.attempt_id).bind(attempt.generation).execute(&mut *tx).await?;
        if updated.rows_affected() != 1 {
            return Err(Fault::Conflict.into());
        }
        tx.commit().await?;
        let outcome = tokio::time::timeout(
            timeout,
            port.execute(&permit.command, &permit.body, &permit.invocation, timeout),
        )
        .await
        .ok()
        .and_then(|r| r.ok());
        self.record_outcome(
            &attempt,
            permit.command.generation,
            permit.claims.recovery_epoch,
            outcome,
        )
        .await
    }
    async fn record_outcome(
        &self,
        expected: &AttemptView,
        generation: u64,
        epoch: u64,
        outcome: Option<ConsumerResult>,
    ) -> Result<AttemptView> {
        let mut tx = self.begin().await?;
        let (_, mut state) =
            Self::root(&mut tx, &expected.consumer_id, &expected.root_task_id).await?;
        let existing = Self::attempt(&mut tx, expected.attempt_id).await?;
        // An old worker cannot mutate a successor. Recovery with fresh authority
        // can subsequently look up the committed external result by original ID.
        if state.generation != generation
            || Self::epoch(&mut tx).await? != epoch
            || self.external_epoch != epoch
        {
            tx.commit().await?;
            return Ok(existing);
        }
        if existing.state != "effect-unknown" {
            tx.commit().await?;
            return Ok(existing);
        }
        if let Some(outcome) = outcome {
            let valid = outcome.owner == existing.effect_owner
                && outcome.effect_intent_id == existing.effect_intent_id
                && outcome.request_sha256 == existing.request_sha256;
            if valid {
                match outcome.status {
                    ConsumerStatus::Completed => {
                        if let Some(reference) = outcome
                            .result_ref
                            .filter(|r| llull_buzz_wire::id(r).is_ok())
                        {
                            sqlx::query("UPDATE attempts SET state='completed',result_ref=$2 WHERE attempt_id=$1 AND state='effect-unknown'")
                                .bind(existing.attempt_id).bind(reference).execute(&mut *tx).await?;
                        }
                    }
                    ConsumerStatus::DeniedBeforeEffect if outcome.result_ref.is_none() => {
                        sqlx::query("UPDATE attempts SET state='denied' WHERE attempt_id=$1 AND state='effect-unknown'")
                            .bind(existing.attempt_id).execute(&mut *tx).await?;
                    }
                    _ => {}
                }
            }
        }
        let result = Self::attempt(&mut tx, expected.attempt_id).await?;
        if result.state == "effect-unknown" || state.phase == Execution::EffectUnknown {
            let unresolved:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE consumer_id=$1 AND root_task_id=$2 AND state IN ('pending','effect-unknown'))")
                .bind(&expected.consumer_id).bind(&expected.root_task_id).fetch_one(&mut *tx).await?;
            state.recovery_pending(unresolved)?;
            Self::save_state(
                &mut tx,
                &expected.consumer_id,
                &expected.root_task_id,
                &state,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(result)
    }
    pub async fn recover_effect<C: ConsumerCommand, P: ConsumerPort<C>>(
        &self,
        attempt_id: Uuid,
        body: &[u8],
        headers: Headers<'_>,
        port: &P,
    ) -> Result<AttemptView> {
        let c: Command = Self::decode(body)?;
        if c.operation != "reconcile-effect" {
            return Err(Fault::Unavailable.into());
        }
        let request: RecoverEffect = c.payload()?;
        let mut tx = self.begin().await?;
        let attempt = Self::attempt(&mut tx, attempt_id).await?;
        if attempt.consumer_id != c.consumer_id
            || request.attempt_id != attempt_id
            || request.task_id != attempt.task_id
            || request.effect_owner != attempt.effect_owner
            || request.effect_intent_id != attempt.effect_intent_id
            || request.request_sha256 != attempt.request_sha256
            || port.owner() != attempt.effect_owner
        {
            return Err(Fault::Denied.into());
        }
        let (root, state) = Self::root(&mut tx, &c.consumer_id, &attempt.root_task_id).await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                &format!(
                    "/integration/foundation/v1/effects/{attempt_id}/reconcile/{}",
                    C::SCHEMA_ID
                ),
                Some(&attempt.root_task_id),
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        root.scope.recovery(&claims)?;
        if state.generation != request.expected_generation {
            return Err(Fault::Conflict.into());
        }
        let bytes: Vec<u8> =
            sqlx::query_scalar("SELECT request_bytes FROM attempts WHERE attempt_id=$1")
                .bind(attempt_id)
                .fetch_one(&mut *tx)
                .await?;
        let original: ToolCall<C> = parse(&bytes)?;
        if c.resource != original.resource
            || original.schema_id != C::SCHEMA_ID
            || original.action != C::ACTION
        {
            return Err(Fault::Denied.into());
        }
        if matches!(attempt.state.as_str(), "completed" | "denied") {
            tx.commit().await?;
            return Ok(attempt);
        }
        // Pending can be a process crash before dispatch. Conservatively consume its
        // dispatch eligibility; lookup is the only action taken by this method.
        sqlx::query(
            "UPDATE attempts SET state='effect-unknown' WHERE attempt_id=$1 AND state='pending'",
        )
        .bind(attempt_id)
        .execute(&mut *tx)
        .await?;
        let remaining =
            (claims.exp * 1000 - Self::now(&mut tx).await?.timestamp_millis()).min(30_000);
        if remaining <= 0 {
            return Err(Fault::Denied.into());
        }
        let timeout = Duration::from_millis(remaining as u64);
        tx.commit().await?;
        let query = canonical(&c)?;
        let outcome =
            tokio::time::timeout(timeout, port.lookup(&query, headers.invocation, timeout))
                .await
                .ok()
                .and_then(|r| r.ok());
        self.record_outcome(&attempt, state.generation, claims.recovery_epoch, outcome)
            .await
    }
    pub async fn admit_publication(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "publish" {
            return Err(Fault::Unavailable.into());
        }
        let publication: Publication = c.payload()?;
        publication.validate()?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/publications",
                None,
                auth::PUBLICATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        if publication.community_id != registration.community_id {
            return Err(Fault::Denied.into());
        }
        claims.release_for(&publication, Self::now(&mut tx).await?.timestamp())?;
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        if let Some(root_id) = &claims.root_task_id {
            let (root, state) = Self::root(&mut tx, &c.consumer_id, root_id).await?;
            root.scope.new_work(&claims)?;
            state.live(&root.manifest, Self::now(&mut tx).await?)?;
        }
        let existing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM publications WHERE consumer_id=$1 AND (intent_id=$2 OR release_ref=$3))")
            .bind(&c.consumer_id).bind(&c.intent_id).bind(&publication.release_ref).fetch_one(&mut *tx).await?;
        if existing {
            return Err(Fault::Conflict.into());
        }
        let publication_id = Uuid::new_v4();
        sqlx::query("INSERT INTO publications(consumer_id,intent_id,publication_id,release_ref,request_sha256,publication,release,enrollment_id,recovery_epoch) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(&c.consumer_id).bind(&c.intent_id).bind(publication_id).bind(&publication.release_ref).bind(c.fingerprint()?)
            .bind(Json(&publication)).bind(Json(&claims.release)).bind(&claims.enrollment_id).bind(claims.recovery_epoch as i64).execute(&mut *tx).await?;
        let now = Self::now(&mut tx).await?.timestamp();
        claims.fresh(now)?;
        claims.release_for(&publication, now)?;
        let result=Self::remember(&mut tx,&c,publication_id.to_string(),Execution::Pending,1,
            serde_json::json!({"publication_id":publication_id,"delivery":"unavailable","final_native_audience_check":"not-implemented","signed_native_event":null})).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) async fn attempt(tx: &mut Tx, id: Uuid) -> Result<AttemptView> {
        Ok(
            sqlx::query_as("SELECT * FROM attempts WHERE attempt_id=$1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or(Fault::Denied)?,
        )
    }
    pub(crate) async fn attempts(
        tx: &mut Tx,
        consumer: &str,
        root: &str,
    ) -> Result<Vec<AttemptView>> {
        Ok(sqlx::query_as("SELECT * FROM attempts WHERE consumer_id=$1 AND root_task_id=$2 ORDER BY created_at,attempt_id")
            .bind(consumer).bind(root).fetch_all(&mut **tx).await?)
    }
}
