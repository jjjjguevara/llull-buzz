use crate::{
    auth::{self, Claims, Headers, Registration, Target},
    db::{CommandResult, Provider, Result, Tx},
};
use chrono::{DateTime, Utc};
use llull_buzz_wire::{
    Command, Execution, Fault, Resource, Spent, TaskControl, TaskManifest, TaskState, Worker,
};
use serde::{Deserialize, Serialize};
use sqlx::{types::Json, Row};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeStamp {
    module: String,
    context_domain: String,
    enrollment_id: Option<String>,
    enrollment_revision: Option<u64>,
    authority_epoch: u64,
    recovery_epoch: u64,
    registration_revision: u64,
    represented_principal: Option<String>,
    delegation_id: Option<String>,
    grant_revision: Option<String>,
}
impl ScopeStamp {
    pub(crate) fn from_claims(c: &Claims) -> Self {
        Self {
            module: c.module_id.clone(),
            context_domain: c.context_domain.clone(),
            enrollment_id: c.enrollment_id.clone(),
            enrollment_revision: c.enrollment_revision,
            authority_epoch: c.authority_epoch,
            recovery_epoch: c.recovery_epoch,
            registration_revision: c.registration_revision,
            represented_principal: c.represented_principal.clone(),
            delegation_id: c.delegation_id.clone(),
            grant_revision: c.grant_revision.clone(),
        }
    }
    pub(crate) fn new_work(&self, c: &Claims) -> Result<()> {
        if *self != Self::from_claims(c) {
            Err(Fault::Denied.into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn recovery(&self, c: &Claims) -> Result<()> {
        if self.module != c.module_id || self.context_domain != c.context_domain {
            Err(Fault::Denied.into())
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootRecord {
    pub(crate) manifest: TaskManifest,
    pub(crate) scope: ScopeStamp,
    pub(crate) resource: Resource,
    pub(crate) intent_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskView {
    pub task_id: String,
    pub root_task_id: String,
    pub generation: u64,
    pub revision: u64,
    pub execution: Execution,
    pub expires_at: DateTime<Utc>,
    pub spent: Spent,
    pub stop_new_work: bool,
    pub worker_lease_until: Option<DateTime<Utc>>,
}
impl TaskView {
    pub(crate) fn new(task: &str, record: &RootRecord, state: &TaskState) -> Self {
        Self {
            task_id: task.into(),
            root_task_id: record.manifest.root_task_id.clone(),
            generation: state.generation,
            revision: state.revision,
            execution: state.phase,
            expires_at: record.manifest.expires_at,
            spent: state.spent.clone(),
            stop_new_work: state.stop_new_work,
            worker_lease_until: state.worker.as_ref().map(|w| w.lease_until),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub task_id: String,
    pub expected_generation: u64,
    pub worker_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompletedEffect {
    pub attempt_id: uuid::Uuid,
    pub effect_owner: String,
    pub effect_intent: String,
    pub request_sha256: String,
    pub result_ref: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteTask {
    pub task_id: String,
    pub expected_generation: u64,
    pub completed_effects: Vec<CompletedEffect>,
}

impl Provider {
    pub async fn start_task(&self, body: &[u8], headers: Headers<'_>) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "start-task" {
            return Err(Fault::Unavailable.into());
        }
        let manifest: TaskManifest = c.payload()?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/tasks",
                Some(&manifest.root_task_id),
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        if let Some(mut result) = Self::replay(&mut tx, &c).await? {
            let (root, state) = Self::root(&mut tx, &c.consumer_id, &manifest.root_task_id).await?;
            root.scope.recovery(&claims)?;
            result.result = serde_json::to_value(TaskView::new(&manifest.task_id, &root, &state))
                .map_err(|_| Fault::Invalid)?;
            result.receipt.execution = state.phase;
            result.receipt.revision = state.revision;
            tx.commit().await?;
            return Ok(result);
        }
        let now = Self::now(&mut tx).await?;
        manifest.validate(&c.consumer_id, now)?;
        crate::native::segment(&manifest.task_id)?;
        crate::native::segment(&manifest.root_task_id)?;
        Self::manifest_policy(&registration, &claims, &manifest)?;
        let (record, state) = if manifest.task_id == manifest.root_task_id {
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM task_roots WHERE NOT closed AND expires_at > clock_timestamp()")
                .fetch_one(&mut *tx).await?;
            if count >= 4 {
                return Err(Fault::Exhausted.into());
            }
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM task_roots WHERE consumer_id=$1 AND (root_task_id=$2 OR root_intent_id=$3))")
                .bind(&c.consumer_id).bind(&manifest.root_task_id).bind(&c.intent_id).fetch_one(&mut *tx).await?;
            if exists {
                return Err(Fault::Conflict.into());
            }
            let record = RootRecord {
                manifest: manifest.clone(),
                scope: ScopeStamp::from_claims(&claims),
                resource: c.resource.clone(),
                intent_id: c.intent_id.clone(),
            };
            let state = TaskState::default();
            sqlx::query("INSERT INTO task_roots(consumer_id,root_task_id,root_intent_id,request_sha256,enrollment_id,record,state,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                .bind(&c.consumer_id).bind(&manifest.root_task_id).bind(&c.intent_id).bind(c.fingerprint()?).bind(&claims.enrollment_id)
                .bind(Json(&record)).bind(Json(&state)).bind(now).bind(manifest.expires_at).execute(&mut *tx).await?;
            (record, state)
        } else {
            let (root, state) = Self::root(&mut tx, &c.consumer_id, &manifest.root_task_id).await?;
            root.scope.new_work(&claims)?;
            state.live(&root.manifest, now)?;
            manifest.check_child(&root.manifest)?;
            let children: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM task_members WHERE consumer_id=$1 AND root_task_id=$2",
            )
            .bind(&c.consumer_id)
            .bind(&manifest.root_task_id)
            .fetch_one(&mut *tx)
            .await?;
            // Metadata growth is also finite; children do not allocate a fresh root budget.
            if children >= 33 {
                return Err(Fault::Exhausted.into());
            }
            (root, state)
        };
        let inserted=sqlx::query("INSERT INTO task_members(consumer_id,task_id,root_task_id,manifest,request_sha256) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(&c.consumer_id).bind(&manifest.task_id).bind(&manifest.root_task_id).bind(Json(&manifest)).bind(c.fingerprint()?).execute(&mut *tx).await?;
        if inserted.rows_affected() != 1 {
            return Err(Fault::Conflict.into());
        }
        let final_now = Self::now(&mut tx).await?;
        claims.fresh(final_now.timestamp())?;
        state.live(&record.manifest, final_now)?;
        let result = Self::remember(
            &mut tx,
            (&c, &claims),
            manifest.task_id.clone(),
            Execution::Pending,
            state.revision,
            TaskView::new(&manifest.task_id, &record, &state),
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    fn manifest_policy(
        registration: &Registration,
        claims: &Claims,
        manifest: &TaskManifest,
    ) -> Result<()> {
        let module = registration
            .modules
            .get(&claims.module_id)
            .ok_or(Fault::Denied)?;
        if claims.context_domain != manifest.context_domain
            || !module.task_schemas.contains(&manifest.task_schema_id)
        {
            return Err(Fault::Unavailable.into());
        }
        for tool in &manifest.tools {
            let policy = module
                .tools
                .get(&tool.schema_id)
                .ok_or(Fault::Unavailable)?;
            if policy.action != tool.action || policy.schema_sha256 != tool.schema_sha256 {
                return Err(Fault::Denied.into());
            }
        }
        if manifest
            .verdict_refs
            .iter()
            .any(|reference| !claims.verdicts.iter().any(|v| &v.reference == reference))
        {
            return Err(Fault::Denied.into());
        }
        Ok(())
    }
    pub async fn worker_control(
        &self,
        task_id: &str,
        renew: bool,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        let expected_op = if renew {
            "renew-worker"
        } else {
            "claim-worker"
        };
        if c.operation != expected_op {
            return Err(Fault::Unavailable.into());
        }
        let request: WorkerRequest = c.payload()?;
        if task_id != request.task_id {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (record, mut state) = Self::root_for_task(&mut tx, &c.consumer_id, task_id).await?;
        let path = format!(
            "/integration/foundation/v1/tasks/{}/{}",
            crate::native::segment(task_id)?,
            if renew { "renew" } else { "claim" }
        );
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                &path,
                Some(&record.manifest.root_task_id),
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        record.scope.new_work(&claims)?;
        if c.resource.reference != task_id
            || c.resource.revision != request.expected_generation.to_string()
        {
            return Err(Fault::Conflict.into());
        }
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        if state.generation != request.expected_generation {
            return Err(Fault::Conflict.into());
        }
        let now = Self::now(&mut tx).await?;
        // Replacement reads attempts before doing anything with the new process.
        let unresolved:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE consumer_id=$1 AND root_task_id=$2 AND state IN ('pending','effect-unknown'))")
            .bind(&c.consumer_id).bind(&record.manifest.root_task_id).fetch_one(&mut *tx).await?;
        if !renew && unresolved && state.worker.as_ref().is_some_and(|w| w.lease_until <= now) {
            self.fence_root(
                &mut tx,
                &c.consumer_id,
                &record.manifest.root_task_id,
                &mut state,
            )
            .await?;
            let result = Self::remember(
                &mut tx,
                (&c, &claims),
                task_id.into(),
                Execution::EffectUnknown,
                state.revision,
                TaskView::new(task_id, &record, &state),
            )
            .await?;
            tx.commit().await?;
            return Ok(result);
        }
        let worker: Worker = if renew {
            state.renew(
                &request.worker_id,
                request.expected_generation,
                &record.manifest,
                now,
            )?
        } else {
            state.acquire(&request.worker_id, &record.manifest, now)?
        };
        Self::save_state(
            &mut tx,
            &c.consumer_id,
            &record.manifest.root_task_id,
            &state,
        )
        .await?;
        let final_now = Self::now(&mut tx).await?;
        claims.fresh(final_now.timestamp())?;
        state.worker(
            &request.worker_id,
            state.generation,
            &record.manifest,
            final_now,
        )?;
        let result = Self::remember(
            &mut tx,
            (&c, &claims),
            task_id.into(),
            Execution::Running,
            state.revision,
            &worker,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    /// Authenticated record access uses fresh authority, independently of an expired
    /// task's original new-effect grant. It cannot renew the task or its budget.
    pub async fn observe_task(
        &self,
        consumer: &str,
        task_id: &str,
        headers: Headers<'_>,
    ) -> Result<TaskView> {
        let mut tx = self.begin().await?;
        let (record, state) = Self::root_for_task(&mut tx, consumer, task_id).await?;
        let resource = Resource {
            namespace: consumer.into(),
            reference: task_id.into(),
            revision: state.generation.to_string(),
        };
        let fingerprint = llull_buzz_wire::sha256(b"");
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &auth::SignedRequest {
                    headers: &headers,
                    body: b"",
                },
                auth::INVOCATION,
                &format!("/integration/v1/tasks/{}", crate::native::segment(task_id)?),
                "GET",
                &Target {
                    consumer,
                    intent: task_id,
                    operation: "observe-task",
                    resource: &resource,
                    fingerprint: &fingerprint,
                    root: Some(&record.manifest.root_task_id),
                },
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        record.scope.recovery(&claims)?;
        let view = TaskView::new(task_id, &record, &state);
        tx.commit().await?;
        Ok(view)
    }
    pub async fn control_task(
        &self,
        task_id: &str,
        reconcile: bool,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation
            != if reconcile {
                "reconcile-task"
            } else {
                "cancel-task"
            }
        {
            return Err(Fault::Unavailable.into());
        }
        let request: TaskControl = c.payload()?;
        if request.task_id != task_id
            || request.reason.is_empty()
            || request.reason.chars().count() > 1024
            || c.resource.reference != task_id
            || c.resource.revision != request.expected_generation.to_string()
        {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (record, mut state) = Self::root_for_task(&mut tx, &c.consumer_id, task_id).await?;
        let path = format!(
            "/integration/v1/tasks/{}/{}",
            crate::native::segment(task_id)?,
            if reconcile { "reconcile" } else { "cancel" }
        );
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                &path,
                Some(&record.manifest.root_task_id),
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        record.scope.recovery(&claims)?;
        if let Some(mut result) = Self::replay(&mut tx, &c).await? {
            result.result = serde_json::to_value(TaskView::new(task_id, &record, &state))
                .map_err(|_| Fault::Invalid)?;
            result.receipt.execution = state.phase;
            result.receipt.revision = state.revision;
            tx.commit().await?;
            return Ok(result);
        }
        if state.generation != request.expected_generation {
            return Err(Fault::Conflict.into());
        }
        if state.phase != Execution::Completed {
            self.fence_root(
                &mut tx,
                &c.consumer_id,
                &record.manifest.root_task_id,
                &mut state,
            )
            .await?;
        }
        let attempts =
            Self::attempts(&mut tx, &c.consumer_id, &record.manifest.root_task_id).await?;
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result=Self::remember(&mut tx,(&c, &claims),task_id.into(),state.phase,state.revision,serde_json::json!({"task":TaskView::new(task_id,&record,&state),"attempts":attempts,"recovery":"lookup-original-owner-only"})).await?;
        tx.commit().await?;
        Ok(result)
    }
    /// Explicit completion attestation, not an ACP end_turn or a model label.
    /// At least one known completed effect and no unresolved attempt are required.
    pub async fn complete_task(
        &self,
        task_id: &str,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        if c.operation != "complete-task" {
            return Err(Fault::Unavailable.into());
        }
        let request: CompleteTask = c.payload()?;
        if request.task_id != task_id
            || c.resource.reference != task_id
            || c.resource.revision != request.expected_generation.to_string()
        {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (record, mut state) = Self::root_for_task(&mut tx, &c.consumer_id, task_id).await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                &format!(
                    "/integration/foundation/v1/tasks/{}/complete",
                    crate::native::segment(task_id)?
                ),
                Some(&record.manifest.root_task_id),
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        record.scope.recovery(&claims)?;
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        if state.generation != request.expected_generation
            || task_id != record.manifest.root_task_id
        {
            return Err(Fault::Conflict.into());
        }
        let effects =
            Self::attempts(&mut tx, &c.consumer_id, &record.manifest.root_task_id).await?;
        let known: Vec<CompletedEffect> = effects
            .iter()
            .filter(|a| a.state == "completed")
            .map(|a| CompletedEffect {
                attempt_id: a.attempt_id,
                effect_owner: a.effect_owner.clone(),
                effect_intent: a.effect_intent_id.clone(),
                request_sha256: a.request_sha256.clone(),
                result_ref: a.result_ref.clone().unwrap_or_default(),
            })
            .collect();
        if known != request.completed_effects {
            return Err(Fault::Conflict.into());
        }
        state.complete(
            effects.iter().any(|a| a.state == "completed"),
            effects
                .iter()
                .any(|a| matches!(a.state.as_str(), "pending" | "effect-unknown")),
        )?;
        Self::save_state(
            &mut tx,
            &c.consumer_id,
            &record.manifest.root_task_id,
            &state,
        )
        .await?;
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result = Self::remember(
            &mut tx,
            (&c, &claims),
            task_id.into(),
            Execution::Completed,
            state.revision,
            TaskView::new(task_id, &record, &state),
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) async fn root(
        tx: &mut Tx,
        consumer: &str,
        root: &str,
    ) -> Result<(RootRecord, TaskState)> {
        let row=sqlx::query("SELECT record,state FROM task_roots WHERE consumer_id=$1 AND root_task_id=$2 FOR UPDATE")
            .bind(consumer).bind(root).fetch_optional(&mut **tx).await?.ok_or(Fault::Denied)?;
        Ok((
            row.try_get::<Json<RootRecord>, _>("record")?.0,
            row.try_get::<Json<TaskState>, _>("state")?.0,
        ))
    }
    pub(crate) async fn root_for_task(
        tx: &mut Tx,
        consumer: &str,
        task: &str,
    ) -> Result<(RootRecord, TaskState)> {
        let root: String = sqlx::query_scalar(
            "SELECT root_task_id FROM task_members WHERE consumer_id=$1 AND task_id=$2",
        )
        .bind(consumer)
        .bind(task)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Fault::Denied)?;
        Self::root(tx, consumer, &root).await
    }
    pub(crate) async fn save_state(
        tx: &mut Tx,
        consumer: &str,
        root: &str,
        state: &TaskState,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE task_roots SET state=$3,closed=$4 WHERE consumer_id=$1 AND root_task_id=$2",
        )
        .bind(consumer)
        .bind(root)
        .bind(Json(state))
        .bind(state.stop_new_work)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
    pub(crate) async fn fence_root(
        &self,
        tx: &mut Tx,
        consumer: &str,
        root: &str,
        state: &mut TaskState,
    ) -> Result<()> {
        sqlx::query("UPDATE attempts SET state='effect-unknown' WHERE consumer_id=$1 AND root_task_id=$2 AND state='pending'")
            .bind(consumer).bind(root).execute(&mut **tx).await?;
        let unknown:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE consumer_id=$1 AND root_task_id=$2 AND state='effect-unknown')")
            .bind(consumer).bind(root).fetch_one(&mut **tx).await?;
        let completed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE consumer_id=$1 AND root_task_id=$2 AND state='completed')")
            .bind(consumer).bind(root).fetch_one(&mut **tx).await?;
        state.fence(unknown, completed)?;
        Self::save_state(tx, consumer, root, state).await
    }
    pub(crate) async fn fence_consumer(&self, tx: &mut Tx, consumer: &str) -> Result<()> {
        let roots: Vec<String> =
            sqlx::query_scalar("SELECT root_task_id FROM task_roots WHERE consumer_id=$1")
                .bind(consumer)
                .fetch_all(&mut **tx)
                .await?;
        for root in roots {
            let (_, mut state) = Self::root(tx, consumer, &root).await?;
            self.fence_root(tx, consumer, &root, &mut state).await?;
        }
        Ok(())
    }
    pub(crate) async fn fence_enrollment(
        &self,
        tx: &mut Tx,
        consumer: &str,
        enrollment: &str,
    ) -> Result<()> {
        let roots: Vec<String> = sqlx::query_scalar(
            "SELECT root_task_id FROM task_roots WHERE consumer_id=$1 AND enrollment_id=$2",
        )
        .bind(consumer)
        .bind(enrollment)
        .fetch_all(&mut **tx)
        .await?;
        for root in roots {
            let (_, mut state) = Self::root(tx, consumer, &root).await?;
            self.fence_root(tx, consumer, &root, &mut state).await?;
        }
        Ok(())
    }
    /// Run only by an operator after advancing the separately held deployment epoch.
    /// A restored DB with an old epoch cannot authorize work against that new epoch.
    pub async fn advance_recovery_epoch(&self, expected: u64) -> Result<u64> {
        let mut tx = self.begin().await?;
        if Self::epoch(&mut tx).await? != expected || self.external_epoch <= expected {
            return Err(Fault::Conflict.into());
        }
        let consumers: Vec<String> =
            sqlx::query_scalar("SELECT consumer_id FROM consumer_registry")
                .fetch_all(&mut *tx)
                .await?;
        for consumer in consumers {
            self.fence_consumer(&mut tx, &consumer).await?;
        }
        sqlx::query("UPDATE provider_control SET recovery_epoch=$1 WHERE singleton=1")
            .bind(self.external_epoch as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(self.external_epoch)
    }
}
