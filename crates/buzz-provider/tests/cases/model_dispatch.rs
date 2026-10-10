//! Real signed/PostgreSQL accounting boundaries; no vendor transport is emulated
//! as live-model evidence. The trusted gateway supplies synthetic usage receipts.
use super::*;
use llull_buzz_provider::budget::{
    BeginModelDispatch, ModelReservation, ModelUsage, SettleModelDispatch,
};

const BEGIN: &str = "/integration/foundation/v1/model-dispatches";
const SETTLE: &str = "/integration/foundation/v1/model-settlements";

async fn reserve(rig: &Rig, task: &TaskManifest) -> Command {
    let request_sha256 =
        digest(&json!({"model":"synthetic","input":"hello","max_output_tokens":100})).unwrap();
    let request = ModelReservation {
        task_id: task.task_id.clone(),
        expected_generation: 1,
        worker_id: "synthetic-worker".into(),
        pricing_revision: "synthetic-not-a-vendor-quote".into(),
        prompt_sha256: request_sha256.clone(),
        input_upper_bound: 100,
        output_upper_bound: 100,
    };
    let command = rig.command(
        "reserve-model-budget",
        rig.resource(&task.task_id, 1),
        &request,
    );
    let claims = rig.claims(&command, "module-a", Some(&task.root_task_id), None);
    let (body, headers) = rig.prepare(
        "/integration/foundation/v1/model-reservations",
        &command,
        &claims,
    );
    let result = rig
        .p
        .reserve_model_budget(&body, headers.headers())
        .await
        .unwrap();
    rig.command(
        "begin-model-dispatch",
        rig.resource(&task.task_id, 1),
        BeginModelDispatch {
            reservation_id: serde_json::from_value(result.result["reservation_id"].clone())
                .unwrap(),
            task_id: task.task_id.clone(),
            expected_generation: 1,
            worker_id: "synthetic-worker".into(),
            model_owner: "synthetic-model-gateway".into(),
            request_sha256,
            counted_input_tokens: 80,
            output_upper_bound: 100,
        },
    )
}

async fn begin(
    rig: &Rig,
    task: &TaskManifest,
    command: &Command,
) -> llull_buzz_provider::Result<CommandResult> {
    let claims = rig.claims(command, "module-a", Some(&task.root_task_id), None);
    let (body, headers) = rig.prepare(BEGIN, command, &claims);
    rig.p.begin_model_dispatch(&body, headers.headers()).await
}

fn settlement(rig: &Rig, begin: &Command, output_tokens: u64) -> Command {
    let dispatch: BeginModelDispatch = begin.payload().unwrap();
    rig.command(
        "settle-model-dispatch",
        rig.resource(&dispatch.task_id, dispatch.expected_generation),
        SettleModelDispatch {
            reservation_id: dispatch.reservation_id,
            task_id: dispatch.task_id,
            expected_generation: dispatch.expected_generation,
            model_owner: dispatch.model_owner,
            request_sha256: dispatch.request_sha256,
            outcome_sha256: sha256(b"synthetic exact vendor result bytes"),
            usage: ModelUsage {
                input_tokens: 80,
                output_tokens,
                observed_usd_micros: 900,
            },
        },
    )
}

async fn settle(
    rig: &Rig,
    task: &TaskManifest,
    command: &Command,
) -> llull_buzz_provider::Result<CommandResult> {
    let claims = rig.claims(command, "module-a", Some(&task.root_task_id), None);
    let (body, headers) = rig.prepare(SETTLE, command, &claims);
    rig.p.settle_model_dispatch(&body, headers.headers()).await
}

async fn state(rig: &Rig, task: &TaskManifest) -> TaskState {
    sqlx::query_scalar::<_, sqlx::types::Json<TaskState>>(
        "SELECT state FROM task_roots WHERE consumer_id=$1 AND root_task_id=$2",
    )
    .bind(&rig.registration.consumer_id)
    .bind(&task.root_task_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap()
    .0
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 via scripts/test-postgres.sh"]
async fn one_reservation_dispatches_once_and_settles_without_refunding() {
    let rig = Rig::new().await;
    let task = rig.start(None, "module-a", 600).await;
    rig.worker(&task, None, "module-a", 1, false).await;
    let command = reserve(&rig, &task).await;
    let (left, right) = tokio::join!(begin(&rig, &task, &command), begin(&rig, &task, &command));
    let results = [left.unwrap(), right.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| r.result["dispatch_permitted"] == true)
            .count(),
        1
    );
    assert!(results
        .iter()
        .all(|r| r.result["dispatch"]["state"] == "unknown"));
    let deadline: chrono::DateTime<Utc> =
        serde_json::from_value(results[0].result["dispatch"]["dispatch_deadline"].clone()).unwrap();
    assert!(deadline <= task.expires_at);
    assert!(deadline <= state(&rig, &task).await.worker.unwrap().lease_until);
    let reserved = state(&rig, &task).await.spent;
    assert_eq!(reserved.model_attempts, 1);

    // A new command identity cannot replay an existing reservation either.
    let mut retry = command.clone();
    retry.intent_id = Uuid::new_v4().to_string();
    assert_eq!(
        begin(&rig, &task, &retry).await.unwrap().result["dispatch_permitted"],
        false
    );
    retry.payload["model_owner"] = json!("different-owner");
    assert!(begin(&rig, &task, &retry).await.is_err());
    let mut wrong_scope = rig.claims(&command, "module-b", Some(&task.root_task_id), None);
    wrong_scope.jti = Uuid::new_v4().to_string();
    let (body, headers) = rig.prepare(BEGIN, &command, &wrong_scope);
    assert!(rig
        .p
        .begin_model_dispatch(&body, headers.headers())
        .await
        .is_err());

    let completion = settlement(&rig, &command, 60);
    let result = settle(&rig, &task, &completion).await.unwrap();
    assert_eq!(result.result["dispatch"]["state"], "settled");
    assert_eq!(state(&rig, &task).await.spent, reserved);
    assert_eq!(
        settle(&rig, &task, &completion).await.unwrap().result,
        result.result
    );
    let mut conflicting = completion.clone();
    conflicting.intent_id = Uuid::new_v4().to_string();
    conflicting.payload["usage"]["output_tokens"] = json!(59);
    assert!(settle(&rig, &task, &conflicting).await.is_err());
    let replay = begin(&rig, &task, &command).await.unwrap();
    assert_eq!(replay.result["dispatch_permitted"], false);
    assert_eq!(replay.receipt.execution, Execution::EffectUnknown);
    assert_eq!(replay.result["dispatch"]["state"], "settled");
    let dispatch: BeginModelDispatch = command.payload().unwrap();
    assert!(
        sqlx::query("DELETE FROM model_dispatches WHERE reservation_id=$1")
            .bind(dispatch.reservation_id)
            .execute(&rig.pool)
            .await
            .is_err()
    );
    assert!(sqlx::query("UPDATE model_dispatches SET state='unknown',settlement=NULL,settled_at=NULL WHERE reservation_id=$1")
        .bind(dispatch.reservation_id).execute(&rig.pool).await.is_err());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 via scripts/test-postgres.sh"]
async fn unknown_model_outcome_survives_cancel_and_late_settlement_cannot_reopen_root() {
    let rig = Rig::new().await;
    let task = rig.start(None, "module-a", 600).await;
    rig.worker(&task, None, "module-a", 1, false).await;
    let command = reserve(&rig, &task).await;
    begin(&rig, &task, &command).await.unwrap();
    let consumer = Consumer::default();
    let effect = rig
        .p
        .dispatch(
            permit(
                rig.admit(&rig.tool(&task, 1), None, "module-a")
                    .await
                    .unwrap(),
            ),
            &consumer,
        )
        .await
        .unwrap();
    let complete = rig.command(
        "complete-task",
        rig.resource(&task.task_id, 1),
        CompleteTask {
            task_id: task.task_id.clone(),
            expected_generation: 1,
            completed_effects: vec![CompletedEffect {
                attempt_id: effect.attempt_id,
                effect_owner: effect.effect_owner,
                effect_intent: effect.effect_intent_id,
                request_sha256: effect.request_sha256,
                result_ref: effect.result_ref.unwrap(),
            }],
        },
    );
    let claims = rig.claims(&complete, "module-a", Some(&task.root_task_id), None);
    let (body, headers) = rig.prepare(
        &format!("/integration/foundation/v1/tasks/{}/complete", task.task_id),
        &complete,
        &claims,
    );
    assert!(rig
        .p
        .complete_task(&task.task_id, &body, headers.headers())
        .await
        .is_err());
    let cancel = rig.command(
        "cancel-task",
        rig.resource(&task.task_id, 1),
        TaskControl {
            task_id: task.task_id.clone(),
            expected_generation: 1,
            reason: "synthetic crash boundary".into(),
        },
    );
    let claims = rig.claims(&cancel, "module-a", Some(&task.root_task_id), None);
    let (body, headers) = rig.prepare(
        &format!("/integration/v1/tasks/{}/cancel", task.task_id),
        &cancel,
        &claims,
    );
    rig.p
        .control_task(&task.task_id, false, &body, headers.headers())
        .await
        .unwrap();
    let fenced = state(&rig, &task).await;
    assert_eq!(fenced.phase, Execution::EffectUnknown);
    assert!(fenced.stop_new_work);
    assert_eq!(
        begin(&rig, &task, &command).await.unwrap().result["dispatch_permitted"],
        false
    );
    settle(&rig, &task, &settlement(&rig, &command, 60))
        .await
        .unwrap();
    let after = state(&rig, &task).await;
    assert_eq!(after.generation, fenced.generation);
    assert_eq!(after.spent, fenced.spent);
    assert!(after.stop_new_work);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 via scripts/test-postgres.sh"]
async fn count_mismatch_is_denied_and_usage_overrun_stops_model_admission() {
    let rig = Rig::new().await;
    let task = rig.start(None, "module-a", 600).await;
    rig.worker(&task, None, "module-a", 1, false).await;
    let command = reserve(&rig, &task).await;
    for (field, value) in [
        ("counted_input_tokens", json!(101)),
        ("output_upper_bound", json!(101)),
        ("request_sha256", json!("a".repeat(64))),
    ] {
        let mut wrong = command.clone();
        wrong.payload[field] = value;
        assert!(begin(&rig, &task, &wrong).await.is_err());
    }
    begin(&rig, &task, &command).await.unwrap();
    let result = settle(&rig, &task, &settlement(&rig, &command, 101))
        .await
        .unwrap();
    assert_eq!(result.result["dispatch"]["state"], "incident");
    assert!(state(&rig, &task).await.stop_new_work);
    // A fresh root does not hide the same consumer's unresolved profile incident.
    let next = rig.start(None, "module-a", 600).await;
    rig.worker(&next, None, "module-a", 1, false).await;
    let reservation = ModelReservation {
        task_id: next.task_id.clone(),
        expected_generation: 1,
        worker_id: "synthetic-worker".into(),
        pricing_revision: "synthetic-not-a-vendor-quote".into(),
        prompt_sha256: sha256(b"fresh"),
        input_upper_bound: 100,
        output_upper_bound: 100,
    };
    let c = rig.command(
        "reserve-model-budget",
        rig.resource(&next.task_id, 1),
        reservation,
    );
    let claims = rig.claims(&c, "module-a", Some(&next.root_task_id), None);
    let (body, headers) = rig.prepare("/integration/foundation/v1/model-reservations", &c, &claims);
    assert!(rig
        .p
        .reserve_model_budget(&body, headers.headers())
        .await
        .is_err());
}
