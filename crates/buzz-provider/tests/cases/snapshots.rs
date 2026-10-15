use super::*;
use llull_buzz_provider::{SnapshotPage, SnapshotQuery};

async fn page(
    rig: &Rig,
    module: &str,
    id: Uuid,
    cursor: Option<Uuid>,
) -> llull_buzz_provider::Result<SnapshotPage> {
    let query = SnapshotQuery {
        cursor,
        limit: Some(1),
    };
    let mut c = rig.command("read-snapshot", rig.resource(&id.to_string(), 1), json!({}));
    c.intent_id = id.to_string();
    let mut claims = rig.claims(&c, module, None, None);
    claims.payload_sha256 = sha256(b"");
    let h = rig.sign(&query.path(id)?, "GET", b"", &claims, INVOCATION);
    rig.p
        .snapshot_page(&c.consumer_id, id, query, h.headers())
        .await
}

async fn ack(
    rig: &Rig,
    module: &str,
    id: Uuid,
    cursor: Uuid,
    receipt: &str,
) -> llull_buzz_provider::Result<CommandResult> {
    let c = rig.command(
        "ack-snapshot",
        rig.resource("observations", 1),
        json!({"snapshot_id":id,"cursor":cursor,"durable_receipt_id":receipt}),
    );
    let claims = rig.claims(&c, module, None, None);
    let (body, h) = rig.prepare(
        &format!("/integration/v1/observation-snapshots/{id}/ack"),
        &c,
        &claims,
    );
    rig.p.ack_snapshot(id, &body, h.headers()).await
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn snapshot_recovers_gap_with_frozen_scope_and_explicit_durable_ack() {
    let rig = Rig::new().await;
    let native = nostr::Keys::generate();
    rig.enroll("module-a", &native).await;
    rig.enroll("module-b", &native).await;
    sqlx::query(
        "UPDATE observation_counters SET retained_after=next_sequence WHERE consumer_id=$1",
    )
    .bind(&rig.registration.consumer_id)
    .execute(&rig.pool)
    .await
    .unwrap();
    let c = rig.command(
        "create-snapshot",
        rig.resource("observations", 1),
        json!({}),
    );
    let claims = rig.claims(&c, "module-a", None, None);
    let (body, h) = rig.prepare("/integration/v1/observation-snapshots", &c, &claims);
    let created = rig.p.create_snapshot(&body, h.headers()).await.unwrap();
    let id = Uuid::parse_str(created.result["snapshot_id"].as_str().unwrap()).unwrap();
    assert_eq!(created.result["count"], 2);
    let first = page(&rig, "module-a", id, None).await.unwrap();
    assert_eq!(first.observations.len(), 1);
    assert!(!first.complete);
    assert!(page(&rig, "module-b", id, None).await.is_err());
    assert!(page(&rig, "module-a", id, Some(Uuid::new_v4()))
        .await
        .is_err());
    assert!(ack(&rig, "module-a", id, first.cursor, "incomplete")
        .await
        .is_err());
    // New work after capture must be delivered after the snapshot boundary.
    let root = rig.start(None, "module-a", 300).await;
    let final_page = page(&rig, "module-a", id, Some(first.cursor))
        .await
        .unwrap();
    assert_eq!(final_page.observations.len(), 1);
    assert!(final_page.complete);
    assert_eq!(first.committed_high_water, final_page.committed_high_water);
    let accepted = ack(&rig, "module-a", id, final_page.cursor, "snapshot-receipt")
        .await
        .unwrap();
    assert_eq!(accepted.result["acknowledged"], first.committed_high_water);
    assert_eq!(
        ack(&rig, "module-a", id, final_page.cursor, "snapshot-receipt")
            .await
            .unwrap()
            .result,
        accepted.result
    );
    assert!(
        ack(&rig, "module-a", id, final_page.cursor, "different-receipt")
            .await
            .is_err()
    );
    let query = ObservationQuery::default();
    let mut observe = rig.command("observe", rig.resource("observations", 1), json!({}));
    observe.intent_id = "observations".into();
    let mut claims = rig.claims(&observe, "module-a", None, None);
    claims.payload_sha256 = sha256(b"");
    let h = rig.sign(&query.path().unwrap(), "GET", b"", &claims, INVOCATION);
    let resumed = rig
        .p
        .observations(&observe.consumer_id, query, h.headers())
        .await
        .unwrap();
    assert_eq!(resumed.observations.len(), 1);
    assert!(resumed
        .observations
        .iter()
        .all(|o| o.sequence > first.committed_high_water));
    let bytes = serde_json::to_string(&final_page).unwrap();
    assert!(!bytes.contains("invocation_jws"));
    assert!(!bytes.contains("synthetic-person"));
    rig.cancel(&root, None, "module-a", 1).await;
}
