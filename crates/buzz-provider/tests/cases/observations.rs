use super::*;
use llull_buzz_provider::{ObservationPage, ObservationQuery};

async fn page(
    rig: &Rig,
    module: &str,
    query: ObservationQuery,
) -> llull_buzz_provider::Result<ObservationPage> {
    let mut request = rig.command("observe", rig.resource("observations", 1), json!({}));
    request.intent_id = "observations".into();
    let mut claims = rig.claims(&request, module, None, None);
    claims.payload_sha256 = sha256(b"");
    let h = rig.sign(&query.path()?, "GET", b"", &claims, INVOCATION);
    rig.p
        .observations(&request.consumer_id, query, h.headers())
        .await
}

async fn ack(
    rig: &Rig,
    module: &str,
    cursor: &str,
    receipt: &str,
) -> llull_buzz_provider::Result<CommandResult> {
    let c = rig.command(
        "ack-observations",
        rig.resource("observations", 1),
        json!({"cursor":cursor,"durable_receipt_id":receipt}),
    );
    let claims = rig.claims(&c, module, None, None);
    let (body, h) = rig.prepare("/integration/v1/observation-acks", &c, &claims);
    rig.p.ack_observations(&body, h.headers()).await
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn observations_are_scoped_contiguous_and_durable() {
    let rig = Rig::new().await;
    let native = nostr::Keys::generate();
    rig.enroll("module-a", &native).await;
    rig.enroll("module-b", &native).await;
    let a = page(
        &rig,
        "module-a",
        ObservationQuery {
            cursor: None,
            limit: Some(1),
        },
    )
    .await
    .unwrap();
    assert_eq!(a.observations.len(), 1);
    assert_eq!(a.observations[0].operation, "enroll");
    let b = page(
        &rig,
        "module-a",
        ObservationQuery {
            cursor: Some(a.cursor.clone()),
            limit: Some(100),
        },
    )
    .await
    .unwrap();
    assert_eq!(b.observations.len(), 1);
    assert_eq!(b.observations[0].operation, "prove-key");
    assert!(ack(&rig, "module-a", &b.cursor, "skipped-prefix")
        .await
        .is_err());
    assert!(ack(&rig, "module-b", &a.cursor, "wrong-module")
        .await
        .is_err());
    let forged = format!("{}x", a.cursor);
    assert!(page(
        &rig,
        "module-a",
        ObservationQuery {
            cursor: Some(forged),
            limit: None
        }
    )
    .await
    .is_err());
    assert!(page(
        &rig,
        "module-a",
        ObservationQuery {
            cursor: None,
            limit: Some(101)
        }
    )
    .await
    .is_err());
    let first = ack(&rig, "module-a", &a.cursor, "receipt-a").await.unwrap();
    let duplicate = ack(&rig, "module-a", &a.cursor, "receipt-a").await.unwrap();
    assert_eq!(first.result, duplicate.result);
    assert!(ack(&rig, "module-a", &a.cursor, "changed-receipt")
        .await
        .is_err());
    ack(&rig, "module-a", &b.cursor, "receipt-b").await.unwrap();
    let reconnect = page(
        &rig,
        "module-a",
        ObservationQuery {
            cursor: None,
            limit: None,
        },
    )
    .await
    .unwrap();
    assert!(reconnect.observations.is_empty());
    // ACK never erases retained source records and has no recursive ACK event.
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM observations WHERE consumer_id=$1")
            .bind(&rig.registration.consumer_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(retained, 4);
    let serialized = serde_json::to_string(&b).unwrap();
    assert!(!serialized.contains("invocation_jws"));
    assert!(!serialized.contains("synthetic-person"));
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn observation_retention_gap_is_explicit_and_keys_rotate() {
    let rig = Rig::new().await;
    rig.enroll("module-a", &nostr::Keys::generate()).await;
    let a = page(
        &rig,
        "module-a",
        ObservationQuery {
            cursor: None,
            limit: Some(1),
        },
    )
    .await
    .unwrap();
    rig.p.rotate_observation_key().await.unwrap();
    let resumed = page(
        &rig,
        "module-a",
        ObservationQuery {
            cursor: Some(a.cursor.clone()),
            limit: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(resumed.observations.len(), 1);
    // Retention watermark is durable and scoped; old cursors cannot hide a gap.
    sqlx::query(
        "UPDATE observation_counters SET retained_after=next_sequence WHERE consumer_id=$1",
    )
    .bind(&rig.registration.consumer_id)
    .execute(&rig.pool)
    .await
    .unwrap();
    assert!(matches!(
        page(
            &rig,
            "module-a",
            ObservationQuery {
                cursor: Some(a.cursor),
                limit: None
            }
        )
        .await,
        Err(ProviderError::Admission(Fault::Gap))
    ));
}
