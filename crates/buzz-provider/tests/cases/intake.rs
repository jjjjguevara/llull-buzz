//! Ledger tests use real native signatures and PostgreSQL. The source transport
//! fixture supplies original event bytes; separate relay tests qualify that seam.
use super::*;
use llull_buzz_provider::{Intake, NativeEventSource};

struct Source(Vec<u8>);
#[async_trait]
impl NativeEventSource for Source {
    async fn event(
        &self,
        _community: &str,
        _channel: &str,
        _event: &str,
    ) -> std::result::Result<Vec<u8>, PortError> {
        Ok(self.0.clone())
    }
}
async fn accept(
    rig: &Rig,
    module: &str,
    c: &Command,
    source: &Source,
) -> llull_buzz_provider::Result<CommandResult> {
    let claims = rig.claims(c, module, None, None);
    let (body, h) = rig.prepare("/integration/v1/conversation-intakes", c, &claims);
    rig.p.intake(&body, h.headers(), source).await
}
async fn read(
    rig: &Rig,
    module: &str,
    source: &str,
) -> llull_buzz_provider::Result<RetainedEvidence> {
    let mut c = rig.command("read-evidence", rig.resource(source, 1), json!({}));
    c.intent_id = source.into();
    let mut claims = rig.claims(&c, module, None, None);
    claims.payload_sha256 = sha256(b"");
    let path = format!("/integration/v1/evidence/{source}");
    let h = rig.sign(&path, "GET", b"", &claims, EVIDENCE);
    rig.p.evidence(&c.consumer_id, source, h.headers()).await
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn native_intake_retains_original_identity_and_separate_consumer_registration() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let (binding, _, _) = rig.enroll("module-a", &key).await;
    let attachment_channel = Uuid::new_v4().to_string();
    let first_hash = sha256(b"first synthetic attachment");
    let second_hash = sha256(b"second synthetic attachment");
    let attached = nostr::EventBuilder::new(
        nostr::Kind::Custom(buzz_core::kind::KIND_STREAM_MESSAGE as u16),
        "Two synthetic attachments",
    )
    .tag(nostr::Tag::parse(["h", attachment_channel.as_str()]).unwrap())
    .tag(
        nostr::Tag::parse(vec![
            "imeta".to_owned(),
            "url https://relay.synthetic.invalid/media/first".to_owned(),
            format!("x {first_hash}"),
            "m image/png".to_owned(),
            "size 26".to_owned(),
        ])
        .unwrap(),
    )
    .tag(
        nostr::Tag::parse(vec![
            "imeta".to_owned(),
            "url https://relay.synthetic.invalid/media/second".to_owned(),
            format!("x {second_hash}"),
            "m image/png".to_owned(),
            "size 27".to_owned(),
        ])
        .unwrap(),
    )
    .sign_with_keys(&key)
    .unwrap();
    let repeated = Evidence {
        source_id: Uuid::new_v4().to_string(),
        sha256: first_hash,
        media_type: "image/png".into(),
        size_bytes: 26,
        release_ref: Uuid::new_v4().to_string(),
    };
    let mut second = repeated.clone();
    second.source_id = Uuid::new_v4().to_string();
    let attachment_intake = Intake {
        event_id: attached.id.to_hex(),
        community_id: rig.registration.community_id.clone(),
        channel_id: attachment_channel,
        content_sha256: sha256(attached.content.as_bytes()),
        evidence: vec![repeated, second],
    };
    let attachment_command = rig.command(
        "intake",
        rig.resource(&attached.id.to_hex(), 1),
        &attachment_intake,
    );
    assert!(accept(
        &rig,
        "module-a",
        &attachment_command,
        &Source(serde_json::to_vec(&attached).unwrap())
    )
    .await
    .is_err());
    let mut exact_attachment_intake = attachment_intake.clone();
    exact_attachment_intake.evidence[1].sha256 = second_hash;
    exact_attachment_intake.evidence[1].size_bytes = 27;
    let exact_attachment_command = rig.command(
        "intake",
        rig.resource(&attached.id.to_hex(), 1),
        &exact_attachment_intake,
    );
    let exact = accept(
        &rig,
        "module-a",
        &exact_attachment_command,
        &Source(serde_json::to_vec(&attached).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(exact.result["attachment_bytes_durable"], false);
    let exact_retained = read(
        &rig,
        "module-a",
        exact.result["source_id"].as_str().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(exact_retained.intake.evidence.len(), 2);
    assert_eq!(
        exact_retained.native_event,
        serde_json::to_value(&attached).unwrap()
    );
    let channel = Uuid::new_v4().to_string();
    let event = nostr::EventBuilder::new(
        nostr::Kind::Custom(buzz_core::kind::KIND_STREAM_MESSAGE as u16),
        "Synthetic native input",
    )
    .tag(nostr::Tag::parse(["h", channel.as_str()]).unwrap())
    .sign_with_keys(&key)
    .unwrap();
    let raw = serde_json::to_vec(&event).unwrap();
    let source = Source(raw.clone());
    let payload = Intake {
        event_id: event.id.to_hex(),
        community_id: rig.registration.community_id.clone(),
        channel_id: channel,
        content_sha256: sha256(event.content.as_bytes()),
        evidence: vec![],
    };
    let c = rig.command("intake", rig.resource(&event.id.to_hex(), 1), &payload);
    let mut damaged = serde_json::to_value(&event).unwrap();
    damaged["content"] = json!("tampered");
    assert!(accept(
        &rig,
        "module-a",
        &c,
        &Source(serde_json::to_vec(&damaged).unwrap())
    )
    .await
    .is_err());
    let first = accept(&rig, "module-a", &c, &source).await.unwrap();
    let id = first.result["source_id"].as_str().unwrap();
    assert_eq!(first.result["consumer_registration"], "pending");
    assert_eq!(first.result["bytes_durable"], true);
    let mut duplicate = c.clone();
    duplicate.intent_id = Uuid::new_v4().to_string();
    // Retained original remains usable even when the source transport cannot
    // supply any event. No second consumer acceptance or source identity appears.
    let again = accept(&rig, "module-a", &duplicate, &Source(vec![]))
        .await
        .unwrap();
    assert_eq!(again.result, first.result);
    let recovered = read(&rig, "module-a", id).await.unwrap();
    assert_eq!(
        recovered.native_event,
        serde_json::to_value(&event).unwrap()
    );
    assert_eq!(recovered.enrollment_id, binding.enrollment_id);
    assert_eq!(recovered.source_bytes_sha256, sha256(&raw));
    assert!(read(&rig, "module-b", id).await.is_err());
    assert!(accept(&rig, "module-b", &duplicate, &source).await.is_err());
    let mut wrong = payload.clone();
    wrong.content_sha256 = sha256(b"substituted");
    let c_wrong = rig.command("intake", c.resource.clone(), wrong);
    assert!(accept(&rig, "module-a", &c_wrong, &source).await.is_err());
    let registration = rig.command(
        "register-intake",
        rig.resource(id, 1),
        json!({"source_id":id,"durable_receipt_id":"synthetic-consumer-accepted"}),
    );
    let claims = rig.claims(&registration, "module-a", None, None);
    let (body, h) = rig.prepare(
        "/integration/v1/intake-registrations",
        &registration,
        &claims,
    );
    rig.p.register_intake(&body, h.headers()).await.unwrap();
    let registered = read(&rig, "module-a", id).await.unwrap();
    assert_eq!(
        registered.consumer_receipt.as_deref(),
        Some("synthetic-consumer-accepted")
    );
    assert_eq!(registered.native_event, recovered.native_event);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM native_inputs WHERE consumer_id=$1")
        .bind(&c.consumer_id)
        .fetch_one(&rig.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let immutability =
        sqlx::query("UPDATE native_inputs SET event_bytes='changed' WHERE consumer_id=$1")
            .bind(&c.consumer_id)
            .execute(&rig.pool)
            .await;
    assert!(immutability.is_err());
}
