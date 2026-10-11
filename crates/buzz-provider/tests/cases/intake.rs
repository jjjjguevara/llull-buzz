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
    let ambiguous_channel = Uuid::new_v4().to_string();
    let ambiguous = nostr::EventBuilder::new(
        nostr::Kind::Custom(buzz_core::kind::KIND_STREAM_MESSAGE as u16),
        "Ambiguous synthetic attachment",
    )
    .tag(nostr::Tag::parse(["h", ambiguous_channel.as_str()]).unwrap())
    .tag(
        nostr::Tag::parse(vec![
            "imeta".to_owned(),
            "url https://relay.synthetic.invalid/media/ambiguous".to_owned(),
            format!("x {}", sha256(b"first synthetic attachment")),
            format!("x {}", sha256(b"second synthetic attachment")),
            "m image/png".to_owned(),
            "size 26".to_owned(),
        ])
        .unwrap(),
    )
    .sign_with_keys(&key)
    .unwrap();
    let ambiguous_intake = Intake {
        event_id: ambiguous.id.to_hex(),
        community_id: rig.registration.community_id.clone(),
        channel_id: ambiguous_channel,
        content_sha256: sha256(ambiguous.content.as_bytes()),
        evidence: vec![Evidence {
            source_id: Uuid::new_v4().to_string(),
            sha256: sha256(b"first synthetic attachment"),
            media_type: "image/png".into(),
            size_bytes: 26,
            release_ref: Uuid::new_v4().to_string(),
        }],
    };
    let ambiguous_command = rig.command(
        "intake",
        rig.resource(&ambiguous.id.to_hex(), 1),
        &ambiguous_intake,
    );
    assert!(accept(
        &rig,
        "module-a",
        &ambiguous_command,
        &Source(serde_json::to_vec(&ambiguous).unwrap())
    )
    .await
    .is_err());
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

struct AttachmentSource {
    bytes: Vec<u8>,
    calls: AtomicUsize,
    delay: Duration,
}
#[async_trait]
impl NativeAttachmentSource for AttachmentSource {
    fn attachment_owner(&self) -> &str {
        "synthetic-fixed-native-origin"
    }
    async fn attachment(&self, _: &str, _: &Evidence) -> std::result::Result<Vec<u8>, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(self.bytes.clone())
    }
}
async fn attached_input(rig: &Rig) -> (Uuid, Evidence, Binding) {
    let (source, evidence, binding, _) = attached_input_with_key(rig).await;
    (source, evidence, binding)
}
async fn attached_input_with_key(rig: &Rig) -> (Uuid, Evidence, Binding, nostr::Keys) {
    let key = nostr::Keys::generate();
    let (binding, _, _) = rig.enroll("module-a", &key).await;
    let channel = Uuid::new_v4().to_string();
    let evidence = Evidence {
        source_id: Uuid::new_v4().to_string(),
        sha256: sha256(b"original"),
        media_type: "image/png".into(),
        size_bytes: 8,
        release_ref: "synthetic-release".into(),
    };
    let event = nostr::EventBuilder::new(
        nostr::Kind::Custom(buzz_core::kind::KIND_STREAM_MESSAGE as u16),
        "Original attachment",
    )
    .tag(nostr::Tag::parse(["h", channel.as_str()]).unwrap())
    .tag(
        nostr::Tag::parse(vec![
            "imeta".into(),
            "url https://untrusted.invalid/never-fetch".into(),
            format!("x {}", evidence.sha256),
            "m image/png".into(),
            "size 8".into(),
        ])
        .unwrap(),
    )
    .sign_with_keys(&key)
    .unwrap();
    let intake = Intake {
        event_id: event.id.to_hex(),
        community_id: rig.registration.community_id.clone(),
        channel_id: channel,
        content_sha256: sha256(event.content.as_bytes()),
        evidence: vec![evidence.clone()],
    };
    let command = rig.command("intake", rig.resource(&intake.event_id, 1), intake);
    let result = accept(
        rig,
        "module-a",
        &command,
        &Source(serde_json::to_vec(&event).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(result.result["attachment_bytes_durable"], false);
    (
        Uuid::parse_str(result.result["source_id"].as_str().unwrap()).unwrap(),
        evidence,
        binding,
        key,
    )
}
fn retention(rig: &Rig, source: Uuid, evidence: &Evidence) -> Command {
    rig.command(
        "retain-attachment",
        rig.resource(&format!("{source}/{}", evidence.sha256), 1),
        RetainAttachment {
            source_id: source,
            evidence: evidence.clone(),
        },
    )
}
async fn retain(
    rig: &Rig,
    module: &str,
    c: &Command,
    source: &AttachmentSource,
) -> llull_buzz_provider::Result<CommandResult> {
    let claims = rig.claims(c, module, None, None);
    let (body, h) = rig.prepare("/integration/v1/attachment-retentions", c, &claims);
    rig.p.retain_attachment(&body, h.headers(), source).await
}
async fn read_attachment(
    rig: &Rig,
    module: &str,
    source: Uuid,
    evidence: &Evidence,
    binding: Option<&Binding>,
) -> llull_buzz_provider::Result<Vec<u8>> {
    let mut command = rig.command(
        "read-attachment",
        rig.resource(&format!("{source}/{}", evidence.sha256), 1),
        json!({}),
    );
    command.intent_id = source.to_string();
    let mut claims = rig.claims(&command, module, None, binding);
    claims.payload_sha256 = sha256(b"");
    let h = rig.sign(
        &format!(
            "/integration/v1/evidence/{source}/attachments/{}",
            evidence.sha256
        ),
        "GET",
        b"",
        &claims,
        EVIDENCE,
    );
    rig.p
        .attachment_bytes(
            &command.consumer_id,
            &source.to_string(),
            &evidence.sha256,
            h.headers(),
        )
        .await
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn attachment_bytes_are_separate_durable_current_scoped_evidence() {
    let rig = Rig::new().await;
    let (source, evidence, binding) = attached_input(&rig).await;
    let origin = AttachmentSource {
        bytes: b"original".to_vec(),
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
    };
    let command = retention(&rig, source, &evidence);
    assert!(
        read_attachment(&rig, "module-a", source, &evidence, None)
            .await
            .is_err(),
        "metadata is not durable bytes"
    );
    assert!(retain(&rig, "module-b", &command, &origin).await.is_err());
    let mut forged = evidence.clone();
    forged.release_ref = "another-release".into();
    assert!(
        retain(&rig, "module-a", &retention(&rig, source, &forged), &origin)
            .await
            .is_err()
    );
    assert_eq!(origin.calls.load(Ordering::SeqCst), 0);
    let claims = rig.claims(&command, "module-a", None, None);
    let body = canonical(&command).unwrap();
    let wrong_purpose = rig.sign(
        "/integration/v1/attachment-retentions",
        "POST",
        &body,
        &claims,
        EVIDENCE,
    );
    assert!(
        rig.p
            .retain_attachment(&body, wrong_purpose.headers(), &origin)
            .await
            .is_err(),
        "read purpose cannot retain new bytes"
    );
    let first = retain(&rig, "module-a", &command, &origin).await.unwrap();
    assert_eq!(first.result["attachment_bytes_durable"], true);
    assert_eq!(first.receipt.execution, Execution::Completed);
    let replay = retain(&rig, "module-a", &command, &origin).await.unwrap();
    assert_eq!(
        serde_json::to_value(&first.receipt).unwrap(),
        serde_json::to_value(&replay.receipt).unwrap()
    );
    assert!(replay.replayed);
    assert_eq!(first.result, replay.result);
    let duplicate = retention(&rig, source, &evidence);
    retain(&rig, "module-a", &duplicate, &origin).await.unwrap();
    assert_eq!(
        origin.calls.load(Ordering::SeqCst),
        1,
        "immutable retained bytes survive origin loss"
    );
    assert_eq!(
        read_attachment(&rig, "module-a", source, &evidence, Some(&binding))
            .await
            .unwrap(),
        b"original"
    );
    assert!(read_attachment(&rig, "module-b", source, &evidence, None)
        .await
        .is_err());
    let mut read_command = rig.command("read-attachment", command.resource.clone(), json!({}));
    read_command.intent_id = source.to_string();
    let mut read_claims = rig.claims(&read_command, "module-a", None, None);
    read_claims.payload_sha256 = sha256(b"");
    let read_path = format!(
        "/integration/v1/evidence/{source}/attachments/{}",
        evidence.sha256
    );
    let wrong_purpose = rig.sign(&read_path, "GET", b"", &read_claims, INVOCATION);
    assert!(
        rig.p
            .attachment_bytes(
                &command.consumer_id,
                &source.to_string(),
                &evidence.sha256,
                wrong_purpose.headers()
            )
            .await
            .is_err(),
        "write invocation is not EvidenceAccess"
    );
    read_claims.exp = read_claims.iat;
    let expired = rig.sign(&read_path, "GET", b"", &read_claims, EVIDENCE);
    assert!(rig
        .p
        .attachment_bytes(
            &command.consumer_id,
            &source.to_string(),
            &evidence.sha256,
            expired.headers()
        )
        .await
        .is_err());
    let foreign = Rig::new().await;
    assert!(
        read_attachment(&foreign, "module-a", source, &evidence, None)
            .await
            .is_err()
    );
    let mut wrong = evidence.clone();
    wrong.sha256 = sha256(b"foreign");
    assert!(read_attachment(&rig, "module-a", source, &wrong, None)
        .await
        .is_err());
    assert!(
        sqlx::query("UPDATE native_attachments SET bytes='changed' WHERE consumer_id=$1")
            .bind(&command.consumer_id)
            .execute(&rig.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM native_attachments WHERE consumer_id=$1")
            .bind(&command.consumer_id)
            .execute(&rig.pool)
            .await
            .is_err()
    );
    let retained = read(&rig, "module-a", &source.to_string()).await.unwrap();
    assert_eq!(retained.intake.evidence, vec![evidence.clone()]);
    assert!(
        retained.consumer_receipt.is_none(),
        "no fabricated consumer acceptance"
    );
    let revoke = rig.command(
        "change-access",
        rig.resource(&binding.enrollment_id, 1),
        ChangeAccess {
            enrollment_id: binding.enrollment_id.clone(),
            expected_revision: "1".into(),
            change: AccessChange::Revoke,
        },
    );
    let claims = rig.claims(&revoke, "module-a", None, None);
    let (body, h) = rig.prepare("/integration/v1/access-changes", &revoke, &claims);
    rig.p.change_access(&body, h.headers()).await.unwrap();
    assert!(
        read_attachment(&rig, "module-a", source, &evidence, Some(&binding))
            .await
            .is_err()
    );
    rig.p
        .set_service_active(
            &command.consumer_id,
            false,
            &digest(&rig.registration).unwrap(),
        )
        .await
        .unwrap();
    assert!(read_attachment(&rig, "module-a", source, &evidence, None)
        .await
        .is_err());
    assert!(
        retain(&rig, "module-a", &command, &origin).await.is_err(),
        "revocation before receipt replay"
    );
    assert_eq!(origin.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn attachment_mismatch_expiry_and_receipt_failure_leave_no_partial_bytes() {
    let rig = Rig::new().await;
    let (source, evidence, _) = attached_input(&rig).await;
    let command = retention(&rig, source, &evidence);
    let mut origin = AttachmentSource {
        bytes: b"changed!".to_vec(),
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
    };
    assert!(retain(&rig, "module-a", &command, &origin).await.is_err());
    origin.bytes = b"original".to_vec();
    origin.delay = Duration::from_secs(2);
    let mut claims = rig.claims(&command, "module-a", None, None);
    claims.exp = claims.iat + 1;
    let (body, h) = rig.prepare("/integration/v1/attachment-retentions", &command, &claims);
    assert!(
        rig.p
            .retain_attachment(&body, h.headers(), &origin)
            .await
            .is_err(),
        "expiry during source read"
    );
    origin.delay = Duration::ZERO;
    // Real PostgreSQL failure after blob insert must roll back blob and receipt.
    sqlx::raw_sql("CREATE FUNCTION fail_attachment_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation='retain-attachment' THEN RAISE EXCEPTION 'synthetic receipt failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER synthetic_attachment_failure BEFORE INSERT ON commands FOR EACH ROW EXECUTE FUNCTION fail_attachment_receipt();").execute(&rig.pool).await.unwrap();
    assert!(retain(&rig, "module-a", &command, &origin).await.is_err());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM native_attachments WHERE consumer_id=$1")
            .bind(&command.consumer_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM commands WHERE consumer_id=$1 AND operation='retain-attachment'",
    )
    .bind(&command.consumer_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
    sqlx::raw_sql("DROP TRIGGER synthetic_attachment_failure ON commands; DROP FUNCTION fail_attachment_receipt();").execute(&rig.pool).await.unwrap();
    retain(&rig, "module-a", &command, &origin).await.unwrap();
    assert_eq!(
        read_attachment(&rig, "module-a", source, &evidence, None)
            .await
            .unwrap(),
        b"original"
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn attachment_original_retention_deadline_is_rechecked_after_fetch() {
    let rig = Rig::new().await;
    // Only this disposable database's new inputs get a short original retention
    // deadline; immutable input history is never updated or bypassed.
    sqlx::raw_sql("CREATE FUNCTION short_attachment_retention() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.retain_until=clock_timestamp()+interval '3 seconds'; RETURN NEW; END $$; CREATE TRIGGER synthetic_short_attachment BEFORE INSERT ON native_inputs FOR EACH ROW EXECUTE FUNCTION short_attachment_retention();").execute(&rig.pool).await.unwrap();
    let (source, evidence, _) = attached_input(&rig).await;
    sqlx::raw_sql("DROP TRIGGER synthetic_short_attachment ON native_inputs; DROP FUNCTION short_attachment_retention();").execute(&rig.pool).await.unwrap();
    let origin = AttachmentSource {
        bytes: b"original".to_vec(),
        calls: AtomicUsize::new(0),
        delay: Duration::from_secs(4),
    };
    assert!(
        matches!(
            retain(
                &rig,
                "module-a",
                &retention(&rig, source, &evidence),
                &origin
            )
            .await,
            Err(ProviderError::Admission(Fault::Denied))
        ),
        "fresh invocation is denied at the original retention deadline, not a transport timeout"
    );
    assert_eq!(
        origin.calls.load(Ordering::SeqCst),
        1,
        "deadline crossed during actual origin read"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM native_attachments WHERE consumer_id=$1")
            .bind(&rig.registration.consumer_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    assert!(read_attachment(&rig, "module-a", source, &evidence, None)
        .await
        .is_err());
}

struct MediaAudience {
    key: nostr::Keys,
    audience: Mutex<Audience>,
    delay: Mutex<Duration>,
}
#[async_trait]
impl NativeEventSource for MediaAudience {
    async fn event(&self, _: &str, _: &str, _: &str) -> std::result::Result<Vec<u8>, PortError> {
        panic!("native byte access must not dispatch or invent native events")
    }
}
#[async_trait]
impl PublicationPort for MediaAudience {
    fn owner(&self) -> &str {
        "synthetic-fixed-native-origin"
    }
    fn public_key(&self) -> nostr::PublicKey {
        self.key.public_key()
    }
    async fn audience(&self, _: &str, _: &str) -> std::result::Result<Audience, PortError> {
        let delay = *self.delay.lock().unwrap();
        tokio::time::sleep(delay).await;
        Ok(self.audience.lock().unwrap().clone())
    }
    async fn submit(&self, _: &str, _: &[u8]) -> std::result::Result<bool, PortError> {
        panic!("a read lease is never publication authority")
    }
}
async fn lease_fixture(
    rig: &Rig,
) -> (
    Command,
    nostr::Keys,
    std::sync::Arc<MediaAudience>,
    std::sync::Arc<NativeMedia<MediaAudience>>,
) {
    let (source, evidence, binding, key) = attached_input_with_key(rig).await;
    retain(
        rig,
        "module-a",
        &retention(rig, source, &evidence),
        &AttachmentSource {
            bytes: b"original".to_vec(),
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        },
    )
    .await
    .unwrap();
    let intake: sqlx::types::Json<Intake> = sqlx::query_scalar(
        "SELECT intake FROM native_inputs WHERE consumer_id=$1 AND source_id=$2",
    )
    .bind(&rig.registration.consumer_id)
    .bind(source)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    let port = std::sync::Arc::new(MediaAudience {
        key: rig.key.clone(),
        delay: Mutex::new(Duration::ZERO),
        audience: Mutex::new(Audience {
            community_id: intake.0.community_id,
            channel_id: intake.0.channel_id,
            revision: "audience-1".into(),
            members: BTreeSet::from([rig.key.public_key().to_hex(), key.public_key().to_hex()]),
        }),
    });
    let media = std::sync::Arc::new(
        NativeMedia::new(port.clone(), "https://relay.synthetic.invalid").unwrap(),
    );
    let command = rig.command(
        "lease-native-attachment",
        rig.resource(&format!("{source}/{}", evidence.sha256), 1),
        NativeAttachmentLease {
            source_id: source,
            evidence,
            enrollment_id: binding.enrollment_id,
            enrollment_revision: binding.revision as u64,
            audience_policy: "synthetic-current-policy".into(),
            audience_revision: "audience-1".into(),
            release_ref: "synthetic-exact-read-release".into(),
            expires_at: Utc::now() + CD::seconds(40),
        },
    );
    (command, key, port, media)
}
async fn mint_lease(
    rig: &Rig,
    command: &Command,
    media: &NativeMedia<MediaAudience>,
) -> llull_buzz_provider::Result<CommandResult> {
    let body = canonical(command).unwrap();
    let claims = rig.claims(command, "module-a", None, None);
    let signed = rig.sign(
        "/integration/v1/native-attachment-leases",
        "POST",
        &body,
        &claims,
        EVIDENCE,
    );
    rig.p
        .lease_native_attachment(&body, signed.headers(), media)
        .await
}
fn native_get_proof(key: &nostr::Keys) -> String {
    let expiration = (Utc::now().timestamp() + 600).to_string();
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(24242), "Get media")
        .tags([
            nostr::Tag::parse(["t", "get"]).unwrap(),
            nostr::Tag::parse(["expiration", &expiration]).unwrap(),
            nostr::Tag::parse(["server", "relay.synthetic.invalid"]).unwrap(),
        ])
        .sign_with_keys(key)
        .unwrap();
    format!(
        "Nostr {}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&event).unwrap())
    )
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn native_media_lease_is_exact_current_and_head_is_not_a_metadata_bypass() {
    let rig = Rig::new().await;
    let (command, key, port, media) = lease_fixture(&rig).await;
    let sha = command.payload["evidence"]["sha256"].as_str().unwrap();
    let auth = native_get_proof(&key);
    assert!(rig
        .p
        .native_attachment_bytes(sha, "relay.synthetic.invalid", &auth, &media)
        .await
        .is_err());
    let bytes = canonical(&command).unwrap();
    let wrong_purpose = rig.sign(
        "/integration/v1/native-attachment-leases",
        "POST",
        &bytes,
        &rig.claims(&command, "module-a", None, None),
        INVOCATION,
    );
    assert!(rig
        .p
        .lease_native_attachment(&bytes, wrong_purpose.headers(), &media)
        .await
        .is_err());
    for (field, value) in [
        ("enrollment_revision", json!(999)),
        ("enrollment_id", json!("foreign-binding")),
        ("native_key", json!(key.public_key().to_hex())),
        ("audience_revision", json!("stale")),
    ] {
        let mut changed = command.clone();
        changed.payload[field] = value;
        assert!(mint_lease(&rig, &changed, &media).await.is_err());
    }
    let first = mint_lease(&rig, &command, &media).await.unwrap();
    let replay = mint_lease(&rig, &command, &media).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(
        serde_json::to_value(&first.receipt).unwrap(),
        serde_json::to_value(&replay.receipt).unwrap()
    );
    assert_eq!(first.result, replay.result);
    assert_eq!(first.result["native_delivery"], "not-observed");
    assert_eq!(
        rig.p
            .native_attachment_bytes(sha, "relay.synthetic.invalid", &auth, &media)
            .await
            .unwrap(),
        b"original"
    );
    let outsider = native_get_proof(&nostr::Keys::generate());
    assert!(rig
        .p
        .native_attachment_bytes(sha, "relay.synthetic.invalid", &outsider, &media)
        .await
        .is_err());
    assert!(rig
        .p
        .native_attachment_bytes(sha, "foreign.invalid", &auth, &media)
        .await
        .is_err());
    assert!(rig
        .p
        .native_attachment_bytes(&sha256(b"other"), "relay.synthetic.invalid", &auth, &media)
        .await
        .is_err());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = api::native_media_routes(rig.p.clone(), media.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{address}/media/{sha}");
    for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
        let response = client
            .request(method.clone(), &url)
            .header("host", "relay.synthetic.invalid")
            .header("authorization", &auth)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-length"], "8");
        assert_eq!(
            response.headers()["content-type"],
            "application/octet-stream"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = response.bytes().await.unwrap();
        if method == reqwest::Method::HEAD {
            assert!(bytes.is_empty());
        } else {
            assert_eq!(bytes.as_ref(), b"original");
        }
    }
    let range = client
        .get(&url)
        .header("host", "relay.synthetic.invalid")
        .header("authorization", &auth)
        .header("range", "bytes=0-0")
        .send()
        .await
        .unwrap();
    assert_eq!(range.status(), 501);
    for suffix in [".thumb.jpg", "?consumer=foreign"] {
        assert!(!client
            .get(format!("{url}{suffix}"))
            .header("host", "relay.synthetic.invalid")
            .header("authorization", &auth)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
    }
    port.audience
        .lock()
        .unwrap()
        .members
        .remove(&key.public_key().to_hex());
    for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
        let response = client
            .request(method.clone(), &url)
            .header("host", "relay.synthetic.invalid")
            .header("authorization", &auth)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let body = response.bytes().await.unwrap();
        assert!(!body.windows(8).any(|v| v == b"original"));
        if method == reqwest::Method::HEAD {
            assert!(body.is_empty());
        }
    }
    server.abort();
    let _ = server.await;
    port.audience
        .lock()
        .unwrap()
        .members
        .insert(key.public_key().to_hex());
    let enrollment = command.payload["enrollment_id"].as_str().unwrap();
    let binding: Binding = sqlx::query_as("SELECT * FROM enrollments WHERE enrollment_id=$1")
        .bind(enrollment)
        .fetch_one(&rig.pool)
        .await
        .unwrap();
    let revoke = rig.command(
        "change-access",
        rig.resource(enrollment, binding.revision as u64),
        ChangeAccess {
            enrollment_id: enrollment.into(),
            expected_revision: binding.revision.to_string(),
            change: AccessChange::Revoke,
        },
    );
    let claims = rig.claims(&revoke, "module-a", None, None);
    let (body, signed) = rig.prepare("/integration/v1/access-changes", &revoke, &claims);
    rig.p.change_access(&body, signed.headers()).await.unwrap();
    assert!(rig
        .p
        .native_attachment_bytes(sha, "relay.synthetic.invalid", &auth, &media)
        .await
        .is_err());
    assert!(mint_lease(&rig, &command, &media).await.is_err());
    assert!(sqlx::query(
        "UPDATE native_attachment_leases SET expires_at=expires_at+interval '1 hour'"
    )
    .execute(&rig.pool)
    .await
    .is_err());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn native_media_lease_denies_ambiguous_intents_and_revoked_registration_or_epoch() {
    let rig = Rig::new().await;
    let (command, key, _, media) = lease_fixture(&rig).await;
    let sha = command.payload["evidence"]["sha256"].as_str().unwrap();
    let auth = native_get_proof(&key);
    mint_lease(&rig, &command, &media).await.unwrap();
    let restored =
        Provider::new(rig.pool.clone(), "https://provider.synthetic.invalid", 2).unwrap();
    assert!(restored
        .native_attachment_bytes(sha, "relay.synthetic.invalid", &auth, &media)
        .await
        .is_err());
    let mut duplicate = command.clone();
    duplicate.intent_id = Uuid::new_v4().to_string();
    mint_lease(&rig, &duplicate, &media).await.unwrap();
    assert!(
        rig.p
            .native_attachment_bytes(sha, "relay.synthetic.invalid", &auth, &media)
            .await
            .is_err(),
        "hash-only path may not guess between retained leases"
    );

    let other = Rig::new().await;
    let (command, key, _, media) = lease_fixture(&other).await;
    let sha = command.payload["evidence"]["sha256"].as_str().unwrap();
    let auth = native_get_proof(&key);
    mint_lease(&other, &command, &media).await.unwrap();
    other
        .p
        .set_service_active(
            &other.registration.consumer_id,
            false,
            &digest(&other.registration).unwrap(),
        )
        .await
        .unwrap();
    assert!(other
        .p
        .native_attachment_bytes(sha, "relay.synthetic.invalid", &auth, &media)
        .await
        .is_err());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn native_media_lease_cannot_outlive_release_or_survive_unknown_partial_commit() {
    let rig = Rig::new().await;
    let (mut command, key, port, media) = lease_fixture(&rig).await;
    let sha = command.payload["evidence"]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let auth = native_get_proof(&key);
    command.payload["expires_at"] = json!(Utc::now() + CD::minutes(2));
    assert!(mint_lease(&rig, &command, &media).await.is_err());
    command.payload["expires_at"] = json!(Utc::now() + CD::seconds(40));
    sqlx::raw_sql("CREATE FUNCTION fail_native_lease_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation='lease-native-attachment' THEN RAISE EXCEPTION 'synthetic receipt failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER synthetic_lease_failure BEFORE INSERT ON commands FOR EACH ROW EXECUTE FUNCTION fail_native_lease_receipt();").execute(&rig.pool).await.unwrap();
    assert!(mint_lease(&rig, &command, &media).await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM native_attachment_leases")
        .fetch_one(&rig.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::raw_sql("DROP TRIGGER synthetic_lease_failure ON commands; DROP FUNCTION fail_native_lease_receipt();").execute(&rig.pool).await.unwrap();
    command.payload["expires_at"] = json!(Utc::now() + CD::seconds(2));
    mint_lease(&rig, &command, &media).await.unwrap();
    *port.delay.lock().unwrap() = Duration::from_millis(2100);
    assert!(rig
        .p
        .native_attachment_bytes(&sha, "relay.synthetic.invalid", &auth, &media)
        .await
        .is_err());
    *port.delay.lock().unwrap() = Duration::ZERO;
    assert!(
        mint_lease(&rig, &command, &media).await.is_err(),
        "fresh transport does not renew an expired original lease"
    );
}
