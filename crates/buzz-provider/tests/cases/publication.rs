//! Publication ledger fault tests. The native transport fixture is explicitly
//! separate from the pinned relay/client integration scenario.
use super::*;
use llull_buzz_provider::{Audience, NativeEventSource, PublicationPort, Publisher};
use sqlx::types::Json;
use std::sync::{atomic::AtomicBool, Arc};

struct Sink {
    key: nostr::PublicKey,
    revision: Mutex<String>,
    events: Mutex<BTreeMap<String, Vec<u8>>>,
    calls: AtomicUsize,
    lose: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl NativeEventSource for Sink {
    async fn event(
        &self,
        _community: &str,
        _channel: &str,
        event: &str,
    ) -> std::result::Result<Vec<u8>, PortError> {
        self.events
            .lock()
            .unwrap()
            .get(event)
            .cloned()
            .ok_or(PortError)
    }
}
#[async_trait]
impl PublicationPort for Sink {
    fn owner(&self) -> &str {
        "synthetic-native-origin"
    }
    fn public_key(&self) -> nostr::PublicKey {
        self.key
    }
    async fn audience(
        &self,
        community: &str,
        channel: &str,
    ) -> std::result::Result<Audience, PortError> {
        Ok(Audience {
            community_id: community.into(),
            channel_id: channel.into(),
            revision: self.revision.lock().unwrap().clone(),
            members: BTreeSet::from([self.key.to_hex()]),
        })
    }
    async fn submit(&self, _community: &str, bytes: &[u8]) -> std::result::Result<bool, PortError> {
        let event = llull_buzz_provider::native::event(bytes).map_err(|_| PortError)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.events
            .lock()
            .unwrap()
            .entry(event.id.to_hex())
            .or_insert_with(|| bytes.to_vec());
        if self.lose.swap(false, Ordering::SeqCst) {
            Err(PortError)
        } else {
            Ok(true)
        }
    }
}

// Uses real database time and an actual await in the native lookup boundary,
// without changing the immutable task, assertion, or provider clock.
struct ExpiringAudience {
    inner: Sink,
    pool: PgPool,
    deadline: chrono::DateTime<Utc>,
    expire_on: usize,
    reads: AtomicUsize,
}
#[async_trait]
impl NativeEventSource for ExpiringAudience {
    async fn event(
        &self,
        community: &str,
        channel: &str,
        event: &str,
    ) -> std::result::Result<Vec<u8>, PortError> {
        self.inner.event(community, channel, event).await
    }
}
#[async_trait]
impl PublicationPort for ExpiringAudience {
    fn owner(&self) -> &str {
        self.inner.owner()
    }
    fn public_key(&self) -> nostr::PublicKey {
        self.inner.public_key()
    }
    async fn audience(
        &self,
        community: &str,
        channel: &str,
    ) -> std::result::Result<Audience, PortError> {
        if self.reads.fetch_add(1, Ordering::SeqCst) + 1 == self.expire_on {
            let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&self.pool)
                .await
                .unwrap();
            assert!(
                now < self.deadline,
                "fixture must reach the awaited boundary before expiry"
            );
            let wait = (self.deadline - now).to_std().unwrap() + Duration::from_millis(20);
            assert!(
                wait < Duration::from_secs(4),
                "keep within the native lookup timeout"
            );
            tokio::time::sleep(wait).await;
            let expired: bool = sqlx::query_scalar("SELECT clock_timestamp() >= $1")
                .bind(self.deadline)
                .fetch_one(&self.pool)
                .await
                .unwrap();
            assert!(expired);
        }
        self.inner.audience(community, channel).await
    }
    async fn submit(&self, community: &str, bytes: &[u8]) -> std::result::Result<bool, PortError> {
        self.inner.submit(community, bytes).await
    }
}

fn signed_publication(rig: &Rig, c: &Command) -> (Vec<u8>, Signed) {
    signed_with_root(rig, c, None)
}
fn signed_with_root(rig: &Rig, c: &Command, root: Option<&str>) -> (Vec<u8>, Signed) {
    let publication: Publication = c.payload().unwrap();
    let mut claims = rig.claims(c, "module-a", root, None);
    claims.release = Some(Release {
        release_ref: publication.release_ref.clone(),
        community_id: publication.community_id.clone(),
        channel_id: publication.channel_id.clone(),
        audience_policy: publication.audience_policy.clone(),
        audience_revision: publication.audience_revision.clone(),
        publication_sha256: digest(&publication).unwrap(),
        checked_at: Utc::now().timestamp(),
    });
    let body = canonical(c).unwrap();
    let h = rig.sign(
        "/integration/v1/publications",
        "POST",
        &body,
        &claims,
        PUBLICATION,
    );
    (body, h)
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn publication_root_expiry_during_native_lookup_never_dispatches_or_rewrites_unknown() {
    for boundary in [0, 1, 2] {
        let rig = Rig::new().await;
        let root = rig
            .start(None, "module-a", if boundary == 0 { 30 } else { 3 })
            .await;
        let key = nostr::Keys::generate();
        let channel = Uuid::new_v4();
        let parent = buzz_sdk::build_message(
            channel,
            "Original signed mention",
            None,
            &[],
            false,
            &[],
            &[],
        )
        .unwrap()
        .sign_with_keys(&nostr::Keys::generate())
        .unwrap();
        let sink = Arc::new(ExpiringAudience {
            inner: Sink {
                key: key.public_key(),
                revision: Mutex::new("audience-1".into()),
                events: Mutex::new(BTreeMap::from([(
                    parent.id.to_hex(),
                    serde_json::to_vec(&parent).unwrap(),
                )])),
                calls: AtomicUsize::new(0),
                lose: false.into(),
            },
            pool: rig.pool.clone(),
            deadline: root.expires_at,
            expire_on: boundary,
            reads: AtomicUsize::new(0),
        });
        let publisher =
            Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap();
        let publication = Publication {
            community_id: rig.registration.community_id.clone(),
            channel_id: channel.to_string(),
            audience_policy: "synthetic-private".into(),
            audience_revision: "audience-1".into(),
            release_ref: Uuid::new_v4().to_string(),
            text: "Approved reply".into(),
            text_sha256: sha256(b"Approved reply"),
            copy_mode: CopyMode::SummaryLink,
            attachments: vec![],
            reply_to_event: Some(parent.id.to_hex()),
        };
        let command = rig.command("publish", rig.resource("deadline-result", 1), &publication);
        let (body, signed) = signed_with_root(&rig, &command, Some(&root.root_task_id));
        let original = rig
            .p
            .admit_publication(&body, signed.headers())
            .await
            .unwrap();
        let id = Uuid::parse_str(&original.receipt.operation_id).unwrap();
        let stored: Value = sqlx::query_scalar("SELECT result FROM commands WHERE consumer_id=$1 AND operation='publish' AND intent_id=$2")
            .bind(&command.consumer_id).bind(&command.intent_id).fetch_one(&rig.pool).await.unwrap();
        let (body, signed) = signed_with_root(&rig, &command, Some(&root.root_task_id));
        let result = rig.p.publish(&body, signed.headers(), &publisher).await;
        if boundary == 0 {
            assert_eq!(result.unwrap().publication.state, "completed");
            assert_eq!(sink.inner.calls.load(Ordering::SeqCst), 1);
            continue;
        }
        assert!(matches!(
            result,
            Err(ProviderError::Admission(Fault::Exhausted))
        ));
        assert_eq!(sink.reads.load(Ordering::SeqCst), boundary);
        assert_eq!(sink.inner.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            sink.inner.events.lock().unwrap().len(),
            1,
            "only the original mention exists"
        );
        let delivery: Option<(String, String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT state,native_event_id,signed_event,revision FROM publication_deliveries WHERE publication_id=$1")
            .bind(id).fetch_optional(&rig.pool).await.unwrap();
        if boundary == 1 {
            assert!(
                delivery.is_none(),
                "expired preflight cannot commit signed custody"
            );
            let (body, signed) = signed_with_root(&rig, &command, Some(&root.root_task_id));
            assert!(matches!(
                rig.p.publish(&body, signed.headers(), &publisher).await,
                Err(ProviderError::Admission(Fault::Exhausted))
            ));
        } else {
            let retained = delivery.unwrap();
            assert_eq!(retained.0, "unknown");
            assert_eq!(
                llull_buzz_provider::native::event(&retained.2)
                    .unwrap()
                    .id
                    .to_hex(),
                retained.1
            );
            let (body, signed) = signed_with_root(&rig, &command, Some(&root.root_task_id));
            let retry = rig
                .p
                .publish(&body, signed.headers(), &publisher)
                .await
                .unwrap();
            assert_eq!(retry.publication.state, "unknown");
            assert_eq!(
                retry.publication.native_event_id.as_deref(),
                Some(retained.1.as_str())
            );
            // Current record-access authority may observe an expired original
            // root, but a missing event never authorizes a new send or identity.
            let recovery = rig.command(
                "reconcile-publication",
                rig.resource(&id.to_string(), 1),
                json!({"publication_id": id}),
            );
            let claims = rig.claims(&recovery, "module-a", None, None);
            let (body, signed) = rig.prepare(
                &format!("/integration/v1/publications/{id}/reconcile"),
                &recovery,
                &claims,
            );
            assert_eq!(
                rig.p
                    .reconcile_publication(id, &body, signed.headers(), &publisher)
                    .await
                    .unwrap()
                    .state,
                "unknown"
            );
            let after: (String, String, Vec<u8>, i64) = sqlx::query_as(
                "SELECT state,native_event_id,signed_event,revision FROM publication_deliveries WHERE publication_id=$1")
                .bind(id).fetch_one(&rig.pool).await.unwrap();
            assert_eq!(after, retained);
        }
        let after: Value = sqlx::query_scalar("SELECT result FROM commands WHERE consumer_id=$1 AND operation='publish' AND intent_id=$2")
            .bind(&command.consumer_id).bind(&command.intent_id).fetch_one(&rig.pool).await.unwrap();
        assert_eq!(after, stored, "original admission receipt is immutable");
        assert_eq!(sink.inner.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn publication_reply_requires_original_signed_same_channel_event() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let channel = Uuid::new_v4();
    let thread_root =
        buzz_sdk::build_message(channel, "Original conversation", None, &[], false, &[], &[])
            .unwrap()
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();
    let original = buzz_sdk::build_message(
        channel,
        "Synthetic native mention",
        Some(&buzz_sdk::ThreadRef {
            root_event_id: thread_root.id,
            parent_event_id: thread_root.id,
        }),
        &[],
        false,
        &[],
        &[],
    )
    .unwrap()
    .sign_with_keys(&nostr::Keys::generate())
    .unwrap();
    let sink = Arc::new(Sink {
        key: key.public_key(),
        revision: Mutex::new("audience-1".into()),
        events: Mutex::new(BTreeMap::from([
            (original.id.to_hex(), serde_json::to_vec(&original).unwrap()),
            (
                thread_root.id.to_hex(),
                serde_json::to_vec(&thread_root).unwrap(),
            ),
        ])),
        calls: AtomicUsize::new(0),
        lose: false.into(),
    });
    let publisher =
        Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap();
    let mut publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: Uuid::new_v4().to_string(),
        audience_policy: "synthetic-private".into(),
        audience_revision: "audience-1".into(),
        release_ref: Uuid::new_v4().to_string(),
        text: "Approved result link".into(),
        text_sha256: sha256(b"Approved result link"),
        copy_mode: CopyMode::SummaryLink,
        attachments: vec![],
        reply_to_event: Some(original.id.to_hex()),
    };
    let wrong = rig.command("publish", rig.resource("wrong-channel", 1), &publication);
    let (bytes, signed) = signed_publication(&rig, &wrong);
    assert!(rig
        .p
        .publish(&bytes, signed.headers(), &publisher)
        .await
        .is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    publication.channel_id = channel.to_string();
    publication.release_ref = Uuid::new_v4().to_string();
    let command = rig.command("publish", rig.resource("same-channel", 1), &publication);
    let (bytes, signed) = signed_publication(&rig, &command);
    let result = rig
        .p
        .publish(&bytes, signed.headers(), &publisher)
        .await
        .unwrap();
    assert_eq!(result.publication.state, "completed");
    let identity = result.publication.native_event_id.unwrap();
    let retained = sink.events.lock().unwrap()[&identity].clone();
    let reply = llull_buzz_provider::native::event(&retained).unwrap();
    assert!(reply
        .tags
        .iter()
        .any(|tag| tag.as_slice() == ["e", &original.id.to_hex(), "", "reply"]));
    assert!(reply
        .tags
        .iter()
        .any(|tag| tag.as_slice() == ["h", &channel.to_string()]));
    assert_eq!(
        buzz_core::nip10::parse_thread_markers(&reply.tags).resolve(),
        Some((thread_root.id.to_hex(), original.id.to_hex()))
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    // A changed reply target is a different frozen release, never a retry.
    let mut changed = command.clone();
    changed.payload["reply_to_event"] = json!("f".repeat(64));
    let (bytes, signed) = signed_publication(&rig, &changed);
    assert!(rig
        .p
        .publish(&bytes, signed.headers(), &publisher)
        .await
        .is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn publication_freezes_signed_identity_and_recovers_without_duplicate_delivery() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let sink = Arc::new(Sink {
        key: key.public_key(),
        revision: Mutex::new("audience-1".into()),
        events: Mutex::new(BTreeMap::new()),
        calls: AtomicUsize::new(0),
        lose: true.into(),
    });
    let publisher =
        Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap();
    let publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: Uuid::new_v4().to_string(),
        audience_policy: "synthetic-private".into(),
        audience_revision: "audience-1".into(),
        release_ref: Uuid::new_v4().to_string(),
        text: "Synthetic approved reply".into(),
        text_sha256: sha256(b"Synthetic approved reply"),
        copy_mode: CopyMode::ExplicitCopy,
        reply_to_event: None,
        attachments: vec![],
    };
    let c = rig.command("publish", rig.resource("synthetic-result", 1), &publication);
    let (body, h) = signed_publication(&rig, &c);
    let unknown = rig.p.publish(&body, h.headers(), &publisher).await.unwrap();
    assert_eq!(unknown.publication.state, "unknown");
    let id = unknown.publication.publication_id;
    let event_id = unknown.publication.native_event_id.clone().unwrap();
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT signed_event FROM publication_deliveries WHERE publication_id=$1",
    )
    .bind(id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(sink.events.lock().unwrap()[&event_id], retained);
    assert_eq!(
        llull_buzz_provider::native::event(&retained)
            .unwrap()
            .content,
        publication.text
    );
    // A same-command retry cannot infer that the lost response means the
    // original relay submission failed. It must retain the original unknown
    // state until original-owner reconciliation, without another send.
    let (retry_body, retry_signed) = signed_publication(&rig, &c);
    let retry = rig
        .p
        .publish(&retry_body, retry_signed.headers(), &publisher)
        .await
        .unwrap();
    assert_eq!(retry.publication.state, "unknown");
    assert_eq!(
        retry.publication.native_event_id.as_deref(),
        Some(event_id.as_str())
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    let recovery = rig.command(
        "reconcile-publication",
        rig.resource(&id.to_string(), 1),
        json!({"publication_id":id}),
    );
    let claims = rig.claims(&recovery, "module-a", None, None);
    let (body, h) = rig.prepare(
        &format!("/integration/v1/publications/{id}/reconcile"),
        &recovery,
        &claims,
    );
    // Audience changes cannot rewrite the signed event or require another send
    // to learn that the original publication was already committed.
    *sink.revision.lock().unwrap() = "audience-2".into();
    let complete = rig
        .p
        .reconcile_publication(id, &body, h.headers(), &publisher)
        .await
        .unwrap();
    assert_eq!(complete.state, "completed");
    assert_eq!(complete.native_event_id.as_deref(), Some(event_id.as_str()));
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);

    // A canceled task's admitted publication cannot shed its original root or
    // acquire a new service identity through a fresh assertion of the same body.
    *sink.revision.lock().unwrap() = "audience-1".into();
    let root = rig.start(None, "module-a", 300).await;
    let mut bound = c.clone();
    bound.intent_id = Uuid::new_v4().to_string();
    bound.payload["release_ref"] = json!(Uuid::new_v4().to_string());
    let (body, h) = signed_with_root(&rig, &bound, Some(&root.root_task_id));
    rig.p.admit_publication(&body, h.headers()).await.unwrap();
    rig.cancel(&root, None, "module-a", 1).await;
    let (body, h) = signed_publication(&rig, &bound);
    assert!(rig.p.publish(&body, h.headers(), &publisher).await.is_err());
    let (body, h) = signed_with_root(&rig, &bound, Some(&root.root_task_id));
    assert!(rig.p.publish(&body, h.headers(), &publisher).await.is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    *sink.revision.lock().unwrap() = "audience-2".into();
    assert_eq!(sink.events.lock().unwrap().len(), 1);
    let changed = sqlx::query(
        "UPDATE publication_deliveries SET signed_event='changed' WHERE publication_id=$1",
    )
    .bind(id)
    .execute(&rig.pool)
    .await;
    assert!(changed.is_err());
    let mut next = c.clone();
    next.intent_id = Uuid::new_v4().to_string();
    next.payload["release_ref"] = json!(Uuid::new_v4().to_string());
    let (body, h) = signed_publication(&rig, &next);
    assert!(rig.p.publish(&body, h.headers(), &publisher).await.is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn attachment_publication_keeps_admission_without_unsafe_native_delivery() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let sink = Arc::new(Sink {
        key: key.public_key(),
        revision: Mutex::new("audience-1".into()),
        events: Mutex::new(BTreeMap::new()),
        calls: AtomicUsize::new(0),
        lose: AtomicBool::new(false),
    });
    let publisher = Publisher::new(
        sink.clone(),
        key.clone(),
        "https://provider.synthetic.invalid",
    )
    .unwrap();
    let text = "Synthetic attachment announcement";
    let publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: Uuid::new_v4().to_string(),
        audience_policy: "synthetic-private".into(),
        audience_revision: "audience-1".into(),
        release_ref: Uuid::new_v4().to_string(),
        text: text.into(),
        text_sha256: sha256(text.as_bytes()),
        copy_mode: CopyMode::ExplicitCopy,
        reply_to_event: None,
        attachments: vec![Evidence {
            source_id: Uuid::new_v4().to_string(),
            sha256: sha256(b"synthetic attachment bytes"),
            media_type: "image/png".into(),
            size_bytes: 26,
            release_ref: Uuid::new_v4().to_string(),
        }],
    };
    let command = rig.command("publish", rig.resource("synthetic-result", 1), &publication);
    let (body, signed) = signed_publication(&rig, &command);
    let result = rig.p.publish(&body, signed.headers(), &publisher).await;
    assert!(matches!(
        result,
        Err(ProviderError::Admission(Fault::Unavailable))
    ));
    let admission_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM publications WHERE consumer_id=$1 AND intent_id=$2",
    )
    .bind(&command.consumer_id)
    .bind(&command.intent_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    let delivery_count: i64 = sqlx::query_scalar("SELECT count(*) FROM publication_deliveries")
        .fetch_one(&rig.pool)
        .await
        .unwrap();
    assert_eq!(admission_count, 1);
    assert_eq!(delivery_count, 0);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);

    // Simulate an unknown signed attachment retained by a previous provider
    // version. A retry must not bypass the gate merely because signing is done.
    let (admit_body, admit_signed) = signed_publication(&rig, &command);
    let admitted = rig
        .p
        .admit_publication(&admit_body, admit_signed.headers())
        .await
        .unwrap();
    let publication_id = Uuid::parse_str(&admitted.receipt.operation_id).unwrap();
    let channel = Uuid::parse_str(&publication.channel_id).unwrap();
    let media = vec![vec![
        "imeta".into(),
        "url https://provider.synthetic.invalid/media/legacy".into(),
        format!("x {}", publication.attachments[0].sha256),
        "m image/png".into(),
        "size 26".into(),
    ]];
    let original = buzz_sdk::build_message(channel, text, None, &[], false, &media, &[])
        .unwrap()
        .sign_with_keys(&key)
        .unwrap();
    let original_id = original.id.to_hex();
    let original_bytes = serde_json::to_vec(&original).unwrap();
    let audience = Audience {
        community_id: publication.community_id.clone(),
        channel_id: publication.channel_id.clone(),
        revision: publication.audience_revision.clone(),
        members: BTreeSet::from([key.public_key().to_hex()]),
    };
    sqlx::query("INSERT INTO publication_deliveries(publication_id,consumer_id,module_id,context_domain,owner,native_event_id,signed_event,event_sha256,audience,state) VALUES($1,$2,'module-a','synthetic-domain','synthetic-native-origin',$3,$4,$5,$6,'unknown')")
        .bind(publication_id)
        .bind(&command.consumer_id)
        .bind(&original_id)
        .bind(&original_bytes)
        .bind(sha256(&original_bytes))
        .bind(sqlx::types::Json(&audience))
        .execute(&rig.pool)
        .await
        .unwrap();
    let (retry_body, retry_signed) = signed_publication(&rig, &command);
    let retry = rig
        .p
        .publish(&retry_body, retry_signed.headers(), &publisher)
        .await;
    assert!(matches!(
        retry,
        Err(ProviderError::Admission(Fault::Unavailable))
    ));
    let retained_state: String = sqlx::query_scalar(
        "SELECT state FROM publication_deliveries WHERE publication_id=$1 AND native_event_id=$2",
    )
    .bind(publication_id)
    .bind(&original_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(retained_state, "unknown");
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);

    sqlx::query("UPDATE publication_deliveries SET state='completed',revision=revision+1,completed_at=clock_timestamp() WHERE publication_id=$1")
        .bind(publication_id)
        .execute(&rig.pool)
        .await
        .unwrap();
    let (complete_body, complete_signed) = signed_publication(&rig, &command);
    let complete = rig
        .p
        .publish(&complete_body, complete_signed.headers(), &publisher)
        .await
        .unwrap();
    assert_eq!(complete.publication.state, "completed");
    assert_eq!(
        complete.publication.native_event_id.as_deref(),
        Some(original_id.as_str())
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
}

/// This case targets the running provider and the unmodified pinned relay on
/// an isolated task network. Ordinary library/DB suites keep the fixture above.
#[tokio::test]
#[ignore = "requires the task-owned live provider, relay and PostgreSQL stack"]
async fn live_provider_publishes_one_signed_event_to_pinned_relay() {
    let config: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("NATIVE_ORIGIN_CONFIG").unwrap()).unwrap(),
    )
    .unwrap();
    let secret = std::fs::read_to_string(config["service_key_file"].as_str().unwrap()).unwrap();
    let key = nostr::Keys::parse(secret.trim()).unwrap();
    let origin = Arc::new(
        HttpNativeOrigin::new(
            config["community_id"].as_str().unwrap().into(),
            config["private_origin"].as_str().unwrap(),
            config["public_origin"].as_str().unwrap(),
            key,
            nostr::PublicKey::from_hex(config["relay_public_key"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    );
    let channel = std::env::var("BZ_TEST_CHANNEL").unwrap();
    let audience = origin
        .audience("synthetic-community", &channel)
        .await
        .unwrap();
    assert!(audience.members.contains(&origin.public_key().to_hex()));

    let rig = Rig::new().await;
    let text = format!("synthetic live provider publication {}", Uuid::new_v4());
    let publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: channel,
        audience_policy: "synthetic-private".into(),
        audience_revision: audience.revision,
        release_ref: Uuid::new_v4().to_string(),
        text_sha256: sha256(text.as_bytes()),
        text: text.clone(),
        copy_mode: CopyMode::ExplicitCopy,
        reply_to_event: None,
        attachments: vec![],
    };
    let command = rig.command(
        "publish",
        rig.resource("live-provider-result", 1),
        &publication,
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    let deliver = |body: Vec<u8>, signed: Signed| {
        client
            .post("http://provider.synthetic.invalid:8080/integration/v1/publications")
            .header("authorization", signed.resource)
            .header("x-llull-invocation", signed.assertion)
            .header("content-type", "application/json")
            .body(body)
    };
    let (body, signed) = signed_publication(&rig, &command);
    let response = deliver(body, signed).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let delivered: PublishResult = response.json().await.unwrap();
    assert_eq!(delivered.publication.state, "completed");
    let event_id = delivered.publication.native_event_id.unwrap();
    let native_bytes = origin
        .event(
            &publication.community_id,
            &publication.channel_id,
            &event_id,
        )
        .await
        .unwrap();
    let native_event = llull_buzz_provider::native::event(&native_bytes).unwrap();
    assert_eq!(native_event.content, text);
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT signed_event FROM publication_deliveries WHERE publication_id=$1",
    )
    .bind(delivered.publication.publication_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(
        llull_buzz_provider::native::event(&retained).unwrap(),
        native_event
    );

    // A fresh signed retry of the exact command must return the original
    // event identity without another publication ledger entry.
    let (body, signed) = signed_publication(&rig, &command);
    let response = deliver(body, signed).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let recovered: PublishResult = response.json().await.unwrap();
    assert_eq!(recovered.publication.state, "completed");
    assert_eq!(
        recovered.publication.native_event_id.as_deref(),
        Some(event_id.as_str())
    );
    let identities: i64 =
        sqlx::query_scalar("SELECT count(*) FROM publication_deliveries WHERE publication_id=$1")
            .bind(delivered.publication.publication_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(identities, 1);
    println!(
        "{}",
        json!({
            "publication_id": delivered.publication.publication_id,
            "native_event_id": event_id,
            "signed_event_recovered_from_relay": true,
            "same_command_retry_reused_event": true,
        })
    );
}

struct RelayFaultProxy {
    client: reqwest::Client,
    lose_committed_response: AtomicBool,
    submissions: AtomicUsize,
}

async fn relay_fault_proxy(
    axum::extract::State(proxy): axum::extract::State<Arc<RelayFaultProxy>>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let target = format!(
        "http://buzz-relay.synthetic.invalid:3000{}",
        uri.path_and_query()
            .map_or(uri.path(), |value| value.as_str())
    );
    let mut request = proxy.client.post(target).body(body);
    for name in ["host", "authorization", "content-type"] {
        if let Some(value) = headers.get(name) {
            request = request.header(name, value);
        }
    }
    let Ok(response) = request.send().await else {
        return axum::http::StatusCode::BAD_GATEWAY.into_response();
    };
    let status = response.status();
    let Ok(bytes) = response.bytes().await else {
        return axum::http::StatusCode::BAD_GATEWAY.into_response();
    };
    if uri.path() == "/events" {
        proxy.submissions.fetch_add(1, Ordering::SeqCst);
        let committed = status.is_success()
            && serde_json::from_slice::<Value>(&bytes)
                .is_ok_and(|receipt| receipt["accepted"] == true);
        if committed && proxy.lose_committed_response.swap(false, Ordering::SeqCst) {
            return axum::http::StatusCode::BAD_GATEWAY.into_response();
        }
    }
    (
        axum::http::StatusCode::from_u16(status.as_u16()).unwrap(),
        bytes,
    )
        .into_response()
}

/// The relay commits the original event, but the provider sees only a failed
/// transport response. Recovery must query that original owner and never send
/// another event, even though the publication was durably marked unknown.
#[tokio::test]
#[ignore = "requires the task-owned pinned relay and PostgreSQL stack"]
async fn live_relay_response_loss_reconciles_original_event_without_resend() {
    let config: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("NATIVE_ORIGIN_CONFIG").unwrap()).unwrap(),
    )
    .unwrap();
    let secret = std::fs::read_to_string(config["service_key_file"].as_str().unwrap()).unwrap();
    let key = nostr::Keys::parse(secret.trim()).unwrap();
    let community = config["community_id"].as_str().unwrap();
    let public_origin = config["public_origin"].as_str().unwrap();
    let relay_key =
        nostr::PublicKey::from_hex(config["relay_public_key"].as_str().unwrap()).unwrap();
    let direct = HttpNativeOrigin::new(
        community.into(),
        config["private_origin"].as_str().unwrap(),
        public_origin,
        key.clone(),
        relay_key,
    )
    .unwrap();
    let channel = std::env::var("BZ_TEST_CHANNEL").unwrap();
    let audience = direct.audience(community, &channel).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy = Arc::new(RelayFaultProxy {
        client: reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
        lose_committed_response: AtomicBool::new(true),
        submissions: AtomicUsize::new(0),
    });
    let server_proxy = proxy.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new()
                .fallback(relay_fault_proxy)
                .with_state(server_proxy),
        )
        .await
        .unwrap();
    });
    let proxied = Arc::new(
        HttpNativeOrigin::new(
            community.into(),
            &format!("http://127.0.0.1:{port}"),
            public_origin,
            key.clone(),
            relay_key,
        )
        .unwrap(),
    );
    let publisher = Publisher::new(proxied, key, "https://provider.synthetic.invalid").unwrap();
    let rig = Rig::new().await;
    let text = format!("synthetic lost native response {}", Uuid::new_v4());
    let publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: channel,
        audience_policy: "synthetic-private".into(),
        audience_revision: audience.revision,
        release_ref: Uuid::new_v4().to_string(),
        text_sha256: sha256(text.as_bytes()),
        text: text.clone(),
        copy_mode: CopyMode::ExplicitCopy,
        reply_to_event: None,
        attachments: vec![],
    };
    let command = rig.command(
        "publish",
        rig.resource("live-lost-response-result", 1),
        &publication,
    );
    let (body, signed) = signed_publication(&rig, &command);
    let unknown = rig
        .p
        .publish(&body, signed.headers(), &publisher)
        .await
        .unwrap();
    assert_eq!(unknown.publication.state, "unknown");
    let id = unknown.publication.publication_id;
    let event_id = unknown.publication.native_event_id.unwrap();
    assert_eq!(proxy.submissions.load(Ordering::SeqCst), 1);
    let original = direct
        .event(
            &publication.community_id,
            &publication.channel_id,
            &event_id,
        )
        .await
        .unwrap();
    assert_eq!(
        llull_buzz_provider::native::event(&original)
            .unwrap()
            .content,
        text
    );
    let (retry_body, retry_signed) = signed_publication(&rig, &command);
    let retry = rig
        .p
        .publish(&retry_body, retry_signed.headers(), &publisher)
        .await
        .unwrap();
    assert_eq!(retry.publication.state, "unknown");
    assert_eq!(
        retry.publication.native_event_id.as_deref(),
        Some(event_id.as_str())
    );
    assert_eq!(proxy.submissions.load(Ordering::SeqCst), 1);

    let recovery = rig.command(
        "reconcile-publication",
        rig.resource(&id.to_string(), 1),
        json!({"publication_id":id}),
    );
    let claims = rig.claims(&recovery, "module-a", None, None);
    let (body, signed) = rig.prepare(
        &format!("/integration/v1/publications/{id}/reconcile"),
        &recovery,
        &claims,
    );
    let complete = rig
        .p
        .reconcile_publication(id, &body, signed.headers(), &publisher)
        .await
        .unwrap();
    assert_eq!(complete.state, "completed");
    assert_eq!(complete.native_event_id.as_deref(), Some(event_id.as_str()));
    assert_eq!(proxy.submissions.load(Ordering::SeqCst), 1);
    server.abort();
    println!(
        "{}",
        json!({"native_event_id":event_id,"original_owner_lookup":true,"relay_submissions":1})
    );
}

// A completed business root cannot be reopened to send a reply. The separately
// admitted consumer publication uses its own exact output release, never model
// text or an implied permission from the completed business effect.
async fn completed_root_independent_reply(lost_ack: bool) {
    let rig = Rig::new().await;
    let root = rig.start(None, "module-a", 30).await;
    rig.worker(&root, None, "module-a", 1, false).await;
    let call = rig.tool(&root, 1);
    let business = Consumer::default();
    let effect = rig
        .p
        .dispatch(
            permit(rig.admit(&call, None, "module-a").await.unwrap()),
            &business,
        )
        .await
        .unwrap();
    assert_eq!(effect.state, "completed");
    let key = nostr::Keys::generate();
    let channel = Uuid::new_v4();
    let parent = buzz_sdk::build_message(
        channel,
        "Original signed mention",
        None,
        &[],
        false,
        &[],
        &[],
    )
    .unwrap()
    .sign_with_keys(&nostr::Keys::generate())
    .unwrap();
    let sink = Arc::new(Sink {
        key: key.public_key(),
        revision: Mutex::new("audience-1".into()),
        events: Mutex::new(BTreeMap::from([(
            parent.id.to_hex(),
            serde_json::to_vec(&parent).unwrap(),
        )])),
        calls: AtomicUsize::new(0),
        lose: lost_ack.into(),
    });
    let publisher =
        Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap();
    let publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: channel.to_string(),
        audience_policy: "synthetic-private".into(),
        audience_revision: "audience-1".into(),
        release_ref: Uuid::new_v4().to_string(),
        text: "https://consumer.synthetic.invalid/results/exact-owned-result".into(),
        text_sha256: sha256(b"https://consumer.synthetic.invalid/results/exact-owned-result"),
        copy_mode: CopyMode::SummaryLink,
        attachments: vec![],
        reply_to_event: Some(parent.id.to_hex()),
    };
    let bound = rig.command("publish", rig.resource("synthetic-result", 1), &publication);
    let (body, headers) = signed_with_root(&rig, &bound, Some(&root.root_task_id));
    let pending = rig
        .p
        .admit_publication(&body, headers.headers())
        .await
        .unwrap();
    let completion = rig.command(
        "complete-task",
        rig.resource(&root.task_id, 1),
        CompleteTask {
            task_id: root.task_id.clone(),
            expected_generation: 1,
            completed_effects: vec![CompletedEffect {
                attempt_id: effect.attempt_id,
                effect_owner: effect.effect_owner.clone(),
                effect_intent: effect.effect_intent_id.clone(),
                request_sha256: effect.request_sha256.clone(),
                result_ref: effect.result_ref.clone().unwrap(),
            }],
        },
    );
    let claims = rig.claims(&completion, "module-a", Some(&root.root_task_id), None);
    let (body, headers) = rig.prepare(
        &format!("/integration/foundation/v1/tasks/{}/complete", root.task_id),
        &completion,
        &claims,
    );
    assert_eq!(
        rig.p
            .complete_task(&root.task_id, &body, headers.headers())
            .await
            .unwrap()
            .receipt
            .execution,
        Execution::Completed
    );
    let state_before: sqlx::types::Json<TaskState> =
        sqlx::query_scalar("SELECT state FROM task_roots WHERE consumer_id=$1 AND root_task_id=$2")
            .bind(&call.consumer_id)
            .bind(&root.root_task_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert!(state_before.0.stop_new_work && state_before.0.worker.is_none());
    assert_eq!(state_before.0.spent.tool_admissions, 1);
    let (body, headers) = signed_with_root(&rig, &bound, Some(&root.root_task_id));
    assert!(rig
        .p
        .publish(&body, headers.headers(), &publisher)
        .await
        .is_err());
    // Removing the root from an already admitted intent is not a separate grant.
    let (body, headers) = signed_publication(&rig, &bound);
    assert!(rig
        .p
        .publish(&body, headers.headers(), &publisher)
        .await
        .is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM publication_deliveries WHERE publication_id=$1"
        )
        .bind(Uuid::parse_str(&pending.receipt.operation_id).unwrap())
        .fetch_one(&rig.pool)
        .await
        .unwrap(),
        0
    );

    let mut separate = publication.clone();
    separate.release_ref = Uuid::new_v4().to_string();
    let command = rig.command(
        "publish",
        rig.resource("separate-native-publication", 1),
        &separate,
    );
    let (body, headers) = signed_publication(&rig, &command);
    let delivered = rig
        .p
        .publish(&body, headers.headers(), &publisher)
        .await
        .unwrap();
    let id = delivered.publication.publication_id;
    let event_id = delivered.publication.native_event_id.clone().unwrap();
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT signed_event FROM publication_deliveries WHERE publication_id=$1",
    )
    .bind(id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    let event = llull_buzz_provider::native::event(&original).unwrap();
    assert_eq!(event.content, separate.text);
    assert_eq!(
        buzz_core::nip10::parse_thread_markers(&event.tags).resolve(),
        Some((parent.id.to_hex(), parent.id.to_hex()))
    );
    assert_eq!(sink.events.lock().unwrap()[&event_id], original);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        delivered.publication.state,
        if lost_ack { "unknown" } else { "completed" }
    );
    let (body, headers) = signed_publication(&rig, &command);
    let retry = rig
        .p
        .publish(&body, headers.headers(), &publisher)
        .await
        .unwrap();
    assert_eq!(
        retry.publication.native_event_id.as_deref(),
        Some(event_id.as_str())
    );
    assert_eq!(retry.publication.state, delivered.publication.state);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    // A changed exact release/body cannot turn the old delivery into a new send.
    let mut changed = command.clone();
    changed.payload["release_ref"] = json!(Uuid::new_v4().to_string());
    let (body, headers) = signed_publication(&rig, &changed);
    assert!(rig
        .p
        .publish(&body, headers.headers(), &publisher)
        .await
        .is_err());
    *sink.revision.lock().unwrap() = "audience-2".into();
    let mut fresh = command.clone();
    fresh.intent_id = Uuid::new_v4().to_string();
    fresh.payload["release_ref"] = json!(Uuid::new_v4().to_string());
    let (body, headers) = signed_publication(&rig, &fresh);
    assert!(rig
        .p
        .publish(&body, headers.headers(), &publisher)
        .await
        .is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    if lost_ack {
        let recovery = rig.command(
            "reconcile-publication",
            rig.resource(&id.to_string(), 1),
            json!({"publication_id":id}),
        );
        let claims = rig.claims(&recovery, "module-a", None, None);
        let (body, headers) = rig.prepare(
            &format!("/integration/v1/publications/{id}/reconcile"),
            &recovery,
            &claims,
        );
        let recovered = rig
            .p
            .reconcile_publication(id, &body, headers.headers(), &publisher)
            .await
            .unwrap();
        assert_eq!(recovered.state, "completed");
        assert_eq!(
            recovered.native_event_id.as_deref(),
            Some(event_id.as_str())
        );
    }
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT signed_event FROM publication_deliveries WHERE publication_id=$1"
        )
        .bind(id)
        .fetch_one(&rig.pool)
        .await
        .unwrap(),
        original
    );
    let state_after: sqlx::types::Json<TaskState> =
        sqlx::query_scalar("SELECT state FROM task_roots WHERE consumer_id=$1 AND root_task_id=$2")
            .bind(&call.consumer_id)
            .bind(&root.root_task_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(
        serde_json::to_value(&state_after.0).unwrap(),
        serde_json::to_value(&state_before.0).unwrap()
    );
    assert_eq!(state_after.0.phase, Execution::Completed);
    assert_eq!(business.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn completed_root_denies_publication_but_independent_exact_release_delivers_once() {
    completed_root_independent_reply(false).await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn completed_root_independent_reply_lost_ack_recovers_original_without_resend() {
    completed_root_independent_reply(true).await;
}

fn publication_evidence_headers(rig: &Rig, identity: Uuid, module: &str) -> Signed {
    let mut command = rig.command(
        "observe-publication",
        rig.resource(&identity.to_string(), 1),
        json!({}),
    );
    command.intent_id = identity.to_string();
    let mut claims = rig.claims(&command, module, None, None);
    claims.payload_sha256 = sha256(b"");
    rig.sign(
        &format!("/integration/v1/publications/{identity}/evidence"),
        "GET",
        b"",
        &claims,
        INVOCATION,
    )
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn publication_evidence_reads_original_signed_reply_without_dispatch_or_recovery() {
    for lost_ack in [false, true] {
        let rig = Rig::new().await;
        let key = nostr::Keys::generate();
        let channel = Uuid::new_v4();
        let parent = buzz_sdk::build_message(
            channel,
            "Original approved mention",
            None,
            &[],
            false,
            &[],
            &[],
        )
        .unwrap()
        .sign_with_keys(&nostr::Keys::generate())
        .unwrap();
        let sink = Arc::new(Sink {
            key: key.public_key(),
            revision: Mutex::new("audience-1".into()),
            events: Mutex::new(BTreeMap::from([(
                parent.id.to_hex(),
                serde_json::to_vec(&parent).unwrap(),
            )])),
            calls: AtomicUsize::new(0),
            lose: lost_ack.into(),
        });
        let publisher =
            Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap();
        let publication = Publication {
            community_id: rig.registration.community_id.clone(),
            channel_id: channel.to_string(),
            audience_policy: "synthetic-private".into(),
            audience_revision: "audience-1".into(),
            release_ref: Uuid::new_v4().to_string(),
            text: "https://consumer.synthetic.invalid/resource/exact".into(),
            text_sha256: sha256(b"https://consumer.synthetic.invalid/resource/exact"),
            copy_mode: CopyMode::SummaryLink,
            attachments: vec![],
            reply_to_event: Some(parent.id.to_hex()),
        };
        let command = rig.command(
            "publish",
            rig.resource(&publication.release_ref, 1),
            &publication,
        );
        let (body, signed) = signed_publication(&rig, &command);
        let admitted = rig
            .p
            .admit_publication(&body, signed.headers())
            .await
            .unwrap();
        let identity = Uuid::parse_str(&admitted.receipt.operation_id).unwrap();
        let h = publication_evidence_headers(&rig, identity, "module-a");
        let (pending, _, _) = rig
            .p
            .observe_publication_evidence(&command.consumer_id, identity, h.headers(), &publisher)
            .await
            .unwrap();
        assert_eq!(pending.state, "pending");
        assert!(pending.signed_event_base64.is_none() && pending.completed_at.is_none());
        assert_eq!(pending.request_sha256, command.fingerprint().unwrap());
        assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
        let (body, signed) = signed_publication(&rig, &command);
        let sent = rig
            .p
            .publish(&body, signed.headers(), &publisher)
            .await
            .unwrap();
        let before: (String,String,Vec<u8>,i64) = sqlx::query_as("SELECT state,native_event_id,signed_event,revision FROM publication_deliveries WHERE publication_id=$1")
            .bind(identity).fetch_one(&rig.pool).await.unwrap();
        let counts: (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM commands WHERE consumer_id=$1),(SELECT count(*) FROM observations WHERE consumer_id=$1)")
            .bind(&command.consumer_id).fetch_one(&rig.pool).await.unwrap();
        for _ in 0..2 {
            let h = publication_evidence_headers(&rig, identity, "module-a");
            let (evidence, encoded, deadline) = rig
                .p
                .observe_publication_evidence(
                    &command.consumer_id,
                    identity,
                    h.headers(),
                    &publisher,
                )
                .await
                .unwrap();
            assert_eq!(evidence.format, "llull-buzz-publication-evidence/v1");
            assert_eq!(
                serde_json::from_slice::<Value>(&encoded).unwrap()["state"],
                evidence.state
            );
            assert!(tokio::time::Instant::now() < deadline);
            assert_eq!(
                evidence.state,
                if lost_ack { "unknown" } else { "completed" }
            );
            assert_eq!(evidence.completed_at.is_some(), !lost_ack);
            assert_eq!(
                evidence.admission.receipt.request_sha256,
                admitted.receipt.request_sha256
            );
            assert_eq!(
                serde_json::to_value(&evidence.publication).unwrap(),
                serde_json::to_value(&publication).unwrap()
            );
            let raw = STANDARD
                .decode(evidence.signed_event_base64.unwrap())
                .unwrap();
            assert_eq!(raw, before.2);
            assert_eq!(sha256(&raw), evidence.event_sha256.unwrap());
            let event = llull_buzz_provider::native::event(&raw).unwrap();
            assert_eq!(
                event.id.to_hex(),
                sent.publication.native_event_id.clone().unwrap()
            );
            assert_eq!(event.pubkey.to_hex(), evidence.publisher_public_key);
            assert_eq!(
                buzz_core::nip10::parse_thread_markers(&event.tags).resolve(),
                Some((parent.id.to_hex(), parent.id.to_hex()))
            );
            assert_eq!(
                sink.calls.load(Ordering::SeqCst),
                1,
                "observation cannot submit another native event"
            );
        }
        let after: (String,String,Vec<u8>,i64) = sqlx::query_as("SELECT state,native_event_id,signed_event,revision FROM publication_deliveries WHERE publication_id=$1")
            .bind(identity).fetch_one(&rig.pool).await.unwrap();
        assert_eq!(after, before);
        let after_counts: (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM commands WHERE consumer_id=$1),(SELECT count(*) FROM observations WHERE consumer_id=$1)")
            .bind(&command.consumer_id).fetch_one(&rig.pool).await.unwrap();
        assert_eq!(
            after_counts, counts,
            "read does not append a mutation receipt or observation"
        );
        let foreign_scope = publication_evidence_headers(&rig, identity, "module-b");
        assert!(rig
            .p
            .observe_publication_evidence(
                &command.consumer_id,
                identity,
                foreign_scope.headers(),
                &publisher
            )
            .await
            .is_err());
        let nonexistent = Uuid::new_v4();
        let h = publication_evidence_headers(&rig, nonexistent, "module-a");
        assert!(rig
            .p
            .observe_publication_evidence(
                &command.consumer_id,
                nonexistent,
                h.headers(),
                &publisher
            )
            .await
            .is_err());
        rig.p
            .set_service_active(
                &command.consumer_id,
                false,
                &digest(&rig.registration).unwrap(),
            )
            .await
            .unwrap();
        let h = publication_evidence_headers(&rig, identity, "module-a");
        assert!(rig
            .p
            .observe_publication_evidence(&command.consumer_id, identity, h.headers(), &publisher)
            .await
            .is_err());
        assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn publication_evidence_expiry_during_original_share_lock_returns_no_private_proof() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let sink = Arc::new(Sink {
        key: key.public_key(),
        revision: Mutex::new("audience-1".into()),
        events: Mutex::new(BTreeMap::new()),
        calls: AtomicUsize::new(0),
        lose: false.into(),
    });
    let publisher =
        Arc::new(Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap());
    let publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: Uuid::new_v4().to_string(),
        audience_policy: "synthetic-private".into(),
        audience_revision: "audience-1".into(),
        release_ref: Uuid::new_v4().to_string(),
        text: "Authorized original".into(),
        text_sha256: sha256(b"Authorized original"),
        copy_mode: CopyMode::SummaryLink,
        attachments: vec![],
        reply_to_event: None,
    };
    let command = rig.command(
        "publish",
        rig.resource(&publication.release_ref, 1),
        &publication,
    );
    let (body, signed) = signed_publication(&rig, &command);
    let admitted = rig
        .p
        .admit_publication(&body, signed.headers())
        .await
        .unwrap();
    let identity = Uuid::parse_str(&admitted.receipt.operation_id).unwrap();
    let mut blocker = rig.pool.begin().await.unwrap();
    sqlx::query("SELECT publication_id FROM publications WHERE publication_id=$1 FOR UPDATE")
        .bind(identity)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let mut observe = rig.command(
        "observe-publication",
        rig.resource(&identity.to_string(), 1),
        json!({}),
    );
    observe.intent_id = identity.to_string();
    let mut claims = rig.claims(&observe, "module-a", None, None);
    claims.payload_sha256 = sha256(b"");
    claims.exp = claims.iat + 2;
    let h = rig.sign(
        &format!("/integration/v1/publications/{identity}/evidence"),
        "GET",
        b"",
        &claims,
        INVOCATION,
    );
    let provider = rig.p.clone();
    let consumer = command.consumer_id.clone();
    let reader = tokio::spawn(async move {
        provider
            .observe_publication_evidence(&consumer, identity, h.headers(), publisher.as_ref())
            .await
    });
    let maximum = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM publications p JOIN publication_scopes%')")
            .fetch_one(&rig.pool).await.unwrap();
        if waiting {
            break;
        }
        assert!(
            tokio::time::Instant::now() < maximum,
            "actual original publication SHARE lock must be reached"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    loop {
        let expired: bool = sqlx::query_scalar(
            "SELECT extract(epoch FROM clock_timestamp()) >= $1::double precision",
        )
        .bind(claims.exp as f64)
        .fetch_one(&rig.pool)
        .await
        .unwrap();
        if expired {
            break;
        }
        assert!(
            tokio::time::Instant::now() < maximum,
            "bounded actual database expiry"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    blocker.rollback().await.unwrap();
    assert!(reader.await.unwrap().is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM publication_deliveries WHERE publication_id=$1")
            .bind(identity)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(
        count, 0,
        "expired evidence read never signs or creates delivery"
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn publication_evidence_http_is_canonical_empty_get_no_store_and_no_effect() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let sink = Arc::new(Sink {
        key: key.public_key(),
        revision: Mutex::new("audience-1".into()),
        events: Mutex::new(BTreeMap::new()),
        calls: AtomicUsize::new(0),
        lose: false.into(),
    });
    let publisher =
        Arc::new(Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap());
    let publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: Uuid::new_v4().to_string(),
        audience_policy: "synthetic-private".into(),
        audience_revision: "audience-1".into(),
        release_ref: Uuid::new_v4().to_string(),
        text: "Original exact link".into(),
        text_sha256: sha256(b"Original exact link"),
        copy_mode: CopyMode::SummaryLink,
        attachments: vec![],
        reply_to_event: None,
    };
    let command = rig.command(
        "publish",
        rig.resource(&publication.release_ref, 1),
        &publication,
    );
    let (body, signed) = signed_publication(&rig, &command);
    let admitted = rig
        .p
        .admit_publication(&body, signed.headers())
        .await
        .unwrap();
    let identity = Uuid::parse_str(&admitted.receipt.operation_id).unwrap();
    // Cleartext loopback models the existing trusted HTTPS terminator only.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = llull_buzz_provider::api::publication_routes(rig.p.clone(), publisher);
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::new();
    for mutation in [
        "none",
        "query",
        "body",
        "head",
        "post",
        "oversize-body",
        "compact-uuid",
    ] {
        let h = publication_evidence_headers(&rig, identity, "module-a");
        let raw_identity = if mutation == "compact-uuid" {
            identity.simple().to_string()
        } else {
            identity.to_string()
        };
        let path = format!(
            "http://{address}/integration/v1/publications/{raw_identity}/evidence{}",
            if mutation == "query" { "?extra=1" } else { "" }
        );
        let request = if mutation == "head" {
            client.head(&path)
        } else if mutation == "post" {
            client.post(&path)
        } else {
            client.get(&path)
        };
        let request = request
            .header("Authorization", h.headers().authorization)
            .header("X-Llull-Invocation", h.headers().invocation)
            .header("X-Llull-Consumer", &command.consumer_id);
        let response = if mutation == "body" {
            request.body("{}").send().await.unwrap()
        } else if mutation == "oversize-body" {
            request
                .body(vec![b' '; llull_buzz_wire::MAX_BYTES + 1])
                .send()
                .await
                .unwrap()
        } else {
            request.send().await.unwrap()
        };
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(
            response.status().is_success(),
            mutation == "none",
            "{mutation}"
        );
        if mutation == "none" {
            let proof: Value = response.json().await.unwrap();
            assert_eq!(proof["format"], "llull-buzz-publication-evidence/v1");
            assert_eq!(proof["signed_event_base64"], Value::Null);
            assert_eq!(proof.as_object().unwrap().len(), 19);
        }
    }
    server.abort();
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn publication_evidence_delayed_commit_cannot_emit_after_original_invocation_expiry() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let sink = Arc::new(Sink {
        key: key.public_key(),
        revision: Mutex::new("audience-1".into()),
        events: Mutex::new(BTreeMap::new()),
        calls: AtomicUsize::new(0),
        lose: false.into(),
    });
    let publisher =
        Arc::new(Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap());
    let publication = Publication {
        community_id: rig.registration.community_id.clone(),
        channel_id: Uuid::new_v4().to_string(),
        audience_policy: "synthetic-private".into(),
        audience_revision: "audience-1".into(),
        release_ref: Uuid::new_v4().to_string(),
        text: "Original admitted link".into(),
        text_sha256: sha256(b"Original admitted link"),
        copy_mode: CopyMode::SummaryLink,
        attachments: vec![],
        reply_to_event: None,
    };
    let command = rig.command(
        "publish",
        rig.resource(&publication.release_ref, 1),
        &publication,
    );
    let (body, h) = signed_publication(&rig, &command);
    let admitted = rig.p.admit_publication(&body, h.headers()).await.unwrap();
    let identity = Uuid::parse_str(&admitted.receipt.operation_id).unwrap();
    // This real deferred trigger waits only at COMMIT, after proof validation
    // and the final fractional database-clock sample. It is fixture-owned.
    let marker = ((identity.as_u128() & 0x7fff_ffff) as i64) + 1001;
    // Rig supplies a synthetic UUID consumer; marker is an integer derived
    // above from the fixture publication UUID. No request SQL enters this DDL.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE FUNCTION evidence_slow_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.consumer_id='{}' THEN PERFORM pg_advisory_xact_lock({marker}); PERFORM pg_sleep(4); END IF; RETURN NEW; END $$",command.consumer_id)))
        .execute(&rig.pool).await.unwrap();
    sqlx::query("CREATE CONSTRAINT TRIGGER evidence_slow_commit AFTER INSERT ON assertion_replays DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION evidence_slow_commit()")
        .execute(&rig.pool).await.unwrap();
    let mut read = rig.command(
        "observe-publication",
        rig.resource(&identity.to_string(), 1),
        json!({}),
    );
    read.intent_id = identity.to_string();
    let mut claims = rig.claims(&read, "module-a", None, None);
    claims.payload_sha256 = sha256(b"");
    claims.exp = claims.iat + 3;
    let h = rig.sign(
        &format!("/integration/v1/publications/{identity}/evidence"),
        "GET",
        b"",
        &claims,
        INVOCATION,
    );
    let started = tokio::time::Instant::now();
    let provider = rig.p.clone();
    let consumer = command.consumer_id.clone();
    let reader = tokio::spawn(async move {
        provider
            .observe_publication_evidence(&consumer, identity, h.headers(), publisher.as_ref())
            .await
    });
    let maximum = started + Duration::from_secs(4);
    loop {
        let at_commit: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE l.locktype='advisory' AND l.classid=0 AND l.objid::bigint=$1 AND l.granted AND a.wait_event='PgSleep' AND a.query LIKE 'COMMIT%')")
            .bind(marker).fetch_one(&rig.pool).await.unwrap();
        if at_commit {
            break;
        }
        assert!(
            !reader.is_finished(),
            "read must reach its actual scoped deferred COMMIT before denial"
        );
        assert!(
            tokio::time::Instant::now() < maximum,
            "bounded actual deferred COMMIT observation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let result = reader.await.unwrap();
    assert!(
        result.is_err(),
        "late read must return neither typed private proof nor encoded response"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "original expiry consumes commit wait"
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM commands WHERE consumer_id=$1")
        .bind(&command.consumer_id)
        .fetch_one(&rig.pool)
        .await
        .unwrap();
    assert_eq!(
        receipts, 1,
        "no replacement command after unknown authentication commit"
    );
}

fn publication_intent_evidence_headers(
    rig: &Rig,
    original: (&str, &str, &str),
    module: &str,
) -> (String, Signed) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let (intent, release, fingerprint) = original;
    let mut command = rig.command("observe-publication", rig.resource(release, 1), json!({}));
    command.intent_id = intent.into();
    let mut claims = rig.claims(&command, module, None, None);
    claims.payload_sha256 = fingerprint.into();
    let path = format!(
        "/integration/v1/publication-intents/{}/{}/{fingerprint}/evidence",
        URL_SAFE_NO_PAD.encode(intent.as_bytes()),
        URL_SAFE_NO_PAD.encode(release.as_bytes())
    );
    let signed = rig.sign(&path, "GET", b"", &claims, INVOCATION);
    (path, signed)
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn lost_publication_admission_ack_lookup_keeps_original_identity_and_never_resends() {
    for lost_delivery_ack in [false, true] {
        let rig = Rig::new().await;
        let key = nostr::Keys::generate();
        let sink = Arc::new(Sink {
            key: key.public_key(),
            revision: Mutex::new("audience-1".into()),
            events: Mutex::new(BTreeMap::new()),
            calls: AtomicUsize::new(0),
            lose: lost_delivery_ack.into(),
        });
        let publisher =
            Publisher::new(sink.clone(), key, "https://provider.synthetic.invalid").unwrap();
        let publication = Publication {
            community_id: rig.registration.community_id.clone(),
            channel_id: Uuid::new_v4().to_string(),
            audience_policy: "synthetic-private".into(),
            audience_revision: "audience-1".into(),
            release_ref: "exact release/原本? bytes".into(),
            text: "Original authorized link".into(),
            text_sha256: sha256(b"Original authorized link"),
            copy_mode: CopyMode::SummaryLink,
            attachments: vec![],
            reply_to_event: None,
        };
        let mut command = rig.command(
            "publish",
            rig.resource(&publication.release_ref, 1),
            &publication,
        );
        command.intent_id = "original intent/公開? exact bytes".into();
        let fingerprint = command.fingerprint().unwrap();
        let original = (
            command.intent_id.as_str(),
            publication.release_ref.as_str(),
            fingerprint.as_str(),
        );
        let (body, signed) = signed_publication(&rig, &command);
        // The consumer deliberately discards the POST ACK, including its UUID.
        rig.p
            .admit_publication(&body, signed.headers())
            .await
            .unwrap();
        let (_, h) = publication_intent_evidence_headers(&rig, original, "module-a");
        let (pending, _, _) = rig
            .p
            .observe_publication_intent_evidence(
                &command.consumer_id,
                original,
                h.headers(),
                &publisher,
            )
            .await
            .unwrap();
        assert_eq!(pending.state, "pending");
        assert!(pending.signed_event_base64.is_none());
        assert_eq!(pending.intent_id, command.intent_id);
        assert_eq!(pending.request_sha256, fingerprint);
        let identity = pending.publication_id;
        assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
        for change in ["intent", "release", "hash", "module", "binding"] {
            let altered = (
                if change == "intent" {
                    "another intent"
                } else {
                    original.0
                },
                if change == "release" {
                    "another release"
                } else {
                    original.1
                },
                if change == "hash" {
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                } else {
                    original.2
                },
            );
            let signed_original = if change == "binding" {
                original
            } else {
                altered
            };
            let (_, h) = publication_intent_evidence_headers(
                &rig,
                signed_original,
                if change == "module" {
                    "module-b"
                } else {
                    "module-a"
                },
            );
            let supplied = if change == "binding" {
                ("changed intent", original.1, original.2)
            } else {
                altered
            };
            assert!(
                rig.p
                    .observe_publication_intent_evidence(
                        &command.consumer_id,
                        supplied,
                        h.headers(),
                        &publisher
                    )
                    .await
                    .is_err(),
                "{change}"
            );
        }
        let (body, signed) = signed_publication(&rig, &command);
        rig.p
            .publish(&body, signed.headers(), &publisher)
            .await
            .unwrap();
        let before: (String, String, Vec<u8>, i64) = sqlx::query_as("SELECT state,native_event_id,signed_event,revision FROM publication_deliveries WHERE publication_id=$1")
            .bind(identity).fetch_one(&rig.pool).await.unwrap();
        let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM commands WHERE consumer_id=$1),(SELECT count(*) FROM observations WHERE consumer_id=$1)")
            .bind(&command.consumer_id).fetch_one(&rig.pool).await.unwrap();
        for _ in 0..2 {
            let (_, h) = publication_intent_evidence_headers(&rig, original, "module-a");
            let (evidence, encoded, deadline) = rig
                .p
                .observe_publication_intent_evidence(
                    &command.consumer_id,
                    original,
                    h.headers(),
                    &publisher,
                )
                .await
                .unwrap();
            assert_eq!(evidence.publication_id, identity);
            assert_eq!(
                evidence.state,
                if lost_delivery_ack {
                    "unknown"
                } else {
                    "completed"
                }
            );
            assert_eq!(evidence.native_event_id.as_deref(), Some(before.1.as_str()));
            assert_eq!(evidence.revision, before.3 as u64);
            assert!(tokio::time::Instant::now() < deadline);
            assert_eq!(
                serde_json::from_slice::<Value>(&encoded).unwrap()["publication_id"],
                identity.to_string()
            );
        }
        let after: (String, String, Vec<u8>, i64) = sqlx::query_as("SELECT state,native_event_id,signed_event,revision FROM publication_deliveries WHERE publication_id=$1")
            .bind(identity).fetch_one(&rig.pool).await.unwrap();
        assert_eq!(before, after);
        assert_eq!(
            sink.calls.load(Ordering::SeqCst),
            1,
            "read cannot submit another native event"
        );
        let after_counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM commands WHERE consumer_id=$1),(SELECT count(*) FROM observations WHERE consumer_id=$1)")
            .bind(&command.consumer_id).fetch_one(&rig.pool).await.unwrap();
        assert_eq!(counts, after_counts);
        // A separate synthetic source lacks the original observation. Original
        // append-only history and its immutability triggers remain untouched.
        let unseen_identity = Uuid::new_v4();
        let mut unseen_publication = publication.clone();
        unseen_publication.release_ref = "unobserved release".into();
        let mut unseen_command = command.clone();
        unseen_command.intent_id = "unobserved original intent".into();
        unseen_command.resource = rig.resource(&unseen_publication.release_ref, 1);
        unseen_command.payload = serde_json::to_value(&unseen_publication).unwrap();
        let unseen_fingerprint = unseen_command.fingerprint().unwrap();
        sqlx::query("INSERT INTO publications(consumer_id,intent_id,publication_id,release_ref,request_sha256,publication,release,enrollment_id,recovery_epoch) SELECT consumer_id,$2,$3,$4,$5,$6,release,enrollment_id,recovery_epoch FROM publications WHERE consumer_id=$1 AND publication_id=$7")
            .bind(&command.consumer_id).bind(&unseen_command.intent_id).bind(unseen_identity)
            .bind(&unseen_publication.release_ref).bind(&unseen_fingerprint).bind(Json(&unseen_publication)).bind(identity)
            .execute(&rig.pool).await.unwrap();
        sqlx::query("INSERT INTO publication_scopes(publication_id,scope,root_task_id) SELECT $1,scope,root_task_id FROM publication_scopes WHERE publication_id=$2")
            .bind(unseen_identity).bind(identity).execute(&rig.pool).await.unwrap();
        let mut unseen_admission: Value = sqlx::query_scalar::<_, Json<Value>>("SELECT result FROM commands WHERE consumer_id=$1 AND operation='publish' AND intent_id=$2")
            .bind(&command.consumer_id).bind(&command.intent_id).fetch_one(&rig.pool).await.unwrap().0;
        unseen_admission["receipt"]["intent_id"] = json!(unseen_command.intent_id);
        unseen_admission["receipt"]["operation_id"] = json!(unseen_identity);
        unseen_admission["receipt"]["request_sha256"] = json!(unseen_fingerprint);
        unseen_admission["result"]["publication_id"] = json!(unseen_identity);
        sqlx::query("INSERT INTO commands(consumer_id,operation,intent_id,request_sha256,result) VALUES($1,'publish',$2,$3,$4)")
            .bind(&command.consumer_id).bind(&unseen_command.intent_id).bind(&unseen_fingerprint).bind(Json(&unseen_admission))
            .execute(&rig.pool).await.unwrap();
        let no_original_observation: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM observations WHERE consumer_id=$1 AND record->>'operation_id'=$2)")
            .bind(&command.consumer_id).bind(unseen_identity.to_string()).fetch_one(&rig.pool).await.unwrap();
        assert!(no_original_observation);
        let unseen = (
            unseen_command.intent_id.as_str(),
            unseen_publication.release_ref.as_str(),
            unseen_fingerprint.as_str(),
        );
        let (_, h) = publication_intent_evidence_headers(&rig, unseen, "module-a");
        assert!(rig
            .p
            .observe_publication_intent_evidence(
                &command.consumer_id,
                unseen,
                h.headers(),
                &publisher
            )
            .await
            .is_err());
        assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    }
}
