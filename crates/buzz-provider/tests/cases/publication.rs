//! Publication ledger fault tests. The native transport fixture is explicitly
//! separate from the pinned relay/client integration scenario.
use super::*;
use llull_buzz_provider::{Audience, NativeEventSource, PublicationPort, Publisher};
use std::sync::Arc;

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
