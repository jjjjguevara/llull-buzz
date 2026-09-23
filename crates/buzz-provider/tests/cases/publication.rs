//! Publication ledger fault tests. The native transport fixture is explicitly
//! separate from the pinned relay/client integration scenario.
use super::*;
use llull_buzz_provider::{Audience, NativeEventSource, PublicationPort, Publisher};
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
