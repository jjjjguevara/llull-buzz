//! Synthetic native-client wire journey through a real loopback WebSocket and
//! real PostgreSQL custody. The HTTPS/WSS terminator and named desktop/mobile
//! human interaction remain separate qualification, not simulated passes here.
use super::*;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct NativeSocket(tokio::net::TcpStream);

impl NativeSocket {
    async fn connect(address: std::net::SocketAddr, path: &str) -> Self {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let key = STANDARD.encode(Uuid::new_v4().as_bytes());
        stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: relay.synthetic.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            assert!(response.len() < 4096);
            response.push(stream.read_u8().await.unwrap());
        }
        assert!(
            response.starts_with(b"HTTP/1.1 101"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        Self(stream)
    }

    async fn send(&mut self, value: Value) {
        let bytes = canonical(&value).unwrap();
        assert!(bytes.len() <= 65_536);
        let mut wire = vec![0x81];
        if bytes.len() < 126 {
            wire.push(0x80 | bytes.len() as u8);
        } else {
            wire.push(0x80 | 126);
            wire.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        let nonce = Uuid::new_v4();
        let mask = &nonce.as_bytes()[..4];
        wire.extend_from_slice(mask);
        wire.extend(
            bytes
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        self.0.write_all(&wire).await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let opcode = self.0.read_u8().await.unwrap();
        assert_eq!(opcode, 0x81, "expected one unfragmented text frame");
        let size = self.0.read_u8().await.unwrap();
        assert_eq!(size & 0x80, 0, "server frames must be unmasked");
        let size = if size == 126 {
            self.0.read_u16().await.unwrap() as usize
        } else {
            size as usize
        };
        assert!(size < 65_536);
        let mut bytes = vec![0; size];
        self.0.read_exact(&mut bytes).await.unwrap();
        parse(&bytes).unwrap()
    }

    async fn authenticate(&mut self, key: &nostr::Keys, relay: &str) -> nostr::Event {
        let challenge = self.recv().await;
        assert_eq!(challenge[0], "AUTH");
        let event = nostr::EventBuilder::new(nostr::Kind::Custom(22242), "")
            .tags([
                nostr::Tag::parse(["relay", relay]).unwrap(),
                nostr::Tag::parse(["challenge", challenge[1].as_str().unwrap()]).unwrap(),
            ])
            .sign_with_keys(key)
            .unwrap();
        self.send(json!(["AUTH", event])).await;
        let result = self.recv().await;
        assert_eq!(result[0], "OK");
        assert_eq!(result[1], event.id.to_hex());
        assert_eq!(result[2], true);
        event
    }
}

async fn pending(rig: &Rig, key: &nostr::Keys) -> EnrollmentChallenge {
    let command = rig.command(
        "enroll",
        rig.resource("principal", 1),
        Enroll {
            issuer: rig.browser.issuer.clone(),
            subject: rig.browser.subject.clone(),
            intended_public_key: key.public_key().to_hex(),
            community_id: rig.registration.community_id.clone(),
            module_id: "module-a".into(),
            browser_transaction_id: rig.browser.transaction_id.clone(),
            native_challenge: None,
        },
    );
    let mut claims = rig.claims(&command, "module-a", None, None);
    claims.browser_authentication = Some(rig.browser.clone());
    let (body, signed) = rig.prepare("/integration/v1/enrollments", &command, &claims);
    serde_json::from_value(rig.p.enroll(&body, signed.headers()).await.unwrap().result).unwrap()
}

fn message(challenge: &EnrollmentChallenge, key: &nostr::Keys, text: &str) -> nostr::Event {
    // Use the selected upstream ordinary message builder, with a native-client
    // key signing the returned builder. buzz-sdk deliberately owns no transport.
    buzz_sdk::build_message(
        Uuid::parse_str(&challenge.channel_id).unwrap(),
        text,
        None,
        &[challenge.bot_public_key.as_str()],
        false,
        &[],
        &[],
    )
    .unwrap()
    .sign_with_keys(key)
    .unwrap()
}

async fn read(
    rig: &Rig,
    challenge: &EnrollmentChallenge,
    module: &str,
    browser: &BrowserAuthentication,
) -> llull_buzz_provider::Result<EnrollmentNativeProof> {
    let command = rig.command(
        "read-enrollment-proof",
        rig.resource(&challenge.enrollment_id, 1),
        json!({"enrollment_id":challenge.enrollment_id}),
    );
    let mut claims = rig.claims(&command, module, None, None);
    claims.registration_revision = rig.registration.revision;
    claims.authority_epoch = rig.registration.authority_epoch;
    claims.browser_authentication = Some(browser.clone());
    let (body, signed) = rig.prepare("/integration/v1/enrollment-proofs", &command, &claims);
    rig.p.read_enrollment_proof(&body, signed.headers()).await
}

async fn server(
    rig: &Rig,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = enrollment_gateway_routes(rig.p.clone(), "wss://relay.synthetic.invalid").unwrap();
    let (stop, done) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = done.await;
            })
            .await
            .unwrap();
    });
    (address, stop, handle)
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn native_enrollment_separates_relay_login_recovers_exact_message_and_binds_once() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let challenge = pending(&rig, &key).await;
    let path = format!(
        "/native/enrollment/{}/{}",
        rig.registration.consumer_id, challenge.enrollment_id
    );
    let relay = format!("wss://relay.synthetic.invalid{path}");
    let (address, stop, handle) = server(&rig).await;
    assert!(read(&rig, &challenge, "module-a", &rig.browser)
        .await
        .is_err());

    // NIP-42 uses a connection nonce, intended key and exact public relay URL.
    let mut wrong = NativeSocket::connect(address, &path).await;
    let nonce = wrong.recv().await;
    let foreign = nostr::EventBuilder::new(nostr::Kind::Custom(22242), "")
        .tags([
            nostr::Tag::parse(["relay", relay.as_str()]).unwrap(),
            nostr::Tag::parse(["challenge", nonce[1].as_str().unwrap()]).unwrap(),
        ])
        .sign_with_keys(&nostr::Keys::generate())
        .unwrap();
    wrong.send(json!(["AUTH", foreign])).await;
    assert_eq!(wrong.recv().await[2], false);
    drop(wrong);

    let mut socket = NativeSocket::connect(address, &path).await;
    let authentication = socket.authenticate(&key, &relay).await;
    // A valid relay login event cannot serve as the separate kind-9 proof.
    socket.send(json!(["EVENT", authentication])).await;
    assert_eq!(socket.recv().await[2], false);
    drop(socket);
    assert!(read(&rig, &challenge, "module-a", &rig.browser)
        .await
        .is_err());

    let mut socket = NativeSocket::connect(address, &path).await;
    socket.authenticate(&key, &relay).await;
    socket
        .send(json!([
            "EVENT",
            message(&challenge, &key, "changed challenge text")
        ]))
        .await;
    assert_eq!(socket.recv().await[2], false);
    drop(socket);

    let mut socket = NativeSocket::connect(address, &path).await;
    let authentication = socket.authenticate(&key, &relay).await;
    socket
        .send(json!(["REQ", "native-startup-subscription", {"kinds":[39000]}]))
        .await;
    let refused = socket.recv().await;
    assert_eq!(refused[0], "CLOSED");
    assert_eq!(refused[1], "native-startup-subscription");
    let event = message(&challenge, &key, &challenge.message_text);
    socket.send(json!(["EVENT", event])).await;
    // Deliberately lose the OK response. Lookup recovers the exact original
    // human-signed message without another challenge, signature or binding.
    drop(socket);
    let retained = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(proof) = read(&rig, &challenge, "module-a", &rig.browser).await {
                break proof;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(retained.native_event, serde_json::to_value(&event).unwrap());
    assert_eq!(
        retained.nip42_event,
        serde_json::to_value(&authentication).unwrap()
    );
    assert_eq!(retained.relay_url, relay);
    assert_eq!(
        read(&rig, &challenge, "module-a", &rig.browser)
            .await
            .unwrap()
            .native_event,
        retained.native_event
    );
    assert!(read(&rig, &challenge, "module-b", &rig.browser)
        .await
        .is_err());
    let mut changed = rig.browser.clone();
    changed.transaction_id = Uuid::new_v4().to_string();
    assert!(read(&rig, &challenge, "module-a", &changed).await.is_err());

    // Identical EVENT retry is idempotent, and its first NIP-42 custody remains.
    let mut socket = NativeSocket::connect(address, &path).await;
    socket.authenticate(&key, &relay).await;
    socket.send(json!(["EVENT", event])).await;
    assert_eq!(socket.recv().await[2], true);
    drop(socket);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM enrollment_native_proofs WHERE consumer_id=$1")
            .bind(&rig.registration.consumer_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        read(&rig, &challenge, "module-a", &rig.browser)
            .await
            .unwrap()
            .nip42_event,
        retained.nip42_event
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM enrollments WHERE consumer_id=$1")
        .bind(&rig.registration.consumer_id)
        .fetch_one(&rig.pool)
        .await
        .unwrap();
    assert_eq!(
        rows, 0,
        "native relay authentication and message custody never create a binding"
    );

    // The consumer passes the exact retrieved event to the existing proof
    // operation. The provider still enforces original browser admission.
    let proof = rig.command(
        "prove-key",
        rig.resource(&challenge.enrollment_id, 1),
        ProveKey {
            enrollment_id: challenge.enrollment_id.clone(),
            native_event: retained.native_event.clone(),
        },
    );
    let mut claims = rig.claims(&proof, "module-a", None, None);
    claims.browser_authentication = Some(rig.browser.clone());
    let proof_path = format!(
        "/integration/v1/enrollments/{}/proof",
        challenge.enrollment_id
    );
    let (body, signed) = rig.prepare(&proof_path, &proof, &claims);
    let binding: Binding = serde_json::from_value(
        rig.p
            .prove_key(&challenge.enrollment_id, &body, signed.headers())
            .await
            .unwrap()
            .result,
    )
    .unwrap();
    assert_eq!(binding.proof_event, retained.native_event);
    assert_eq!(binding.proof_event_id, event.id.to_hex());
    assert_eq!(binding.native_key, key.public_key().to_hex());
    assert!(
        read(&rig, &challenge, "module-a", &rig.browser)
            .await
            .is_err(),
        "a consumed transaction cannot bootstrap another native proof"
    );
    stop.send(()).unwrap();
    handle.await.unwrap();
}

fn native_http_auth(key: &nostr::Keys, url: &str, body: &[u8]) -> String {
    let event = nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
        .tags([
            nostr::Tag::parse(["u", url]).unwrap(),
            nostr::Tag::parse(["method", "POST"]).unwrap(),
            nostr::Tag::parse(["payload", sha256(body).as_str()]).unwrap(),
            nostr::Tag::parse(["nonce", Uuid::new_v4().to_string().as_str()]).unwrap(),
        ])
        .sign_with_keys(key)
        .unwrap();
    format!(
        "Nostr {}",
        STANDARD.encode(serde_json::to_vec(&event).unwrap())
    )
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn desktop_native_http_challenge_requires_separate_login_exact_nip98_and_original_event() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let challenge = pending(&rig, &key).await;
    let path = format!(
        "/native/enrollment/{}/{}",
        rig.registration.consumer_id, challenge.enrollment_id
    );
    let relay = format!("wss://relay.synthetic.invalid{path}");
    let url = format!("https://relay.synthetic.invalid{path}/events");
    let (address, stop, handle) = server(&rig).await;
    let endpoint = format!("http://{address}{path}/events");
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let event = message(&challenge, &key, &challenge.message_text);
    let body = canonical(&event).unwrap();
    let post = |authorization: String, bytes: Vec<u8>| {
        client
            .post(&endpoint)
            .header("authorization", authorization)
            .body(bytes)
            .send()
    };
    // Desktop's NIP-98 HTTP event submission cannot substitute for its NIP-42
    // native login. No service/private signer is involved in either native proof.
    assert_eq!(
        post(native_http_auth(&key, &url, &body), body.clone())
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let mut socket = NativeSocket::connect(address, &path).await;
    let authentication = socket.authenticate(&key, &relay).await;
    socket
        .send(json!(["REQ", "desktop-channel-state", {"kinds":[39000]}]))
        .await;
    assert_eq!(socket.recv().await[0], "CLOSED");

    let wrong = nostr::Keys::generate();
    assert_eq!(
        post(native_http_auth(&wrong, &url, &body), body.clone())
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(
            native_http_auth(&key, "https://private.synthetic.invalid/events", &body),
            body.clone()
        )
        .await
        .unwrap()
        .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let changed = message(&challenge, &key, "changed message");
    assert_eq!(
        post(
            native_http_auth(&key, &url, &body),
            canonical(&changed).unwrap()
        )
        .await
        .unwrap()
        .status(),
        reqwest::StatusCode::FORBIDDEN
    );

    let authorization = native_http_auth(&key, &url, &body);
    let response = post(authorization.clone(), body.clone()).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let accepted: Value = parse(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(
        accepted,
        json!({"event_id":event.id.to_hex(),"accepted":true,"message":""})
    );
    assert_eq!(
        post(authorization, body.clone()).await.unwrap().status(),
        reqwest::StatusCode::FORBIDDEN,
        "identical NIP-98 transport proof cannot replay"
    );
    // Fresh transport proof recovers the same native event, never another effect.
    assert_eq!(
        post(native_http_auth(&key, &url, &body), body)
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let retained = read(&rig, &challenge, "module-a", &rig.browser)
        .await
        .unwrap();
    assert_eq!(retained.native_event, serde_json::to_value(&event).unwrap());
    assert_eq!(
        retained.nip42_event,
        serde_json::to_value(&authentication).unwrap()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM enrollment_native_proofs WHERE consumer_id=$1")
            .bind(&rig.registration.consumer_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    drop(socket);
    stop.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn enrollment_relay_rechecks_service_revocation_before_message_custody() {
    let rig = Rig::new().await;
    let key = nostr::Keys::generate();
    let challenge = pending(&rig, &key).await;
    let path = format!(
        "/native/enrollment/{}/{}",
        rig.registration.consumer_id, challenge.enrollment_id
    );
    let relay = format!("wss://relay.synthetic.invalid{path}");
    let (address, stop, handle) = server(&rig).await;
    let mut socket = NativeSocket::connect(address, &path).await;
    socket.authenticate(&key, &relay).await;
    rig.p
        .set_service_active(
            &rig.registration.consumer_id,
            false,
            &digest(&rig.registration).unwrap(),
        )
        .await
        .unwrap();
    socket
        .send(json!([
            "EVENT",
            message(&challenge, &key, &challenge.message_text)
        ]))
        .await;
    assert_eq!(socket.recv().await[2], false);
    drop(socket);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM enrollment_native_proofs WHERE consumer_id=$1")
            .bind(&rig.registration.consumer_id)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    assert!(read(&rig, &challenge, "module-a", &rig.browser)
        .await
        .is_err());
    stop.send(()).unwrap();
    handle.await.unwrap();
}

// Real native-owner signatures in a bounded synthetic source. The production
// fixed-origin HTTP adapter is exercised separately by enrollment_directory tests.
struct DirectorySource {
    view: Mutex<NativeEnrollmentView>,
    relay: nostr::Keys,
    calls: AtomicUsize,
    pause_next: AtomicBool,
    entered: tokio::sync::Notify,
    released: tokio::sync::Notify,
}

#[async_trait]
impl EnrollmentDirectoryPort for DirectorySource {
    async fn enrollment_directory(
        &self,
        community: &str,
        channel: &str,
        intended: &str,
        bot: &str,
    ) -> std::result::Result<NativeEnrollmentView, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.pause_next.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.released.notified().await;
        }
        let view = self.view.lock().unwrap().clone();
        assert_eq!(community, view.community_id);
        assert_eq!(channel, view.channel_id);
        assert_eq!(intended, view.intended_public_key);
        assert_eq!(bot, view.bot_public_key);
        Ok(view)
    }
}

fn directory_event(key: &nostr::Keys, kind: u16, tags: Value, content: &str) -> Value {
    let tags: Vec<Vec<String>> = serde_json::from_value(tags).unwrap();
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(kind), content)
        .tags(
            tags.into_iter()
                .map(|fields| nostr::Tag::parse(fields).unwrap()),
        )
        .sign_with_keys(key)
        .unwrap();
    serde_json::to_value(event).unwrap()
}

async fn directory_setup() -> (Rig, nostr::Keys, EnrollmentChallenge, Arc<DirectorySource>) {
    directory_setup_with_browser_window(None).await
}

async fn directory_setup_with_browser_window(
    seconds: Option<i64>,
) -> (Rig, nostr::Keys, EnrollmentChallenge, Arc<DirectorySource>) {
    let mut rig = Rig::new().await;
    if let Some(seconds) = seconds {
        rig.browser.expires_at = (Utc::now() + CD::seconds(seconds)).timestamp();
    }
    let bot = nostr::Keys::generate();
    let human = nostr::Keys::generate();
    let relay = nostr::Keys::generate();
    let old_digest = digest(&rig.registration).unwrap();
    rig.registration.revision += 1;
    rig.registration.enrollment_bot_key = bot.public_key().to_hex();
    rig.registration.enrollment_bot_mention = Some("@enrollment_bot".into());
    rig.p
        .register(rig.registration.clone(), Some(&old_digest))
        .await
        .unwrap();
    let command = rig.command(
        "enroll",
        rig.resource("principal", 1),
        Enroll {
            issuer: rig.browser.issuer.clone(),
            subject: rig.browser.subject.clone(),
            intended_public_key: human.public_key().to_hex(),
            community_id: rig.registration.community_id.clone(),
            module_id: "module-a".into(),
            browser_transaction_id: rig.browser.transaction_id.clone(),
            native_challenge: Some(NativeChallenge {
                version: "mention-json/v1".into(),
                bot_mention: "@enrollment_bot".into(),
            }),
        },
    );
    let mut claims = rig.claims(&command, "module-a", None, None);
    claims.registration_revision = rig.registration.revision;
    claims.authority_epoch = rig.registration.authority_epoch;
    claims.browser_authentication = Some(rig.browser.clone());
    let (body, signed) = rig.prepare("/integration/v1/enrollments", &command, &claims);
    let challenge: EnrollmentChallenge =
        serde_json::from_value(rig.p.enroll(&body, signed.headers()).await.unwrap().result)
            .unwrap();
    assert!(challenge.message_text.starts_with("@enrollment_bot {"));
    let channel = &rig.registration.enrollment_channel;
    let intended = human.public_key().to_hex();
    let bot_key = bot.public_key().to_hex();
    // The synthetic native owner explicitly admits its moderator read. The
    // real tracked fixed-origin request and denial cases have separate controls.
    let checked_at = Utc::now();
    let moderation_request = directory_event(
        &relay,
        27235,
        json!([
            [
                "u",
                "https://native-owner.synthetic.invalid/moderation/restricted"
            ],
            ["method", "GET"],
            ["payload", sha256(b"")],
            ["nonce", Uuid::new_v4().to_string()],
        ]),
        "",
    );
    let view = NativeEnrollmentView {
        community_id: rig.registration.community_id.clone(),
        channel_id: channel.clone(),
        intended_public_key: intended.clone(),
        bot_public_key: bot_key.clone(),
        relay_public_key: relay.public_key().to_hex(),
        channel_metadata: directory_event(
            &relay,
            39000,
            json!([
                ["d", channel],
                ["name", "Native enrollment"],
                ["t", "stream"],
                ["private"],
                ["closed"]
            ]),
            "",
        ),
        channel_membership: directory_event(
            &relay,
            39002,
            json!([
                ["d", channel],
                ["p", intended, "", "member"],
                ["p", bot_key, "", "bot"]
            ]),
            "",
        ),
        profiles: vec![
            directory_event(
                &human,
                0,
                json!([]),
                &json!({"display_name":"Native Human"}).to_string(),
            ),
            directory_event(
                &bot,
                0,
                json!([]),
                &json!({"display_name":"enrollment_bot"}).to_string(),
            ),
        ],
        relay_information: json!({"self":relay.public_key().to_hex(),"supported_nips":[1,11,29,42,98]}),
        relay_membership: None,
        join_policy: Some(
            json!({"policy":{"version":"native-owner-v1","age_attestation_required":true,"terms_markdown":"Synthetic native terms"}}),
        ),
        admission_check: NativeEnrollmentAdmissionCheck {
            kind: "llull-buzz-native-enrollment-admission/v1".into(),
            community_id: rig.registration.community_id.clone(),
            intended_public_key: human.public_key().to_hex(),
            moderation_endpoint: "https://native-owner.synthetic.invalid/moderation/restricted"
                .into(),
            request_event_id: moderation_request["id"].as_str().unwrap().into(),
            response_sha256: sha256(b"[]"),
            checked_at,
            valid_until: checked_at + CD::seconds(30),
        },
    };
    view.validate().unwrap();
    let source = Arc::new(DirectorySource {
        view: Mutex::new(view),
        relay,
        calls: AtomicUsize::new(0),
        pause_next: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        released: tokio::sync::Notify::new(),
    });
    (rig, human, challenge, source)
}

async fn directory_server(
    rig: &Rig,
    directory: Arc<DirectorySource>,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = enrollment_gateway_routes_with_directory(
        rig.p.clone(),
        "wss://relay.synthetic.invalid",
        directory,
    )
    .unwrap();
    let (stop, done) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = done.await;
            })
            .await
            .unwrap();
    });
    (address, stop, handle)
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn native_unsupported_events_preserve_authenticated_challenge_journey_and_original_expiry() {
    let (rig, key, challenge, source) = directory_setup_with_browser_window(Some(12)).await;
    let view = source.view.lock().unwrap().clone();
    let path = format!(
        "/native/enrollment/{}/{}",
        rig.registration.consumer_id, challenge.enrollment_id
    );
    let relay = format!("wss://relay.synthetic.invalid{path}");
    let (address, stop, handle) = directory_server(&rig, source).await;

    // A connection authenticating the intended key cannot subsequently switch
    // authors, even for an unsupported event that will never be published.
    let mut wrong = NativeSocket::connect(address, &path).await;
    wrong.authenticate(&key, &relay).await;
    let foreign = directory_event(&nostr::Keys::generate(), 20001, json!([]), "online");
    wrong.send(json!(["EVENT", foreign])).await;
    let denied = wrong.recv().await;
    assert_eq!(denied[0], "OK");
    assert_eq!(denied[1], foreign["id"]);
    assert_eq!(denied[2], false);
    let closed = tokio::time::timeout(Duration::from_secs(2), wrong.0.read_u8())
        .await
        .expect("wrong-author publication must retire its socket");
    match closed {
        Ok(opcode) => assert_eq!(opcode, 0x88, "expected WebSocket close"),
        Err(error) => assert!(matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
        )),
    }
    drop(wrong);

    let mut socket = NativeSocket::connect(address, &path).await;
    let authentication = socket.authenticate(&key, &relay).await;
    let original_challenge: Value = sqlx::query_scalar(
        "SELECT to_jsonb(c) FROM enrollment_challenges c WHERE consumer_id=$1 AND enrollment_id=$2",
    )
    .bind(&rig.registration.consumer_id)
    .bind(&challenge.enrollment_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    let original_login: Value = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM enrollment_native_authentications a WHERE consumer_id=$1 AND enrollment_id=$2 AND nip42_event_id=$3",
    )
    .bind(&rig.registration.consumer_id)
    .bind(&challenge.enrollment_id)
    .bind(authentication.id.to_hex())
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(
        original_login["expires_at"],
        original_challenge["expires_at"]
    );
    assert!(original_challenge["consumed_at"].is_null());
    let initial_effects: Vec<i64> = sqlx::query_scalar(
        "SELECT ARRAY[(SELECT count(*) FROM commands WHERE consumer_id=$1),(SELECT count(*) FROM enrollment_native_proofs WHERE consumer_id=$1),(SELECT count(*) FROM native_inputs WHERE consumer_id=$1),(SELECT count(*) FROM publications WHERE consumer_id=$1),(SELECT count(*) FROM enrollments WHERE consumer_id=$1)]",
    )
    .bind(&rig.registration.consumer_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(&initial_effects[1..], &[0, 0, 0, 0]);

    // These are valid native-key signatures for the ordinary desktop's
    // presence, typing and conditional read-state publication kinds. The
    // unsupported read-state body stays opaque at this rejection boundary.
    // Negative acknowledgements must leave this exact authenticated socket
    // usable; none of these messages is an enrollment proof or accepted write.
    for (kind, tags, content) in [
        (20001, json!([]), "online"),
        (20002, json!([["h", view.channel_id]]), ""),
        (
            30078,
            json!([["d", "read-state:synthetic-client"], ["t", "read-state"]]),
            "synthetic opaque read-state",
        ),
    ] {
        let event = directory_event(&key, kind, tags, content);
        socket.send(json!(["EVENT", event])).await;
        let refused = socket.recv().await;
        assert_eq!(refused[0], "OK");
        assert_eq!(refused[1], event["id"]);
        assert_eq!(refused[2], false);
        assert_eq!(
            refused[3],
            "restricted: only enrollment challenge messages are supported"
        );
    }
    let unchanged_effects: Vec<i64> = sqlx::query_scalar(
        "SELECT ARRAY[(SELECT count(*) FROM commands WHERE consumer_id=$1),(SELECT count(*) FROM enrollment_native_proofs WHERE consumer_id=$1),(SELECT count(*) FROM native_inputs WHERE consumer_id=$1),(SELECT count(*) FROM publications WHERE consumer_id=$1),(SELECT count(*) FROM enrollments WHERE consumer_id=$1)]",
    )
    .bind(&rig.registration.consumer_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(unchanged_effects, initial_effects);

    socket
        .send(json!(["REQ","after-unsupported-events",{"kinds":[39000],"#d":[view.channel_id]}]))
        .await;
    let metadata = socket.recv().await;
    assert_eq!(
        metadata,
        json!(["EVENT", "after-unsupported-events", view.channel_metadata])
    );
    assert_eq!(
        socket.recv().await,
        json!(["EOSE", "after-unsupported-events"])
    );
    let event = message(&challenge, &key, &challenge.message_text);
    socket.send(json!(["EVENT", event])).await;
    let accepted = socket.recv().await;
    assert_eq!(accepted[0], "OK");
    assert_eq!(accepted[1], event.id.to_hex());
    assert_eq!(accepted[2], true);
    let proof = read(&rig, &challenge, "module-a", &rig.browser)
        .await
        .unwrap();
    assert_eq!(proof.native_event, serde_json::to_value(&event).unwrap());
    assert_eq!(
        proof.nip42_event,
        serde_json::to_value(&authentication).unwrap()
    );

    // Use an actually short original browser transaction, rather than changing
    // stored deadlines or replacing the database clock. Late auxiliary traffic
    // must not give this socket a fresh challenge/login lifetime.
    let until_late = (challenge.expires_at - CD::seconds(2) - Utc::now())
        .to_std()
        .expect("synthetic journey must finish before its original deadline");
    tokio::time::sleep(until_late).await;
    let late = directory_event(&key, 20001, json!([]), "away");
    socket.send(json!(["EVENT", late])).await;
    let refused = socket.recv().await;
    assert_eq!(refused[0], "OK");
    assert_eq!(refused[1], late["id"]);
    assert_eq!(refused[2], false);
    let remaining = (challenge.expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let closed = tokio::time::timeout(remaining + Duration::from_secs(1), socket.0.read_u8())
        .await
        .expect("auxiliary traffic cannot renew the original socket deadline");
    match closed {
        Ok(opcode) => assert_eq!(opcode, 0x88, "expected WebSocket close"),
        Err(error) => assert!(matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
        )),
    }
    drop(socket);
    let final_challenge: Value = sqlx::query_scalar(
        "SELECT to_jsonb(c) FROM enrollment_challenges c WHERE consumer_id=$1 AND enrollment_id=$2",
    )
    .bind(&rig.registration.consumer_id)
    .bind(&challenge.enrollment_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    let final_login: Value = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM enrollment_native_authentications a WHERE consumer_id=$1 AND enrollment_id=$2 AND nip42_event_id=$3",
    )
    .bind(&rig.registration.consumer_id)
    .bind(&challenge.enrollment_id)
    .bind(authentication.id.to_hex())
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(final_challenge, original_challenge);
    assert_eq!(final_login, original_login);
    let final_effects: Vec<i64> = sqlx::query_scalar(
        "SELECT ARRAY[(SELECT count(*) FROM commands WHERE consumer_id=$1),(SELECT count(*) FROM enrollment_native_proofs WHERE consumer_id=$1),(SELECT count(*) FROM native_inputs WHERE consumer_id=$1),(SELECT count(*) FROM publications WHERE consumer_id=$1),(SELECT count(*) FROM enrollments WHERE consumer_id=$1)]",
    )
    .bind(&rig.registration.consumer_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(final_effects, vec![initial_effects[0], 1, 0, 0, 0]);
    stop.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn native_directory_http_and_ws_supply_original_channel_profiles_and_own_challenge() {
    let (rig, key, challenge, source) = directory_setup().await;
    let view = source.view.lock().unwrap().clone();
    let path = format!(
        "/native/enrollment/{}/{}",
        rig.registration.consumer_id, challenge.enrollment_id
    );
    let relay = format!("wss://relay.synthetic.invalid{path}");
    let (address, stop, handle) = directory_server(&rig, source.clone()).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let endpoint = format!("http://{address}{path}");
    let info = client.get(format!("{endpoint}/info")).send().await.unwrap();
    assert_eq!(info.status(), reqwest::StatusCode::OK);
    assert_eq!(
        parse::<Value>(&info.bytes().await.unwrap()).unwrap(),
        view.gateway_information().unwrap()
    );
    let info = client
        .get(&endpoint)
        .header("accept", "application/nostr+json")
        .send()
        .await
        .unwrap();
    assert_eq!(info.status(), reqwest::StatusCode::OK);
    assert_eq!(info.headers()["content-type"], "application/nostr+json");
    assert_eq!(
        parse::<Value>(&info.bytes().await.unwrap()).unwrap(),
        view.gateway_information().unwrap()
    );
    let policy = client
        .get(format!("{endpoint}/api/join-policy"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        parse::<Value>(&policy.bytes().await.unwrap()).unwrap(),
        view.join_policy.clone().unwrap()
    );
    source.view.lock().unwrap().join_policy = None;
    assert_eq!(
        client
            .get(format!("{endpoint}/api/join-policy"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .get(format!("{endpoint}/info?elsewhere=1"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let filters = json!([
        {"kinds":[39002],"#p":[key.public_key().to_hex()],"limit":500},
        {"kinds":[39000],"#d":[view.channel_id],"limit":1},
        {"kinds":[0],"authors":[key.public_key().to_hex(),view.bot_public_key],"limit":2},
    ]);
    let body = canonical(&filters).unwrap();
    let url = format!("https://relay.synthetic.invalid{path}/query");
    let query_endpoint = format!("{endpoint}/query");
    let post = |credential: String, bytes: Vec<u8>| {
        client
            .post(&query_endpoint)
            .header("authorization", credential)
            .body(bytes)
            .send()
    };
    assert_eq!(
        post(native_http_auth(&key, &url, &body), body.clone())
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN,
        "HTTP native reads require separate NIP-42 login"
    );
    let mut socket = NativeSocket::connect(address, &path).await;
    socket.authenticate(&key, &relay).await;
    socket
        .send(json!([
            "REQ",
            "native-bootstrap",
            filters[0],
            filters[1],
            filters[2]
        ]))
        .await;
    let mut received = Vec::new();
    loop {
        let frame = socket.recv().await;
        if frame[0] == "EOSE" {
            assert_eq!(frame[1], "native-bootstrap");
            break;
        }
        assert_eq!(frame[0], "EVENT");
        assert_eq!(frame[1], "native-bootstrap");
        received.push(frame[2].clone());
    }
    assert_eq!(received.len(), 4);
    for original in [
        &view.channel_metadata,
        &view.channel_membership,
        &view.profiles[0],
        &view.profiles[1],
    ] {
        assert!(received.contains(original));
    }
    let credential = native_http_auth(&key, &url, &body);
    let response = post(credential.clone(), body.clone()).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let rows: Vec<Value> = parse(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(rows, received);
    assert_eq!(
        post(credential, body.clone()).await.unwrap().status(),
        reqwest::StatusCode::FORBIDDEN,
        "native read transport proof is single-use"
    );
    let foreign = canonical(&json!([{"kinds":[39000],"#d":[Uuid::new_v4().to_string()]}])).unwrap();
    assert_eq!(
        post(native_http_auth(&key, &url, &foreign), foreign)
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(
            native_http_auth(&nostr::Keys::generate(), &url, &body),
            body.clone()
        )
        .await
        .unwrap()
        .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(
            native_http_auth(&key, "https://elsewhere.invalid/query", &body),
            body.clone()
        )
        .await
        .unwrap()
        .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let auth = native_http_auth(&key, &url, &body);
    assert_eq!(
        client
            .post(&query_endpoint)
            .header("authorization", auth.clone())
            .header("authorization", auth)
            .body(body.clone())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let event = message(&challenge, &key, &challenge.message_text);
    socket.send(json!(["EVENT", event])).await;
    assert_eq!(socket.recv().await[2], true);
    let own_filter = json!([{"kinds":[9,40002,45001,45003],"#h":[view.channel_id],"limit":1}]);
    let own_body = canonical(&own_filter).unwrap();
    let response = post(native_http_auth(&key, &url, &own_body), own_body)
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        parse::<Vec<Value>>(&response.bytes().await.unwrap()).unwrap(),
        vec![serde_json::to_value(&event).unwrap()]
    );
    let proof = read(&rig, &challenge, "module-a", &rig.browser)
        .await
        .unwrap();
    assert_eq!(proof.native_event, serde_json::to_value(&event).unwrap());
    // A real signed native owner revocation replaces only the fixture roster;
    // the provider does not mint or restore membership to make the read pass.
    source.view.lock().unwrap().channel_membership = directory_event(
        &source.relay,
        39002,
        json!([
            ["d", view.channel_id],
            ["p", view.bot_public_key, "", "bot"]
        ]),
        "",
    );
    assert_eq!(
        post(native_http_auth(&key, &url, &body), body)
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    socket
        .send(json!(["REQ","after-native-revocation",{"kinds":[39000],"#d":[view.channel_id]}]))
        .await;
    assert_eq!(socket.recv().await[0], "CLOSED");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM enrollments WHERE consumer_id=$1")
        .bind(&rig.registration.consumer_id)
        .fetch_one(&rig.pool)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "directory and relay operations never create a binding"
    );
    drop(socket);
    stop.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn native_directory_rechecks_revocation_after_source_read_without_holding_provider_lock() {
    let (rig, key, challenge, source) = directory_setup().await;
    let view = source.view.lock().unwrap().clone();
    let path = format!(
        "/native/enrollment/{}/{}",
        rig.registration.consumer_id, challenge.enrollment_id
    );
    let relay = format!("wss://relay.synthetic.invalid{path}");
    let (address, stop, handle) = directory_server(&rig, source.clone()).await;
    let mut socket = NativeSocket::connect(address, &path).await;
    socket.authenticate(&key, &relay).await;
    let body = canonical(&json!([{"kinds":[39000],"#d":[view.channel_id]}])).unwrap();
    let credential = native_http_auth(
        &key,
        &format!("https://relay.synthetic.invalid{path}/query"),
        &body,
    );
    source.pause_next.store(true, Ordering::SeqCst);
    let endpoint = format!("http://{address}{path}/query");
    let request = tokio::spawn(async move {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(endpoint)
            .header("authorization", credential)
            .body(body)
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), source.entered.notified())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        rig.p.set_service_active(
            &rig.registration.consumer_id,
            false,
            &digest(&rig.registration).unwrap(),
        ),
    )
    .await
    .expect("native I/O must not hold provider admission lock")
    .unwrap();
    source.released.notify_one();
    assert_eq!(
        request.await.unwrap().status(),
        reqwest::StatusCode::FORBIDDEN
    );
    socket
        .send(json!(["REQ","after-provider-revocation",{"kinds":[39000],"#d":[view.channel_id]}]))
        .await;
    assert_eq!(socket.recv().await[0], "CLOSED");
    drop(socket);
    stop.send(()).unwrap();
    handle.await.unwrap();
}

fn refresh_synthetic_native_admission(source: &DirectorySource, seconds: i64) {
    let mut view = source.view.lock().unwrap();
    let request = directory_event(
        &source.relay,
        27235,
        json!([
            [
                "u",
                "https://native-owner.synthetic.invalid/moderation/restricted"
            ],
            ["method", "GET"],
            ["payload", sha256(b"")],
            ["nonce", Uuid::new_v4().to_string()],
        ]),
        "",
    );
    let checked_at = Utc::now();
    view.admission_check = NativeEnrollmentAdmissionCheck {
        kind: "llull-buzz-native-enrollment-admission/v1".into(),
        community_id: view.community_id.clone(),
        intended_public_key: view.intended_public_key.clone(),
        moderation_endpoint: "https://native-owner.synthetic.invalid/moderation/restricted".into(),
        request_event_id: request["id"].as_str().unwrap().into(),
        response_sha256: sha256(b"[]"),
        checked_at,
        valid_until: checked_at + CD::seconds(seconds),
    };
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn native_admission_expiry_during_final_custody_rolls_back_then_fresh_read_succeeds() {
    let (rig, key, challenge, source) = directory_setup().await;
    let path = format!(
        "/native/enrollment/{}/{}",
        rig.registration.consumer_id, challenge.enrollment_id
    );
    let relay = format!("wss://relay.synthetic.invalid{path}");
    let (address, stop, handle) = directory_server(&rig, source.clone()).await;
    let mut socket = NativeSocket::connect(address, &path).await;
    let nonce = socket.recv().await;
    assert_eq!(nonce[0], "AUTH");
    // This task-owned database delay is after the real native admission read,
    // inside final provider custody. It does not replace either clock or extend
    // the original challenge/browser transaction.
    sqlx::raw_sql("CREATE FUNCTION synthetic_native_final_custody_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE TRIGGER synthetic_native_final_custody_wait BEFORE INSERT ON enrollment_native_authentications FOR EACH ROW EXECUTE FUNCTION synthetic_native_final_custody_wait();")
        .execute(&rig.pool).await.unwrap();
    refresh_synthetic_native_admission(&source, 1);
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(22242), "")
        .tags([
            nostr::Tag::parse(["relay", relay.as_str()]).unwrap(),
            nostr::Tag::parse(["challenge", nonce[1].as_str().unwrap()]).unwrap(),
        ])
        .sign_with_keys(&key)
        .unwrap();
    socket.send(json!(["AUTH", event])).await;
    let denied = socket.recv().await;
    assert_eq!(denied[0], "OK");
    assert_eq!(denied[1], event.id.to_hex());
    assert_eq!(denied[2], false);
    drop(socket);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM enrollment_native_authentications WHERE consumer_id=$1",
    )
    .bind(&rig.registration.consumer_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(
        count, 0,
        "expired native authority cannot commit a login-custody row"
    );
    // A new actual synthetic-owner observation, with its own nonce/request ID,
    // succeeds under the same unchanged challenge despite the same DB delay.
    refresh_synthetic_native_admission(&source, 30);
    let mut socket = NativeSocket::connect(address, &path).await;
    socket.authenticate(&key, &relay).await;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM enrollment_native_authentications WHERE consumer_id=$1",
    )
    .bind(&rig.registration.consumer_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    drop(socket);
    stop.send(()).unwrap();
    handle.await.unwrap();
}
