//! Synthetic native-client wire journey through a real loopback WebSocket and
//! real PostgreSQL custody. The HTTPS/WSS terminator and named desktop/mobile
//! human interaction remain separate qualification, not simulated passes here.
use super::*;
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
