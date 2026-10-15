//! Synthetic external owner with real TLS, ES256/Nostr verification and its own
//! PostgreSQL database. This is protocol qualification, not a private consumer.
use super::*;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use sqlx::types::Json;
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Notify, task::JoinSet};
use tokio_rustls::{rustls, TlsAcceptor};

struct OwnerState {
    pool: PgPool,
    registration: Registration,
    origin: String,
    lose_response: std::sync::atomic::AtomicBool,
    pause: std::sync::atomic::AtomicBool,
    received: Notify,
    resume: Notify,
}
struct HttpsOwner {
    state: Arc<OwnerState>,
    listener: tokio::task::JoinHandle<()>,
    certificate: Vec<u8>,
    database: String,
}

impl HttpsOwner {
    async fn start(rig: &Rig) -> Self {
        let database = format!("bz_owner_{}", Uuid::new_v4().simple());
        // Identifier is a fixed test prefix plus OS-generated UUID hex, never wire input.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&rig.pool)
            .await
            .unwrap();
        let mut url = url::Url::parse(&std::env::var("TEST_DATABASE_URL").unwrap()).unwrap();
        url.set_path(&database);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(url.as_str())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TABLE authority(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),active boolean NOT NULL,epoch bigint NOT NULL); INSERT INTO authority(active,epoch) VALUES(true,1); CREATE TABLE resources(id text PRIMARY KEY,revision bigint NOT NULL,label text NOT NULL); CREATE TABLE effects(intent text PRIMARY KEY,digest text NOT NULL,resource jsonb NOT NULL,result jsonb NOT NULL); CREATE TABLE proofs(event_id text PRIMARY KEY,jti text UNIQUE NOT NULL);")
            .execute(&pool).await.unwrap();
        let (certificate, key) = certificate();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(certificate.clone())],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = Arc::new(OwnerState {
            pool,
            registration: rig.registration.clone(),
            origin: format!(
                "https://127.0.0.1:{}",
                listener.local_addr().unwrap().port()
            ),
            lose_response: false.into(),
            pause: false.into(),
            received: Notify::new(),
            resume: Notify::new(),
        });
        let serving = state.clone();
        let handle = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{
                        let Ok((socket,_))=accepted else {break};
                        let acceptor=acceptor.clone();
                        let state=serving.clone();
                        connections.spawn(async move {
                            let Ok(stream)=acceptor.accept(socket).await else {return};
                            let service=hyper::service::service_fn(move |request| owner_request(state.clone(),request));
                            let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream),service).await;
                        });
                    },
                    _=connections.join_next(),if !connections.is_empty()=>{}
                }
            }
        });
        Self {
            state,
            listener: handle,
            certificate,
            database,
        }
    }
    fn port(&self, rig: &Rig) -> HttpConsumer<SetLabel> {
        HttpConsumer::with_roots(
            "synthetic-owner".into(),
            &format!("{}/command", self.state.origin),
            &format!("{}/lookup", self.state.origin),
            rig.key.clone(),
            vec![reqwest::Certificate::from_der(&self.certificate).unwrap()],
        )
        .unwrap()
    }
    async fn resource(&self, resource: &Resource) {
        sqlx::query("INSERT INTO resources(id,revision,label) VALUES($1,$2,'before')")
            .bind(&resource.reference)
            .bind(resource.revision.parse::<i64>().unwrap())
            .execute(&self.state.pool)
            .await
            .unwrap();
    }
    async fn close(self, rig: &Rig) {
        self.listener.abort();
        let _ = self.listener.await;
        self.state.pool.close().await;
        assert!(
            self.database.starts_with("bz_owner_")
                && self
                    .database
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        // The task-owned identifier is checked above; no shared database is eligible.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.database
        )))
        .execute(&rig.pool)
        .await
        .unwrap();
    }
}

fn certificate() -> (Vec<u8>, Vec<u8>) {
    use std::os::unix::fs::PermissionsExt;
    let directory = std::env::temp_dir().join(format!("bz-tls-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    for args in [
        vec![
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
        ],
        vec![
            "x509", "-in", "cert.pem", "-outform", "DER", "-out", "cert.der",
        ],
        vec![
            "pkcs8", "-topk8", "-nocrypt", "-in", "key.pem", "-outform", "DER", "-out", "key.der",
        ],
    ] {
        let output = std::process::Command::new("openssl")
            .args(args)
            .current_dir(&directory)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic certificate command failed"
        );
    }
    let cert = std::fs::read(directory.join("cert.der")).unwrap();
    let key = std::fs::read(directory.join("key.der")).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    (cert, key)
}

async fn owner_request(
    state: Arc<OwnerState>,
    request: Request<Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, std::io::Error> {
    let path = request.uri().path().to_owned();
    let headers = request.headers().clone();
    let method = request.method().clone();
    let body = Limited::new(request.into_body(), MAX_BYTES)
        .collect()
        .await
        .map_err(std::io::Error::other)?
        .to_bytes();
    let result = owner_effect(&state, &method, &path, &headers, &body).await;
    match result {
        Ok(result) => {
            if path == "/command" && state.lose_response.swap(false, Ordering::SeqCst) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "synthetic lost response after committed owner transaction",
                ));
            }
            Ok(Response::new(Full::new(Bytes::from(
                serde_json::to_vec(&result).unwrap(),
            ))))
        }
        Err(error) => {
            eprintln!("synthetic owner rejection: {error}");
            Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from_static(b"denied")))
                .unwrap())
        }
    }
}

async fn owner_effect(
    state: &OwnerState,
    method: &hyper::Method,
    path: &str,
    headers: &hyper::HeaderMap,
    body: &[u8],
) -> std::result::Result<ConsumerResult, Box<dyn std::error::Error + Send + Sync>> {
    if method != hyper::Method::POST || !matches!(path, "/command" | "/lookup") {
        return Err("unsupported route".into());
    }
    let native_header = headers
        .get("authorization")
        .ok_or("missing native proof")?
        .to_str()?;
    let native_bytes = STANDARD.decode(
        native_header
            .strip_prefix("Nostr ")
            .ok_or("native scheme")?,
    )?;
    let event = llull_buzz_provider::native::event(&native_bytes)?;
    let payload_tags: Vec<_> = event
        .tags
        .iter()
        .filter(|t| t.as_slice().first().is_some_and(|s| s == "payload"))
        .collect();
    if payload_tags.len() != 1 || payload_tags[0].as_slice() != ["payload", sha256(body).as_str()] {
        return Err("wrong raw body".into());
    }
    let key = buzz_auth::verify_nip98_event(
        std::str::from_utf8(&native_bytes)?,
        &format!("{}{path}", state.origin),
        "POST",
        Some(body),
    )?;
    if key.to_hex() != state.registration.service_public_key {
        return Err("wrong peer".into());
    }
    let token = headers
        .get("x-llull-invocation")
        .ok_or("missing evidence")?
        .to_str()?;
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("bad compact JWS".into());
    }
    let header: Value = parse(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?)?;
    if header.as_object().ok_or("bad header")?.len() != 3
        || header["alg"] != "ES256"
        || header["typ"] != INVOCATION
        || header["kid"] != "disposable-key"
    {
        return Err("wrong evidence type".into());
    }
    let _: Claims = parse(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.leeway = 0;
    validation.set_audience(&[&state.registration.audiences[INVOCATION]]);
    validation.set_issuer(&[&state.registration.issuer]);
    let key = jsonwebtoken::DecodingKey::from_ec_pem(
        state.registration.verification_keys["disposable-key"].as_bytes(),
    )?;
    let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)?.claims;
    let now = Utc::now().timestamp();
    if claims.consumer_id != state.registration.consumer_id
        || claims.sub != state.registration.service_principal
        || claims.registration_revision != state.registration.revision
        || claims.policy_revision != state.registration.policy_revision
        || claims.iat > now + 30
        || claims.exp - claims.iat > 60
        || claims.authority_checked_at > now
        || now - claims.authority_checked_at >= 60
    {
        return Err("stale or wrong scope".into());
    }
    if state.pause.swap(false, Ordering::SeqCst) {
        state.received.notify_one();
        state.resume.notified().await;
    }
    let mut tx = state.pool.begin().await?;
    let (active, epoch): (bool, i64) =
        sqlx::query_as("SELECT active,epoch FROM authority WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("INSERT INTO proofs(event_id,jti) VALUES($1,$2)")
        .bind(event.id.to_hex())
        .bind(&claims.jti)
        .execute(&mut *tx)
        .await?;
    if path == "/lookup" {
        let command: Command = parse(body)?;
        let recovery: RecoverEffect = command.payload()?;
        if command.operation != "reconcile-effect"
            || claims.operation != command.operation
            || claims.payload_sha256 != command.fingerprint()?
            || claims.intent_id != command.intent_id
            || claims.resource != command.resource
            || recovery.effect_owner != "synthetic-owner"
            || !active
            || claims.authority_epoch != epoch as u64
        {
            return Err("lookup denied".into());
        }
        let result: Option<(String, Value, Json<ConsumerResult>)> =
            sqlx::query_as("SELECT digest,resource,result FROM effects WHERE intent=$1")
                .bind(&recovery.effect_intent_id)
                .fetch_optional(&mut *tx)
                .await?;
        let result = match result {
            Some((digest, resource, result))
                if digest == recovery.request_sha256
                    && resource == serde_json::to_value(&command.resource)? =>
            {
                result.0
            }
            None => ConsumerResult {
                owner: "synthetic-owner".into(),
                effect_intent_id: recovery.effect_intent_id,
                request_sha256: recovery.request_sha256,
                status: ConsumerStatus::Unknown,
                result_ref: None,
            },
            _ => return Err("changed recovery identity".into()),
        };
        tx.commit().await?;
        return Ok(result);
    }
    let call: ToolCall<SetLabel> = parse(body)?;
    call.arguments.validate()?;
    if claims.operation != SetLabel::ACTION
        || call.action != SetLabel::ACTION
        || claims.payload_sha256 != digest(&call)?
        || claims.intent_id != call.intent_id
        || claims.resource != call.resource
        || claims.resource_revision != call.resource.revision
        || call.schema_id != SetLabel::SCHEMA_ID
        || call.schema_sha256 != digest(&SetLabel::schema())?
        || call.consumer_id != claims.consumer_id
        || claims.root_task_id.as_deref() != Some(&call.root_task_id)
        || call.effect_owner != "synthetic-owner"
    {
        return Err("wrong exact intent".into());
    }
    let fingerprint = digest(&call)?;
    let prior: Option<(String, Json<ConsumerResult>)> =
        sqlx::query_as("SELECT digest,result FROM effects WHERE intent=$1")
            .bind(&call.effect_intent_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((digest, result)) = prior {
        if digest != fingerprint || !active || claims.authority_epoch != epoch as u64 {
            return Err("replay denied".into());
        }
        tx.commit().await?;
        return Ok(result.0);
    }
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM resources WHERE id=$1 FOR UPDATE")
            .bind(&call.resource.reference)
            .fetch_optional(&mut *tx)
            .await?;
    let allowed = active
        && claims.authority_epoch == epoch as u64
        && claims.exp > Utc::now().timestamp()
        && revision.is_some_and(|r| r.to_string() == call.resource.revision);
    let status = if allowed {
        sqlx::query("UPDATE resources SET label=$2,revision=revision+1 WHERE id=$1")
            .bind(&call.resource.reference)
            .bind(&call.arguments.label)
            .execute(&mut *tx)
            .await?;
        ConsumerStatus::Completed
    } else {
        ConsumerStatus::DeniedBeforeEffect
    };
    let result = ConsumerResult {
        owner: "synthetic-owner".into(),
        effect_intent_id: call.effect_intent_id.clone(),
        request_sha256: fingerprint.clone(),
        result_ref: allowed.then(|| format!("synthetic-result/{}", call.effect_intent_id)),
        status,
    };
    sqlx::query("INSERT INTO effects(intent,digest,resource,result) VALUES($1,$2,$3,$4)")
        .bind(&call.effect_intent_id)
        .bind(fingerprint)
        .bind(Json(&call.resource))
        .bind(Json(&result))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(result)
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 and openssl"]
async fn https_owner_commits_once_recovers_lost_response_and_rechecks_revocation() {
    let rig = Rig::new().await;
    let owner = HttpsOwner::start(&rig).await;
    let port = owner.port(&rig);
    let root = rig.start(None, "module-a", 300).await;
    owner.resource(&root.tools[0].resources[0]).await;
    rig.worker(&root, None, "module-a", 1, false).await;
    let call = rig.tool(&root, 1);
    let untrusted = HttpConsumer::<SetLabel>::new(
        "synthetic-owner".into(),
        &format!("{}/command", owner.state.origin),
        &format!("{}/lookup", owner.state.origin),
        rig.key.clone(),
    )
    .unwrap();
    let (raw, claims) = rig.tool_request(&call, None, "module-a");
    let signed = rig.sign("/unused-by-owner", "POST", &raw, &claims, INVOCATION);
    assert!(untrusted
        .execute(&call, &raw, &signed.assertion, Duration::from_secs(5))
        .await
        .is_err());
    owner.state.lose_response.store(true, Ordering::SeqCst);
    let unknown = rig
        .p
        .dispatch(
            permit(rig.admit(&call, None, "module-a").await.unwrap()),
            &port,
        )
        .await
        .unwrap();
    assert_eq!(unknown.state, "effect-unknown");
    let committed: i64 = sqlx::query_scalar("SELECT count(*) FROM effects")
        .fetch_one(&owner.state.pool)
        .await
        .unwrap();
    assert_eq!(
        committed, 1,
        "uncertainty must follow an actual owner commit"
    );
    let recovery = rig.command(
        "reconcile-effect",
        call.resource.clone(),
        RecoverEffect {
            task_id: root.task_id.clone(),
            expected_generation: 1,
            attempt_id: unknown.attempt_id,
            effect_owner: call.effect_owner.clone(),
            effect_intent_id: call.effect_intent_id.clone(),
            request_sha256: unknown.request_sha256.clone(),
        },
    );
    let claims = rig.claims(&recovery, "module-a", Some(&root.root_task_id), None);
    let path = format!(
        "/integration/foundation/v1/effects/{}/reconcile/{}",
        unknown.attempt_id,
        SetLabel::SCHEMA_ID
    );
    let (body, h) = rig.prepare(&path, &recovery, &claims);
    let result = rig
        .p
        .recover_effect::<SetLabel, _>(unknown.attempt_id, &body, h.headers(), &port)
        .await
        .unwrap();
    assert_eq!(result.state, "completed");
    let transitions: Vec<Json<Observation>> = sqlx::query_scalar(
        "SELECT record FROM observations WHERE consumer_id=$1 AND record->>'operation'='effect-outcome' ORDER BY sequence",
    )
    .bind(&call.consumer_id)
    .fetch_all(&rig.pool)
    .await
    .unwrap();
    assert_eq!(transitions.len(), 2);
    assert_eq!(
        transitions[0].0.operation_id,
        unknown.attempt_id.to_string()
    );
    assert_eq!(transitions[0].0.execution, Execution::EffectUnknown);
    assert_eq!(
        transitions[1].0.operation_id,
        unknown.attempt_id.to_string()
    );
    assert_eq!(transitions[1].0.execution, Execution::Completed);
    assert_eq!(
        transitions[0].0.resource.reference,
        unknown.attempt_id.to_string()
    );
    assert_eq!(transitions[1].0.sequence, transitions[0].0.sequence + 1);
    let row: (String, i64) = sqlx::query_as("SELECT label,revision FROM resources WHERE id=$1")
        .bind(&call.resource.reference)
        .fetch_one(&owner.state.pool)
        .await
        .unwrap();
    assert_eq!(row, ("Synthetic ready".into(), 2));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM effects")
        .fetch_one(&owner.state.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let complete = rig.command(
        "complete-task",
        rig.resource(&root.task_id, 1),
        CompleteTask {
            task_id: root.task_id.clone(),
            expected_generation: 1,
            completed_effects: vec![CompletedEffect {
                attempt_id: result.attempt_id,
                effect_owner: result.effect_owner.clone(),
                effect_intent: result.effect_intent_id.clone(),
                request_sha256: result.request_sha256.clone(),
                result_ref: result.result_ref.clone().unwrap(),
            }],
        },
    );
    let claims = rig.claims(&complete, "module-a", Some(&root.root_task_id), None);
    let (body, h) = rig.prepare(
        &format!("/integration/foundation/v1/tasks/{}/complete", root.task_id),
        &complete,
        &claims,
    );
    assert_eq!(
        rig.p
            .complete_task(&root.task_id, &body, h.headers())
            .await
            .unwrap()
            .receipt
            .execution,
        Execution::Completed
    );

    let root = rig.start(None, "module-b", 300).await;
    owner.resource(&root.tools[0].resources[0]).await;
    rig.worker(&root, None, "module-b", 1, false).await;
    let call = rig.tool(&root, 1);
    let admitted = permit(rig.admit(&call, None, "module-b").await.unwrap());
    owner.state.pause.store(true, Ordering::SeqCst);
    let p = rig.p.clone();
    let dispatch = tokio::spawn(async move { p.dispatch(admitted, &port).await });
    tokio::time::timeout(Duration::from_secs(20), owner.state.received.notified())
        .await
        .unwrap();
    sqlx::query("UPDATE authority SET active=false,epoch=epoch+1")
        .execute(&owner.state.pool)
        .await
        .unwrap();
    owner.state.resume.notify_one();
    let denied = dispatch.await.unwrap().unwrap();
    assert_eq!(denied.state, "denied");
    let row: (String, i64) = sqlx::query_as("SELECT label,revision FROM resources WHERE id=$1")
        .bind(&call.resource.reference)
        .fetch_one(&owner.state.pool)
        .await
        .unwrap();
    assert_eq!(row, ("before".into(), 1));
    rig.cancel(&root, None, "module-b", 1).await;
    owner.close(&rig).await;
}
