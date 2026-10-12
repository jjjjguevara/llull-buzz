//! Fixed HTTP control surface. Mount behind a trusted HTTPS terminator preserving
//! canonical paths; Host/Forwarded headers never select the signed request target.
use crate::{
    auth::Headers,
    ports::{ConsumerCommand, ConsumerPort},
    Provider, ProviderError, ToolAdmission,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use llull_buzz_wire::Fault;
use serde_json::json;
use std::sync::Arc;

fn value<'a>(headers: &'a HeaderMap, name: &str) -> crate::Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(Fault::Denied)?;
    if values.next().is_some() {
        return Err(Fault::Denied.into());
    }
    value.to_str().map_err(|_| Fault::Denied.into())
}
fn credentials(headers: &HeaderMap) -> crate::Result<Headers<'_>> {
    Ok(Headers {
        authorization: value(headers, "authorization")?,
        invocation: value(headers, "x-llull-invocation")?,
    })
}
impl IntoResponse for ProviderError {
    fn into_response(self) -> Response {
        let (status, outcome) = match self {
            ProviderError::Admission(Fault::Invalid) => (StatusCode::BAD_REQUEST, "denied"),
            ProviderError::Admission(Fault::TooLarge) => (StatusCode::PAYLOAD_TOO_LARGE, "denied"),
            ProviderError::Admission(Fault::Denied) => (StatusCode::FORBIDDEN, "denied"),
            ProviderError::Admission(Fault::Conflict) => (StatusCode::CONFLICT, "conflict"),
            ProviderError::Admission(Fault::Unavailable) => {
                (StatusCode::NOT_IMPLEMENTED, "unavailable")
            }
            ProviderError::Admission(Fault::Exhausted) => {
                (StatusCode::CONFLICT, "denied-budget-or-expiry")
            }
            ProviderError::Admission(Fault::Unknown) => {
                (StatusCode::CONFLICT, "unknown-requires-lookup")
            }
            ProviderError::Admission(Fault::Gap) => (StatusCode::GONE, "gap-requires-snapshot"),
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unknown-provider-commit-status",
            ),
        };
        (
            status,
            Json(json!({"outcome":outcome,"restricted_profile_active":false})),
        )
            .into_response()
    }
}
async fn unavailable() -> Response {
    ProviderError::from(Fault::Unavailable).into_response()
}
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ConfiguredSurfaces {
    pub native_intake: bool,
    pub native_handoff: bool,
    pub publication_delivery: bool,
    pub native_gateway: bool,
    pub media_gateway: bool,
    pub model_dispatch: bool,
}
macro_rules! body_handler {
    ($name:ident,$method:ident) => {
        async fn $name(
            State(p): State<Provider>,
            h: HeaderMap,
            b: Bytes,
        ) -> crate::Result<Json<crate::CommandResult>> {
            Ok(Json(p.$method(&b, credentials(&h)?).await?))
        }
    };
}
body_handler!(enroll, enroll);
body_handler!(access, change_access);
body_handler!(retire, retire_key);
body_handler!(start, start_task);
body_handler!(model_reservation, reserve_model_budget);
body_handler!(model_dispatch, begin_model_dispatch);
body_handler!(model_settlement, settle_model_dispatch);
body_handler!(observation_ack, ack_observations);
body_handler!(intake_registration, register_intake);
body_handler!(create_snapshot, create_snapshot);
async fn snapshot_page(
    State(p): State<Provider>,
    Path(id): Path<uuid::Uuid>,
    Query(query): Query<crate::SnapshotQuery>,
    h: HeaderMap,
) -> crate::Result<Json<crate::SnapshotPage>> {
    Ok(Json(
        p.snapshot_page(value(&h, "x-llull-consumer")?, id, query, credentials(&h)?)
            .await?,
    ))
}
async fn snapshot_ack(
    State(p): State<Provider>,
    Path(id): Path<uuid::Uuid>,
    h: HeaderMap,
    b: Bytes,
) -> crate::Result<Json<crate::CommandResult>> {
    Ok(Json(p.ack_snapshot(id, &b, credentials(&h)?).await?))
}
async fn evidence(
    State(p): State<Provider>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> crate::Result<Json<crate::RetainedEvidence>> {
    Ok(Json(
        p.evidence(value(&h, "x-llull-consumer")?, &id, credentials(&h)?)
            .await?,
    ))
}
async fn attachment_bytes(
    State(p): State<Provider>,
    Path((id, digest)): Path<(String, String)>,
    h: HeaderMap,
) -> crate::Result<Response> {
    let bytes = p
        .attachment_bytes(
            value(&h, "x-llull-consumer")?,
            &id,
            &digest,
            credentials(&h)?,
        )
        .await?;
    Ok((
        [
            ("content-type", "application/octet-stream"),
            ("content-disposition", "attachment"),
            ("x-content-type-options", "nosniff"),
            ("cache-control", "no-store"),
        ],
        bytes,
    )
        .into_response())
}

/// Partial native media surface: original leased bytes only. It deliberately does
/// not mark the whole media gateway qualified or enable publisher attachments.
pub fn native_media_routes<P: crate::PublicationPort + 'static>(
    provider: Provider,
    media: Arc<crate::NativeMedia<P>>,
) -> Router {
    let lease_provider = provider.clone();
    let lease_media = media.clone();
    let lease = move |headers: HeaderMap, body: Bytes| {
        let provider = lease_provider.clone();
        let media = lease_media.clone();
        async move {
            Ok::<_, ProviderError>(Json(
                provider
                    .lease_native_attachment(&body, credentials(&headers)?, media.as_ref())
                    .await?,
            ))
        }
    };
    let read = move |Path(digest): Path<String>,
                     OriginalUri(uri): OriginalUri,
                     method: Method,
                     headers: HeaderMap,
                     body: Bytes| {
        let provider = provider.clone();
        let media = media.clone();
        async move {
            let result = async {
                // No transformations, ranges, conditionals or alternate source URLs.
                if !body.is_empty()
                    || uri.query().is_some()
                    || uri.path() != format!("/media/{digest}")
                    || ["range", "if-range", "if-none-match", "if-modified-since"]
                        .iter()
                        .any(|h| headers.contains_key(*h))
                {
                    return Err::<Vec<u8>, ProviderError>(Fault::Unavailable.into());
                }
                provider
                    .native_attachment_bytes(
                        &digest,
                        value(&headers, "host")?,
                        value(&headers, "authorization")?,
                        media.as_ref(),
                    )
                    .await
            }
            .await;
            let mut response = match result {
                Ok(bytes) => {
                    let length = bytes.len();
                    let mut response = if method == Method::HEAD {
                        Vec::<u8>::new().into_response()
                    } else {
                        bytes.into_response()
                    };
                    response
                        .headers_mut()
                        .insert("content-length", length.into());
                    response.headers_mut().insert(
                        "content-type",
                        "application/octet-stream".parse().expect("static header"),
                    );
                    response.headers_mut().insert(
                        "content-disposition",
                        "attachment".parse().expect("static header"),
                    );
                    response
                }
                Err(error) => error.into_response(),
            };
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().expect("static header"));
            response.headers_mut().insert(
                "x-content-type-options",
                "nosniff".parse().expect("static header"),
            );
            response
        }
    };
    Router::new()
        .route("/integration/v1/native-attachment-leases", post(lease))
        .route("/media/{digest}", get(read.clone()).head(read))
        .layer(DefaultBodyLimit::max(llull_buzz_wire::MAX_BYTES))
}
async fn publication_view(
    State(p): State<Provider>,
    Path(id): Path<uuid::Uuid>,
    h: HeaderMap,
) -> crate::Result<Json<crate::PublicationView>> {
    Ok(Json(
        p.observe_publication(value(&h, "x-llull-consumer")?, id, credentials(&h)?)
            .await?,
    ))
}
async fn effect_view(
    State(p): State<Provider>,
    Path(id): Path<uuid::Uuid>,
    h: HeaderMap,
) -> crate::Result<Json<crate::AttemptView>> {
    Ok(Json(
        p.observe_effect(value(&h, "x-llull-consumer")?, id, credentials(&h)?)
            .await?,
    ))
}
async fn observations(
    State(p): State<Provider>,
    Query(query): Query<crate::ObservationQuery>,
    h: HeaderMap,
) -> crate::Result<Json<crate::ObservationPage>> {
    Ok(Json(
        p.observations(value(&h, "x-llull-consumer")?, query, credentials(&h)?)
            .await?,
    ))
}
async fn profile(
    State(p): State<Provider>,
    h: HeaderMap,
) -> crate::Result<Json<crate::ProfileView>> {
    Ok(Json(
        p.discover_profile(value(&h, "x-llull-consumer")?, credentials(&h)?)
            .await?,
    ))
}
async fn proof(
    State(p): State<Provider>,
    Path(id): Path<String>,
    h: HeaderMap,
    b: Bytes,
) -> crate::Result<Json<crate::CommandResult>> {
    Ok(Json(p.prove_key(&id, &b, credentials(&h)?).await?))
}
async fn observe(
    State(p): State<Provider>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> crate::Result<Json<crate::TaskView>> {
    Ok(Json(
        p.observe_task(value(&h, "x-llull-consumer")?, &id, credentials(&h)?)
            .await?,
    ))
}
async fn cancel(
    State(p): State<Provider>,
    Path(id): Path<String>,
    h: HeaderMap,
    b: Bytes,
) -> crate::Result<Json<crate::CommandResult>> {
    Ok(Json(
        p.control_task(&id, false, &b, credentials(&h)?).await?,
    ))
}
async fn reconcile(
    State(p): State<Provider>,
    Path(id): Path<String>,
    h: HeaderMap,
    b: Bytes,
) -> crate::Result<Json<crate::CommandResult>> {
    Ok(Json(p.control_task(&id, true, &b, credentials(&h)?).await?))
}
async fn claim(
    State(p): State<Provider>,
    Path(id): Path<String>,
    h: HeaderMap,
    b: Bytes,
) -> crate::Result<Json<crate::CommandResult>> {
    Ok(Json(
        p.worker_control(&id, false, &b, credentials(&h)?).await?,
    ))
}
async fn renew(
    State(p): State<Provider>,
    Path(id): Path<String>,
    h: HeaderMap,
    b: Bytes,
) -> crate::Result<Json<crate::CommandResult>> {
    Ok(Json(
        p.worker_control(&id, true, &b, credentials(&h)?).await?,
    ))
}
async fn complete(
    State(p): State<Provider>,
    Path(id): Path<String>,
    h: HeaderMap,
    b: Bytes,
) -> crate::Result<Json<crate::CommandResult>> {
    Ok(Json(p.complete_task(&id, &b, credentials(&h)?).await?))
}

pub fn router(provider: Provider) -> Router {
    router_with_surfaces(provider, ConfiguredSurfaces::default())
}
/// Configuration status is distinct from runtime readiness and qualification.
pub fn router_with_surfaces(provider: Provider, surfaces: ConfiguredSurfaces) -> Router {
    let health = move || {
        let configured = surfaces.clone();
        async move {
            Json(
                json!({"service":"llull-buzz","stage":"implementation","restricted_profile_active":false,"configured":configured,"qualification":"in-progress"}),
            )
        }
    };
    Router::new()
        .route("/healthz", get(health))
        .route("/integration/v1/profile", get(profile))
        .route("/integration/v1/observations", get(observations))
        .route("/integration/v1/observation-acks", post(observation_ack))
        .route(
            "/integration/v1/observation-snapshots",
            post(create_snapshot),
        )
        .route(
            "/integration/v1/observation-snapshots/{id}",
            get(snapshot_page),
        )
        .route(
            "/integration/v1/observation-snapshots/{id}/ack",
            post(snapshot_ack),
        )
        .route("/integration/v1/enrollments", post(enroll))
        .route("/integration/v1/enrollments/{id}/proof", post(proof))
        .route("/integration/v1/access-changes", post(access))
        .route("/integration/v1/tasks", post(start))
        .route("/integration/v1/tasks/{id}", get(observe))
        .route("/integration/v1/tasks/{id}/cancel", post(cancel))
        .route("/integration/v1/tasks/{id}/reconcile", post(reconcile))
        .route("/integration/v1/publications/{id}", get(publication_view))
        .route("/integration/v1/effects/{id}", get(effect_view))
        .route("/integration/v1/evidence/{id}", get(evidence))
        .route(
            "/integration/v1/evidence/{id}/attachments/{digest}",
            get(attachment_bytes),
        )
        .route(
            "/integration/v1/intake-registrations",
            post(intake_registration),
        )
        .route("/integration/foundation/v1/key-retirements", post(retire))
        .route("/integration/foundation/v1/tasks/{id}/claim", post(claim))
        .route("/integration/foundation/v1/tasks/{id}/renew", post(renew))
        .route(
            "/integration/foundation/v1/tasks/{id}/complete",
            post(complete),
        )
        .route(
            "/integration/foundation/v1/model-reservations",
            post(model_reservation),
        )
        .route(
            "/integration/foundation/v1/model-dispatches",
            post(model_dispatch),
        )
        .route(
            "/integration/foundation/v1/model-settlements",
            post(model_settlement),
        )
        .fallback(unavailable)
        .layer(DefaultBodyLimit::max(llull_buzz_wire::MAX_BYTES))
        .with_state(provider)
}

/// Mount a fixed, trusted native origin. Payloads cannot choose its route or key.
pub fn native_routes<S: crate::NativeEventSource + 'static>(
    provider: Provider,
    source: Arc<S>,
) -> Router {
    let intake = move |headers: HeaderMap, body: Bytes| {
        let provider = provider.clone();
        let source = source.clone();
        async move {
            Ok::<_, ProviderError>(Json(
                provider
                    .intake(&body, credentials(&headers)?, source.as_ref())
                    .await?,
            ))
        }
    };
    Router::new()
        .route("/integration/v1/conversation-intakes", post(intake))
        .layer(DefaultBodyLimit::max(llull_buzz_wire::MAX_BYTES))
}

/// Authenticated current navigation through an operator-selected native owner.
/// No redirect, caller-selected callback, prompt, publication or key is accepted.
pub fn native_handoff_routes<P: crate::PublicationPort + 'static>(
    provider: Provider,
    source: Arc<P>,
) -> Router {
    let handoff = move |OriginalUri(uri): OriginalUri, headers: HeaderMap, body: Bytes| {
        let provider = provider.clone();
        let source = source.clone();
        async move {
            let result = async {
                if uri.path() != "/integration/v1/native-handoffs" || uri.query().is_some() {
                    return Err(ProviderError::from(Fault::Invalid));
                }
                Ok(Json(
                    provider
                        .native_handoff(&body, credentials(&headers)?, source.as_ref())
                        .await?,
                ))
            }
            .await;
            let mut response = result.into_response();
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
            response
        }
    };
    Router::new()
        .route("/integration/v1/native-handoffs", post(handoff))
        .layer(DefaultBodyLimit::max(llull_buzz_wire::MAX_BYTES))
}

/// Separate from the transparent native media gateway: retains original input
/// bytes only, under a registered service action and the original intake scope.
pub fn attachment_routes<S: crate::NativeAttachmentSource + 'static>(
    provider: Provider,
    source: Arc<S>,
) -> Router {
    let retain = move |headers: HeaderMap, body: Bytes| {
        let provider = provider.clone();
        let source = source.clone();
        async move {
            Ok::<_, ProviderError>(Json(
                provider
                    .retain_attachment(&body, credentials(&headers)?, source.as_ref())
                    .await?,
            ))
        }
    };
    Router::new()
        .route("/integration/v1/attachment-retentions", post(retain))
        .layer(DefaultBodyLimit::max(llull_buzz_wire::MAX_BYTES))
}

async fn publication_evidence_no_store(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().expect("static header"));
    response
}

pub fn publication_routes<P: crate::PublicationPort + 'static>(
    provider: Provider,
    publisher: Arc<crate::Publisher<P>>,
) -> Router {
    let evidence_provider = provider.clone();
    let evidence_publisher = publisher.clone();
    let evidence = move |Path(identity): Path<String>,
                         OriginalUri(uri): OriginalUri,
                         method: Method,
                         h: HeaderMap,
                         b: Bytes| {
        let provider = evidence_provider.clone();
        let publisher = evidence_publisher.clone();
        async move {
            let result = async {
                let id = uuid::Uuid::parse_str(&identity).map_err(|_| Fault::Invalid)?;
                if method != Method::GET
                    || !b.is_empty()
                    || id.to_string() != identity
                    || uri.query().is_some()
                    || uri.path() != format!("/integration/v1/publications/{identity}/evidence")
                {
                    return Err(ProviderError::from(Fault::Invalid));
                }
                let (_, encoded, deadline) = provider
                    .observe_publication_evidence(
                        value(&h, "x-llull-consumer")?,
                        id,
                        credentials(&h)?,
                        publisher.as_ref(),
                    )
                    .await?;
                let response = ([("content-type", "application/json")], encoded).into_response();
                if tokio::time::Instant::now() >= deadline {
                    return Err(ProviderError::from(Fault::Denied));
                }
                Ok(response)
            }
            .await;
            let mut response = result.into_response();
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().expect("static header"));
            response
        }
    };
    let ep = provider.clone();
    let outgoing = publisher.clone();
    let publish = move |h: HeaderMap, b: Bytes| {
        let p = ep.clone();
        let publisher = outgoing.clone();
        async move {
            Ok::<_, ProviderError>(Json(
                p.publish(&b, credentials(&h)?, publisher.as_ref()).await?,
            ))
        }
    };
    let recover = move |Path(id): Path<uuid::Uuid>, h: HeaderMap, b: Bytes| {
        let p = provider.clone();
        let publisher = publisher.clone();
        async move {
            Ok::<_, ProviderError>(Json(
                p.reconcile_publication(id, &b, credentials(&h)?, publisher.as_ref())
                    .await?,
            ))
        }
    };
    Router::new()
        .route("/integration/v1/publications", post(publish))
        .route("/integration/v1/publications/{id}/reconcile", post(recover))
        .merge(
            Router::new()
                .route("/integration/v1/publications/{id}/evidence", get(evidence))
                .route_layer(axum::middleware::from_fn(publication_evidence_no_store)),
        )
        .layer(DefaultBodyLimit::max(llull_buzz_wire::MAX_BYTES))
}

/// Compile and mount one particular consumer command, not a generic execute tool.
/// The gateway's worker identity and credential-bearing port are trusted assembly
/// inputs; no wire/header field can select a consumer URL, key, binary or worker.
pub fn typed_routes<C, P>(
    provider: Provider,
    port: Arc<P>,
    worker_id: String,
) -> crate::Result<Router>
where
    C: ConsumerCommand,
    P: ConsumerPort<C> + 'static,
{
    llull_buzz_wire::id(&worker_id)?;
    if C::SCHEMA_ID.is_empty()
        || !C::SCHEMA_ID
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(Fault::Invalid.into());
    }
    let execute_path = format!(
        "/integration/foundation/v1/tool-admissions/{}",
        C::SCHEMA_ID
    );
    let recovery_path = format!(
        "/integration/foundation/v1/effects/{{id}}/reconcile/{}",
        C::SCHEMA_ID
    );
    let ep = provider.clone();
    let execution_port = port.clone();
    let execute = move |headers: HeaderMap, body: Bytes| {
        let provider = ep.clone();
        let port = execution_port.clone();
        let worker = worker_id.clone();
        async move {
            let admission = provider
                .admit_tool::<C>(&worker, &body, credentials(&headers)?)
                .await?;
            let result = match admission {
                ToolAdmission::Dispatch(permit) => {
                    provider.dispatch(*permit, port.as_ref()).await?
                }
                ToolAdmission::Existing(record) => *record,
            };
            Ok::<_, ProviderError>(Json(result))
        }
    };
    let recover = move |Path(id): Path<uuid::Uuid>, headers: HeaderMap, body: Bytes| {
        let provider = provider.clone();
        let port = port.clone();
        async move {
            Ok::<_, ProviderError>(Json(
                provider
                    .recover_effect::<C, P>(id, &body, credentials(&headers)?, port.as_ref())
                    .await?,
            ))
        }
    };
    Ok(Router::new()
        .route(&execute_path, post(execute))
        .route(&recovery_path, post(recover))
        .layer(DefaultBodyLimit::max(llull_buzz_wire::MAX_BYTES)))
}
