//! Fixed HTTP control surface. Mount behind a trusted HTTPS terminator preserving
//! canonical paths; Host/Forwarded headers never select the signed request target.
use crate::{
    auth::Headers,
    ports::{ConsumerCommand, ConsumerPort},
    Provider, ProviderError, ToolAdmission,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
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
body_handler!(observation_ack, ack_observations);
body_handler!(intake_registration, register_intake);
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
        .route("/integration/v1/enrollments", post(enroll))
        .route("/integration/v1/enrollments/{id}/proof", post(proof))
        .route("/integration/v1/access-changes", post(access))
        .route("/integration/v1/tasks", post(start))
        .route("/integration/v1/tasks/{id}", get(observe))
        .route("/integration/v1/tasks/{id}/cancel", post(cancel))
        .route("/integration/v1/tasks/{id}/reconcile", post(reconcile))
        .route("/integration/v1/publications/{id}", get(publication_view))
        .route("/integration/v1/evidence/{id}", get(evidence))
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

pub fn publication_routes<P: crate::PublicationPort + 'static>(
    provider: Provider,
    publisher: Arc<crate::Publisher<P>>,
) -> Router {
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
