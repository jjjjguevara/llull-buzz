//! A deliberately narrow public native enrollment relay. Native keys stay in
//! their clients: NIP-42 connection authentication and the separate signed kind-9
//! bot message are verified and retained, never created by this provider.
//!
//! This surface carries no restricted conversation data, subscriptions, general
//! publication or native access changes. It does not qualify the full native
//! gateway. The original browser transaction and challenge deadlines still gate
//! proof admission; fetching an event never consumes a challenge or binds a key.
use crate::{
    auth::{self, Claims, Headers, Registration},
    db::Tx,
    native, Provider, Result,
};
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, OriginalUri, Path,
    },
    http::HeaderMap,
    response::Response,
    routing::{get, post},
    Json as HttpJson, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use futures_util::SinkExt;
use llull_buzz_wire::{canonical, digest, id, parse, sha256, Command, Enroll, Fault};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{types::Json, Row};
use std::time::Duration;

const MAX_FRAME_BYTES: usize = 65_536;
const AUTH_SECONDS: u64 = 10;
const MAX_FRAMES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentNativeProof {
    pub format: String,
    pub consumer_id: String,
    pub enrollment_id: String,
    pub module_id: String,
    pub context_domain: String,
    pub request_sha256: String,
    pub native_event: Value,
    pub nip42_event: Value,
    pub relay_url: String,
    pub received_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadProof {
    enrollment_id: String,
}

struct Pending {
    registration: Registration,
    requested: Enroll,
    original: Claims,
    challenge: String,
    fingerprint: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

struct MessageCustody<'a> {
    consumer: &'a str,
    enrollment: &'a str,
    relay: &'a str,
    authentication: &'a nostr::Event,
    event: &'a nostr::Event,
}

struct RelayAuthentication<'a> {
    relay: &'a str,
    challenge: &'a str,
    opened_at: i64,
    event: &'a nostr::Event,
}

fn relay_origin(origin: &str) -> Result<String> {
    let url = url::Url::parse(origin).map_err(|_| Fault::Invalid)?;
    if url.scheme() != "wss"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || origin.trim_end_matches('/') != url.as_str().trim_end_matches('/')
    {
        return Err(Fault::Invalid.into());
    }
    Ok(origin.trim_end_matches('/').into())
}

fn relay_path(consumer: &str, enrollment: &str) -> Result<String> {
    Ok(format!(
        "/native/enrollment/{}/{}",
        native::segment(consumer)?,
        native::segment(enrollment)?
    ))
}

fn verify_auth(
    event: &nostr::Event,
    key: &str,
    relay: &str,
    challenge: &str,
    opened_at: i64,
    now: i64,
) -> Result<()> {
    if event.kind.as_u16() != 22242
        || event.pubkey.to_hex() != key
        || !event.content.is_empty()
        || native::tag(event, "relay")? != relay
        || native::tag(event, "challenge")? != challenge
        || event.created_at.as_secs() as i64 > now + 30
        || (event.created_at.as_secs() as i64) < opened_at.saturating_sub(30)
        || now.saturating_sub(opened_at) >= AUTH_SECONDS as i64
    {
        return Err(Fault::Denied.into());
    }
    Ok(())
}

fn frame(bytes: &[u8], kind: &str) -> Result<nostr::Event> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Fault::TooLarge.into());
    }
    let raw: Vec<Value> = parse(bytes)?;
    if raw.len() != 2 || raw[0] != kind {
        return Err(Fault::Denied.into());
    }
    Ok(native::event(&canonical(&raw[1])?)?)
}

impl Provider {
    async fn pending_enrollment(
        &self,
        tx: &mut Tx,
        consumer: &str,
        enrollment: &str,
    ) -> Result<Pending> {
        id(consumer)?;
        id(enrollment)?;
        let row = sqlx::query(
            "SELECT registration,active FROM consumer_registry WHERE consumer_id=$1 FOR UPDATE",
        )
        .bind(consumer)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Fault::Denied)?;
        if !row.try_get::<bool, _>("active")? {
            return Err(Fault::Denied.into());
        }
        let registration = row.try_get::<Json<Registration>, _>("registration")?.0;
        let row = sqlx::query("SELECT requested,challenge,request_sha256,issued_at,expires_at,recovery_epoch,registration_revision,consumed_at FROM enrollment_challenges WHERE consumer_id=$1 AND enrollment_id=$2 FOR UPDATE")
            .bind(consumer).bind(enrollment).fetch_optional(&mut **tx).await?.ok_or(Fault::Denied)?;
        let requested = row.try_get::<Json<Enroll>, _>("requested")?.0;
        let fingerprint: String = row.try_get("request_sha256")?;
        let original = sqlx::query_scalar::<_, Json<Claims>>("SELECT claims FROM admission_evidence WHERE consumer_id=$1 AND request_sha256=$2 AND claims->>'operation'='enroll' ORDER BY recorded_at LIMIT 1")
            .bind(consumer).bind(&fingerprint).fetch_optional(&mut **tx).await?.ok_or(Fault::Denied)?.0;
        let now = Self::now(tx).await?;
        let expiry: DateTime<Utc> = row.try_get("expires_at")?;
        let recovery = Self::epoch(tx).await?;
        let module = registration
            .modules
            .get(&requested.module_id)
            .ok_or(Fault::Denied)?;
        // A pending challenge never grants native business access. Its original
        // service/browser/module/context admission remains the only bootstrap.
        if row
            .try_get::<Option<DateTime<Utc>>, _>("consumed_at")?
            .is_some()
            || expiry <= now
            || row.try_get::<i64, _>("recovery_epoch")? as u64 != recovery
            || recovery != self.external_epoch
            || row.try_get::<i64, _>("registration_revision")? as u64 != registration.revision
            || original.recovery_epoch != recovery
            || original.registration_revision != registration.revision
            || original.module_id != requested.module_id
            || original.payload_sha256 != fingerprint
            || !module.actions.contains("enroll")
            || !module.actions.contains("prove-key")
            || !module.context_domains.contains(&original.context_domain)
            || !module.principal_issuers.contains(&requested.issuer)
            || requested.community_id != registration.community_id
        {
            return Err(Fault::Denied.into());
        }
        self.service_scope(&registration, &original)?;
        let browser = original.browser(false, now.timestamp())?;
        if browser.issuer != requested.issuer
            || browser.subject != requested.subject
            || browser.transaction_id != requested.browser_transaction_id
        {
            return Err(Fault::Denied.into());
        }
        Ok(Pending {
            registration,
            requested,
            original,
            challenge: row.try_get("challenge")?,
            fingerprint,
            issued_at: row.try_get("issued_at")?,
            expires_at: expiry,
        })
    }

    /// Current service-authenticated read of the exact native-client message.
    /// This is not prove-key, a binding grant or historical-result recovery.
    pub async fn read_enrollment_proof(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<EnrollmentNativeProof> {
        let command: Command = Self::decode(body)?;
        if command.operation != "read-enrollment-proof" {
            return Err(Fault::Unavailable.into());
        }
        let read: ReadProof = command.payload()?;
        if command.resource.reference != read.enrollment_id || command.resource.revision != "1" {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &command,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/enrollment-proofs",
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let pending = self
            .pending_enrollment(&mut tx, &command.consumer_id, &read.enrollment_id)
            .await?;
        let browser = claims.browser(false, Self::now(&mut tx).await?.timestamp())?;
        let original_browser = pending
            .original
            .browser_authentication
            .as_ref()
            .ok_or(Fault::Denied)?;
        if claims.module_id != pending.original.module_id
            || claims.context_domain != pending.original.context_domain
            || browser.issuer != pending.requested.issuer
            || browser.subject != pending.requested.subject
            || browser.transaction_id != pending.requested.browser_transaction_id
            || browser.authenticated_at != original_browser.authenticated_at
            || browser.expires_at != original_browser.expires_at
        {
            return Err(Fault::Denied.into());
        }
        let row = sqlx::query("SELECT native_event,nip42_event,relay_url,received_at,module_id,context_domain,request_sha256 FROM enrollment_native_proofs WHERE consumer_id=$1 AND enrollment_id=$2")
            .bind(&command.consumer_id).bind(&read.enrollment_id).fetch_optional(&mut *tx).await?.ok_or(Fault::Unknown)?;
        if row.try_get::<String, _>("module_id")? != claims.module_id
            || row.try_get::<String, _>("context_domain")? != claims.context_domain
            || row.try_get::<String, _>("request_sha256")? != pending.fingerprint
        {
            return Err(Fault::Denied.into());
        }
        let proof = EnrollmentNativeProof {
            format: "llull-buzz-enrollment-native-proof/v1".into(),
            consumer_id: command.consumer_id,
            enrollment_id: read.enrollment_id,
            module_id: claims.module_id.clone(),
            context_domain: claims.context_domain.clone(),
            request_sha256: pending.fingerprint,
            native_event: row.try_get("native_event")?,
            nip42_event: row.try_get("nip42_event")?,
            relay_url: row.try_get("relay_url")?,
            received_at: row.try_get("received_at")?,
        };
        let now = Self::now(&mut tx).await?;
        claims.fresh(now.timestamp())?;
        claims.browser(false, now.timestamp())?;
        if now >= pending.expires_at {
            return Err(Fault::Denied.into());
        }
        tx.commit().await?;
        Ok(proof)
    }

    async fn retain_enrollment_authentication(
        &self,
        consumer: &str,
        enrollment: &str,
        login: RelayAuthentication<'_>,
    ) -> Result<()> {
        let RelayAuthentication {
            relay,
            challenge,
            opened_at,
            event: authentication,
        } = login;
        let mut tx = self.begin().await?;
        let pending = self
            .pending_enrollment(&mut tx, consumer, enrollment)
            .await?;
        verify_auth(
            authentication,
            &pending.requested.intended_public_key,
            relay,
            challenge,
            opened_at,
            Self::now(&mut tx).await?.timestamp(),
        )?;
        sqlx::query("INSERT INTO enrollment_native_authentications(consumer_id,enrollment_id,nip42_event_id,nip42_event,relay_url,request_sha256,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(consumer).bind(enrollment).bind(authentication.id.to_hex()).bind(Json(authentication))
            .bind(relay).bind(&pending.fingerprint).bind(pending.expires_at).execute(&mut *tx).await?;
        if Self::now(&mut tx).await? >= pending.expires_at {
            return Err(Fault::Denied.into());
        }
        tx.commit().await?;
        Ok(())
    }

    async fn remember_enrollment_message(
        tx: &mut Tx,
        pending: &Pending,
        custody: MessageCustody<'_>,
    ) -> Result<()> {
        let MessageCustody {
            consumer,
            enrollment,
            relay,
            authentication,
            event,
        } = custody;
        let now = Self::now(tx).await?;
        let login = sqlx::query("SELECT nip42_event,request_sha256,expires_at FROM enrollment_native_authentications WHERE consumer_id=$1 AND enrollment_id=$2 AND nip42_event_id=$3 AND relay_url=$4")
            .bind(consumer).bind(enrollment).bind(authentication.id.to_hex()).bind(relay)
            .fetch_optional(&mut **tx).await?.ok_or(Fault::Denied)?;
        if login.try_get::<DateTime<Utc>, _>("expires_at")? <= now
            || login.try_get::<String, _>("request_sha256")? != pending.fingerprint
            || login.try_get::<Json<nostr::Event>, _>("nip42_event")?.0 != *authentication
            || authentication.pubkey != event.pubkey
        {
            return Err(Fault::Denied.into());
        }
        native::verify_enrollment_proof(
            event,
            &pending.requested.intended_public_key,
            &pending.registration.enrollment_bot_key,
            &pending.registration.enrollment_channel,
            &native::enrollment_text(
                consumer,
                &pending.requested.community_id,
                enrollment,
                &pending.challenge,
            ),
            pending.issued_at.timestamp()..pending.expires_at.timestamp(),
            now.timestamp(),
        )?;
        let existing = sqlx::query_scalar::<_, String>("SELECT native_event_id FROM enrollment_native_proofs WHERE consumer_id=$1 AND enrollment_id=$2")
            .bind(consumer).bind(enrollment).fetch_optional(&mut **tx).await?;
        if let Some(existing) = existing {
            if existing != event.id.to_hex() {
                return Err(Fault::Conflict.into());
            }
        } else {
            sqlx::query("INSERT INTO enrollment_native_proofs(consumer_id,enrollment_id,module_id,context_domain,request_sha256,native_event_id,native_event,nip42_event_id,nip42_event,relay_url) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                .bind(consumer).bind(enrollment).bind(&pending.original.module_id).bind(&pending.original.context_domain)
                .bind(&pending.fingerprint).bind(event.id.to_hex()).bind(Json(event))
                .bind(authentication.id.to_hex()).bind(Json(authentication)).bind(relay).execute(&mut **tx).await?;
        }
        if Self::now(tx).await? >= pending.expires_at {
            return Err(Fault::Denied.into());
        }
        Ok(())
    }

    async fn retain_enrollment_event(
        &self,
        consumer: &str,
        enrollment: &str,
        relay: &str,
        authentication: &nostr::Event,
        event: &nostr::Event,
    ) -> Result<()> {
        let mut tx = self.begin().await?;
        let pending = self
            .pending_enrollment(&mut tx, consumer, enrollment)
            .await?;
        Self::remember_enrollment_message(
            &mut tx,
            &pending,
            MessageCustody {
                consumer,
                enrollment,
                relay,
                authentication,
                event,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn enrollment_http_event(
        &self,
        consumer: &str,
        enrollment: &str,
        relay: &str,
        authorization: &str,
        body: &[u8],
    ) -> Result<String> {
        if authorization.len() > 64_000 || body.len() > MAX_FRAME_BYTES {
            return Err(Fault::TooLarge.into());
        }
        let authentication = STANDARD
            .decode(authorization.strip_prefix("Nostr ").ok_or(Fault::Denied)?)
            .map_err(|_| Fault::Denied)?;
        let nip98 = native::event(&authentication)?;
        let event = native::event(body)?;
        let url = format!(
            "https://{}/events",
            relay.strip_prefix("wss://").ok_or(Fault::Invalid)?
        );
        if nip98.kind.as_u16() != 27235
            || native::tag(&nip98, "u")? != url
            || native::tag(&nip98, "method")? != "POST"
            || native::tag(&nip98, "payload")? != sha256(body)
        {
            return Err(Fault::Denied.into());
        }
        let verifier_text = std::str::from_utf8(&authentication).map_err(|_| Fault::Denied)?;
        let key = buzz_auth::verify_nip98_event(verifier_text, &url, "POST", Some(body))
            .map_err(|_| Fault::Denied)?;
        let mut tx = self.begin().await?;
        let pending = self
            .pending_enrollment(&mut tx, consumer, enrollment)
            .await?;
        let now = Self::now(&mut tx).await?;
        if key.to_hex() != pending.requested.intended_public_key
            || (now.timestamp() - nip98.created_at.as_secs() as i64).abs() > 60
        {
            return Err(Fault::Denied.into());
        }
        let scope = digest(&("enrollment-native-http", consumer, enrollment, relay))?;
        let inserted = sqlx::query("INSERT INTO resource_replays(scope,event_id,expires_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(scope).bind(nip98.id.to_hex()).bind(now + chrono::Duration::seconds(120)).execute(&mut *tx).await?;
        if inserted.rows_affected() != 1 {
            return Err(Fault::Denied.into());
        }
        // The desktop uses NIP-98 HTTP for submission, but it must first have
        // completed its separate native NIP-42 login for this exact transaction.
        let login = sqlx::query_scalar::<_, Json<nostr::Event>>("SELECT nip42_event FROM enrollment_native_authentications WHERE consumer_id=$1 AND enrollment_id=$2 AND relay_url=$3 AND request_sha256=$4 AND expires_at>$5 ORDER BY received_at DESC,nip42_event_id LIMIT 1")
            .bind(consumer).bind(enrollment).bind(relay).bind(&pending.fingerprint).bind(now)
            .fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?.0;
        Self::remember_enrollment_message(
            &mut tx,
            &pending,
            MessageCustody {
                consumer,
                enrollment,
                relay,
                authentication: &login,
                event: &event,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(event.id.to_hex())
    }
}

async fn send(socket: &mut WebSocket, value: Value) -> bool {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .is_ok()
}

async fn session(
    mut socket: WebSocket,
    provider: Provider,
    consumer: String,
    enrollment: String,
    relay: String,
    opened_at: i64,
    expires: tokio::time::Instant,
) {
    // The outer timeout retires this connection at its original challenge
    // deadline even if an idle/partial sender never supplies another frame.
    let run = async {
        let challenge = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let auth_deadline = tokio::time::Instant::now() + Duration::from_secs(AUTH_SECONDS);
        if !send(&mut socket, json!(["AUTH", challenge])).await {
            return;
        }
        let mut authentication = None;
        for _ in 0..MAX_FRAMES {
            let deadline = if authentication.is_none() {
                auth_deadline.min(expires)
            } else {
                expires
            };
            let message = match tokio::time::timeout_at(deadline, socket.recv()).await {
                Ok(Some(Ok(message))) => message,
                _ => return,
            };
            let bytes = match message {
                Message::Text(text) => text.as_bytes().to_vec(),
                Message::Ping(_) | Message::Pong(_) => continue,
                _ => return,
            };
            // Selected native sessions replay subscriptions after NIP-42. This
            // limited relay must refuse a general read without killing a valid
            // connection before the client can send its challenge message.
            let raw: Vec<Value> = match parse(&bytes) {
                Ok(raw) => raw,
                Err(_) => return,
            };
            if raw.first() == Some(&json!("REQ")) && (3..=10).contains(&raw.len()) {
                let Some(subscription) = raw[1].as_str().filter(|s| id(s).is_ok()) else {
                    return;
                };
                if !send(
                    &mut socket,
                    json!([
                        "CLOSED",
                        subscription,
                        "restricted: enrollment challenge relay has no subscriptions"
                    ]),
                )
                .await
                {
                    return;
                }
                continue;
            }
            if raw.len() == 2 && raw[0] == "CLOSE" && raw[1].as_str().is_some_and(|s| id(s).is_ok())
            {
                continue;
            }
            if authentication.is_none() {
                let event = match frame(&bytes, "AUTH") {
                    Ok(event) => event,
                    Err(_) => return,
                };
                let result = provider
                    .retain_enrollment_authentication(
                        &consumer,
                        &enrollment,
                        RelayAuthentication {
                            relay: &relay,
                            challenge: &challenge,
                            opened_at,
                            event: &event,
                        },
                    )
                    .await;
                if !send(
                    &mut socket,
                    json!([
                        "OK",
                        event.id.to_hex(),
                        result.is_ok(),
                        if result.is_ok() {
                            ""
                        } else {
                            "restricted: enrollment authentication denied"
                        }
                    ]),
                )
                .await
                    || result.is_err()
                {
                    return;
                }
                authentication = Some(event);
            } else {
                let event = match frame(&bytes, "EVENT") {
                    Ok(event) => event,
                    Err(_) => return,
                };
                let result = provider
                    .retain_enrollment_event(
                        &consumer,
                        &enrollment,
                        &relay,
                        authentication.as_ref().expect("authenticated branch"),
                        &event,
                    )
                    .await;
                // Loss of this OK is recoverable by the original enrollment and
                // event identity. Another EVENT can never overwrite the first.
                if !send(
                    &mut socket,
                    json!([
                        "OK",
                        event.id.to_hex(),
                        result.is_ok(),
                        if result.is_ok() {
                            ""
                        } else {
                            "restricted: enrollment message denied"
                        }
                    ]),
                )
                .await
                    || result.is_err()
                {
                    return;
                }
            }
        }
    };
    let _ = tokio::time::timeout_at(expires, run).await;
    let _ = socket.close().await;
}

/// Fixed public enrollment relay origin, supplied by trusted assembly. Native
/// clients use the returned canonical path in their NIP-42 relay tag; Host and
/// Forwarded headers never select a target or a private native origin.
pub fn enrollment_gateway_routes(provider: Provider, public_relay_origin: &str) -> Result<Router> {
    let origin = relay_origin(public_relay_origin)?;
    let http_provider = provider.clone();
    let http_origin = origin.clone();
    let submit = move |Path((consumer, enrollment)): Path<(String, String)>,
                       OriginalUri(uri): OriginalUri,
                       headers: HeaderMap,
                       body: Bytes| {
        let provider = http_provider.clone();
        let origin = http_origin.clone();
        async move {
            let path = relay_path(&consumer, &enrollment)?;
            if uri.path() != format!("{path}/events") || uri.query().is_some() {
                return Err(crate::ProviderError::from(Fault::Invalid));
            }
            let mut authorization = headers.get_all("authorization").iter();
            let credential = authorization
                .next()
                .and_then(|h| h.to_str().ok())
                .ok_or(Fault::Denied)?;
            if authorization.next().is_some() {
                return Err(Fault::Denied.into());
            }
            let event = provider
                .enrollment_http_event(
                    &consumer,
                    &enrollment,
                    &format!("{origin}{path}"),
                    credential,
                    &body,
                )
                .await?;
            Ok::<_, crate::ProviderError>(HttpJson(
                json!({"event_id":event,"accepted":true,"message":""}),
            ))
        }
    };
    let upgrade = move |Path((consumer, enrollment)): Path<(String, String)>,
                        OriginalUri(uri): OriginalUri,
                        ws: WebSocketUpgrade| {
        let provider = provider.clone();
        let origin = origin.clone();
        async move {
            let path = relay_path(&consumer, &enrollment)?;
            if uri.path() != path || uri.query().is_some() {
                return Err(crate::ProviderError::from(Fault::Invalid));
            }
            let mut tx = provider.begin().await?;
            let pending = provider
                .pending_enrollment(&mut tx, &consumer, &enrollment)
                .await?;
            let now = Provider::now(&mut tx).await?;
            let remaining = (pending.expires_at - now)
                .to_std()
                .map_err(|_| Fault::Denied)?;
            let expires = tokio::time::Instant::now() + remaining;
            tx.commit().await?;
            let relay = format!("{origin}{path}");
            Ok::<Response, crate::ProviderError>(
                ws.max_frame_size(MAX_FRAME_BYTES)
                    .max_message_size(MAX_FRAME_BYTES)
                    .on_upgrade(move |socket| {
                        session(
                            socket,
                            provider,
                            consumer,
                            enrollment,
                            relay,
                            now.timestamp(),
                            expires,
                        )
                    }),
            )
        }
    };
    Ok(Router::new()
        .route("/native/enrollment/{consumer}/{enrollment}", get(upgrade))
        .route(
            "/native/enrollment/{consumer}/{enrollment}/events",
            post(submit),
        )
        .layer(DefaultBodyLimit::max(MAX_FRAME_BYTES)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(key: &nostr::Keys, relay: &str, challenge: &str, now: i64) -> nostr::Event {
        nostr::EventBuilder::new(nostr::Kind::Custom(22242), "")
            .tags([
                nostr::Tag::parse(["relay", relay]).unwrap(),
                nostr::Tag::parse(["challenge", challenge]).unwrap(),
            ])
            .custom_created_at(nostr::Timestamp::from(now as u64))
            .sign_with_keys(key)
            .unwrap()
    }

    #[test]
    fn relay_origin_and_path_are_operator_fixed() {
        assert_eq!(
            relay_origin("wss://relay.synthetic.invalid").unwrap(),
            "wss://relay.synthetic.invalid"
        );
        assert_eq!(
            relay_path("consumer a", "enrollment").unwrap(),
            "/native/enrollment/consumer%20a/enrollment"
        );
        for origin in [
            "ws://relay.synthetic.invalid",
            "wss://user@relay.synthetic.invalid",
            "wss://relay.synthetic.invalid/other",
            "wss://relay.synthetic.invalid/?target=private",
            "wss://relay.synthetic.invalid/#fragment",
        ] {
            assert!(relay_origin(origin).is_err(), "{origin}");
        }
    }

    #[test]
    fn nip42_login_is_distinct_from_exact_kind9_enrollment_proof() {
        let key = nostr::Keys::generate();
        let other = nostr::Keys::generate();
        let now = Utc::now().timestamp();
        let relay = "wss://relay.synthetic.invalid/native/enrollment/consumer/enrollment";
        let authentication = auth(&key, relay, "connection-nonce", now);
        assert!(verify_auth(
            &authentication,
            &key.public_key().to_hex(),
            relay,
            "connection-nonce",
            now,
            now
        )
        .is_ok());
        for (intended, target, nonce, opened, observed) in [
            (
                other.public_key().to_hex(),
                relay,
                "connection-nonce",
                now,
                now,
            ),
            (
                key.public_key().to_hex(),
                "wss://private.synthetic.invalid",
                "connection-nonce",
                now,
                now,
            ),
            (key.public_key().to_hex(), relay, "changed", now, now),
            (
                key.public_key().to_hex(),
                relay,
                "connection-nonce",
                now,
                now + AUTH_SECONDS as i64,
            ),
            (
                key.public_key().to_hex(),
                relay,
                "connection-nonce",
                now + 31,
                now + 31,
            ),
        ] {
            assert!(
                verify_auth(&authentication, &intended, target, nonce, opened, observed).is_err()
            );
        }
        assert!(native::verify_enrollment_proof(
            &authentication,
            &key.public_key().to_hex(),
            &other.public_key().to_hex(),
            "channel",
            "message",
            now..now + 300,
            now
        )
        .is_err());
        let proof = nostr::EventBuilder::new(nostr::Kind::Custom(9), "message")
            .tags([
                nostr::Tag::parse(["p", other.public_key().to_hex().as_str()]).unwrap(),
                nostr::Tag::parse(["h", "channel"]).unwrap(),
            ])
            .sign_with_keys(&key)
            .unwrap();
        assert!(native::verify_enrollment_proof(
            &proof,
            &key.public_key().to_hex(),
            &other.public_key().to_hex(),
            "channel",
            "message",
            now..now + 300,
            now
        )
        .is_ok());
        assert!(verify_auth(
            &proof,
            &key.public_key().to_hex(),
            relay,
            "connection-nonce",
            now,
            now
        )
        .is_err());
        assert!(frame(
            &canonical(&json!(["AUTH", authentication])).unwrap(),
            "AUTH"
        )
        .is_ok());
        assert!(frame(&canonical(&json!(["EVENT", proof])).unwrap(), "AUTH").is_err());
        assert!(frame(br#"["REQ","arbitrary",{}]"#, "EVENT").is_err());
    }

    #[test]
    fn duplicate_auth_tags_and_changed_native_message_are_denied() {
        let key = nostr::Keys::generate();
        let now = Utc::now().timestamp();
        let event = nostr::EventBuilder::new(nostr::Kind::Custom(22242), "")
            .tags([
                nostr::Tag::parse(["relay", "wss://relay.synthetic.invalid"]).unwrap(),
                nostr::Tag::parse(["relay", "wss://relay.synthetic.invalid"]).unwrap(),
                nostr::Tag::parse(["challenge", "nonce"]).unwrap(),
            ])
            .sign_with_keys(&key)
            .unwrap();
        assert!(verify_auth(
            &event,
            &key.public_key().to_hex(),
            "wss://relay.synthetic.invalid",
            "nonce",
            now,
            now
        )
        .is_err());
        let proof = nostr::EventBuilder::new(nostr::Kind::Custom(9), "changed-message")
            .tags([
                nostr::Tag::parse(["p", key.public_key().to_hex().as_str()]).unwrap(),
                nostr::Tag::parse(["h", "channel"]).unwrap(),
            ])
            .sign_with_keys(&key)
            .unwrap();
        assert!(native::verify_enrollment_proof(
            &proof,
            &key.public_key().to_hex(),
            &key.public_key().to_hex(),
            "channel",
            "exact-message",
            now..now + 300,
            now
        )
        .is_err());
    }
}
