//! Compiled consumer adapters. No consumer business model or role vocabulary is
//! embedded in this provider. Test implementations may replace the remote consumer,
//! never the production PostgreSQL ledger or signature verifier.
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use llull_buzz_wire::{sha256, ToolCall};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{marker::PhantomData, time::Duration};

pub trait ConsumerCommand: Serialize + DeserializeOwned + Send + Sync + 'static {
    const SCHEMA_ID: &'static str;
    const ACTION: &'static str;
    /// Closed JSON Schema of the locally compiled argument type.
    fn schema() -> serde_json::Value;
    /// Enforce domain constraints beyond Serde field/type checks. No permissive default.
    fn validate(&self) -> llull_buzz_wire::Result<()>;
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConsumerStatus {
    Completed,
    /// Authoritative terminal denial: the owner has fenced this intent against
    /// any later commit. A lookup miss, 404, timeout or absent receipt is Unknown.
    DeniedBeforeEffect,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerResult {
    pub owner: String,
    pub effect_intent_id: String,
    pub request_sha256: String,
    pub status: ConsumerStatus,
    pub result_ref: Option<String>,
}
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("consumer result uncertain or unavailable")]
pub struct PortError;

#[async_trait]
pub trait ConsumerPort<C: ConsumerCommand>: Send + Sync {
    fn owner(&self) -> &str;
    async fn execute(
        &self,
        command: &ToolCall<C>,
        canonical_body: &[u8],
        invocation: &str,
        timeout: Duration,
    ) -> std::result::Result<ConsumerResult, PortError>;
    /// Lookup must not execute the original command. The canonical, independently
    /// signed recovery command includes the recorded owner/intent/request digest.
    /// Not-found is Unknown, never DeniedBeforeEffect: the original network
    /// request can still be in flight. Only an owner-fenced terminal decision
    /// can discharge uncertainty without a completed result.
    async fn lookup(
        &self,
        canonical_recovery: &[u8],
        invocation: &str,
        timeout: Duration,
    ) -> std::result::Result<ConsumerResult, PortError>;
}

/// Credential-bearing production adapter. Instantiate only in the trusted gateway.
/// Endpoints and the service key are operator-supplied, never model arguments.
pub struct HttpConsumer<C: ConsumerCommand> {
    owner: String,
    command_url: url::Url,
    lookup_url: url::Url,
    key: nostr::Keys,
    client: reqwest::Client,
    marker: PhantomData<C>,
}
impl<C: ConsumerCommand> HttpConsumer<C> {
    pub fn new(
        owner: String,
        command_url: &str,
        lookup_url: &str,
        key: nostr::Keys,
    ) -> std::result::Result<Self, PortError> {
        Self::with_roots(owner, command_url, lookup_url, key, vec![])
    }
    /// Operator-selected private PKI, with ordinary chain and hostname checks.
    /// Nonempty roots replace platform roots; no caller can disable TLS verification.
    pub fn with_roots(
        owner: String,
        command_url: &str,
        lookup_url: &str,
        key: nostr::Keys,
        roots: Vec<reqwest::Certificate>,
    ) -> std::result::Result<Self, PortError> {
        llull_buzz_wire::id(&owner).map_err(|_| PortError)?;
        let command_url = endpoint(command_url)?;
        let lookup_url = endpoint(lookup_url)?;
        if command_url.origin() != lookup_url.origin() || command_url == lookup_url {
            return Err(PortError);
        }
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));
        if !roots.is_empty() {
            builder = builder.tls_certs_only(roots);
        }
        let client = builder.build().map_err(|_| PortError)?;
        Ok(Self {
            owner,
            command_url,
            lookup_url,
            key,
            client,
            marker: PhantomData,
        })
    }
    async fn post(
        &self,
        url: &url::Url,
        body: &[u8],
        invocation: &str,
        timeout: Duration,
    ) -> std::result::Result<ConsumerResult, PortError> {
        let payload = sha256(body);
        let tags = vec![
            nostr::Tag::parse(["u", url.as_str()]).map_err(|_| PortError)?,
            nostr::Tag::parse(["method", "POST"]).map_err(|_| PortError)?,
            nostr::Tag::parse(["payload", payload.as_str()]).map_err(|_| PortError)?,
            nostr::Tag::parse(["nonce", uuid::Uuid::new_v4().to_string().as_str()])
                .map_err(|_| PortError)?,
        ];
        let event = nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(&self.key)
            .map_err(|_| PortError)?;
        let authorization = format!(
            "Nostr {}",
            STANDARD.encode(serde_json::to_vec(&event).map_err(|_| PortError)?)
        );
        let response = self
            .client
            .post(url.clone())
            .header("Authorization", authorization)
            .header("X-Llull-Invocation", invocation)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .timeout(timeout.min(Duration::from_secs(30)))
            .send()
            .await
            .map_err(|_| PortError)?;
        // A transport status alone never proves that an effect failed before commit.
        if !response.status().is_success() {
            return Err(PortError);
        }
        if response.content_length().is_some_and(|n| n > 65_536) {
            return Err(PortError);
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| PortError)?;
            if bytes.len() + chunk.len() > 65_536 {
                return Err(PortError);
            }
            bytes.extend_from_slice(&chunk);
        }
        llull_buzz_wire::parse(&bytes).map_err(|_| PortError)
    }
}
fn endpoint(s: &str) -> std::result::Result<url::Url, PortError> {
    let url = url::Url::parse(s).map_err(|_| PortError)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(PortError);
    }
    Ok(url)
}
#[async_trait]
impl<C: ConsumerCommand> ConsumerPort<C> for HttpConsumer<C> {
    fn owner(&self) -> &str {
        &self.owner
    }
    async fn execute(
        &self,
        _command: &ToolCall<C>,
        canonical_body: &[u8],
        invocation: &str,
        timeout: Duration,
    ) -> std::result::Result<ConsumerResult, PortError> {
        self.post(&self.command_url, canonical_body, invocation, timeout)
            .await
    }
    async fn lookup(
        &self,
        body: &[u8],
        invocation: &str,
        timeout: Duration,
    ) -> std::result::Result<ConsumerResult, PortError> {
        self.post(&self.lookup_url, body, invocation, timeout).await
    }
}
