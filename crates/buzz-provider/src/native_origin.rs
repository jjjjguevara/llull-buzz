//! Fixed private native origin. Credentials and routing are trusted operator inputs.
use crate::{native, ports::PortError, Audience, NativeEventSource, PublicationPort};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use llull_buzz_wire::{canonical, id, parse, sha256, MAX_BYTES};
use serde_json::{json, Value};
use std::{collections::BTreeSet, time::Duration};
use url::Url;

pub struct HttpNativeOrigin {
    community: String,
    private_origin: Url,
    public_origin: Url,
    key: nostr::Keys,
    relay_key: nostr::PublicKey,
    owner: String,
    client: reqwest::Client,
}
impl HttpNativeOrigin {
    pub fn new(
        community: String,
        private_origin: &str,
        public_origin: &str,
        key: nostr::Keys,
        relay_key: nostr::PublicKey,
    ) -> std::result::Result<Self, PortError> {
        id(&community).map_err(|_| PortError)?;
        let private_origin = origin(private_origin, false)?;
        let public_origin = origin(public_origin, true)?;
        let owner=format!("native:{}",llull_buzz_wire::digest(&json!({"community":community,"origin":public_origin.as_str(),"sender":key.public_key().to_hex(),"relay":relay_key.to_hex()})).map_err(|_|PortError)?);
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| PortError)?;
        Ok(Self {
            community,
            private_origin,
            public_origin,
            key,
            relay_key,
            owner,
            client,
        })
    }
    async fn post(&self, path: &str, body: &[u8]) -> std::result::Result<Vec<u8>, PortError> {
        if !matches!(path, "/query" | "/events") || body.len() > MAX_BYTES {
            return Err(PortError);
        }
        let public_url = self.public_origin.join(path).map_err(|_| PortError)?;
        let private_url = self.private_origin.join(path).map_err(|_| PortError)?;
        let digest = sha256(body);
        let event = nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
            .tags([
                nostr::Tag::parse(["u", public_url.as_str()]).map_err(|_| PortError)?,
                nostr::Tag::parse(["method", "POST"]).map_err(|_| PortError)?,
                nostr::Tag::parse(["payload", digest.as_str()]).map_err(|_| PortError)?,
                nostr::Tag::parse(["nonce", uuid::Uuid::new_v4().to_string().as_str()])
                    .map_err(|_| PortError)?,
            ])
            .sign_with_keys(&self.key)
            .map_err(|_| PortError)?;
        let authorization = format!(
            "Nostr {}",
            STANDARD.encode(serde_json::to_vec(&event).map_err(|_| PortError)?)
        );
        let host = &public_url[url::Position::BeforeHost..url::Position::AfterPort];
        let response = self
            .client
            .post(private_url)
            .header("Host", host)
            .header("Authorization", authorization)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| PortError)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|s| s > MAX_BYTES as u64)
        {
            return Err(PortError);
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| PortError)?;
            if bytes.len() + chunk.len() > MAX_BYTES {
                return Err(PortError);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    /// Submit already persisted signed bytes. A failure is uncertain; only exact
    /// identity lookup or resubmission of the same event may resolve it.
    pub async fn submit(
        &self,
        community: &str,
        bytes: &[u8],
    ) -> std::result::Result<bool, PortError> {
        if community != self.community {
            return Err(PortError);
        }
        let event = native::event(bytes).map_err(|_| PortError)?;
        if event.pubkey != self.key.public_key() {
            return Err(PortError);
        }
        let response = self.post("/events", bytes).await?;
        let result: Value = parse(&response).map_err(|_| PortError)?;
        if result["event_id"] != event.id.to_hex() {
            return Err(PortError);
        }
        result["accepted"].as_bool().ok_or(PortError)
    }
    pub fn public_key(&self) -> nostr::PublicKey {
        self.key.public_key()
    }
    pub fn public_origin(&self) -> &Url {
        &self.public_origin
    }
}
#[async_trait]
impl PublicationPort for HttpNativeOrigin {
    fn owner(&self) -> &str {
        &self.owner
    }
    fn public_key(&self) -> nostr::PublicKey {
        self.key.public_key()
    }
    async fn submit(&self, community: &str, bytes: &[u8]) -> std::result::Result<bool, PortError> {
        HttpNativeOrigin::submit(self, community, bytes).await
    }
    async fn audience(
        &self,
        community: &str,
        channel: &str,
    ) -> std::result::Result<Audience, PortError> {
        if community != self.community {
            return Err(PortError);
        }
        uuid::Uuid::parse_str(channel).map_err(|_| PortError)?;
        let request = canonical(&json!([
            {"kinds":[39000],"authors":[self.relay_key.to_hex()],"#d":[channel],"limit":1},
            {"kinds":[39002],"authors":[self.relay_key.to_hex()],"#d":[channel],"limit":1}
        ]))
        .map_err(|_| PortError)?;
        let values: Vec<Value> =
            parse(&self.post("/query", &request).await?).map_err(|_| PortError)?;
        if values.len() != 2 {
            return Err(PortError);
        }
        let mut metadata = None;
        let mut roster = None;
        let mut members = BTreeSet::new();
        for value in values {
            let event = native::event(&serde_json::to_vec(&value).map_err(|_| PortError)?)
                .map_err(|_| PortError)?;
            if event.pubkey != self.relay_key
                || native::tag(&event, "d").map_err(|_| PortError)? != channel
            {
                return Err(PortError);
            }
            match event.kind.as_u16() {
                39000 => {
                    if metadata.replace(event.id.to_hex()).is_some()
                        || !event.tags.iter().any(|t| t.as_slice() == ["closed"])
                        || event
                            .tags
                            .iter()
                            .any(|t| t.as_slice() == ["archived", "true"])
                    {
                        return Err(PortError);
                    }
                }
                39002 => {
                    if roster.replace(event.id.to_hex()).is_some() {
                        return Err(PortError);
                    }
                    for tag in event.tags.iter() {
                        let fields = tag.as_slice();
                        if fields.first().is_some_and(|f| f == "p") {
                            if fields.len() != 4 {
                                return Err(PortError);
                            }
                            llull_buzz_wire::hash(&fields[1]).map_err(|_| PortError)?;
                            if !members.insert(fields[1].clone()) {
                                return Err(PortError);
                            }
                        }
                    }
                }
                _ => return Err(PortError),
            }
        }
        let revision=llull_buzz_wire::digest(&json!({"community":community,"channel":channel,"metadata":metadata.ok_or(PortError)?,"roster":roster.ok_or(PortError)?})).map_err(|_|PortError)?;
        Ok(Audience {
            community_id: community.into(),
            channel_id: channel.into(),
            revision,
            members,
        })
    }
}
#[async_trait]
impl NativeEventSource for HttpNativeOrigin {
    async fn event(
        &self,
        community: &str,
        channel: &str,
        event_id: &str,
    ) -> std::result::Result<Vec<u8>, PortError> {
        if community != self.community {
            return Err(PortError);
        }
        llull_buzz_wire::hash(event_id).map_err(|_| PortError)?;
        id(channel).map_err(|_| PortError)?;
        let request = canonical(&json!([{"ids":[event_id],"#h":[channel],"limit":1}]))
            .map_err(|_| PortError)?;
        let response = self.post("/query", &request).await?;
        let mut events: Vec<Value> = parse(&response).map_err(|_| PortError)?;
        if events.len() != 1 {
            return Err(PortError);
        }
        let bytes = serde_json::to_vec(&events.remove(0)).map_err(|_| PortError)?;
        let event = native::event(&bytes).map_err(|_| PortError)?;
        if event.id.to_hex() != event_id
            || native::tag(&event, "h").map_err(|_| PortError)? != channel
        {
            return Err(PortError);
        }
        Ok(bytes)
    }
}
fn origin(value: &str, public: bool) -> std::result::Result<Url, PortError> {
    let url = Url::parse(value).map_err(|_| PortError)?;
    if !(url.scheme() == "https" || !public && url.scheme() == "http")
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(PortError);
    }
    Ok(url)
}
