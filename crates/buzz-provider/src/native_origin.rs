//! Fixed private native origin. Credentials and routing are trusted operator inputs.
use crate::{
    native, ports::PortError, Audience, NativeAttachmentSource, NativeEventSource, PublicationPort,
    MAX_ATTACHMENT_BYTES,
};
use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use futures_util::StreamExt;
use llull_buzz_wire::{canonical, id, parse, sha256, Evidence, MAX_BYTES};
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
/// BUD-11 read authorization is exact-hash scoped; no host-wide `server` tag.
fn attachment_auth(
    key: &nostr::Keys,
    evidence: &Evidence,
) -> std::result::Result<String, PortError> {
    llull_buzz_wire::hash(&evidence.sha256).map_err(|_| PortError)?;
    id(&evidence.media_type).map_err(|_| PortError)?;
    if evidence.size_bytes > MAX_ATTACHMENT_BYTES as u64 {
        return Err(PortError);
    }
    let expiration = (nostr::Timestamp::now().as_secs() + 30).to_string();
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(24242), "Read original attachment")
        .tags([
            nostr::Tag::parse(["t", "get"]).map_err(|_| PortError)?,
            nostr::Tag::parse(["x", &evidence.sha256]).map_err(|_| PortError)?,
            nostr::Tag::parse(["expiration", &expiration]).map_err(|_| PortError)?,
        ])
        .sign_with_keys(key)
        .map_err(|_| PortError)?;
    Ok(format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).map_err(|_| PortError)?)
    ))
}
#[async_trait]
impl NativeAttachmentSource for HttpNativeOrigin {
    fn attachment_owner(&self) -> &str {
        &self.owner
    }
    async fn attachment(
        &self,
        community: &str,
        evidence: &Evidence,
    ) -> std::result::Result<Vec<u8>, PortError> {
        if community != self.community {
            return Err(PortError);
        }
        let authorization = attachment_auth(&self.key, evidence)?;
        // Only the configured private origin and validated hash choose this URL.
        // In particular, the original signed imeta URL is not a fetch instruction.
        let url = self
            .private_origin
            .join(&format!("/media/{}", evidence.sha256))
            .map_err(|_| PortError)?;
        let host = &self.public_origin[url::Position::BeforeHost..url::Position::AfterPort];
        let response = self
            .client
            .get(url)
            .header("Host", host)
            .header("Authorization", authorization)
            .send()
            .await
            .map_err(|_| PortError)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length != evidence.size_bytes)
            || response.headers().contains_key("content-range")
            || response
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                != Some(evidence.media_type.as_str())
        {
            return Err(PortError);
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| PortError)?;
            if bytes.len().saturating_add(chunk.len()) > evidence.size_bytes as usize {
                return Err(PortError);
            }
            bytes.extend_from_slice(&chunk);
        }
        crate::attachments::validate_bytes(evidence, &bytes).map_err(|_| PortError)?;
        Ok(bytes)
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
                            let member = roster_member(fields)?;
                            if !members.insert(member.to_owned()) {
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
/// The pinned relay emits ["p", pubkey, "", role]. A future role or external
/// relay address changes audience meaning and must fail closed at release.
fn roster_member(fields: &[String]) -> std::result::Result<&str, PortError> {
    if fields.len() != 4
        || fields[0] != "p"
        || !fields[2].is_empty()
        || !matches!(
            fields[3].as_str(),
            "owner" | "admin" | "member" | "guest" | "bot"
        )
    {
        return Err(PortError);
    }
    llull_buzz_wire::hash(&fields[1]).map_err(|_| PortError)?;
    Ok(&fields[1])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_token_is_signed_short_lived_and_exact_hash_only() {
        let key = nostr::Keys::generate();
        let mut evidence = Evidence {
            source_id: "source".into(),
            sha256: sha256(b"original"),
            media_type: "image/png".into(),
            size_bytes: 8,
            release_ref: "release".into(),
        };
        let header = attachment_auth(&key, &evidence).unwrap();
        let bytes = URL_SAFE_NO_PAD
            .decode(header.strip_prefix("Nostr ").unwrap())
            .unwrap();
        let event = native::event(&bytes).unwrap();
        assert_eq!(event.kind.as_u16(), 24242);
        assert_eq!(event.pubkey, key.public_key());
        assert_eq!(event.tags.len(), 3);
        assert_eq!(native::tag(&event, "t").unwrap(), "get");
        assert_eq!(native::tag(&event, "x").unwrap(), evidence.sha256);
        let expires = native::tag(&event, "expiration")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!((event.created_at.as_secs()..=event.created_at.as_secs() + 30).contains(&expires));
        assert!(!event
            .tags
            .iter()
            .any(|t| t.as_slice().first().is_some_and(|s| s == "server")));
        evidence.sha256 = "../foreign".into();
        assert!(attachment_auth(&key, &evidence).is_err());
        evidence.sha256 = sha256(b"original");
        evidence.size_bytes = MAX_ATTACHMENT_BYTES as u64 + 1;
        assert!(attachment_auth(&key, &evidence).is_err());
    }
    #[tokio::test]
    async fn attachment_fixed_origin_rejects_redirect_mime_length_and_digest_substitution() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (status, mime, body, extra, accepted) in [
            ("200 OK", "image/png", "original", "", true),
            (
                "302 Found",
                "image/png",
                "original",
                "Location: https://foreign.invalid/media\r\n",
                false,
            ),
            ("200 OK", "text/html", "original", "", false),
            ("200 OK", "image/png", "changed!", "", false),
            ("200 OK", "image/png", "short", "", false),
            (
                "206 Partial Content",
                "image/png",
                "original",
                "Content-Range: bytes 0-7/8\r\n",
                false,
            ),
            (
                "200 OK",
                "image/png",
                "original",
                "Content-Range: bytes 0-7/8\r\n",
                false,
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let evidence = Evidence {
                source_id: "source".into(),
                sha256: sha256(b"original"),
                media_type: "image/png".into(),
                size_bytes: 8,
                release_ref: "release".into(),
            };
            let expected_hash = evidence.sha256.clone();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 16384);
                    request.push(socket.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with(&format!("GET /media/{expected_hash} HTTP/1.1\r\n")));
                assert!(request
                    .to_ascii_lowercase()
                    .contains("host: native.synthetic.invalid:18443\r\n"));
                let auth = request
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization: "))
                    .unwrap()
                    .split_once(": ")
                    .unwrap()
                    .1;
                let event = native::event(
                    &URL_SAFE_NO_PAD
                        .decode(auth.strip_prefix("Nostr ").unwrap())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(native::tag(&event, "x").unwrap(), expected_hash);
                assert_eq!(native::tag(&event, "t").unwrap(), "get");
                let reply=format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {mime}\r\n{extra}Connection: close\r\n\r\n{body}",body.len());
                socket.write_all(reply.as_bytes()).await.unwrap();
            });
            let source = HttpNativeOrigin::new(
                "community".into(),
                &format!("http://{address}/"),
                "https://native.synthetic.invalid:18443/",
                nostr::Keys::generate(),
                nostr::Keys::generate().public_key(),
            )
            .unwrap();
            assert!(source.attachment("foreign", &evidence).await.is_err());
            assert_eq!(
                source.attachment("community", &evidence).await.is_ok(),
                accepted
            );
            server.await.unwrap();
        }
    }
    #[test]
    fn roster_member_requires_the_pinned_relay_shape() {
        let key = "a".repeat(64);
        for role in ["owner", "admin", "member", "guest", "bot"] {
            let fields = vec!["p".into(), key.clone(), "".into(), role.into()];
            assert_eq!(roster_member(&fields).unwrap(), key);
        }
        for fields in [
            vec![
                "p".into(),
                key.clone(),
                "https://elsewhere.invalid".into(),
                "member".into(),
            ],
            vec!["p".into(), key.clone(), "".into(), "pending".into()],
            vec![
                "p".into(),
                key.clone(),
                "".into(),
                "member".into(),
                "extra".into(),
            ],
            vec!["p".into(), "not-a-key".into(), "".into(), "member".into()],
        ] {
            assert!(roster_member(&fields).is_err());
        }
    }
}
