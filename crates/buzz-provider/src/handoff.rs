//! Current human navigation into the pinned native client. No business effect,
//! publication, authentication grant, task, or callback is created by this read.
use crate::{
    auth::{self, Claims, Headers},
    native, Binding, Provider, PublicationPort, Result,
};
use llull_buzz_wire::{hash, id, Command, Fault, Resource};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHandoffTarget {
    pub community_id: String,
    pub channel_id: String,
    pub audience_revision: String,
    pub event_id: Option<String>,
}

impl NativeHandoffTarget {
    fn validate(&self) -> Result<()> {
        id(&self.community_id)?;
        id(&self.audience_revision)?;
        let channel = uuid::Uuid::parse_str(&self.channel_id).map_err(|_| Fault::Invalid)?;
        // Exact intersection of the selected desktop and mobile route parsers.
        if channel.to_string() != self.channel_id || channel.get_variant() != uuid::Variant::RFC4122
        {
            return Err(Fault::Invalid.into());
        }
        if let Some(event) = &self.event_id {
            hash(event)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHandoff {
    pub format: String,
    pub consumer_id: String,
    pub intent_id: String,
    pub module_id: String,
    pub context_domain: String,
    pub resource: Resource,
    pub enrollment_id: String,
    pub enrollment_revision: u64,
    pub native_key: String,
    pub community_id: String,
    pub channel_id: String,
    pub audience_revision: String,
    pub event_id: Option<String>,
    pub thread_root_id: Option<String>,
    pub native_uri: String,
    pub verified_until: i64,
    pub registration_revision: u64,
    pub policy_revision: String,
    pub recovery_epoch: u64,
}

fn browser_deadline(claims: &Claims, binding: &Binding, now: i64) -> Result<i64> {
    let browser = claims.native_handoff_browser(now)?;
    if browser.issuer != binding.issuer || browser.subject != binding.subject {
        return Err(Fault::Denied.into());
    }
    let deadline = claims
        .exp
        .min(browser.expires_at)
        .min(browser.authenticated_at + 60);
    if deadline <= now {
        return Err(Fault::Denied.into());
    }
    Ok(deadline)
}

async fn message<P: PublicationPort>(
    port: &P,
    target: &NativeHandoffTarget,
    identity: &str,
) -> Result<nostr::Event> {
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        port.event(&target.community_id, &target.channel_id, identity),
    )
    .await
    .map_err(|_| Fault::Unknown)?
    .map_err(|_| Fault::Unknown)?;
    let event = native::event(&bytes)?;
    if event.id.to_hex() != identity
        || event.kind.as_u16() as u32 != buzz_core::kind::KIND_STREAM_MESSAGE
        || native::tag(&event, "h")? != target.channel_id
    {
        return Err(Fault::Denied.into());
    }
    Ok(event)
}

impl Provider {
    pub async fn native_handoff<P: PublicationPort>(
        &self,
        body: &[u8],
        headers: Headers<'_>,
        port: &P,
    ) -> Result<NativeHandoff> {
        let command: Command = Self::decode(body)?;
        if command.operation != "read-native-handoff" {
            return Err(Fault::Unavailable.into());
        }
        let target: NativeHandoffTarget = command.payload()?;
        // Option must still be an explicit null/string in this versioned shape.
        if !command
            .payload
            .as_object()
            .is_some_and(|p| p.contains_key("event_id"))
        {
            return Err(Fault::Invalid.into());
        }
        target.validate()?;
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &command,
                &auth::SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/native-handoffs",
                None,
                auth::INVOCATION,
            )
            .await?;
        let binding = self
            .scope(&mut tx, &registration, &claims)
            .await?
            .ok_or(Fault::Denied)?;
        if target.community_id != registration.community_id
            || !registration.modules[&claims.module_id]
                .principal_issuers
                .contains(&binding.issuer)
        {
            return Err(Fault::Denied.into());
        }
        browser_deadline(&claims, &binding, Self::now(&mut tx).await?.timestamp())?;
        let thread_root_id = if let Some(identity) = &target.event_id {
            let event = message(port, &target, identity).await?;
            let root = buzz_core::nip10::parse_thread_markers(&event.tags)
                .resolve()
                .map(|(root, _)| root);
            match root {
                Some(root) if root != *identity => {
                    hash(&root)?;
                    message(port, &target, &root).await?;
                    Some(root)
                }
                _ => None,
            }
        } else {
            None
        };
        // Last native read is the existing fixed owner's signed roster. A link
        // never overrides the client's own authenticated relay/key or access.
        let audience = tokio::time::timeout(
            Duration::from_secs(5),
            port.audience(&target.community_id, &target.channel_id),
        )
        .await
        .map_err(|_| Fault::Unknown)?
        .map_err(|_| Fault::Unknown)?;
        if audience.community_id != target.community_id
            || audience.channel_id != target.channel_id
            || audience.revision != target.audience_revision
            || !audience.members.contains(&binding.native_key)
        {
            return Err(Fault::Denied.into());
        }
        for member in &audience.members {
            hash(member)?;
        }
        let native_uri = match &target.event_id {
            None => format!("buzz://channel/{}", target.channel_id),
            Some(event) => format!(
                "buzz://message?channel={}&id={}{}",
                target.channel_id,
                event,
                thread_root_id
                    .as_ref()
                    .map(|root| format!("&thread={root}"))
                    .unwrap_or_default()
            ),
        };
        let current = self
            .scope(&mut tx, &registration, &claims)
            .await?
            .ok_or(Fault::Denied)?;
        let now = Self::now(&mut tx).await?.timestamp();
        claims.fresh(now)?;
        let verified_until = browser_deadline(&claims, &current, now)?;
        let result = NativeHandoff {
            format: "llull-buzz-native-handoff/v1".into(),
            consumer_id: command.consumer_id,
            intent_id: command.intent_id,
            module_id: claims.module_id,
            context_domain: claims.context_domain,
            resource: command.resource,
            enrollment_id: current.enrollment_id,
            enrollment_revision: current.revision as u64,
            native_key: current.native_key,
            community_id: target.community_id,
            channel_id: target.channel_id,
            audience_revision: audience.revision,
            event_id: target.event_id,
            thread_root_id,
            native_uri,
            verified_until,
            registration_revision: registration.revision,
            policy_revision: registration.policy_revision,
            recovery_epoch: claims.recovery_epoch,
        };
        // Repeated intent IDs still perform every current check. No mutation
        // receipt can replay a former navigation permission or start an effect.
        tx.commit().await?;
        Ok(result)
    }
}
