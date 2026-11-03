//! Fixed native-owner directory for the limited enrollment client surface.
//!
//! Every returned native event retains its original owner signature. This view
//! does not create a profile, channel, membership, invitation or native grant.
//! The intended native identity must already belong to the configured native
//! enrollment channel; a browser challenge cannot manufacture that prerequisite.
use crate::{native, ports::PortError};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use llull_buzz_wire::{canonical, hash, id, parse, Fault, MAX_SAFE_INTEGER};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(crate) const ENROLLMENT_MAX_FRAME_BYTES: usize = 65_536;
pub(crate) const ENROLLMENT_MAX_WS_FILTERS: usize = 8;
pub(crate) const ENROLLMENT_MAX_HTTP_FILTERS: usize = 16;
pub(crate) const ENROLLMENT_MAX_FRAMES: usize = 64;
pub(crate) const ENROLLMENT_ADMISSION_SECONDS: i64 = 30;

/// A fresh, successful observation of the fixed owner's complete restricted
/// member list. This is not a membership grant or an owner-signed native event.
/// Private restriction rows/reasons never enter the directory or wire response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEnrollmentAdmissionCheck {
    pub kind: String,
    pub community_id: String,
    pub intended_public_key: String,
    pub moderation_endpoint: String,
    pub request_event_id: String,
    pub response_sha256: String,
    pub checked_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

impl NativeEnrollmentAdmissionCheck {
    pub(crate) fn validate(
        &self,
        community: &str,
        intended: &str,
        now: DateTime<Utc>,
    ) -> std::result::Result<(), Fault> {
        if self.kind != "llull-buzz-native-enrollment-admission/v1"
            || self.community_id != community
            || self.intended_public_key != intended
            || self.checked_at > now
            || self.valid_until <= now
            || self.valid_until <= self.checked_at
            || self.valid_until
                > self.checked_at + ChronoDuration::seconds(ENROLLMENT_ADMISSION_SECONDS)
        {
            return Err(Fault::Denied);
        }
        hash(&self.intended_public_key)?;
        hash(&self.request_event_id)?;
        hash(&self.response_sha256)?;
        let url = url::Url::parse(&self.moderation_endpoint).map_err(|_| Fault::Invalid)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/moderation/restricted"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Fault::Denied);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRestriction {
    pubkey: String,
    banned: bool,
    ban_expires_at: Option<DateTime<Utc>>,
    ban_reason: Option<String>,
    muted_until: Option<DateTime<Utc>>,
    mute_reason: Option<String>,
    actor_pubkey: String,
    updated_at: DateTime<Utc>,
}

/// The selected native endpoint is a complete, unpaginated array. Missing,
/// duplicate, changed or malformed fields are unavailable authority, never an
/// empty successful observation. Any matching row denies admission; the native
/// owner already selects active bans/timeouts and owns expiry interpretation.
pub(crate) fn admit_native_restrictions(
    bytes: &[u8],
    intended: &str,
) -> std::result::Result<(), Fault> {
    hash(intended)?;
    let values: Vec<Value> = parse(bytes)?;
    let fields = [
        "pubkey",
        "banned",
        "ban_expires_at",
        "ban_reason",
        "muted_until",
        "mute_reason",
        "actor_pubkey",
        "updated_at",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut restricted = false;
    for value in values {
        let object = value.as_object().ok_or(Fault::Invalid)?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != fields {
            return Err(Fault::Invalid);
        }
        let row: NativeRestriction = parse(&canonical(&value)?)?;
        hash(&row.pubkey)?;
        hash(&row.actor_pubkey)?;
        if !seen.insert(row.pubkey.clone()) {
            return Err(Fault::Invalid);
        }
        // Retain no private reason or moderator record after closed parsing.
        let _checked_native_fields = (
            row.banned,
            row.ban_expires_at,
            row.ban_reason,
            row.muted_until,
            row.mute_reason,
            row.updated_at,
        );
        if row.pubkey == intended {
            restricted = true;
        }
    }
    if restricted {
        Err(Fault::Denied)
    } else {
        Ok(())
    }
}

/// The only native-origin arguments are trusted enrollment target identities.
/// Wire query filters and URLs never cross this port.
#[async_trait]
pub trait EnrollmentDirectoryPort: Send + Sync {
    async fn enrollment_directory(
        &self,
        community: &str,
        channel: &str,
        intended_key: &str,
        bot: &str,
    ) -> std::result::Result<NativeEnrollmentView, PortError>;
}

/// Original signed directory records plus the fixed owner's public descriptor
/// and optional policy response. The latter are original public HTTP documents,
/// not signed native events or proof that a user accepted any terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEnrollmentView {
    pub community_id: String,
    pub channel_id: String,
    pub intended_public_key: String,
    pub bot_public_key: String,
    pub relay_public_key: String,
    pub channel_metadata: Value,
    pub channel_membership: Value,
    /// Up to two existing self-signed profiles. Native channel membership does
    /// not require either person to publish optional profile metadata.
    pub profiles: Vec<Value>,
    pub relay_information: Value,
    pub relay_membership: Option<Value>,
    pub join_policy: Option<Value>,
    pub admission_check: NativeEnrollmentAdmissionCheck,
}

fn verified(value: &Value) -> std::result::Result<nostr::Event, Fault> {
    native::event(&canonical(value)?)
}

// This public policy response is larger than the command parser's 1MiB bound.
// Its pinned closed shape rejects duplicate/unknown fields before retaining the
// original JSON value. No command/authentication parser limit is changed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicPolicyDocument {
    policy: Option<PublicPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicPolicy {
    terms_markdown: Option<String>,
    privacy_markdown: Option<String>,
    age_attestation_required: bool,
    version: String,
}

pub(crate) fn parse_native_join_policy(bytes: &[u8]) -> std::result::Result<Value, Fault> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(Fault::TooLarge);
    }
    let document: PublicPolicyDocument =
        serde_json::from_slice(bytes).map_err(|_| Fault::Invalid)?;
    if let Some(policy) = document.policy {
        if policy.version.is_empty()
            || [policy.terms_markdown, policy.privacy_markdown]
                .into_iter()
                .flatten()
                .any(|text| text.len() > 256 * 1024)
        {
            return Err(Fault::Invalid);
        }
        let _age_attestation_required = policy.age_attestation_required;
    }
    serde_json::from_slice(bytes).map_err(|_| Fault::Invalid)
}

fn roster_members(event: &nostr::Event) -> std::result::Result<BTreeSet<String>, Fault> {
    let mut members = BTreeSet::new();
    for tag in event.tags.iter() {
        let fields = tag.as_slice();
        if fields.first().is_some_and(|field| field == "p") {
            if fields.len() != 4
                || !fields[2].is_empty()
                || !matches!(
                    fields[3].as_str(),
                    "owner" | "admin" | "member" | "guest" | "bot"
                )
                || !members.insert(fields[1].clone())
            {
                return Err(Fault::Denied);
            }
            hash(&fields[1])?;
        }
    }
    Ok(members)
}

fn relay_members(event: &nostr::Event) -> std::result::Result<BTreeSet<String>, Fault> {
    let mut members = BTreeSet::new();
    for tag in event.tags.iter() {
        let fields = tag.as_slice();
        let member = match fields.first().map(String::as_str) {
            Some("member") => {
                if !matches!(fields.len(), 2 | 3)
                    || fields
                        .get(2)
                        .is_some_and(|role| !matches!(role.as_str(), "owner" | "admin" | "member"))
                {
                    return Err(Fault::Denied);
                }
                Some(&fields[1])
            }
            Some("p") => {
                if fields.len() != 4
                    || !fields[2].is_empty()
                    || !matches!(fields[3].as_str(), "owner" | "admin" | "member")
                {
                    return Err(Fault::Denied);
                }
                Some(&fields[1])
            }
            _ => None,
        };
        if let Some(member) = member {
            hash(member)?;
            if !members.insert(member.clone()) {
                return Err(Fault::Denied);
            }
        }
    }
    Ok(members)
}

impl NativeEnrollmentView {
    /// This declaration describes the limited gateway, rather than forwarding
    /// the native owner's broader capabilities as if they were mounted here.
    /// The unchanged public owner document remains separately named provenance;
    /// original cryptographically signed events are never rewritten.
    pub fn gateway_information(&self) -> std::result::Result<Value, Fault> {
        self.validate()?;
        let has_membership = self.relay_membership.is_some();
        let mut nips = vec![1, 11, 42, 98];
        if has_membership {
            nips.insert(3, 43);
        }
        let mut document = json!({
            "name":"Buzz enrollment gateway",
            "description":"Authenticated pending-enrollment directory and exact challenge messages; one-shot reads only.",
            "self":self.relay_public_key,
            "supported_nips":nips,
            "limitation":{
                "max_message_length":ENROLLMENT_MAX_FRAME_BYTES,
                "max_filters":ENROLLMENT_MAX_WS_FILTERS,
                "max_subscriptions":0,
                "auth_required":true,
                "restricted_writes":true
            },
            "enrollment_gateway":{
                "format":"llull-buzz-enrollment-gateway/v1",
                "scope":"registered-pending-enrollment",
                "read_mode":"one-shot",
                "persistent_subscriptions":false,
                "max_frames_per_connection":ENROLLMENT_MAX_FRAMES,
                "http_query_max_filters":ENROLLMENT_MAX_HTTP_FILTERS,
                "max_query_response_bytes":ENROLLMENT_MAX_FRAME_BYTES,
                "publication":"exact-original-challenge-only",
                "native_membership":if has_membership {"original-owner-read-only-required"} else {"original-channel-membership-required"},
                "channel_join":false,
                "channel_management":false,
                "membership_administration":false,
                "general_publication":false,
                "media":false,
                "gifs":false,
                "push":false,
                "pairing":if self.relay_information.get("pairing_relay_url").is_some() {"explicit-native-owner-relay-only"} else {"unavailable"},
                "native_owner_document":"provenance-only"
            },
            "native_owner":self.relay_information
        });
        // Preserve the actual native owner's public identity fields required by
        // clients. Never inherit its general software/capability declarations.
        for name in ["pubkey", "contact", "icon"] {
            if let Some(value) = self.relay_information.get(name) {
                document[name] = value.clone();
            }
        }
        // A separately advertised real pairing owner may retain its supported
        // encrypted journey. Absence never invents /pair or a permissive relay.
        if let Some(pairing) = self.relay_information.get("pairing_relay_url") {
            document["pairing_relay_url"] = pairing.clone();
        }
        Ok(document)
    }

    /// Recheck every original signature and the existing native membership.
    /// A source adapter cannot turn its service read privilege into membership
    /// for the intended human or return another channel's directory records.
    pub fn validate(&self) -> std::result::Result<(), Fault> {
        self.admission_check
            .validate(&self.community_id, &self.intended_public_key, Utc::now())?;
        id(&self.community_id)?;
        let channel = uuid::Uuid::parse_str(&self.channel_id).map_err(|_| Fault::Invalid)?;
        if channel.to_string() != self.channel_id
            || channel.get_variant() != uuid::Variant::RFC4122
            || self.intended_public_key == self.bot_public_key
        {
            return Err(Fault::Denied);
        }
        for key in [
            &self.intended_public_key,
            &self.bot_public_key,
            &self.relay_public_key,
        ] {
            hash(key)?;
        }
        let metadata = verified(&self.channel_metadata)?;
        let roster = verified(&self.channel_membership)?;
        if metadata.kind.as_u16() != 39000
            || roster.kind.as_u16() != 39002
            || metadata.pubkey.to_hex() != self.relay_public_key
            || roster.pubkey.to_hex() != self.relay_public_key
            || native::tag(&metadata, "d")? != self.channel_id
            || native::tag(&roster, "d")? != self.channel_id
            || metadata
                .tags
                .iter()
                .any(|tag| tag.as_slice() == ["archived", "true"])
            || metadata.tags.iter().any(|tag| {
                let fields = tag.as_slice();
                fields.first().is_some_and(|field| field == "t")
                    && (fields.len() != 2 || !matches!(fields[1].as_str(), "stream" | "dm"))
            })
        {
            return Err(Fault::Denied);
        }
        let members = roster_members(&roster)?;
        if !members.contains(&self.intended_public_key) || !members.contains(&self.bot_public_key) {
            return Err(Fault::Denied);
        }
        if self.profiles.len() > 2 {
            return Err(Fault::Denied);
        }
        let mut profiles = BTreeSet::new();
        for value in &self.profiles {
            let profile = verified(value)?;
            let key = profile.pubkey.to_hex();
            if profile.kind.as_u16() != 0
                || ![&self.intended_public_key, &self.bot_public_key].contains(&&key)
                || !profiles.insert(key)
                || !parse::<Value>(profile.content.as_bytes())?.is_object()
            {
                return Err(Fault::Denied);
            }
        }
        let descriptor = self.relay_information.as_object().ok_or(Fault::Invalid)?;
        if descriptor.get("self").and_then(Value::as_str) != Some(self.relay_public_key.as_str()) {
            return Err(Fault::Denied);
        }
        let supported_nips = descriptor
            .get("supported_nips")
            .and_then(Value::as_array)
            .ok_or(Fault::Invalid)?;
        let mut seen = BTreeSet::new();
        for nip in supported_nips {
            let number = nip
                .as_u64()
                .filter(|number| *number <= MAX_SAFE_INTEGER as u64)
                .ok_or(Fault::Invalid)?;
            if !seen.insert(number) {
                return Err(Fault::Invalid);
            }
        }
        if let Some(pairing) = descriptor.get("pairing_relay_url") {
            let pairing = pairing.as_str().ok_or(Fault::Invalid)?;
            let url = url::Url::parse(pairing).map_err(|_| Fault::Invalid)?;
            if url.scheme() != "wss"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(Fault::Denied);
            }
        }
        match (seen.contains(&43), &self.relay_membership) {
            (true, Some(value)) => {
                let membership = verified(value)?;
                if membership.kind.as_u16() != 13534
                    || membership.pubkey.to_hex() != self.relay_public_key
                    || !relay_members(&membership)?.contains(&self.intended_public_key)
                {
                    return Err(Fault::Denied);
                }
            }
            (false, None) => {}
            _ => return Err(Fault::Denied),
        }
        if let Some(document) = &self.join_policy {
            let document = document.as_object().ok_or(Fault::Invalid)?;
            if let Some(policy) = document.get("policy").filter(|policy| !policy.is_null()) {
                let policy = policy.as_object().ok_or(Fault::Invalid)?;
                if policy
                    .get("age_attestation_required")
                    .and_then(Value::as_bool)
                    .is_none()
                    || policy
                        .get("version")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                    || ["terms_markdown", "privacy_markdown"].iter().any(|name| {
                        policy
                            .get(*name)
                            .is_some_and(|text| !text.is_null() && !text.is_string())
                    })
                {
                    return Err(Fault::Invalid);
                }
            }
        }
        Ok(())
    }

    /// The selected clients serialize visible mentions as `@display_name `.
    /// A configured simple token must resolve to this exact original bot profile;
    /// neither a registration nickname nor a browser assertion can invent it.
    pub fn validate_bot_mention(&self, mention: &str) -> std::result::Result<(), Fault> {
        self.validate()?;
        let label = mention.strip_prefix('@').ok_or(Fault::Invalid)?;
        if label.is_empty()
            || label.len() > 64
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Fault::Invalid);
        }
        let profile = self
            .profiles
            .iter()
            .find(|value| value["pubkey"] == self.bot_public_key)
            .ok_or(Fault::Denied)?;
        let content: Value = parse(
            profile["content"]
                .as_str()
                .ok_or(Fault::Invalid)?
                .as_bytes(),
        )?;
        let effective = content
            .get("display_name")
            .filter(|name| !name.is_null())
            .or_else(|| content.get("name"));
        if effective.and_then(Value::as_str) != Some(label) {
            return Err(Fault::Denied);
        }
        Ok(())
    }

    /// Project a native HTTP query or a WS REQ's filter array from this fixed
    /// authorized view. Nothing in a filter is forwarded to the native owner.
    /// Only the caller's already retained exact kind-9 message may supplement
    /// metadata; the route owns its original challenge/body/deadline checks.
    pub fn query(
        &self,
        filters: &Value,
        own_challenge: Option<&Value>,
    ) -> std::result::Result<Vec<Value>, Fault> {
        self.validate()?;
        let mut available = vec![
            self.channel_metadata.clone(),
            self.channel_membership.clone(),
        ];
        available.extend(self.profiles.iter().cloned());
        if let Some(membership) = &self.relay_membership {
            available.push(membership.clone());
        }
        if let Some(value) = own_challenge {
            let event = verified(value)?;
            if event.kind.as_u16() != 9
                || event.pubkey.to_hex() != self.intended_public_key
                || native::tag(&event, "h")? != self.channel_id
                || native::tag(&event, "p")? != self.bot_public_key
            {
                return Err(Fault::Denied);
            }
            available.push(value.clone());
        }
        let filters = filters.as_array().ok_or(Fault::Invalid)?;
        // A bounded filter list is a resource guard, not a native query proxy.
        if filters.is_empty() || filters.len() > ENROLLMENT_MAX_HTTP_FILTERS {
            return Err(Fault::TooLarge);
        }
        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        for value in filters {
            let filter: EnrollmentFilter = parse(&canonical(value)?)?;
            filter.validate(self)?;
            let mut matches = available
                .iter()
                .filter(|value| filter.matches(value))
                .collect::<Vec<_>>();
            matches.sort_by(|left, right| {
                right["created_at"]
                    .as_u64()
                    .cmp(&left["created_at"].as_u64())
                    .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
            });
            let limit = filter.limit.unwrap_or(500) as usize;
            let start = (filter.page.unwrap_or(1).saturating_sub(1) as usize).saturating_mul(limit);
            for value in matches.into_iter().skip(start).take(limit) {
                if seen.insert(value["id"].as_str().ok_or(Fault::Invalid)?.to_owned()) {
                    result.push(value.clone());
                }
            }
        }
        Ok(result)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentFilter {
    #[serde(default)]
    kinds: Vec<u16>,
    ids: Option<Vec<String>>,
    authors: Option<Vec<String>>,
    #[serde(rename = "#d")]
    coordinates: Option<Vec<String>>,
    #[serde(rename = "#h")]
    channels: Option<Vec<String>>,
    #[serde(rename = "#p")]
    principals: Option<Vec<String>>,
    #[serde(rename = "#t")]
    channel_types: Option<Vec<String>>,
    since: Option<u64>,
    until: Option<u64>,
    before_id: Option<String>,
    limit: Option<u64>,
    search: Option<String>,
    search_mode: Option<String>,
    page: Option<u64>,
}

impl EnrollmentFilter {
    fn validate(&self, view: &NativeEnrollmentView) -> std::result::Result<(), Fault> {
        if (self.kinds.is_empty() && self.ids.is_none())
            || self.kinds.len() > 32
            || self.kinds.iter().collect::<BTreeSet<_>>().len() != self.kinds.len()
            || [self.since, self.until, self.limit, self.page]
                .into_iter()
                .flatten()
                .any(|number| number > MAX_SAFE_INTEGER as u64)
            || self.page == Some(0)
            || self
                .search
                .as_ref()
                .is_some_and(|search| search.len() > 256)
            || self
                .search_mode
                .as_deref()
                .is_some_and(|mode| mode != "prefix")
            || (self.search_mode.is_some() && self.search.is_none())
            || (self.search.is_some() && self.kinds != [0])
        {
            return Err(Fault::Invalid);
        }
        let channel_scoped = self.channels.is_some();
        let directory = self
            .kinds
            .iter()
            .all(|kind| matches!(*kind, 0 | 39000 | 39002 | 13534));
        // These personal snapshots have no records in an enrollment-only view.
        // Correctly return EOSE/[] so ordinary clients can finish their channel
        // bootstrap without exposing general DM, preference or presence data.
        let personal_empty = self.kinds.iter().all(|kind| matches!(*kind, 30622 | 20001));
        if !directory && !channel_scoped && !(personal_empty && self.principals.is_some()) {
            return Err(Fault::Denied);
        }
        for values in [&self.coordinates, &self.channels].into_iter().flatten() {
            if values.is_empty() || values.len() != 1 || values[0] != view.channel_id {
                return Err(Fault::Denied);
            }
        }
        if let Some(authors) = &self.authors {
            let native_members = roster_members(&verified(&view.channel_membership)?)?;
            if authors.is_empty()
                || authors.len() > 128
                || authors.iter().any(|author| {
                    hash(author).is_err()
                        || (author != &view.relay_public_key && !native_members.contains(author))
                })
            {
                return Err(Fault::Denied);
            }
        }
        if let Some(principals) = &self.principals {
            if principals.is_empty()
                || principals.len() > 2
                || principals
                    .iter()
                    .any(|key| key != &view.intended_public_key && key != &view.bot_public_key)
            {
                return Err(Fault::Denied);
            }
        }
        if let Some(types) = &self.channel_types {
            if types.is_empty()
                || types
                    .iter()
                    .any(|kind| !matches!(kind.as_str(), "stream" | "dm"))
            {
                return Err(Fault::Denied);
            }
        }
        if self.kinds.contains(&39002) && self.coordinates.is_none() && self.principals.is_none() {
            return Err(Fault::Denied);
        }
        if let Some(ids) = &self.ids {
            if ids.is_empty() || ids.len() > 8 || ids.iter().any(|value| hash(value).is_err()) {
                return Err(Fault::Denied);
            }
            // Exact ids only; unavailable ids do not fetch or disclose another
            // event. Other supplied scope fields must still name this view.
        }
        if let Some(before) = &self.before_id {
            hash(before)?;
            if self.until.is_none() {
                return Err(Fault::Invalid);
            }
        }
        Ok(())
    }

    fn matches(&self, event: &Value) -> bool {
        let Some(kind) = event["kind"].as_u64() else {
            return false;
        };
        let Some(created) = event["created_at"].as_u64() else {
            return false;
        };
        let Some(identity) = event["id"].as_str() else {
            return false;
        };
        if (!self.kinds.is_empty() && !self.kinds.contains(&(kind as u16)))
            || self
                .ids
                .as_ref()
                .is_some_and(|ids| !ids.iter().any(|value| value == identity))
            || self
                .authors
                .as_ref()
                .is_some_and(|keys| !keys.iter().any(|value| event["pubkey"] == *value))
            || self.since.is_some_and(|since| created < since)
            || self.until.is_some_and(|until| created > until)
            || self
                .before_id
                .as_ref()
                .is_some_and(|before| self.until == Some(created) && identity <= before.as_str())
        {
            return false;
        }
        for (name, values) in [
            ("d", &self.coordinates),
            ("h", &self.channels),
            ("p", &self.principals),
            ("t", &self.channel_types),
        ] {
            if let Some(values) = values {
                let matches = event["tags"].as_array().is_some_and(|tags| {
                    tags.iter().any(|tag| {
                        tag[0] == name
                            && tag[1].as_str().is_some_and(|value| {
                                values.iter().any(|requested| requested == value)
                            })
                    })
                });
                if !matches {
                    return false;
                }
            }
        }
        if let Some(search) = &self.search {
            let Some(content) = event["content"].as_str() else {
                return false;
            };
            let Ok(profile) = parse::<Value>(content.as_bytes()) else {
                return false;
            };
            let needle = search.to_lowercase();
            let matches = ["display_name", "name", "nip05"].iter().any(|field| {
                profile[*field].as_str().is_some_and(|text| {
                    let text = text.to_lowercase();
                    if self.search_mode.as_deref() == Some("prefix") {
                        text.split_whitespace()
                            .any(|word| word.starts_with(&needle))
                    } else {
                        text.contains(&needle)
                    }
                })
            });
            if !matches {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
#[path = "enrollment_directory_tests.rs"]
mod tests;
