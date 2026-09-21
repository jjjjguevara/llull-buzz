//! Independently registered resource authentication and exact ES256 evidence.
//! Only the registered issuer can attest consumer policy; no token key discovery.
use crate::native;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use llull_buzz_wire::{digest, hash, id, parse, Fault, Resource, MAX_SAFE_INTEGER};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const INVOCATION: &str = "llull-invocation+jwt";
pub const PUBLICATION: &str = "llull-publication+jwt";
pub const EVIDENCE: &str = "llull-evidence+jwt";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub consumer_id: String,
    pub revision: u64,
    pub policy_revision: String,
    pub authority_epoch: u64,
    pub community_id: String,
    pub service_principal: String,
    pub service_public_key: String,
    pub issuer: String,
    pub audiences: BTreeMap<String, String>,
    /// Admitted ES256 public PEMs keyed by exact kid. Never a token-derived URL.
    pub verification_keys: BTreeMap<String, String>,
    pub enrollment_bot_key: String,
    pub enrollment_channel: String,
    pub modules: BTreeMap<String, ModulePolicy>,
    pub retention: Retention,
    pub pricing: Option<crate::budget::Pricing>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub task_days: u32,
    pub publication_days: u32,
    pub audit_days: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModulePolicy {
    pub actions: BTreeSet<String>,
    pub principal_issuers: BTreeSet<String>,
    pub context_domains: BTreeSet<String>,
    pub task_schemas: BTreeSet<String>,
    pub tools: BTreeMap<String, ToolPolicy>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    pub action: String,
    pub schema_sha256: String,
    pub effect_owner: String,
    pub requires_verdict: bool,
}
impl Registration {
    pub fn validate(&self) -> std::result::Result<(), Fault> {
        for s in [
            &self.consumer_id,
            &self.policy_revision,
            &self.community_id,
            &self.service_principal,
            &self.enrollment_channel,
        ] {
            id(s)?;
        }
        hash(&self.service_public_key)?;
        hash(&self.enrollment_bot_key)?;
        if self.revision == 0
            || self.revision > MAX_SAFE_INTEGER as u64
            || self.authority_epoch == 0
            || self.authority_epoch > MAX_SAFE_INTEGER as u64
            || self.modules.is_empty()
            || self.verification_keys.is_empty()
            || self.verification_keys.len() > 16
            || self.modules.len() > 128
            || self.retention.task_days == 0
            || self.retention.publication_days == 0
            || self.retention.audit_days == 0
        {
            return Err(Fault::Invalid);
        }
        https_origin(&self.issuer)?;
        for purpose in [INVOCATION, PUBLICATION, EVIDENCE] {
            https_origin(self.audiences.get(purpose).ok_or(Fault::Invalid)?)?;
        }
        if self.audiences.len() != 3 {
            return Err(Fault::Invalid);
        }
        for (kid, pem) in &self.verification_keys {
            id(kid)?;
            if pem.len() > 8192 || pem.contains("PRIVATE KEY") {
                return Err(Fault::Invalid);
            }
            DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|_| Fault::Invalid)?;
        }
        for (name, module) in &self.modules {
            id(name)?;
            if module.actions.is_empty()
                || module.context_domains.is_empty()
                || module.principal_issuers.is_empty()
            {
                return Err(Fault::Invalid);
            }
            for s in module
                .actions
                .iter()
                .chain(module.context_domains.iter())
                .chain(module.task_schemas.iter())
            {
                id(s)?;
            }
            for issuer in &module.principal_issuers {
                https_origin(issuer)?;
            }
            for (schema, tool) in &module.tools {
                id(schema)?;
                id(&tool.action)?;
                id(&tool.effect_owner)?;
                hash(&tool.schema_sha256)?;
                if !module.actions.contains(&tool.action) {
                    return Err(Fault::Invalid);
                }
            }
        }
        if let Some(pricing) = &self.pricing {
            pricing.validate()?;
        }
        Ok(())
    }
}

pub fn https_origin(s: &str) -> std::result::Result<(), Fault> {
    let u = url::Url::parse(s).map_err(|_| Fault::Invalid)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || u.query().is_some()
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.path() != "/"
    {
        return Err(Fault::Invalid);
    }
    // Preserve the registered spelling; comparisons below are exact strings.
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserAuthentication {
    pub issuer: String,
    pub subject: String,
    pub transaction_id: String,
    pub authenticated_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub reference: String,
    pub operation: String,
    pub resource: Resource,
    pub payload_sha256: String,
    pub decision: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub release_ref: String,
    pub community_id: String,
    pub channel_id: String,
    pub audience_policy: String,
    pub audience_revision: String,
    /// Hash of the whole canonical Publication, including text, metadata, copy mode and attachments.
    pub publication_sha256: String,
    pub checked_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub consumer_id: String,
    pub intent_id: String,
    pub operation: String,
    pub resource: Resource,
    pub resource_revision: String,
    pub payload_sha256: String,
    pub policy_revision: String,
    pub authority_epoch: u64,
    pub recovery_epoch: u64,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub module_id: String,
    pub context_domain: String,
    pub authority_checked_at: i64,
    pub registration_revision: u64,
    pub enrollment_id: Option<String>,
    pub enrollment_revision: Option<u64>,
    pub represented_principal: Option<String>,
    pub delegation_id: Option<String>,
    pub root_task_id: Option<String>,
    pub grant_revision: Option<String>,
    pub browser_authentication: Option<BrowserAuthentication>,
    pub verdicts: Vec<Verdict>,
    pub release: Option<Release>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// This type cannot be built by a caller or a model. Every admission also checks
/// the current database epoch/binding after it obtains the transaction lock.
pub(crate) struct Verified {
    pub(crate) claims: Claims,
    pub(crate) native_event_id: nostr::EventId,
}

pub struct Headers<'a> {
    pub authorization: &'a str,
    pub invocation: &'a str,
}
/// Keep the authentication evidence paired with the exact received body bytes.
pub(crate) struct SignedRequest<'a> {
    pub headers: &'a Headers<'a>,
    pub body: &'a [u8],
}
pub(crate) struct Target<'a> {
    pub consumer: &'a str,
    pub intent: &'a str,
    pub operation: &'a str,
    pub resource: &'a Resource,
    pub fingerprint: &'a str,
    pub root: Option<&'a str>,
}

pub(crate) fn verify(
    registration: &Registration,
    request: &SignedRequest<'_>,
    purpose: &str,
    public_url: &str,
    method: &str,
    target: &Target<'_>,
    now: i64,
) -> std::result::Result<Verified, Fault> {
    let (headers, body) = (request.headers, request.body);
    if headers.authorization.len() > 64_000 || headers.invocation.len() > 64_000 {
        return Err(Fault::TooLarge);
    }
    let encoded = headers
        .authorization
        .strip_prefix("Nostr ")
        .ok_or(Fault::Denied)?;
    let event_bytes = STANDARD.decode(encoded).map_err(|_| Fault::Denied)?;
    let event = native::event(&event_bytes)?;
    let json = std::str::from_utf8(&event_bytes).map_err(|_| Fault::Denied)?;
    // The upstream shared verifier intentionally permits absent payload tags.
    // This provider does not: even a GET signs SHA256(empty bytes).
    if native::tag(&event, "payload")? != llull_buzz_wire::sha256(body)
        || native::tag(&event, "u")? != public_url
        || native::tag(&event, "method")? != method
    {
        return Err(Fault::Denied);
    }
    let key = buzz_auth::verify_nip98_event(json, public_url, method, Some(body))
        .map_err(|_| Fault::Denied)?;
    if key.to_hex() != registration.service_public_key {
        return Err(Fault::Denied);
    }
    let claims = verify_assertion(registration, headers.invocation, purpose, target, now)?;
    Ok(Verified {
        claims,
        native_event_id: event.id,
    })
}

pub(crate) fn verify_assertion(
    registration: &Registration,
    token: &str,
    purpose: &str,
    target: &Target<'_>,
    now: i64,
) -> std::result::Result<Claims, Fault> {
    let pieces: Vec<_> = token.split('.').collect();
    if pieces.len() != 3 || pieces.iter().any(|p| p.is_empty()) {
        return Err(Fault::Denied);
    }
    let header: Header = parse(
        &URL_SAFE_NO_PAD
            .decode(pieces[0])
            .map_err(|_| Fault::Denied)?,
    )
    .map_err(|_| Fault::Denied)?;
    if header.alg != "ES256" || header.typ != purpose {
        return Err(Fault::Denied);
    }
    let pem = registration
        .verification_keys
        .get(&header.kid)
        .ok_or(Fault::Denied)?;
    let audience = registration.audiences.get(purpose).ok_or(Fault::Denied)?;
    // Decode strictly before the library can collapse duplicate claims. The
    // cryptographic library independently verifies these very same bytes.
    let _: Claims = parse(
        &URL_SAFE_NO_PAD
            .decode(pieces[1])
            .map_err(|_| Fault::Denied)?,
    )
    .map_err(|_| Fault::Denied)?;
    let mut policy = Validation::new(Algorithm::ES256);
    policy.set_audience(&[audience]);
    policy.set_issuer(&[&registration.issuer]);
    // Database time is the admission clock; own checks below are stricter than
    // default expiry leeway and are repeated after every potentially slow wait.
    policy.validate_exp = false;
    policy.validate_nbf = false;
    policy.leeway = 0;
    let key = DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|_| Fault::Denied)?;
    let c = jsonwebtoken::decode::<Claims>(token, &key, &policy)
        .map_err(|_| Fault::Denied)?
        .claims;
    c.fresh(now)?;
    let module = registration
        .modules
        .get(&c.module_id)
        .ok_or(Fault::Denied)?;
    if c.iss != registration.issuer
        || c.aud != *audience
        || c.sub != registration.service_principal
        || c.consumer_id != registration.consumer_id
        || c.consumer_id != target.consumer
        || c.intent_id != target.intent
        || c.operation != target.operation
        || c.resource != *target.resource
        || c.resource_revision != target.resource.revision
        || c.payload_sha256 != target.fingerprint
        || c.policy_revision != registration.policy_revision
        || c.registration_revision != registration.revision
        || !module.actions.contains(target.operation)
        || !module.context_domains.contains(&c.context_domain)
        || target
            .root
            .is_some_and(|r| c.root_task_id.as_deref() != Some(r))
    {
        return Err(Fault::Denied);
    }
    c.resource.validate(&registration.consumer_id)?;
    if c.represented_principal.is_some()
        && (c.delegation_id.is_none() || c.grant_revision.is_none() || c.root_task_id.is_none())
    {
        return Err(Fault::Denied);
    }
    if c.verdicts.len() > 32 {
        return Err(Fault::Denied);
    }
    let mut references = BTreeSet::new();
    for v in &c.verdicts {
        if !references.insert(&v.reference)
            || v.decision != "approved"
            || v.operation != c.operation
            || v.resource != c.resource
            || v.payload_sha256 != c.payload_sha256
        {
            return Err(Fault::Denied);
        }
        id(&v.reference)?;
    }
    Ok(c)
}
impl Claims {
    pub(crate) fn fresh(&self, now: i64) -> std::result::Result<(), Fault> {
        if !(0..=MAX_SAFE_INTEGER).contains(&now)
            || self.iat < 0
            || self.exp <= self.iat
            || self.exp - self.iat > 60
            || self.iat > now + 30
            || self.exp <= now
            || self.authority_checked_at < 0
            || self.authority_checked_at > now
            || now - self.authority_checked_at >= 60
            || self.exp > self.authority_checked_at + 60
        {
            return Err(Fault::Denied);
        }
        for s in [&self.jti, &self.sub, &self.module_id, &self.context_domain] {
            id(s)?;
        }
        hash(&self.payload_sha256)?;
        Ok(())
    }
    pub(crate) fn browser(
        &self,
        initial: bool,
        now: i64,
    ) -> std::result::Result<&BrowserAuthentication, Fault> {
        let b = self.browser_authentication.as_ref().ok_or(Fault::Denied)?;
        if b.authenticated_at < 0
            || b.authenticated_at > now
            || b.expires_at <= now
            || b.expires_at <= b.authenticated_at
            || b.expires_at - b.authenticated_at > 300
            || (initial && now - b.authenticated_at > 60)
        {
            return Err(Fault::Denied);
        }
        id(&b.subject)?;
        id(&b.transaction_id)?;
        Ok(b)
    }
    pub(crate) fn release_for(
        &self,
        p: &llull_buzz_wire::Publication,
        now: i64,
    ) -> std::result::Result<(), Fault> {
        let r = self.release.as_ref().ok_or(Fault::Denied)?;
        if r.release_ref != p.release_ref
            || r.community_id != p.community_id
            || r.channel_id != p.channel_id
            || r.audience_policy != p.audience_policy
            || r.audience_revision != p.audience_revision
            || r.publication_sha256 != digest(p)?
            || r.checked_at > now
            || r.checked_at < 0
            || now - r.checked_at >= 30
        {
            return Err(Fault::Denied);
        }
        Ok(())
    }
}
