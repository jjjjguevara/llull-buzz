//! Separate private ES256 operator purpose. Existing public purpose/audience rules stay intact.
use super::{clock::Budget, deny, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const PROFILE_PURPOSE: &str = "llull-buzz-inspection-profile+jwt";
pub const REQUEST_PURPOSE: &str = "llull-buzz-inspection-request+jwt";
pub const RESPONSE_PURPOSE: &str = "llull-buzz-inspection-response+jwt";
pub const AUDIENCE: &str = "llull-buzz-private-local-inspection/v1";
pub const INSPECTOR: &str = "buzz_recovery_inspector";
pub const VIEW_OWNER: &str = "buzz_recovery_view_owner";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicKey {
    pub kid: String,
    pub pem: String,
    pub pem_sha256: String,
    pub thumbprint: String,
}
impl PublicKey {
    fn key(&self) -> Result<DecodingKey> {
        llull_buzz_wire::id(&self.kid).map_err(|_| deny("key_identity"))?;
        if self.pem.len() > 8192
            || self.pem.contains("PRIVATE KEY")
            || llull_buzz_wire::sha256(self.pem.as_bytes()) != self.pem_sha256
        {
            return Err(deny("key_identity"));
        }
        let key = DecodingKey::from_ec_pem(self.pem.as_bytes()).map_err(|_| deny("key_format"))?;
        if key_thumbprint(&key)? != self.thumbprint {
            return Err(deny("key_thumbprint"));
        }
        Ok(key)
    }
}
// RFC7638 EC public thumbprint, derived from the selected genuine PEM decoder.
// No production p256 dependency or caller-provided verifier/point factory.
fn key_thumbprint(key: &DecodingKey) -> Result<String> {
    let point = key.as_bytes();
    if point.len() != 65 || point.first() != Some(&4) {
        return Err(deny("key_curve"));
    }
    let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&point[33..]);
    let jwk = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x, y);
    let hex = llull_buzz_wire::sha256(jwk.as_bytes());
    let bytes = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| deny("key_thumbprint_encoding"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trust {
    pub v: u8,
    pub issuer: String,
    pub subject: String,
    pub source_revision: String,
    pub generation: u64,
    pub root_key: PublicKey,
    pub profile_sha256: String,
    pub implementation_sha256: String,
    pub observed_us: i64,
    pub expires_us: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signed<T> {
    pub v: u8,
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub purpose: String,
    pub source_revision: String,
    pub generation: u64,
    pub observed_us: i64,
    pub expires_us: i64,
    pub body: T,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Database {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub database_oid: u32,
    pub inspector_oid: u32,
    pub view_owner_oid: u32,
    pub server_address: String,
    pub server_version_num: i32,
    pub ssl_root_sha256: String,
    pub schema_manifest_sha256: String,
    pub view_definition_sha256: BTreeMap<String, String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Member {
    pub consumer_id: String,
    pub registration_sha256: String,
    pub modules: Vec<String>,
    pub service_principal: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub installation: String,
    pub request_key: PublicKey,
    pub response_key: PublicKey,
    pub database: Database,
    pub implementation_sha256: String,
    pub members: Vec<Member>,
    pub membership_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_standing: Option<super::standing::StandingProfile>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub installation: String,
    pub membership_sha256: String,
    pub operation_ref: String,
    pub operation_sha256: String,
    pub configuration_sha256: String,
    pub configuration_generation: u64,
    pub source_copy_sha256: String,
    pub target_copy_sha256: String,
    pub controller: String,
    pub run: String,
    pub recovery_epoch: u64,
    pub challenge: String,
    pub basis_ref: String,
    pub basis_sha256: String,
    pub deadline_us: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedHeader {
    alg: String,
    typ: String,
    kid: String,
}
fn fresh(observed: i64, expires: i64, now: i64) -> Result<()> {
    if observed < 0 || observed > now || now >= expires {
        return Err(deny("proof_freshness"));
    }
    Ok(())
}
fn verify<T: DeserializeOwned>(raw: &[u8], key: &PublicKey, purpose: &str) -> Result<Signed<T>> {
    if raw.len() > llull_buzz_wire::MAX_BYTES || !raw.is_ascii() {
        return Err(deny("jws_encoding"));
    }
    let token = std::str::from_utf8(raw).map_err(|_| deny("jws_encoding"))?;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(deny("jws_encoding"));
    }
    let header = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| deny("jws_encoding"))?;
    let h: ClosedHeader = llull_buzz_wire::parse(&header).map_err(|_| deny("jws_header"))?;
    if h.alg != "ES256" || h.typ != purpose || h.kid != key.kid {
        return Err(deny("jws_key_or_purpose"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| deny("jws_encoding"))?;
    // Public control records retain the selected duplicate/safe-number parser.
    let _: Signed<T> = llull_buzz_wire::parse(&payload).map_err(|_| deny("jws_payload"))?;
    let mut v = Validation::new(Algorithm::ES256);
    v.required_spec_claims.clear();
    v.validate_exp = false;
    v.validate_nbf = false;
    v.validate_aud = false;
    let signed = jsonwebtoken::decode::<Signed<T>>(token, &key.key()?, &v)
        .map_err(|_| deny("jws_signature"))?
        .claims;
    if signed.v != 1 || signed.aud != AUDIENCE || signed.purpose != purpose {
        return Err(deny("jws_binding"));
    }
    Ok(signed)
}
/// Fields are private: no caller-created authenticated descriptor or mutable key buffer.
pub(crate) struct Authenticated {
    trust: Trust,
    profile: Signed<Profile>,
    request: Signed<Request>,
    request_sha256: String,
    profile_sha256: String,
}
impl Authenticated {
    pub(crate) fn admit(
        trust_raw: &[u8],
        profile_raw: &[u8],
        request_raw: &[u8],
        budget: &mut Budget,
        now: i64,
    ) -> Result<Self> {
        let trust: Trust = llull_buzz_wire::parse(trust_raw).map_err(|_| deny("trust_file"))?;
        if trust.v != 1
            || trust.generation == 0
            || trust.source_revision.len() != 40
            || !trust
                .source_revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || trust.implementation_sha256 != super::relations::implementation_sha256()
        {
            return Err(deny("trust_binding"));
        }
        fresh(trust.observed_us, trust.expires_us, budget.sample(now)?)?;
        let profile_sha256 = llull_buzz_wire::sha256(profile_raw);
        if profile_sha256 != trust.profile_sha256 {
            return Err(deny("profile_bytes"));
        }
        let profile: Signed<Profile> = verify(profile_raw, &trust.root_key, PROFILE_PURPOSE)?;
        if profile.iss != trust.issuer
            || profile.sub != trust.subject
            || profile.source_revision != trust.source_revision
            || profile.generation != trust.generation
            || profile.body.implementation_sha256 != trust.implementation_sha256
        {
            return Err(deny("profile_binding"));
        }
        profile.body.request_key.key()?;
        profile.body.response_key.key()?;
        let key_ids = [
            &trust.root_key.kid,
            &profile.body.request_key.kid,
            &profile.body.response_key.kid,
        ];
        let key_pins = [
            &trust.root_key.thumbprint,
            &profile.body.request_key.thumbprint,
            &profile.body.response_key.thumbprint,
        ];
        if key_ids.into_iter().collect::<BTreeSet<_>>().len() != 3
            || key_pins.into_iter().collect::<BTreeSet<_>>().len() != 3
        {
            return Err(deny("inspection_key_separation"));
        }
        let request: Signed<Request> =
            verify(request_raw, &profile.body.request_key, REQUEST_PURPOSE)?;
        if request.iss != trust.issuer
            || request.sub != trust.subject
            || request.source_revision != trust.source_revision
            || request.generation != trust.generation
            || request.body.installation != profile.body.installation
            || request.body.membership_sha256 != profile.body.membership_sha256
            || request.body.configuration_generation == 0
            || request.body.recovery_epoch == 0
        {
            return Err(deny("request_binding"));
        }
        let mut consumers = BTreeSet::new();
        // A genuinely signed empty configured scope is lawful metadata. Its
        // receipt remains PARTIAL; it never supplies missing external standing.
        for m in &profile.body.members {
            if !consumers.insert(&m.consumer_id)
                || m.modules.is_empty()
                || m.modules.iter().collect::<BTreeSet<_>>().len() != m.modules.len()
            {
                return Err(deny("configured_membership"));
            }
            for id in std::iter::once(&m.consumer_id)
                .chain(std::iter::once(&m.service_principal))
                .chain(m.modules.iter())
            {
                llull_buzz_wire::id(id).map_err(|_| deny("configured_membership"))?;
            }
            llull_buzz_wire::hash(&m.registration_sha256)
                .map_err(|_| deny("configured_membership"))?;
        }
        // Static membership is acyclic and has no original operation/copy/challenge ref.
        if llull_buzz_wire::sha256(
            &serde_json::to_vec(&profile.body.members).map_err(|_| deny("membership_encoding"))?,
        ) != profile.body.membership_sha256
        {
            return Err(deny("membership_bytes"));
        }
        if profile.body.database.view_definition_sha256.len() != super::relations::RELATIONS.len() {
            return Err(deny("view_scope"));
        }
        for r in super::relations::RELATIONS {
            llull_buzz_wire::hash(
                profile
                    .body
                    .database
                    .view_definition_sha256
                    .get(r.name)
                    .ok_or_else(|| deny("view_scope"))?,
            )
            .map_err(|_| deny("view_scope"))?;
        }
        for h in [
            &request.body.operation_sha256,
            &request.body.configuration_sha256,
            &request.body.source_copy_sha256,
            &request.body.target_copy_sha256,
            &request.body.basis_sha256,
            &request.body.challenge,
            &profile.body.database.schema_manifest_sha256,
            &profile.body.database.ssl_root_sha256,
        ] {
            llull_buzz_wire::hash(h).map_err(|_| deny("request_identity"))?;
        }
        for id in [
            &trust.issuer,
            &trust.subject,
            &profile.body.installation,
            &request.body.operation_ref,
            &request.body.controller,
            &request.body.run,
            &request.body.basis_ref,
            &profile.body.database.database,
        ] {
            llull_buzz_wire::id(id).map_err(|_| deny("request_identity"))?;
        }
        if profile.body.database.port == 0
            || profile.body.database.inspector_oid == profile.body.database.view_owner_oid
            || profile.body.database.server_version_num < 160000
        {
            return Err(deny("database_binding"));
        }
        for expires in [
            trust.expires_us,
            profile.expires_us,
            request.expires_us,
            request.body.deadline_us,
        ] {
            budget.constrain(expires)?;
        }
        let request_sha256 = llull_buzz_wire::sha256(request_raw);
        let auth = Self {
            trust,
            profile,
            request,
            request_sha256,
            profile_sha256,
        };
        // Final scalar freshness follows genuine hashing, key import, signatures
        // and descriptor construction; none of that work follows this sample.
        auth.current(budget.sample(super::clock::now())?)?;
        if let Some(standing) = &auth.profile.body.native_standing {
            standing.authenticate(&auth)?;
        }
        Ok(auth)
    }
    pub(crate) fn current(&self, now: i64) -> Result<()> {
        for (observed, expires) in [
            (self.trust.observed_us, self.trust.expires_us),
            (self.profile.observed_us, self.profile.expires_us),
            (self.request.observed_us, self.request.expires_us),
        ] {
            fresh(observed, expires, now)?;
        }
        if now >= self.request.body.deadline_us {
            return Err(deny("request_deadline"));
        }
        Ok(())
    }
    pub(crate) fn profile(&self) -> &Profile {
        &self.profile.body
    }
    pub(crate) fn request(&self) -> &Request {
        &self.request.body
    }
    pub(crate) fn expires(&self) -> i64 {
        [
            self.trust.expires_us,
            self.profile.expires_us,
            self.request.expires_us,
            self.request.body.deadline_us,
        ]
        .into_iter()
        .min()
        .unwrap_or(0)
    }
    pub(crate) fn generation(&self) -> u64 {
        self.trust.generation
    }
    pub(crate) fn source_revision(&self) -> &str {
        &self.trust.source_revision
    }
    pub(crate) fn request_hash(&self) -> &str {
        &self.request_sha256
    }
    pub(crate) fn profile_hash(&self) -> &str {
        &self.profile_sha256
    }
    pub(crate) fn verify_response(&self, raw: &[u8], body_sha256: &str, now: i64) -> Result<()> {
        let signed: Signed<serde_json::Value> =
            verify(raw, &self.profile.body.response_key, RESPONSE_PURPOSE)?;
        self.current(now)?;
        fresh(signed.observed_us, signed.expires_us, now)?;
        if signed.iss != self.trust.issuer
            || signed.sub != self.trust.subject
            || signed.source_revision != self.trust.source_revision
            || signed.generation != self.trust.generation
            || signed.expires_us > self.expires()
            || llull_buzz_wire::sha256(
                &serde_json::to_vec(&signed.body).map_err(|_| deny("response_body"))?,
            ) != body_sha256
        {
            return Err(deny("response_original_binding"));
        }
        Ok(())
    }
    pub(crate) fn sign<T: Serialize + DeserializeOwned>(
        &self,
        body: T,
        private_key: &[u8],
        observed: i64,
        expires: i64,
    ) -> Result<Vec<u8>> {
        self.current(observed)?;
        if expires > self.expires() || expires <= observed {
            return Err(deny("response_lifetime"));
        }
        let claims = Signed {
            v: 1,
            iss: self.trust.issuer.clone(),
            sub: self.trust.subject.clone(),
            aud: AUDIENCE.into(),
            purpose: RESPONSE_PURPOSE.into(),
            source_revision: self.trust.source_revision.clone(),
            generation: self.trust.generation,
            observed_us: observed,
            expires_us: expires,
            body,
        };
        let mut h = Header::new(Algorithm::ES256);
        h.typ = Some(RESPONSE_PURPOSE.into());
        h.kid = Some(self.profile.body.response_key.kid.clone());
        let key = EncodingKey::from_ec_pem(private_key).map_err(|_| deny("response_key"))?;
        let signed =
            jsonwebtoken::encode(&h, &claims, &key).map_err(|_| deny("response_signature"))?;
        // The actual key used must verify under the separately authenticated public key.
        let _: Signed<T> = verify(
            signed.as_bytes(),
            &self.profile.body.response_key,
            RESPONSE_PURPOSE,
        )?;
        Ok(signed.into_bytes())
    }
}

#[cfg(test)]
pub(super) fn synthetic_port_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) {
    tests::port_inputs()
}

#[cfg(test)]
pub(super) fn synthetic_native_standing_inputs(
    native: super::standing::StandingProfile,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) {
    tests::native_standing_inputs(native)
}
#[cfg(test)]
pub(super) fn synthetic_database() -> Database {
    tests::complete_database()
}
#[cfg(test)]
pub(super) fn synthetic_complete_inputs(
    count: usize,
    schema: &[u8],
    certificate: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) {
    tests::complete_inputs(count, schema, certificate)
}
#[cfg(test)]
pub(super) fn synthetic_changed_request(raw: &[u8], key: &str) -> Vec<u8> {
    tests::changed_request(raw, key)
}
#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        SecretKey,
    };
    struct Fixture {
        trust: Vec<u8>,
        profile: Vec<u8>,
        request: Vec<u8>,
        response_key: String,
        request_key: String,
        now: i64,
    }
    fn keys(seed: u8, kid: &str) -> (PublicKey, String) {
        // Public deterministic synthetic fixture scalars; never production key material.
        let private = SecretKey::from_slice(&[seed; 32]).unwrap();
        let pem = private
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        (
            PublicKey {
                kid: kid.into(),
                pem_sha256: llull_buzz_wire::sha256(pem.as_bytes()),
                thumbprint: key_thumbprint(&DecodingKey::from_ec_pem(pem.as_bytes()).unwrap())
                    .unwrap(),
                pem,
            },
            private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
        )
    }
    fn token<T: Serialize>(body: T, key: &str, kid: &str, purpose: &str, now: i64) -> Vec<u8> {
        let claims = Signed {
            v: 1,
            iss: "operator".into(),
            sub: "inspection".into(),
            aud: AUDIENCE.into(),
            purpose: purpose.into(),
            source_revision: "b244ba7560112e498ee6d68a48d035c99cb0b8c2".into(),
            generation: 1,
            observed_us: now,
            expires_us: now + 30_000_000,
            body,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(purpose.into());
        header.kid = Some(kid.into());
        jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(key.as_bytes()).unwrap(),
        )
        .unwrap()
        .into_bytes()
    }
    fn fixture() -> Fixture {
        fixture_count(1)
    }
    fn fixture_count(count: usize) -> Fixture {
        let now = super::super::clock::now();
        let (root, root_key) = keys(1, "root");
        let (request_public, request_key) = keys(2, "request");
        let (response_public, response_key) = keys(3, "response");
        let members = (0..count)
            .map(|index| Member {
                consumer_id: if count == 1 {
                    "consumer-a".into()
                } else {
                    format!("consumer-{index:04}")
                },
                registration_sha256: "a".repeat(64),
                modules: vec!["module-a".into()],
                service_principal: "principal-a".into(),
            })
            .collect::<Vec<_>>();
        let membership_sha256 = llull_buzz_wire::sha256(&serde_json::to_vec(&members).unwrap());
        let profile = Profile {
            installation: "test-installation".into(),
            request_key: request_public,
            response_key: response_public,
            database: Database {
                host: "127.0.0.1".into(),
                port: 5432,
                database: "synthetic-test".into(),
                database_oid: 11,
                inspector_oid: 12,
                view_owner_oid: 13,
                server_address: "127.0.0.1".into(),
                server_version_num: 160000,
                ssl_root_sha256: "b".repeat(64),
                schema_manifest_sha256: "c".repeat(64),
                view_definition_sha256: super::super::relations::RELATIONS
                    .iter()
                    .map(|r| (r.name.into(), "d".repeat(64)))
                    .collect(),
            },
            implementation_sha256: super::super::relations::implementation_sha256(),
            members,
            membership_sha256: membership_sha256.clone(),
            native_standing: None,
        };
        let profile = token(profile, &root_key, "root", PROFILE_PURPOSE, now);
        let trust = serde_json::to_vec(&Trust {
            v: 1,
            issuer: "operator".into(),
            subject: "inspection".into(),
            source_revision: "b244ba7560112e498ee6d68a48d035c99cb0b8c2".into(),
            generation: 1,
            root_key: root,
            profile_sha256: llull_buzz_wire::sha256(&profile),
            implementation_sha256: super::super::relations::implementation_sha256(),
            observed_us: now,
            expires_us: now + 30_000_000,
        })
        .unwrap();
        let request = token(
            Request {
                installation: "test-installation".into(),
                membership_sha256,
                operation_ref: "operation-a".into(),
                operation_sha256: "e".repeat(64),
                configuration_sha256: "f".repeat(64),
                configuration_generation: 1,
                source_copy_sha256: "1".repeat(64),
                target_copy_sha256: "2".repeat(64),
                controller: "controller-a".into(),
                run: "run-a".into(),
                recovery_epoch: 1,
                challenge: "3".repeat(64),
                basis_ref: "basis-a".into(),
                basis_sha256: "4".repeat(64),
                deadline_us: now + 25_000_000,
            },
            &request_key,
            "request",
            REQUEST_PURPOSE,
            now,
        );
        Fixture {
            trust,
            profile,
            request,
            response_key,
            request_key,
            now,
        }
    }
    pub(super) fn port_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) {
        let f = fixture();
        (
            f.trust,
            f.profile,
            f.request,
            f.response_key.into_bytes(),
            f.now,
        )
    }
    pub(super) fn native_standing_inputs(
        native: super::super::standing::StandingProfile,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) {
        let mut f = fixture();
        let mut profile = verify::<Profile>(&f.profile, &keys(1, "root").0, PROFILE_PURPOSE)
            .unwrap()
            .body;
        profile.native_standing = Some(native);
        f.profile = token(profile, &keys(1, "root").1, "root", PROFILE_PURPOSE, f.now);
        let mut trust: Trust = llull_buzz_wire::parse(&f.trust).unwrap();
        trust.profile_sha256 = llull_buzz_wire::sha256(&f.profile);
        f.trust = serde_json::to_vec(&trust).unwrap();
        (
            f.trust,
            f.profile,
            f.request,
            f.response_key.into_bytes(),
            f.now,
        )
    }
    pub(super) fn complete_database() -> Database {
        let f = fixture();
        verify::<Profile>(&f.profile, &keys(1, "root").0, PROFILE_PURPOSE)
            .unwrap()
            .body
            .database
    }
    pub(super) fn complete_inputs(
        count: usize,
        schema: &[u8],
        certificate: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) {
        let mut f = fixture_count(count);
        let mut profile = verify::<Profile>(&f.profile, &keys(1, "root").0, PROFILE_PURPOSE)
            .unwrap()
            .body;
        profile.database.schema_manifest_sha256 = llull_buzz_wire::sha256(schema);
        profile.database.ssl_root_sha256 = llull_buzz_wire::sha256(certificate);
        f.profile = token(profile, &keys(1, "root").1, "root", PROFILE_PURPOSE, f.now);
        let mut trust: Trust = llull_buzz_wire::parse(&f.trust).unwrap();
        trust.profile_sha256 = llull_buzz_wire::sha256(&f.profile);
        f.trust = serde_json::to_vec(&trust).unwrap();
        (
            f.trust,
            f.profile,
            f.request,
            f.response_key.into_bytes(),
            f.now,
        )
    }
    pub(super) fn changed_request(raw: &[u8], key: &str) -> Vec<u8> {
        let mut signed: Signed<serde_json::Value> =
            verify(raw, &keys(2, "request").0, REQUEST_PURPOSE).unwrap();
        match key {
            "subject" => signed.sub = "foreign-subject".into(),
            "source" => signed.source_revision = "0".repeat(40),
            "generation" => signed.generation += 1,
            "epoch" => signed.body["recovery_epoch"] = serde_json::json!(2),
            "config" => signed.body["configuration_sha256"] = serde_json::json!("0".repeat(64)),
            "source-copy" => signed.body["source_copy_sha256"] = serde_json::json!("0".repeat(64)),
            "target-copy" => signed.body["target_copy_sha256"] = serde_json::json!("0".repeat(64)),
            "challenge" => signed.body["challenge"] = serde_json::json!("0".repeat(64)),
            "operation" => signed.body["operation_sha256"] = serde_json::json!("0".repeat(64)),
            _ => panic!("unknown synthetic mutation"),
        }
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(REQUEST_PURPOSE.into());
        header.kid = Some("request".into());
        jsonwebtoken::encode(
            &header,
            &signed,
            &EncodingKey::from_ec_pem(keys(2, "request").1.as_bytes()).unwrap(),
        )
        .unwrap()
        .into_bytes()
    }
    #[test]
    fn genuine_separate_es256_profile_request_and_response() {
        let f = fixture();
        let mut budget = Budget::new(f.now, f.now + 30_000_000).unwrap();
        let auth =
            Authenticated::admit(&f.trust, &f.profile, &f.request, &mut budget, f.now).unwrap();
        let body = serde_json::json!({"standing":"PARTIAL","unresolved":super::super::UNRESOLVED});
        let signed = auth
            .sign(body.clone(), f.response_key.as_bytes(), f.now, f.now + 1000)
            .unwrap();
        let result: Signed<serde_json::Value> =
            verify(&signed, &auth.profile.body.response_key, RESPONSE_PURPOSE).unwrap();
        assert_eq!(result.body, body);
        assert_eq!(result.source_revision, auth.source_revision());
        assert!(auth
            .sign(body, f.request_key.as_bytes(), f.now, f.now + 1000)
            .is_err());
    }
    #[test]
    fn genuine_wrong_request_key_purpose_generation_and_expired_inputs_refuse() {
        let f = fixture();
        let original: Signed<Request> =
            verify(&f.request, &keys(2, "request").0, REQUEST_PURPOSE).unwrap();
        for (key, purpose) in [
            (&f.response_key, REQUEST_PURPOSE),
            (&f.request_key, RESPONSE_PURPOSE),
        ] {
            let raw = token(&original.body, key, "request", purpose, f.now);
            assert!(Authenticated::admit(
                &f.trust,
                &f.profile,
                &raw,
                &mut Budget::new(f.now, f.now + 30_000_000).unwrap(),
                f.now
            )
            .is_err());
        }
        let mut trust: Trust = llull_buzz_wire::parse(&f.trust).unwrap();
        trust.generation = 2;
        assert!(Authenticated::admit(
            &serde_json::to_vec(&trust).unwrap(),
            &f.profile,
            &f.request,
            &mut Budget::new(f.now, f.now + 30_000_000).unwrap(),
            f.now
        )
        .is_err());
        assert!(Authenticated::admit(
            &f.trust,
            &f.profile,
            &f.request,
            &mut Budget::new(f.now + 30_000_000, f.now + 40_000_000).unwrap(),
            f.now + 30_000_000
        )
        .is_err());
    }
    #[test]
    fn closed_duplicate_control_parser_and_response_binding_are_preserved() {
        let f = fixture();
        let mut trust = f.trust.clone();
        trust.insert(1, b' ');
        // Whitespace preserves bytes only for the trust file; profile is exact-byte bound.
        let auth = Authenticated::admit(
            &trust,
            &f.profile,
            &f.request,
            &mut Budget::new(f.now, f.now + 30_000_000).unwrap(),
            f.now,
        )
        .unwrap();
        let mut changed = f.profile.clone();
        changed.push(b' ');
        assert!(Authenticated::admit(
            &f.trust,
            &changed,
            &f.request,
            &mut Budget::new(f.now, f.now + 30_000_000).unwrap(),
            f.now
        )
        .is_err());
        let duplicate = br#"{"v":1,"v":1}"#;
        assert!(Authenticated::admit(
            duplicate,
            &f.profile,
            &f.request,
            &mut Budget::new(f.now, f.now + 30_000_000).unwrap(),
            f.now
        )
        .is_err());
        assert!(auth
            .sign(
                serde_json::json!({}),
                f.response_key.as_bytes(),
                f.now,
                f.now + 25_000_001
            )
            .is_err());
        assert!(auth.current(f.now + 25_000_000).is_err());
    }
    #[test]
    fn actual_p256_public_thumbprint_matches_independent_jcs_and_refuses_wrong_pin() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let private = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let point = private.public_key().to_encoded_point(false);
        let expected = BTreeMap::from([
            ("crv", "P-256".to_string()),
            ("kty", "EC".to_string()),
            ("x", URL_SAFE_NO_PAD.encode(point.x().unwrap())),
            ("y", URL_SAFE_NO_PAD.encode(point.y().unwrap())),
        ]);
        let digest = llull_buzz_wire::digest(&expected).unwrap();
        let bytes = digest
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let (mut public, _) = keys(4, "response");
        assert_eq!(public.thumbprint, URL_SAFE_NO_PAD.encode(bytes));
        assert!(public.key().is_ok());
        public.thumbprint = "a".repeat(43);
        assert!(public.key().is_err());
    }
    #[test]
    fn genuine_signed_full_static_scope_preserves_zero_201_1000_without_global_wire_changes() {
        for count in [0usize, 1, 201, 1000] {
            let f = fixture_count(count);
            let mut budget = Budget::new(f.now, f.now + 30_000_000).unwrap();
            let auth =
                Authenticated::admit(&f.trust, &f.profile, &f.request, &mut budget, f.now).unwrap();
            assert_eq!(auth.profile().members.len(), count);
            assert_eq!(llull_buzz_wire::MAX_BYTES, 1_048_576);
            assert_eq!(super::super::UNRESOLVED.len(), 4);
        }
    }

    #[test]
    fn genuine_persisted_response_verifier_binds_every_original_request_body_field() {
        let f = fixture();
        let mut budget = Budget::new(f.now, f.now + 30_000_000).unwrap();
        let auth =
            Authenticated::admit(&f.trust, &f.profile, &f.request, &mut budget, f.now).unwrap();
        let body = serde_json::to_value(auth.request()).unwrap();
        let expected = llull_buzz_wire::sha256(&serde_json::to_vec(&body).unwrap());
        let signed = auth
            .sign(
                body.clone(),
                f.response_key.as_bytes(),
                f.now,
                f.now + 10_000_000,
            )
            .unwrap();
        auth.verify_response(&signed, &expected, clock_now())
            .unwrap();
        for key in [
            "operation_sha256",
            "configuration_sha256",
            "source_copy_sha256",
            "target_copy_sha256",
            "challenge",
            "basis_sha256",
        ] {
            let mut changed = body.clone();
            changed[key] = serde_json::json!("0".repeat(64));
            let signed = auth
                .sign(
                    changed,
                    f.response_key.as_bytes(),
                    f.now,
                    f.now + 10_000_000,
                )
                .unwrap();
            assert!(
                auth.verify_response(&signed, &expected, clock_now())
                    .is_err(),
                "{key}"
            );
        }
        for key in ["recovery_epoch", "configuration_generation"] {
            let mut changed = body.clone();
            changed[key] = serde_json::json!(2);
            let signed = auth
                .sign(
                    changed,
                    f.response_key.as_bytes(),
                    f.now,
                    f.now + 10_000_000,
                )
                .unwrap();
            assert!(
                auth.verify_response(&signed, &expected, clock_now())
                    .is_err(),
                "{key}"
            );
        }
    }
    fn clock_now() -> i64 {
        super::super::clock::now()
    }
}
