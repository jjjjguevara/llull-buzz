//! Native GET/HEAD custody for a consumer's explicitly leased original bytes.
//! A Blossom proof identifies a key; only current EvidenceAccess authorizes bytes.
use crate::{
    attachments::validate_bytes,
    auth::{self, Claims, Headers, Registration, SignedRequest},
    db::Tx,
    native, Audience, Binding, CommandResult, Intake, Provider, PublicationPort, Result,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use llull_buzz_wire::{digest, hash, id, Command, Evidence, Execution, Fault};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{types::Json, Row};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAttachmentLease {
    pub source_id: Uuid,
    pub evidence: Evidence,
    pub enrollment_id: String,
    pub enrollment_revision: u64,
    pub audience_policy: String,
    pub audience_revision: String,
    pub release_ref: String,
    pub expires_at: DateTime<Utc>,
}

/// Uses the already configured fixed native owner; no model/caller URL is fetched.
pub struct NativeMedia<P: PublicationPort> {
    port: Arc<P>,
    authority: String,
    proof_authority: String,
}
impl<P: PublicationPort> NativeMedia<P> {
    pub fn new(port: Arc<P>, public_origin: &str) -> Result<Self> {
        auth::https_origin(public_origin)?;
        id(port.owner())?;
        let url = url::Url::parse(public_origin).map_err(|_| Fault::Invalid)?;
        let authority = url[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
        // Use the exact producer's normalization for BUD-11, while retaining
        // the full configured authority for the actual HTTP Host boundary.
        let proof_authority = buzz_core::tenant::relay_url_authority(public_origin);
        if proof_authority.is_empty() {
            return Err(Fault::Invalid.into());
        }
        Ok(Self {
            port,
            authority,
            proof_authority,
        })
    }
    async fn audience(&self, intake: &Intake, revision: &str, key: &str) -> Result<Audience> {
        let audience = tokio::time::timeout(
            Duration::from_secs(5),
            self.port.audience(&intake.community_id, &intake.channel_id),
        )
        .await
        .map_err(|_| Fault::Unknown)?
        .map_err(|_| Fault::Unknown)?;
        if audience.community_id != intake.community_id
            || audience.channel_id != intake.channel_id
            || audience.revision != revision
            || !audience.members.contains(key)
            || !audience.members.contains(&self.port.public_key().to_hex())
        {
            return Err(Fault::Denied.into());
        }
        for member in &audience.members {
            hash(member)?;
        }
        Ok(audience)
    }
}

/// Closed selected-client BUD-11 GET proof. No membership or release is inferred.
/// The CLI emits a server tag, while exact-hash callers may use x instead.
fn requester(authorization: &str, authority: &str, sha: &str, now: i64) -> Result<String> {
    hash(sha)?;
    if authorization.len() > 64_000 || now < 0 {
        return Err(Fault::Denied.into());
    }
    let encoded = authorization.strip_prefix("Nostr ").ok_or(Fault::Denied)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| Fault::Denied)?;
    let event = native::event(&bytes)?;
    let expiration: u64 = native::tag(&event, "expiration")?
        .parse()
        .map_err(|_| Fault::Denied)?;
    if event.kind.as_u16() != 24242
        || native::tag(&event, "t")? != "get"
        || event.content.trim().is_empty()
        || event.created_at.as_secs() > now as u64 + 5
        || event.created_at.as_secs().saturating_add(600) < now as u64
        || expiration <= now as u64
    {
        return Err(Fault::Denied.into());
    }
    let mut scope = false;
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        match parts.first().map(String::as_str) {
            Some("server") => {
                // Exact configured authority; never trust the request Host to pick it.
                if parts.len() != 2 || parts[1] != authority {
                    return Err(Fault::Denied.into());
                }
                scope = true;
            }
            Some("x") => {
                if parts.len() != 2 || parts[1] != sha {
                    return Err(Fault::Denied.into());
                }
                scope = true;
            }
            Some("t" | "expiration") => {}
            _ => return Err(Fault::Denied.into()),
        }
    }
    if !scope {
        return Err(Fault::Denied.into());
    }
    Ok(event.pubkey.to_hex())
}

fn binding_current(binding: &Binding, request: &NativeAttachmentLease, module: &str) -> Result<()> {
    if !binding.active
        || binding.key_retired
        || binding.module_id != module
        || binding.revision as u64 != request.enrollment_revision
    {
        return Err(Fault::Denied.into());
    }
    Ok(())
}
fn deadline(
    request: &NativeAttachmentLease,
    claims: &Claims,
    retained: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<()> {
    claims.fresh(now.timestamp())?;
    if request.expires_at <= now
        || request.expires_at > DateTime::from_timestamp(claims.exp, 0).ok_or(Fault::Denied)?
        || request.expires_at > retained
        || request.expires_at
            > DateTime::from_timestamp(claims.authority_checked_at + 60, 0).ok_or(Fault::Denied)?
    {
        return Err(Fault::Denied.into());
    }
    Ok(())
}

impl Provider {
    async fn media_source(
        tx: &mut Tx,
        consumer: &str,
        module: &str,
        context: &str,
        request: &NativeAttachmentLease,
        owner: &str,
    ) -> Result<(Intake, Vec<u8>, DateTime<Utc>)> {
        let row = sqlx::query("SELECT n.intake,n.intake_sha256,n.retain_until,a.evidence,a.bytes,a.origin_owner FROM native_attachments a JOIN native_inputs n USING(consumer_id,source_id) WHERE a.consumer_id=$1 AND a.source_id=$2 AND a.evidence_source_id=$3 AND n.module_id=$4 AND n.context_domain=$5")
            .bind(consumer).bind(request.source_id).bind(&request.evidence.source_id)
            .bind(module).bind(context).fetch_optional(&mut **tx).await?.ok_or(Fault::Denied)?;
        let intake = row.try_get::<Json<Intake>, _>("intake")?.0;
        let evidence = row.try_get::<Json<Evidence>, _>("evidence")?.0;
        let bytes = row.try_get::<Vec<u8>, _>("bytes")?;
        if evidence != request.evidence
            || !intake.evidence.contains(&evidence)
            || row.try_get::<String, _>("origin_owner")? != owner
            || digest(&intake)? != row.try_get::<String, _>("intake_sha256")?
        {
            return Err(Fault::Denied.into());
        }
        validate_bytes(&evidence, &bytes)?;
        Ok((intake, bytes, row.try_get("retain_until")?))
    }

    pub async fn lease_native_attachment<P: PublicationPort>(
        &self,
        body: &[u8],
        headers: Headers<'_>,
        media: &NativeMedia<P>,
    ) -> Result<CommandResult> {
        let command: Command = Self::decode(body)?;
        if command.operation != "lease-native-attachment" {
            return Err(Fault::Unavailable.into());
        }
        let request: NativeAttachmentLease = command.payload()?;
        for value in [
            &request.enrollment_id,
            &request.audience_policy,
            &request.audience_revision,
            &request.release_ref,
        ] {
            id(value)?;
        }
        hash(&request.evidence.sha256)?;
        if command.resource.reference
            != format!("{}/{}", request.source_id, request.evidence.sha256)
            || command.resource.revision != "1"
            || request.enrollment_revision == 0
            || request.enrollment_revision > llull_buzz_wire::MAX_SAFE_INTEGER as u64
        {
            return Err(Fault::Conflict.into());
        }
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &command,
                &SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/native-attachment-leases",
                None,
                auth::EVIDENCE,
            )
            .await?;
        // The registered issuer attests a permitted read for an existing binding.
        // This is not a delegated task, and does not manufacture a task grant.
        self.service_scope(&registration, &claims)?;
        let binding = Self::binding(&mut tx, &command.consumer_id, &request.enrollment_id).await?;
        binding_current(&binding, &request, &claims.module_id)?;
        let (intake, _, retained) = Self::media_source(
            &mut tx,
            &command.consumer_id,
            &claims.module_id,
            &claims.context_domain,
            &request,
            media.port.owner(),
        )
        .await?;
        if intake.community_id != registration.community_id {
            return Err(Fault::Denied.into());
        }
        deadline(&request, &claims, retained, Self::now(&mut tx).await?)?;
        media
            .audience(&intake, &request.audience_revision, &binding.native_key)
            .await?;
        deadline(&request, &claims, retained, Self::now(&mut tx).await?)?;
        if let Some(replay) = Self::replay(&mut tx, &command).await? {
            // A fresh transport assertion never extends the original lease.
            tx.commit().await?;
            return Ok(replay);
        }
        let lease_id = Uuid::new_v4();
        sqlx::query("INSERT INTO native_attachment_leases(lease_id,consumer_id,operation,intent_id,source_id,evidence_source_id,byte_sha256,enrollment_id,enrollment_revision,binding_epoch,native_key,module_id,context_domain,request,claims,owner,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)")
            .bind(lease_id).bind(&command.consumer_id).bind(&command.operation).bind(&command.intent_id)
            .bind(request.source_id).bind(&request.evidence.source_id).bind(&request.evidence.sha256)
            .bind(&binding.enrollment_id).bind(binding.revision).bind(binding.authority_epoch).bind(&binding.native_key)
            .bind(&claims.module_id).bind(&claims.context_domain).bind(Json(&request)).bind(Json(&claims))
            .bind(media.port.owner()).bind(request.expires_at).execute(&mut *tx).await?;
        let result = Self::remember(&mut tx, (&command, &claims), lease_id.to_string(), Execution::Completed, 1,
            json!({"lease_id":lease_id,"source_id":request.source_id,"sha256":request.evidence.sha256,
                "enrollment_id":binding.enrollment_id,"enrollment_revision":binding.revision,
                "expires_at":request.expires_at,"native_delivery":"not-observed","consumer_registration":"unchanged"})).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn native_attachment_bytes<P: PublicationPort>(
        &self,
        sha: &str,
        host: &str,
        authorization: &str,
        media: &NativeMedia<P>,
    ) -> Result<Vec<u8>> {
        hash(sha)?;
        if host != media.authority {
            return Err(Fault::Denied.into());
        }
        let mut tx = self.begin().await?;
        let key = requester(
            authorization,
            &media.proof_authority,
            sha,
            Self::now(&mut tx).await?.timestamp(),
        )?;
        // The native route carries only a digest. Never guess its consumer/source.
        // Even identical bytes in two simultaneously leased contexts are ambiguous.
        let rows = sqlx::query("SELECT * FROM native_attachment_leases WHERE byte_sha256=$1 AND native_key=$2 AND expires_at>clock_timestamp() ORDER BY lease_id LIMIT 2")
            .bind(sha).bind(&key).fetch_all(&mut *tx).await?;
        if rows.len() != 1 {
            return Err(Fault::Denied.into());
        }
        let row = &rows[0];
        let request = row.try_get::<Json<NativeAttachmentLease>, _>("request")?.0;
        let claims = row.try_get::<Json<Claims>, _>("claims")?.0;
        let consumer: String = row.try_get("consumer_id")?;
        let current = sqlx::query(
            "SELECT registration,active FROM consumer_registry WHERE consumer_id=$1 FOR UPDATE",
        )
        .bind(&consumer)
        .fetch_one(&mut *tx)
        .await?;
        let registration = current.try_get::<Json<Registration>, _>("registration")?.0;
        if !current.try_get::<bool, _>("active")?
            || registration.revision != claims.registration_revision
            || registration.policy_revision != claims.policy_revision
            || claims.consumer_id != consumer
            || self.external_epoch != claims.recovery_epoch
            || Self::epoch(&mut tx).await? != claims.recovery_epoch
            || request.evidence.sha256 != sha
            || row.try_get::<String, _>("owner")? != media.port.owner()
        {
            return Err(Fault::Denied.into());
        }
        self.service_scope(&registration, &claims)?;
        let binding = Self::binding(&mut tx, &consumer, &request.enrollment_id).await?;
        binding_current(&binding, &request, &claims.module_id)?;
        if binding.native_key != key
            || binding.authority_epoch != row.try_get::<i64, _>("binding_epoch")?
        {
            return Err(Fault::Denied.into());
        }
        let (intake, bytes, retained) = Self::media_source(
            &mut tx,
            &consumer,
            &claims.module_id,
            &claims.context_domain,
            &request,
            media.port.owner(),
        )
        .await?;
        if intake.community_id != registration.community_id {
            return Err(Fault::Denied.into());
        }
        deadline(&request, &claims, retained, Self::now(&mut tx).await?)?;
        media
            .audience(&intake, &request.audience_revision, &key)
            .await?;
        deadline(&request, &claims, retained, Self::now(&mut tx).await?)?;
        // Identity proof expiry is independent from the shorter authority lease.
        requester(
            authorization,
            &media.proof_authority,
            sha,
            Self::now(&mut tx).await?.timestamp(),
        )?;
        tx.commit().await?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proof(key: &nostr::Keys, tags: Vec<Vec<&str>>, created: u64) -> String {
        let event = nostr::EventBuilder::new(nostr::Kind::Custom(24242), "Get media")
            .tags(tags.into_iter().map(|v| nostr::Tag::parse(v).unwrap()))
            .custom_created_at(nostr::Timestamp::from(created))
            .sign_with_keys(key)
            .unwrap();
        format!(
            "Nostr {}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).unwrap())
        )
    }
    #[test]
    fn selected_cli_proof_is_identity_only_and_has_closed_host_time_and_hash_scope() {
        let key = nostr::Keys::generate();
        let sha = "a".repeat(64);
        let tags = vec![
            vec!["t", "get"],
            vec!["expiration", "1600"],
            vec!["server", "relay.test:18300"],
        ];
        let token = proof(&key, tags.clone(), 1000);
        assert_eq!(
            requester(&token, "relay.test:18300", &sha, 1000).unwrap(),
            key.public_key().to_hex()
        );
        assert!(requester(&token, "another.test:18300", &sha, 1000).is_err());
        assert!(requester(&token, "relay.test:18300", &sha, 1600).is_err());
        assert!(requester(&token, "relay.test:18300", &sha, 994).is_err());
        for extra in [
            vec!["t", "get"],
            vec!["expiration", "1800"],
            vec!["server", "other.test"],
            vec!["x", "b"],
            vec!["u", "https://arbitrary.invalid"],
        ] {
            let mut altered = tags.clone();
            altered.push(extra);
            assert!(
                requester(&proof(&key, altered, 1000), "relay.test:18300", &sha, 1000).is_err()
            );
        }
        let scoped = proof(
            &key,
            vec![
                vec!["t", "get"],
                vec!["expiration", "1600"],
                vec!["x", &sha],
            ],
            1000,
        );
        assert!(requester(&scoped, "relay.test:18300", &sha, 1000).is_ok());
        assert!(requester(&scoped, "relay.test:18300", &"b".repeat(64), 1000).is_err());
        let mut forged = URL_SAFE_NO_PAD
            .decode(token.strip_prefix("Nostr ").unwrap())
            .unwrap();
        let index = forged.iter().position(|b| *b == b'G').unwrap();
        forged[index] = b'B';
        assert!(requester(
            &format!("Nostr {}", URL_SAFE_NO_PAD.encode(forged)),
            "relay.test:18300",
            &sha,
            1000
        )
        .is_err());
    }
    #[test]
    fn lease_payload_has_no_asserted_key_or_ill_formed_expiry_escape() {
        let body = json!({"source_id":"00000000-0000-4000-8000-000000000001",
            "evidence":{"source_id":"part","sha256":"a".repeat(64),"media_type":"text/plain","size_bytes":1,"release_ref":"retained"},
            "enrollment_id":"proved","enrollment_revision":1,"audience_policy":"current",
            "audience_revision":"r1","release_ref":"current-release","expires_at":"2026-10-11T19:00:00Z"});
        assert!(serde_json::from_value::<NativeAttachmentLease>(body.clone()).is_ok());
        for (field, value) in [
            ("native_key", json!("a".repeat(64))),
            ("expires_at", json!("invalid")),
            ("expires_at", json!("2026-02-30T19:00:00Z")),
            ("expires_at", json!(42)),
        ] {
            let mut changed = body.clone();
            changed[field] = value;
            assert!(serde_json::from_value::<NativeAttachmentLease>(changed).is_err());
        }
    }
}
