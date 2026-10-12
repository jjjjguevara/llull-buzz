//! Durable publication through one original native owner. Signed bytes are frozen
//! before any network dispatch; recovery never invents another event identity.
use crate::{
    auth::{self, Claims, Headers, Registration, SignedRequest, Target},
    db::Tx,
    native,
    ports::PortError,
    CommandResult, NativeEventSource, Provider, Result,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use llull_buzz_wire::{
    hash, id, sha256, Admission, Command, Execution, Fault, Publication, Resource, CONTRACT,
    PROFILE,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{types::Json, Row};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Audience {
    pub community_id: String,
    pub channel_id: String,
    pub revision: String,
    pub members: BTreeSet<String>,
}
#[async_trait]
pub trait PublicationPort: NativeEventSource {
    fn owner(&self) -> &str;
    fn public_key(&self) -> nostr::PublicKey;
    async fn audience(
        &self,
        community: &str,
        channel: &str,
    ) -> std::result::Result<Audience, PortError>;
    async fn submit(&self, community: &str, event: &[u8]) -> std::result::Result<bool, PortError>;
}
pub struct Publisher<P: PublicationPort> {
    port: Arc<P>,
    key: nostr::Keys,
    media_origin: url::Url,
}
impl<P: PublicationPort> Publisher<P> {
    pub fn new(port: Arc<P>, key: nostr::Keys, media_origin: &str) -> Result<Self> {
        id(port.owner())?;
        auth::https_origin(media_origin)?;
        if port.public_key() != key.public_key() {
            return Err(Fault::Denied.into());
        }
        Ok(Self {
            port,
            key,
            media_origin: url::Url::parse(media_origin).map_err(|_| Fault::Invalid)?,
        })
    }
    async fn audience(&self, p: &Publication) -> Result<Audience> {
        let a = tokio::time::timeout(
            Duration::from_secs(5),
            self.port.audience(&p.community_id, &p.channel_id),
        )
        .await
        .map_err(|_| Fault::Unknown)?
        .map_err(|_| Fault::Unknown)?;
        if a.community_id != p.community_id
            || a.channel_id != p.channel_id
            || a.revision != p.audience_revision
            || a.members.is_empty()
            || !a.members.contains(&self.key.public_key().to_hex())
        {
            return Err(Fault::Denied.into());
        }
        for key in &a.members {
            hash(key)?;
        }
        Ok(a)
    }
    async fn reply(&self, p: &Publication) -> Result<Option<buzz_sdk::ThreadRef>> {
        let Some(identity) = &p.reply_to_event else {
            return Ok(None);
        };
        // A consumer-supplied hash is not evidence of a native conversation.
        // Resolve through the same fixed owner and verify signed channel bytes.
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            self.port.event(&p.community_id, &p.channel_id, identity),
        )
        .await
        .map_err(|_| Fault::Unknown)?
        .map_err(|_| Fault::Unknown)?;
        let event = native::event(&bytes)?;
        if event.id.to_hex() != *identity
            || event.kind.as_u16() as u32 != buzz_core::kind::KIND_STREAM_MESSAGE
            || native::tag(&event, "h")? != p.channel_id
        {
            return Err(Fault::Denied.into());
        }
        // Match the selected native CLI/ACP/relay ancestry semantics. A mention
        // may itself be a direct or nested reply, not a new thread root.
        let root = buzz_core::nip10::parse_thread_markers(&event.tags)
            .resolve()
            .map(|(root, _)| nostr::EventId::from_hex(&root).map_err(|_| Fault::Invalid))
            .transpose()?
            .unwrap_or(event.id);
        if root != event.id {
            let bytes = tokio::time::timeout(
                Duration::from_secs(5),
                self.port
                    .event(&p.community_id, &p.channel_id, &root.to_hex()),
            )
            .await
            .map_err(|_| Fault::Unknown)?
            .map_err(|_| Fault::Unknown)?;
            let ancestor = native::event(&bytes)?;
            if ancestor.id != root
                || ancestor.kind.as_u16() as u32 != buzz_core::kind::KIND_STREAM_MESSAGE
                || native::tag(&ancestor, "h")? != p.channel_id
            {
                return Err(Fault::Denied.into());
            }
        }
        Ok(Some(buzz_sdk::ThreadRef {
            root_event_id: root,
            parent_event_id: event.id,
        }))
    }
    fn sign(
        &self,
        id: Uuid,
        p: &Publication,
        thread: Option<&buzz_sdk::ThreadRef>,
    ) -> Result<Vec<u8>> {
        // A signed imeta is a disclosure surface. Until the same-origin,
        // artifact-scoped media gateway is installed, the current native CLI
        // cannot read provider-origin URLs and the relay's host-scoped Blossom
        // token cannot prove release of this particular blob. Keep the admitted
        // intent pending so a later governed retry preserves its identity.
        if !p.attachments.is_empty() {
            return Err(Fault::Unavailable.into());
        }
        let channel = Uuid::parse_str(&p.channel_id).map_err(|_| Fault::Invalid)?;
        let mut media = Vec::new();
        for e in &p.attachments {
            let url = self
                .media_origin
                .join(&format!("/media/{}", e.sha256))
                .map_err(|_| Fault::Invalid)?;
            media.push(vec![
                "imeta".into(),
                format!("url {url}"),
                format!("x {}", e.sha256),
                format!("m {}", e.media_type),
                format!("size {}", e.size_bytes),
            ]);
        }
        if p.reply_to_event.as_deref() != thread.map(|t| t.parent_event_id.to_hex()).as_deref() {
            return Err(Fault::Denied.into());
        }
        let event = buzz_sdk::build_message(channel, &p.text, thread, &[], false, &media, &[])
            .map_err(|_| Fault::Invalid)?
            .tag(
                nostr::Tag::parse(["llull-publication", id.to_string().as_str()])
                    .map_err(|_| Fault::Invalid)?,
            )
            .sign_with_keys(&self.key)
            .map_err(|_| Fault::Denied)?;
        serde_json::to_vec(&event).map_err(|_| Fault::Invalid.into())
    }
}
pub(crate) struct PublicationPermit {
    pub(crate) publication_id: Uuid,
    pub(crate) command: Command,
    pub(crate) publication: Publication,
    pub(crate) claims: Claims,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationView {
    pub publication_id: Uuid,
    pub state: String,
    pub native_event_id: Option<String>,
    pub owner: Option<String>,
    pub revision: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishResult {
    pub admission: CommandResult,
    pub publication: PublicationView,
}
/// Existing immutable publication evidence, never a new release or native send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationEvidence {
    pub format: String,
    pub consumer_id: String,
    pub module_id: String,
    pub context_domain: String,
    pub publication_id: Uuid,
    pub intent_id: String,
    pub release_ref: String,
    pub request_sha256: String,
    pub publication: Publication,
    pub admission: CommandResult,
    pub state: String,
    pub native_event_id: Option<String>,
    pub owner: Option<String>,
    pub revision: u64,
    pub event_sha256: Option<String>,
    pub signed_event_base64: Option<String>,
    pub audience: Option<Audience>,
    pub completed_at: Option<i64>,
    pub publisher_public_key: String,
}

fn verified_publication_event<P: PublicationPort>(
    bytes: &[u8],
    publication_id: Uuid,
    publication: &Publication,
    audience: &Audience,
    frozen_identity: (&str, &str, &str),
    publisher: &Publisher<P>,
) -> Result<()> {
    let (owner, event_id, event_sha256) = frozen_identity;
    if bytes.len() > 262_144 || audience.members.is_empty() || audience.members.len() > 1024 {
        return Err(Fault::TooLarge.into());
    }
    publication.validate()?;
    let event = native::event(bytes)?;
    if owner != publisher.port.owner()
        || event.pubkey != publisher.port.public_key()
        || event.pubkey != publisher.key.public_key()
        || event.kind.as_u16() != 9
        || event.id.to_hex() != event_id
        || sha256(bytes) != event_sha256
        || event.content != publication.text
        || native::tag(&event, "h")? != publication.channel_id
        || native::tag(&event, "llull-publication")? != publication_id.to_string()
        || audience.community_id != publication.community_id
        || audience.channel_id != publication.channel_id
        || audience.revision != publication.audience_revision
        || !audience.members.contains(&event.pubkey.to_hex())
        || !publication.attachments.is_empty()
    {
        return Err(Fault::Denied.into());
    }
    for member in &audience.members {
        hash(member)?;
    }
    let ancestry = buzz_core::nip10::parse_thread_markers(&event.tags).resolve();
    match (&publication.reply_to_event, ancestry) {
        (None, None) => {}
        (Some(parent), Some((root, actual_parent))) if parent == &actual_parent => {
            hash(&root)?;
        }
        _ => return Err(Fault::Denied.into()),
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcilePublication {
    publication_id: Uuid,
}

impl Provider {
    async fn current_publication_authority(
        &self,
        tx: &mut Tx,
        permit: &PublicationPermit,
    ) -> Result<()> {
        let row = sqlx::query(
            "SELECT registration,active FROM consumer_registry WHERE consumer_id=$1 FOR UPDATE",
        )
        .bind(&permit.command.consumer_id)
        .fetch_one(&mut **tx)
        .await?;
        let registration: Registration = row.try_get::<Json<Registration>, _>("registration")?.0;
        let claims = &permit.claims;
        if !row.try_get::<bool, _>("active")?
            || registration.revision != claims.registration_revision
            || registration.policy_revision != claims.policy_revision
            || Self::epoch(tx).await? != claims.recovery_epoch
            || self.external_epoch != claims.recovery_epoch
        {
            return Err(Fault::Denied.into());
        }
        self.scope(tx, &registration, claims).await?;
        let root = if let Some(root) = &claims.root_task_id {
            let (root, state) = Self::root(tx, &claims.consumer_id, root).await?;
            root.scope.new_work(claims)?;
            Some((root, state))
        } else {
            None
        };
        // Lock acquisition and native lookups can outlive the immutable root.
        // Sample the database clock after every authority row has been locked;
        // a fresh assertion never extends that original execution deadline.
        let now = Self::now(tx).await?;
        claims.fresh(now.timestamp())?;
        claims.release_for(&permit.publication, now.timestamp())?;
        if let Some((root, state)) = root {
            state.live(&root.manifest, now)?;
        }
        Ok(())
    }
    async fn publication_view(tx: &mut Tx, id: Uuid) -> Result<PublicationView> {
        let row=sqlx::query("SELECT state,native_event_id,owner,revision FROM publication_deliveries WHERE publication_id=$1 FOR UPDATE")
            .bind(id).fetch_optional(&mut **tx).await?;
        Ok(match row {
            Some(row) => PublicationView {
                publication_id: id,
                state: row.try_get("state")?,
                native_event_id: Some(row.try_get("native_event_id")?),
                owner: Some(row.try_get("owner")?),
                revision: row.try_get::<i64, _>("revision")? as u64,
            },
            None => PublicationView {
                publication_id: id,
                state: "pending".into(),
                native_event_id: None,
                owner: None,
                revision: 1,
            },
        })
    }
    pub async fn publish<P: PublicationPort>(
        &self,
        body: &[u8],
        headers: Headers<'_>,
        publisher: &Publisher<P>,
    ) -> Result<PublishResult> {
        let (admission, permit) = self.prepare_publication(body, headers).await?;
        let mut tx = self.begin().await?;
        let mut view = Self::publication_view(&mut tx, permit.publication_id).await?;
        if view
            .owner
            .as_ref()
            .is_some_and(|o| o != publisher.port.owner())
        {
            return Err(Fault::Denied.into());
        }
        if view.state == "completed" || view.state == "denied" {
            tx.commit().await?;
            return Ok(PublishResult {
                admission,
                publication: view,
            });
        }
        // Preserve already terminal truth, but never sign or resubmit a
        // pending/unknown attachment through the unmediated media route.
        if !permit.publication.attachments.is_empty() {
            return Err(Fault::Unavailable.into());
        }
        // A prior dispatch may have committed at the native owner even when
        // its response was lost. Replaying publish cannot prove otherwise.
        // Only the original-owner lookup route may resolve this unknown state;
        // in particular, never resubmit the retained signed event on retry.
        if view.state == "unknown" {
            tx.commit().await?;
            return Ok(PublishResult {
                admission,
                publication: view,
            });
        }
        self.current_publication_authority(&mut tx, &permit).await?;
        let audience = publisher.audience(&permit.publication).await?;
        let thread = publisher.reply(&permit.publication).await?;
        let expected_thread = thread
            .as_ref()
            .map(|t| (t.root_event_id.to_hex(), t.parent_event_id.to_hex()));
        if view.native_event_id.is_none() {
            let bytes =
                publisher.sign(permit.publication_id, &permit.publication, thread.as_ref())?;
            let event = native::event(&bytes)?;
            sqlx::query("INSERT INTO publication_deliveries(publication_id,consumer_id,module_id,context_domain,owner,native_event_id,signed_event,event_sha256,audience,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending')")
                .bind(permit.publication_id).bind(&permit.command.consumer_id).bind(&permit.claims.module_id).bind(&permit.claims.context_domain).bind(publisher.port.owner()).bind(event.id.to_hex()).bind(&bytes).bind(sha256(&bytes)).bind(Json(&audience)).execute(&mut *tx).await?;
        } else {
            let original: Json<Audience> = sqlx::query_scalar(
                "SELECT audience FROM publication_deliveries WHERE publication_id=$1",
            )
            .bind(permit.publication_id)
            .fetch_one(&mut *tx)
            .await?;
            if original.0 != audience {
                return Err(Fault::Denied.into());
            }
        }
        // Unknown is durable BEFORE network I/O, including a crash before send.
        self.current_publication_authority(&mut tx, &permit).await?;
        sqlx::query("UPDATE publication_deliveries SET state='unknown',revision=revision+1,dispatched_at=COALESCE(dispatched_at,clock_timestamp()) WHERE publication_id=$1")
            .bind(permit.publication_id).execute(&mut *tx).await?;
        tx.commit().await?;

        let mut tx = self.begin().await?;
        view = Self::publication_view(&mut tx, permit.publication_id).await?;
        if view.state == "completed" {
            tx.commit().await?;
            return Ok(PublishResult {
                admission,
                publication: view,
            });
        }
        self.current_publication_authority(&mut tx, &permit).await?;
        let fresh = publisher.audience(&permit.publication).await?;
        let fresh_thread = publisher.reply(&permit.publication).await?;
        if fresh != audience
            || fresh_thread
                .as_ref()
                .map(|t| (t.root_event_id.to_hex(), t.parent_event_id.to_hex()))
                != expected_thread
        {
            return Err(Fault::Denied.into());
        }
        let row = sqlx::query(
            "SELECT signed_event,event_sha256 FROM publication_deliveries WHERE publication_id=$1",
        )
        .bind(permit.publication_id)
        .fetch_one(&mut *tx)
        .await?;
        let bytes: Vec<u8> = row.try_get("signed_event")?;
        let event = native::event(&bytes)?;
        if sha256(&bytes) != row.try_get::<String, _>("event_sha256")?
            || Some(event.id.to_hex()) != view.native_event_id
        {
            return Err(Fault::Unknown.into());
        }
        if buzz_core::nip10::parse_thread_markers(&event.tags).resolve() != expected_thread {
            // Never rewrite an old frozen event to repair its ancestry.
            return Err(Fault::Denied.into());
        }
        // All governed native mutations share this admission lock. The private
        // origin must not expose another writer or unmediated subscriber path.
        self.current_publication_authority(&mut tx, &permit).await?;
        let accepted = tokio::time::timeout(
            Duration::from_secs(5),
            publisher
                .port
                .submit(&permit.publication.community_id, &bytes),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
            == Some(true);
        if accepted {
            sqlx::query("UPDATE publication_deliveries SET state='completed',revision=revision+1,completed_at=clock_timestamp() WHERE publication_id=$1")
                .bind(permit.publication_id).execute(&mut *tx).await?;
        }
        view = Self::publication_view(&mut tx, permit.publication_id).await?;
        let mut observed = admission.clone();
        observed.receipt.execution = if accepted {
            Execution::Completed
        } else {
            Execution::EffectUnknown
        };
        observed.receipt.revision = view.revision;
        Self::journal(&mut tx, &permit.command, &permit.claims, &observed).await?;
        tx.commit().await?;
        Ok(PublishResult {
            admission,
            publication: view,
        })
    }

    pub async fn reconcile_publication<P: PublicationPort>(
        &self,
        publication_id: Uuid,
        body: &[u8],
        headers: Headers<'_>,
        publisher: &Publisher<P>,
    ) -> Result<PublicationView> {
        let c: Command = Self::decode(body)?;
        let request: ReconcilePublication = c.payload()?;
        if c.operation != "reconcile-publication"
            || request.publication_id != publication_id
            || c.resource.reference != publication_id.to_string()
            || c.resource.revision != "1"
        {
            return Err(Fault::Denied.into());
        }
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &SignedRequest {
                    headers: &headers,
                    body,
                },
                &format!("/integration/v1/publications/{publication_id}/reconcile"),
                None,
                auth::INVOCATION,
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        let replay = Self::replay(&mut tx, &c).await?;
        let row=sqlx::query("SELECT d.owner,d.native_event_id,d.signed_event,p.publication FROM publication_deliveries d JOIN publications p USING(publication_id) WHERE d.publication_id=$1 AND d.consumer_id=$2 AND d.module_id=$3 AND d.context_domain=$4 FOR UPDATE OF d")
            .bind(publication_id).bind(&c.consumer_id).bind(&claims.module_id).bind(&claims.context_domain).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        if row.try_get::<String, _>("owner")? != publisher.port.owner() {
            return Err(Fault::Denied.into());
        }
        let prior = Self::publication_view(&mut tx, publication_id).await?;
        if matches!(prior.state.as_str(), "completed" | "denied") {
            tx.commit().await?;
            return Ok(prior);
        }
        let publication: Publication = row.try_get::<Json<Publication>, _>("publication")?.0;
        let event_id: String = row.try_get("native_event_id")?;
        let signed: Vec<u8> = row.try_get("signed_event")?;
        let original = native::event(&signed)?;
        let found = tokio::time::timeout(
            Duration::from_secs(5),
            publisher.port.event(
                &publication.community_id,
                &publication.channel_id,
                &event_id,
            ),
        )
        .await
        .ok()
        .and_then(|r| r.ok());
        let exists = found
            .and_then(|b| native::event(&b).ok())
            .is_some_and(|e| e == original && e.id.to_hex() == event_id);
        if exists {
            sqlx::query("UPDATE publication_deliveries SET state='completed',revision=revision+1,completed_at=clock_timestamp() WHERE publication_id=$1")
                .bind(publication_id).execute(&mut *tx).await?;
        }
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let view = Self::publication_view(&mut tx, publication_id).await?;
        // A lookup miss or outage never proves that the original send failed.
        let execution = if exists {
            Execution::Completed
        } else {
            Execution::EffectUnknown
        };
        if let Some(mut record) = replay {
            record.receipt.execution = execution;
            record.receipt.revision = view.revision;
            Self::journal(&mut tx, &c, &claims, &record).await?;
        } else {
            Self::remember(&mut tx,(&c,&claims),publication_id.to_string(),execution,view.revision,json!({"publication_id":publication_id,"native_event_id":view.native_event_id,"state":view.state})).await?;
        }
        tx.commit().await?;
        Ok(view)
    }

    pub async fn observe_publication_evidence<P: PublicationPort>(
        &self,
        consumer: &str,
        publication_id: Uuid,
        headers: Headers<'_>,
        publisher: &Publisher<P>,
    ) -> Result<(PublicationEvidence, Vec<u8>, tokio::time::Instant)> {
        let identity = publication_id.to_string();
        let resource = Resource {
            namespace: consumer.into(),
            reference: identity.clone(),
            revision: "1".into(),
        };
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &SignedRequest {
                    headers: &headers,
                    body: b"",
                },
                auth::INVOCATION,
                &format!("/integration/v1/publications/{identity}/evidence"),
                "GET",
                &Target {
                    consumer,
                    intent: &identity,
                    operation: "observe-publication",
                    resource: &resource,
                    fingerprint: &sha256(b""),
                    root: None,
                },
            )
            .await?;
        // This service read cannot carry a work grant or release capability.
        self.service_scope(&registration, &claims)?;
        if claims.root_task_id.is_some()
            || claims.delegation_id.is_some()
            || claims.grant_revision.is_some()
            || claims.release.is_some()
            || !claims.verdicts.is_empty()
            || claims.browser_authentication.is_some()
        {
            return Err(Fault::Denied.into());
        }
        self.scope(&mut tx, &registration, &claims).await?;
        // Authorize the original observation BEFORE reading private publication,
        // audience or event bytes. Recovery compares scope, never active work.
        let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM observations WHERE consumer_id=$1 AND module_id=$2 AND context_domain=$3 AND record->>'operation'='publish' AND record->>'operation_id'=$4)")
            .bind(consumer).bind(&claims.module_id).bind(&claims.context_domain).bind(&identity).fetch_one(&mut *tx).await?;
        if !allowed {
            return Err(Fault::Denied.into());
        }
        let original = sqlx::query("SELECT p.intent_id,p.release_ref,p.request_sha256,p.publication,s.scope,s.root_task_id,c.result FROM publications p JOIN publication_scopes s USING(publication_id) JOIN commands c ON c.consumer_id=p.consumer_id AND c.operation='publish' AND c.intent_id=p.intent_id AND c.request_sha256=p.request_sha256 WHERE p.consumer_id=$1 AND p.publication_id=$2 FOR SHARE OF p,s,c")
            .bind(consumer).bind(publication_id).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        let scope: crate::tasks::ScopeStamp = original.try_get::<Json<_>, _>("scope")?.0;
        scope.recovery(&claims)?;
        let root_id: Option<String> = original.try_get("root_task_id")?;
        if let Some(root_id) = root_id {
            let root: Json<crate::tasks::RootRecord> = sqlx::query_scalar(
                "SELECT record FROM task_roots WHERE consumer_id=$1 AND root_task_id=$2 FOR SHARE",
            )
            .bind(consumer)
            .bind(&root_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Fault::Denied)?;
            if root.0.manifest.root_task_id != root_id {
                return Err(Fault::Denied.into());
            }
            root.0.scope.recovery(&claims)?;
        }
        let publication: Publication = original.try_get::<Json<_>, _>("publication")?.0;
        publication.validate()?;
        let admission: CommandResult = original.try_get::<Json<_>, _>("result")?.0;
        let intent_id: String = original.try_get("intent_id")?;
        let release_ref: String = original.try_get("release_ref")?;
        let request_sha256: String = original.try_get("request_sha256")?;
        hash(&request_sha256)?;
        id(&intent_id)?;
        if release_ref != publication.release_ref
            || admission.receipt.contract != CONTRACT
            || admission.receipt.profile != PROFILE
            || admission.receipt.consumer_id != consumer
            || admission.receipt.intent_id != intent_id
            || admission.receipt.operation_id != identity
            || admission.receipt.request_sha256 != request_sha256
            || admission.receipt.admission != Admission::Accepted
            || admission.receipt.execution != Execution::Pending
            || admission.receipt.revision != 1
            || !admission.receipt.effect_refs.is_empty()
            || admission.replayed
            || admission.result
                != json!({"publication_id":publication_id,"delivery":"pending","final_native_audience_check":"pending","signed_native_event":null})
        {
            return Err(Fault::Denied.into());
        }
        let mut result = PublicationEvidence {
            format: "llull-buzz-publication-evidence/v1".into(),
            consumer_id: consumer.into(),
            module_id: claims.module_id.clone(),
            context_domain: claims.context_domain.clone(),
            publication_id,
            intent_id,
            release_ref,
            request_sha256,
            publication,
            admission,
            state: "pending".into(),
            native_event_id: None,
            owner: None,
            revision: 1,
            event_sha256: None,
            signed_event_base64: None,
            audience: None,
            completed_at: None,
            publisher_public_key: publisher.port.public_key().to_hex(),
        };
        let delivery = sqlx::query("SELECT owner,native_event_id,signed_event,event_sha256,audience,state,revision,completed_at FROM publication_deliveries WHERE publication_id=$1 AND consumer_id=$2 AND module_id=$3 AND context_domain=$4 FOR SHARE")
            .bind(publication_id).bind(consumer).bind(&claims.module_id).bind(&claims.context_domain).fetch_optional(&mut *tx).await?;
        if let Some(delivery) = delivery {
            let bytes: Vec<u8> = delivery.try_get("signed_event")?;
            let audience: Audience = delivery.try_get::<Json<_>, _>("audience")?.0;
            let owner: String = delivery.try_get("owner")?;
            let event_id: String = delivery.try_get("native_event_id")?;
            let event_sha256: String = delivery.try_get("event_sha256")?;
            verified_publication_event(
                &bytes,
                publication_id,
                &result.publication,
                &audience,
                (&owner, &event_id, &event_sha256),
                publisher,
            )?;
            let state: String = delivery.try_get("state")?;
            let revision: i64 = delivery.try_get("revision")?;
            let completed_at: Option<chrono::DateTime<chrono::Utc>> =
                delivery.try_get("completed_at")?;
            if !matches!(
                state.as_str(),
                "pending" | "unknown" | "completed" | "denied"
            ) || !(1..=llull_buzz_wire::MAX_SAFE_INTEGER).contains(&revision)
                || (state == "completed") != completed_at.is_some()
                || completed_at.is_some_and(|stamp| stamp.timestamp() <= 0)
            {
                return Err(Fault::Denied.into());
            }
            result.state = state;
            result.revision = revision as u64;
            result.completed_at = completed_at.map(|stamp| stamp.timestamp());
            result.native_event_id = Some(event_id);
            result.owner = Some(owner);
            result.event_sha256 = Some(event_sha256);
            result.signed_event_base64 = Some(STANDARD.encode(bytes));
            result.audience = Some(audience);
        } else {
            // A mismatched scoped row is not evidence that no signing happened.
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM publication_deliveries WHERE publication_id=$1)",
            )
            .bind(publication_id)
            .fetch_one(&mut *tx)
            .await?;
            if exists {
                return Err(Fault::Denied.into());
            }
        }
        // One original fractional DB-clock interval bounds encoding and commit.
        let clock_anchor = tokio::time::Instant::now();
        let now = Self::now(&mut tx).await?;
        claims.fresh(now.timestamp())?;
        let expires =
            chrono::DateTime::<chrono::Utc>::from_timestamp(claims.exp, 0).ok_or(Fault::Denied)?;
        let remaining = (expires - now).to_std().map_err(|_| Fault::Denied)?;
        let deadline = clock_anchor.checked_add(remaining).ok_or(Fault::Denied)?;
        let encoded = serde_json::to_vec(&result).map_err(|_| Fault::Invalid)?;
        if encoded.len() > llull_buzz_wire::MAX_BYTES {
            return Err(Fault::TooLarge.into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Fault::Denied.into());
        }
        tokio::time::timeout_at(deadline, tx.commit())
            .await
            .map_err(|_| Fault::Denied)??;
        if tokio::time::Instant::now() >= deadline {
            return Err(Fault::Denied.into());
        }
        Ok((result, encoded, deadline))
    }

    pub async fn observe_publication(
        &self,
        consumer: &str,
        publication_id: Uuid,
        headers: Headers<'_>,
    ) -> Result<PublicationView> {
        let id = publication_id.to_string();
        let resource = Resource {
            namespace: consumer.into(),
            reference: id.clone(),
            revision: "1".into(),
        };
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &SignedRequest {
                    headers: &headers,
                    body: b"",
                },
                auth::INVOCATION,
                &format!("/integration/v1/publications/{id}"),
                "GET",
                &Target {
                    consumer,
                    intent: &id,
                    operation: "observe-publication",
                    resource: &resource,
                    fingerprint: &sha256(b""),
                    root: None,
                },
            )
            .await?;
        self.scope(&mut tx, &registration, &claims).await?;
        let allowed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM observations WHERE consumer_id=$1 AND module_id=$2 AND context_domain=$3 AND record->>'operation'='publish' AND record->>'operation_id'=$4)")
            .bind(consumer).bind(&claims.module_id).bind(&claims.context_domain).bind(&id).fetch_one(&mut *tx).await?;
        if !allowed {
            return Err(Fault::Denied.into());
        }
        let view = Self::publication_view(&mut tx, publication_id).await?;
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        tx.commit().await?;
        Ok(view)
    }
}

#[cfg(test)]
mod reply_tests {
    use super::*;
    use std::collections::BTreeMap;
    struct Origin {
        key: nostr::PublicKey,
        events: BTreeMap<String, Vec<u8>>,
    }
    #[async_trait]
    impl NativeEventSource for Origin {
        async fn event(
            &self,
            _: &str,
            _: &str,
            id: &str,
        ) -> std::result::Result<Vec<u8>, PortError> {
            self.events.get(id).cloned().ok_or(PortError)
        }
    }
    #[async_trait]
    impl PublicationPort for Origin {
        fn owner(&self) -> &str {
            "synthetic-fixed-owner"
        }
        fn public_key(&self) -> nostr::PublicKey {
            self.key
        }
        async fn audience(&self, _: &str, _: &str) -> std::result::Result<Audience, PortError> {
            Err(PortError)
        }
        async fn submit(&self, _: &str, _: &[u8]) -> std::result::Result<bool, PortError> {
            panic!("no transport in source test")
        }
    }
    #[test]
    fn evidence_verifies_original_bytes_and_configured_signer_not_another_audience_member() {
        let key = nostr::Keys::generate();
        let foreign = nostr::Keys::generate();
        let publisher = Publisher::new(
            Arc::new(Origin {
                key: key.public_key(),
                events: BTreeMap::new(),
            }),
            key.clone(),
            "https://synthetic.invalid",
        )
        .unwrap();
        let identity = Uuid::new_v4();
        let publication = Publication {
            community_id: "community-one".into(),
            channel_id: Uuid::new_v4().to_string(),
            audience_policy: "private".into(),
            audience_revision: "1".into(),
            release_ref: "original-release".into(),
            text: "Approved link".into(),
            text_sha256: sha256(b"Approved link"),
            copy_mode: llull_buzz_wire::CopyMode::SummaryLink,
            attachments: vec![],
            reply_to_event: None,
        };
        let bytes = publisher.sign(identity, &publication, None).unwrap();
        let event_id = native::event(&bytes).unwrap().id.to_hex();
        let original_audience = Audience {
            community_id: publication.community_id.clone(),
            channel_id: publication.channel_id.clone(),
            revision: "1".into(),
            members: BTreeSet::from([key.public_key().to_hex(), foreign.public_key().to_hex()]),
        };
        for fault in [
            "none",
            "owner",
            "identity",
            "digest",
            "content",
            "channel",
            "audience",
            "foreign-signer",
            "oversize",
        ] {
            let mut p = publication.clone();
            let mut audience = original_audience.clone();
            let mut raw = bytes.clone();
            let mut id = identity;
            let mut owner = "synthetic-fixed-owner";
            match fault {
                "owner" => owner = "another-owner",
                "identity" => id = Uuid::new_v4(),
                "content" => {
                    p.text = "Changed release".into();
                    p.text_sha256 = sha256(p.text.as_bytes());
                }
                "channel" => p.channel_id = Uuid::new_v4().to_string(),
                "audience" => audience.revision = "2".into(),
                "foreign-signer" => {
                    let channel = Uuid::parse_str(&p.channel_id).unwrap();
                    let event =
                        buzz_sdk::build_message(channel, &p.text, None, &[], false, &[], &[])
                            .unwrap()
                            .tag(
                                nostr::Tag::parse([
                                    "llull-publication",
                                    identity.to_string().as_str(),
                                ])
                                .unwrap(),
                            )
                            .sign_with_keys(&foreign)
                            .unwrap();
                    raw = serde_json::to_vec(&event).unwrap();
                }
                "oversize" => raw.resize(262_145, b' '),
                _ => {}
            }
            let native_id = if fault == "foreign-signer" {
                native::event(&raw).unwrap().id.to_hex()
            } else {
                event_id.clone()
            };
            let checksum = if fault == "digest" {
                "0".repeat(64)
            } else {
                sha256(&raw)
            };
            let result = verified_publication_event(
                &raw,
                id,
                &p,
                &audience,
                (owner, &native_id, &checksum),
                &publisher,
            );
            assert_eq!(result.is_ok(), fault == "none", "{fault}");
        }
    }

    #[test]
    fn evidence_requires_exact_original_reply_parent_without_native_lookup() {
        let key = nostr::Keys::generate();
        let publisher = Publisher::new(
            Arc::new(Origin {
                key: key.public_key(),
                events: BTreeMap::new(),
            }),
            key.clone(),
            "https://synthetic.invalid",
        )
        .unwrap();
        let identity = Uuid::new_v4();
        let thread = buzz_sdk::ThreadRef {
            root_event_id: nostr::EventId::from_hex("a".repeat(64)).unwrap(),
            parent_event_id: nostr::EventId::from_hex("b".repeat(64)).unwrap(),
        };
        let mut publication = Publication {
            community_id: "community-one".into(),
            channel_id: Uuid::new_v4().to_string(),
            audience_policy: "private".into(),
            audience_revision: "1".into(),
            release_ref: "original-release".into(),
            text: "Approved reply link".into(),
            text_sha256: sha256(b"Approved reply link"),
            copy_mode: llull_buzz_wire::CopyMode::SummaryLink,
            attachments: vec![],
            reply_to_event: Some(thread.parent_event_id.to_hex()),
        };
        let bytes = publisher
            .sign(identity, &publication, Some(&thread))
            .unwrap();
        let event_id = native::event(&bytes).unwrap().id.to_hex();
        let audience = Audience {
            community_id: publication.community_id.clone(),
            channel_id: publication.channel_id.clone(),
            revision: "1".into(),
            members: BTreeSet::from([key.public_key().to_hex()]),
        };
        assert!(verified_publication_event(
            &bytes,
            identity,
            &publication,
            &audience,
            ("synthetic-fixed-owner", &event_id, &sha256(&bytes)),
            &publisher
        )
        .is_ok());
        publication.reply_to_event = Some("c".repeat(64));
        assert!(verified_publication_event(
            &bytes,
            identity,
            &publication,
            &audience,
            ("synthetic-fixed-owner", &event_id, &sha256(&bytes)),
            &publisher
        )
        .is_err());
        publication.reply_to_event = None;
        assert!(verified_publication_event(
            &bytes,
            identity,
            &publication,
            &audience,
            ("synthetic-fixed-owner", &event_id, &sha256(&bytes)),
            &publisher
        )
        .is_err());
    }
    #[tokio::test]
    async fn exact_signed_parent_and_native_reply_tag_are_enforced() {
        let key = nostr::Keys::generate();
        let channel = Uuid::new_v4();
        let parent =
            buzz_sdk::build_message(channel, "Original mention", None, &[], false, &[], &[])
                .unwrap()
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();
        let origin = Arc::new(Origin {
            key: key.public_key(),
            events: BTreeMap::from([(parent.id.to_hex(), serde_json::to_vec(&parent).unwrap())]),
        });
        let publisher = Publisher::new(origin, key, "https://synthetic.invalid").unwrap();
        let mut publication = Publication {
            community_id: "community-one".into(),
            channel_id: channel.to_string(),
            audience_policy: "private".into(),
            audience_revision: "1".into(),
            release_ref: "release-one".into(),
            text: "Approved link".into(),
            text_sha256: sha256(b"Approved link"),
            copy_mode: llull_buzz_wire::CopyMode::SummaryLink,
            attachments: vec![],
            reply_to_event: Some(parent.id.to_hex()),
        };
        let thread = publisher.reply(&publication).await.unwrap();
        let event = native::event(
            &publisher
                .sign(Uuid::new_v4(), &publication, thread.as_ref())
                .unwrap(),
        )
        .unwrap();
        assert!(event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["e", &parent.id.to_hex(), "", "reply"]));
        publication.channel_id = Uuid::new_v4().to_string();
        assert!(publisher.reply(&publication).await.is_err());
        publication.channel_id = channel.to_string();
        publication.reply_to_event = Some("a".repeat(64));
        assert!(publisher.reply(&publication).await.is_err());
    }

    #[tokio::test]
    async fn threaded_mentions_preserve_verified_original_root_and_exact_parent() {
        let channel = Uuid::new_v4();
        let source_key = nostr::Keys::generate();
        let message = |thread: Option<&buzz_sdk::ThreadRef>| {
            buzz_sdk::build_message(
                channel,
                "Synthetic thread mention",
                thread,
                &[],
                false,
                &[],
                &[],
            )
            .unwrap()
            .sign_with_keys(&source_key)
            .unwrap()
        };
        let root = message(None);
        let direct = message(Some(&buzz_sdk::ThreadRef {
            root_event_id: root.id,
            parent_event_id: root.id,
        }));
        let nested = message(Some(&buzz_sdk::ThreadRef {
            root_event_id: root.id,
            parent_event_id: direct.id,
        }));
        for parent in [&direct, &nested] {
            let key = nostr::Keys::generate();
            let origin = Arc::new(Origin {
                key: key.public_key(),
                events: [(&root, root.id.to_hex()), (parent, parent.id.to_hex())]
                    .into_iter()
                    .map(|(event, id)| (id, serde_json::to_vec(event).unwrap()))
                    .collect(),
            });
            let publisher = Publisher::new(origin, key, "https://synthetic.invalid").unwrap();
            let publication = Publication {
                community_id: "community-one".into(),
                channel_id: channel.to_string(),
                audience_policy: "private".into(),
                audience_revision: "1".into(),
                release_ref: "release-thread".into(),
                text: "Approved thread reply".into(),
                text_sha256: sha256(b"Approved thread reply"),
                copy_mode: llull_buzz_wire::CopyMode::SummaryLink,
                attachments: vec![],
                reply_to_event: Some(parent.id.to_hex()),
            };
            let thread = publisher.reply(&publication).await.unwrap().unwrap();
            assert_eq!(thread.root_event_id, root.id);
            assert_eq!(thread.parent_event_id, parent.id);
            assert!(publisher.sign(Uuid::new_v4(), &publication, None).is_err());
            let signed = publisher
                .sign(Uuid::new_v4(), &publication, Some(&thread))
                .unwrap();
            let event = native::event(&signed).unwrap();
            assert_eq!(
                buzz_core::nip10::parse_thread_markers(&event.tags).resolve(),
                Some((root.id.to_hex(), parent.id.to_hex()))
            );
            assert_eq!(native::tag(&event, "h").unwrap(), channel.to_string());
        }
    }

    #[tokio::test]
    async fn missing_or_foreign_thread_root_cannot_become_a_new_channel_reply() {
        let channel = Uuid::new_v4();
        let key = nostr::Keys::generate();
        let foreign =
            buzz_sdk::build_message(Uuid::new_v4(), "Other channel", None, &[], false, &[], &[])
                .unwrap()
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();
        let parent = buzz_sdk::build_message(
            channel,
            "Foreign root mention",
            Some(&buzz_sdk::ThreadRef {
                root_event_id: foreign.id,
                parent_event_id: foreign.id,
            }),
            &[],
            false,
            &[],
            &[],
        )
        .unwrap()
        .sign_with_keys(&nostr::Keys::generate())
        .unwrap();
        let publication = Publication {
            community_id: "community-one".into(),
            channel_id: channel.to_string(),
            audience_policy: "private".into(),
            audience_revision: "1".into(),
            release_ref: "release-thread".into(),
            text: "Approved thread reply".into(),
            text_sha256: sha256(b"Approved thread reply"),
            copy_mode: llull_buzz_wire::CopyMode::SummaryLink,
            attachments: vec![],
            reply_to_event: Some(parent.id.to_hex()),
        };
        for root_available in [false, true] {
            let mut events =
                BTreeMap::from([(parent.id.to_hex(), serde_json::to_vec(&parent).unwrap())]);
            if root_available {
                events.insert(foreign.id.to_hex(), serde_json::to_vec(&foreign).unwrap());
            }
            let publisher = Publisher::new(
                Arc::new(Origin {
                    key: key.public_key(),
                    events,
                }),
                key.clone(),
                "https://synthetic.invalid",
            )
            .unwrap();
            assert!(publisher.reply(&publication).await.is_err());
        }
    }
}
