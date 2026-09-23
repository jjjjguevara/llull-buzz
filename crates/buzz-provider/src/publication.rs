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
use llull_buzz_wire::{hash, id, sha256, Command, Execution, Fault, Publication, Resource};
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
    fn sign(&self, id: Uuid, p: &Publication) -> Result<Vec<u8>> {
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
        let event = buzz_sdk::build_message(channel, &p.text, None, &[], false, &media, &[])
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
        let now = Self::now(tx).await?;
        claims.fresh(now.timestamp())?;
        claims.release_for(&permit.publication, now.timestamp())?;
        if let Some(root) = &claims.root_task_id {
            let (root, state) = Self::root(tx, &claims.consumer_id, root).await?;
            root.scope.new_work(claims)?;
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
        self.current_publication_authority(&mut tx, &permit).await?;
        let audience = publisher.audience(&permit.publication).await?;
        if view.native_event_id.is_none() {
            let bytes = publisher.sign(permit.publication_id, &permit.publication)?;
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
        permit.claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        permit
            .claims
            .release_for(&permit.publication, Self::now(&mut tx).await?.timestamp())?;
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
        if fresh != audience {
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
        // All governed native mutations share this admission lock. The private
        // origin must not expose another writer or unmediated subscriber path.
        permit.claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        permit
            .claims
            .release_for(&permit.publication, Self::now(&mut tx).await?.timestamp())?;
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
