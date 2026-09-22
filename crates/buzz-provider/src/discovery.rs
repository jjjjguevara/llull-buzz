//! Independently authenticated contract discovery; no enrollment or task is needed.
use crate::{
    auth::{self, Headers, SignedRequest, Target},
    Provider, Result,
};
use llull_buzz_wire::{sha256, Resource, CONTRACT, PROFILE, UPSTREAM};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileView {
    pub contract: String,
    pub profile: String,
    pub wire: String,
    pub wire_schema_sha256: String,
    pub upstream_revision: String,
    pub consumer_id: String,
    pub registration_revision: u64,
    pub policy_revision: String,
    pub recovery_epoch: u64,
    pub module_id: String,
    pub actions: BTreeSet<String>,
    pub context_domains: BTreeSet<String>,
    pub max_control_bytes: usize,
    pub max_artifact_bytes: u64,
    pub max_observation_page: u16,
}

impl Provider {
    pub async fn discover_profile(
        &self,
        consumer: &str,
        headers: Headers<'_>,
    ) -> Result<ProfileView> {
        llull_buzz_wire::id(consumer)?;
        let mut tx = self.begin().await?;
        let resource = Resource {
            namespace: consumer.into(),
            reference: "profile".into(),
            revision: "1".into(),
        };
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &SignedRequest {
                    headers: &headers,
                    body: b"",
                },
                auth::INVOCATION,
                "/integration/v1/profile",
                "GET",
                &Target {
                    consumer,
                    intent: "profile",
                    operation: "discover-profile",
                    resource: &resource,
                    fingerprint: &sha256(b""),
                    root: None,
                },
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let module = &registration.modules[&claims.module_id];
        let profile = ProfileView {
            contract: CONTRACT.into(),
            profile: PROFILE.into(),
            wire: "bz-wire-v1".into(),
            wire_schema_sha256: sha256(include_bytes!(
                "../../../docs/architecture/contracts/schemas/buzz-wire-v1.schema.json"
            )),
            upstream_revision: UPSTREAM.into(),
            consumer_id: registration.consumer_id,
            registration_revision: registration.revision,
            policy_revision: registration.policy_revision,
            recovery_epoch: self.external_epoch,
            module_id: claims.module_id.clone(),
            actions: module.actions.clone(),
            context_domains: module.context_domains.clone(),
            max_control_bytes: llull_buzz_wire::MAX_BYTES,
            max_artifact_bytes: 26_214_400,
            max_observation_page: 100,
        };
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        tx.commit().await?;
        Ok(profile)
    }
}
