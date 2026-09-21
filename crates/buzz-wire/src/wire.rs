use crate::{digest, hash, id, Fault, Result, CONTRACT, PROFILE};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub namespace: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub revision: String,
}
impl Resource {
    pub fn validate(&self, consumer: &str) -> Result<()> {
        id(&self.namespace)?;
        id(&self.reference)?;
        id(&self.revision)?;
        if self.namespace != consumer {
            return Err(Fault::Denied);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub contract: String,
    pub profile: String,
    pub consumer_id: String,
    pub intent_id: String,
    pub operation: String,
    pub resource: Resource,
    pub correlation_id: String,
    pub causation_id: String,
    pub payload: Value,
}
impl Command {
    pub fn validate(&self) -> Result<()> {
        if self.contract != CONTRACT || self.profile != PROFILE {
            return Err(Fault::Unavailable);
        }
        for s in [
            &self.consumer_id,
            &self.intent_id,
            &self.operation,
            &self.correlation_id,
            &self.causation_id,
        ] {
            id(s)?;
        }
        self.resource.validate(&self.consumer_id)?;
        if !self.payload.is_object() {
            return Err(Fault::Invalid);
        }
        Ok(())
    }
    pub fn payload<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.payload.clone()).map_err(|_| Fault::Invalid)
    }
    pub fn fingerprint(&self) -> Result<String> {
        digest(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Enroll {
    pub issuer: String,
    pub subject: String,
    pub intended_public_key: String,
    pub community_id: String,
    pub module_id: String,
    pub browser_transaction_id: String,
}
impl Enroll {
    pub fn validate(&self) -> Result<()> {
        for s in [
            &self.issuer,
            &self.subject,
            &self.community_id,
            &self.module_id,
            &self.browser_transaction_id,
        ] {
            id(s)?;
        }
        hash(&self.intended_public_key)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveKey {
    pub enrollment_id: String,
    pub native_event: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeAccess {
    pub enrollment_id: String,
    pub expected_revision: String,
    pub change: AccessChange,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AccessChange {
    Revoke,
    Restore,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub schema_id: String,
    pub schema_sha256: String,
    pub action: String,
    pub resources: Vec<Resource>,
}
impl Tool {
    pub fn validate(&self, consumer: &str) -> Result<()> {
        id(&self.schema_id)?;
        id(&self.action)?;
        hash(&self.schema_sha256)?;
        if self.resources.is_empty() || self.resources.len() > 32 {
            return Err(Fault::Invalid);
        }
        for r in &self.resources {
            r.validate(consumer)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskManifest {
    pub task_id: String,
    pub root_task_id: String,
    pub task_schema_id: String,
    pub context_domain: String,
    pub model_profile: String,
    pub expires_at: DateTime<Utc>,
    pub tools: Vec<Tool>,
    pub budgets: crate::Budgets,
    pub verdict_refs: Vec<String>,
}
impl TaskManifest {
    pub fn validate(&self, consumer: &str, now: DateTime<Utc>) -> Result<()> {
        for s in [
            &self.task_id,
            &self.root_task_id,
            &self.task_schema_id,
            &self.context_domain,
        ] {
            id(s)?;
        }
        if self.model_profile != "sonnet-5-adaptive-bounded-v1" {
            return Err(Fault::Unavailable);
        }
        let remaining = self.expires_at.signed_duration_since(now);
        if remaining <= chrono::Duration::zero() || remaining > chrono::Duration::seconds(600) {
            return Err(Fault::Exhausted);
        }
        if self.tools.is_empty() || self.tools.len() > 32 || self.verdict_refs.len() > 32 {
            return Err(Fault::Invalid);
        }
        let mut names = BTreeSet::new();
        for tool in &self.tools {
            tool.validate(consumer)?;
            if !names.insert((&tool.schema_id, &tool.action)) {
                return Err(Fault::Invalid);
            }
        }
        let mut verdicts = BTreeSet::new();
        for v in &self.verdict_refs {
            id(v)?;
            if !verdicts.insert(v) {
                return Err(Fault::Invalid);
            }
        }
        self.budgets.validate()
    }
    pub fn check_child(&self, root: &Self) -> Result<()> {
        if self.task_id == root.task_id
            || self.root_task_id != root.root_task_id
            || self.expires_at != root.expires_at
            || self.context_domain != root.context_domain
            || self.model_profile != root.model_profile
            || self.budgets != root.budgets
        {
            return Err(Fault::Conflict);
        }
        for tool in &self.tools {
            let parent = root
                .tools
                .iter()
                .find(|t| {
                    t.schema_id == tool.schema_id
                        && t.action == tool.action
                        && t.schema_sha256 == tool.schema_sha256
                })
                .ok_or(Fault::Denied)?;
            if tool.resources.iter().any(|r| !parent.resources.contains(r)) {
                return Err(Fault::Denied);
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskControl {
    pub task_id: String,
    pub expected_generation: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source_id: String,
    pub sha256: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub release_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CopyMode {
    SummaryLink,
    ExplicitCopy,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub community_id: String,
    pub channel_id: String,
    pub audience_policy: String,
    pub audience_revision: String,
    pub release_ref: String,
    pub text: String,
    pub text_sha256: String,
    pub copy_mode: CopyMode,
    pub attachments: Vec<Evidence>,
}
impl Publication {
    pub fn validate(&self) -> Result<()> {
        for s in [
            &self.community_id,
            &self.channel_id,
            &self.audience_policy,
            &self.audience_revision,
            &self.release_ref,
        ] {
            id(s)?;
        }
        hash(&self.text_sha256)?;
        if self.text.chars().count() > 16_384 || self.attachments.len() > 32 {
            return Err(Fault::TooLarge);
        }
        if crate::sha256(self.text.as_bytes()) != self.text_sha256 {
            return Err(Fault::Conflict);
        }
        let mut sources = BTreeSet::new();
        for a in &self.attachments {
            id(&a.source_id)?;
            id(&a.media_type)?;
            id(&a.release_ref)?;
            hash(&a.sha256)?;
            if a.size_bytes > 26_214_400 || !sources.insert(&a.source_id) {
                return Err(Fault::Invalid);
            }
        }
        Ok(())
    }
}

/// Provider result, never a copy of consumer business data or a model transcript.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub contract: String,
    pub profile: String,
    pub consumer_id: String,
    pub intent_id: String,
    pub operation_id: String,
    pub request_sha256: String,
    pub admission: Admission,
    pub execution: Execution,
    pub revision: u64,
    pub effect_refs: Vec<EffectRef>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Admission {
    Accepted,
    Denied,
    Conflict,
    Unsupported,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Execution {
    Pending,
    Running,
    AwaitingHuman,
    Completed,
    FailedBeforeEffect,
    EffectUnknown,
    CanceledBeforeEffect,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectRef {
    pub owner: String,
    pub intent_id: String,
    pub outcome: Execution,
    pub result_ref: Option<String>,
}

/// Closed, versioned internal tool-admission frame; not a new generic `execute` tool.
/// C must be a locally compiled consumer command. It contains no trusted principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall<C> {
    pub consumer_id: String,
    pub intent_id: String,
    pub root_task_id: String,
    pub task_id: String,
    pub generation: u64,
    pub effect_owner: String,
    pub effect_intent_id: String,
    pub schema_id: String,
    pub schema_sha256: String,
    pub action: String,
    pub resource: Resource,
    pub arguments: C,
}
