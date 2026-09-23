//! Pure state transitions. Production commits them only under PostgreSQL locks.
use crate::{Execution, Fault, Result, TaskManifest, MAX_SAFE_INTEGER};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub model_attempts: u32,
    pub tool_admissions: u32,
    pub input_tokens_per_generation: u64,
    pub input_tokens_total: u64,
    pub output_tokens_total: u64,
    pub usd_micros: u64,
    pub automatic_restarts: u32,
}
impl Budgets {
    pub fn validate(&self) -> Result<()> {
        if !(1..=8).contains(&self.model_attempts)
            || !(1..=32).contains(&self.tool_admissions)
            || !(1..=32_000).contains(&self.input_tokens_per_generation)
            || !(1..=128_000).contains(&self.input_tokens_total)
            || !(1..=16_000).contains(&self.output_tokens_total)
            || !(1..=1_000_000).contains(&self.usd_micros)
            || self.automatic_restarts > 3
        {
            return Err(Fault::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Spent {
    pub model_attempts: u32,
    pub tool_admissions: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub usd_micros: u64,
    pub restarts: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Charge {
    Tool,
    Model {
        input_tokens: u64,
        output_tokens: u64,
        usd_micros: u64,
    },
}
impl Spent {
    fn charged(&self, charge: &Charge, cap: &Budgets) -> Result<Self> {
        let mut next = self.clone();
        match charge {
            Charge::Tool => {
                next.tool_admissions = next
                    .tool_admissions
                    .checked_add(1)
                    .ok_or(Fault::Exhausted)?
            }
            Charge::Model {
                input_tokens,
                output_tokens,
                usd_micros,
            } => {
                if *input_tokens == 0
                    || *output_tokens == 0
                    || *usd_micros == 0
                    || *input_tokens > cap.input_tokens_per_generation
                {
                    return Err(Fault::Exhausted);
                }
                next.model_attempts = next.model_attempts.checked_add(1).ok_or(Fault::Exhausted)?;
                next.input_tokens = next
                    .input_tokens
                    .checked_add(*input_tokens)
                    .ok_or(Fault::Exhausted)?;
                next.output_tokens = next
                    .output_tokens
                    .checked_add(*output_tokens)
                    .ok_or(Fault::Exhausted)?;
                next.usd_micros = next
                    .usd_micros
                    .checked_add(*usd_micros)
                    .ok_or(Fault::Exhausted)?;
            }
        }
        if next.model_attempts > cap.model_attempts
            || next.tool_admissions > cap.tool_admissions
            || next.input_tokens > cap.input_tokens_total
            || next.output_tokens > cap.output_tokens_total
            || next.usd_micros > cap.usd_micros
        {
            return Err(Fault::Exhausted);
        }
        Ok(next)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Worker {
    pub owner: String,
    pub generation: u64,
    pub lease_until: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskState {
    pub generation: u64,
    pub revision: u64,
    pub phase: Execution,
    pub spent: Spent,
    pub worker: Option<Worker>,
    pub stop_new_work: bool,
}
impl Default for TaskState {
    fn default() -> Self {
        Self {
            generation: 1,
            revision: 1,
            phase: Execution::Pending,
            spent: Spent::default(),
            worker: None,
            stop_new_work: false,
        }
    }
}
impl TaskState {
    fn bump_revision(&mut self) -> Result<()> {
        if self.revision >= MAX_SAFE_INTEGER as u64 {
            return Err(Fault::Exhausted);
        }
        self.revision += 1;
        Ok(())
    }
    pub fn live(&self, manifest: &TaskManifest, now: DateTime<Utc>) -> Result<()> {
        if now >= manifest.expires_at {
            return Err(Fault::Exhausted);
        }
        if self.stop_new_work
            || matches!(
                self.phase,
                Execution::Completed
                    | Execution::CanceledBeforeEffect
                    | Execution::FailedBeforeEffect
                    | Execution::EffectUnknown
            )
        {
            return Err(Fault::Denied);
        }
        Ok(())
    }
    pub fn worker(
        &self,
        owner: &str,
        generation: u64,
        manifest: &TaskManifest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.live(manifest, now)?;
        let w = self.worker.as_ref().ok_or(Fault::Denied)?;
        if self.generation != generation
            || w.generation != generation
            || w.owner != owner
            || now >= w.lease_until
        {
            return Err(Fault::Conflict);
        }
        Ok(())
    }
    pub fn acquire(
        &mut self,
        owner: &str,
        manifest: &TaskManifest,
        now: DateTime<Utc>,
    ) -> Result<Worker> {
        crate::id(owner)?;
        self.live(manifest, now)?;
        if let Some(w) = &self.worker {
            if now < w.lease_until {
                if w.owner != owner {
                    return Err(Fault::Conflict);
                }
                return Ok(w.clone());
            }
            if self.spent.restarts >= manifest.budgets.automatic_restarts
                || self.generation >= MAX_SAFE_INTEGER as u64
            {
                return Err(Fault::Exhausted);
            }
        }
        self.bump_revision()?;
        if self.worker.is_some() {
            self.spent.restarts += 1;
            self.generation += 1;
        }
        let w = Worker {
            owner: owner.into(),
            generation: self.generation,
            lease_until: (now + Duration::seconds(30)).min(manifest.expires_at),
        };
        self.worker = Some(w.clone());
        self.phase = Execution::Running;
        Ok(w)
    }
    pub fn renew(
        &mut self,
        owner: &str,
        generation: u64,
        manifest: &TaskManifest,
        now: DateTime<Utc>,
    ) -> Result<Worker> {
        self.worker(owner, generation, manifest, now)?;
        self.bump_revision()?;
        let w = Worker {
            owner: owner.into(),
            generation,
            lease_until: (now + Duration::seconds(30)).min(manifest.expires_at),
        };
        self.worker = Some(w.clone());
        Ok(w)
    }
    pub fn reserve(
        &mut self,
        owner: &str,
        generation: u64,
        manifest: &TaskManifest,
        charge: &Charge,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.worker(owner, generation, manifest, now)?;
        let spent = self.spent.charged(charge, &manifest.budgets)?;
        // Compute first: failed reservation must not partially spend another dimension.
        self.bump_revision()?;
        self.spent = spent;
        Ok(())
    }
    pub fn fence(&mut self, unknown: bool, has_completed: bool) -> Result<()> {
        if self.generation >= MAX_SAFE_INTEGER as u64 {
            return Err(Fault::Exhausted);
        }
        self.bump_revision()?;
        self.generation += 1;
        self.stop_new_work = true;
        self.worker = None;
        // Fencing revokes work; it never rewrites a known completed effect as
        // "before effect" or promotes a partially completed root to success.
        if self.phase != Execution::Completed {
            self.phase = if unknown {
                Execution::EffectUnknown
            } else if has_completed {
                Execution::Pending
            } else {
                Execution::CanceledBeforeEffect
            };
        }
        Ok(())
    }
    pub fn recovery_pending(&mut self, unknown: bool) -> Result<()> {
        self.bump_revision()?;
        self.stop_new_work = true;
        self.worker = None;
        self.phase = if unknown {
            Execution::EffectUnknown
        } else {
            Execution::Pending
        };
        Ok(())
    }
    pub fn complete(&mut self, has_completed: bool, unresolved: bool) -> Result<()> {
        if !has_completed || unresolved {
            return Err(Fault::Unknown);
        }
        self.bump_revision()?;
        self.stop_new_work = true;
        self.worker = None;
        self.phase = Execution::Completed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn task() -> TaskManifest {
        TaskManifest {
            task_id: "root".into(),
            root_task_id: "root".into(),
            task_schema_id: "typed-v1".into(),
            context_domain: "scope".into(),
            model_profile: "sonnet-5-adaptive-bounded-v1".into(),
            expires_at: DateTime::from_timestamp(1600, 0).unwrap(),
            tools: vec![],
            budgets: Budgets {
                model_attempts: 8,
                tool_admissions: 32,
                input_tokens_per_generation: 32_000,
                input_tokens_total: 128_000,
                output_tokens_total: 16_000,
                usd_micros: 1_000_000,
                automatic_restarts: 3,
            },
            verdict_refs: vec![],
        }
    }
    fn at(t: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(t, 0).unwrap()
    }
    #[test]
    fn positive_charge_and_exhaustion_are_atomic() {
        let t = task();
        let mut s = TaskState::default();
        s.acquire("worker", &t, at(1000)).unwrap();
        for _ in 0..32 {
            s.reserve("worker", 1, &t, &Charge::Tool, at(1001)).unwrap();
        }
        let before = s.spent.clone();
        assert_eq!(
            s.reserve("worker", 1, &t, &Charge::Tool, at(1002)),
            Err(Fault::Exhausted)
        );
        assert_eq!(s.spent, before);
    }
    #[test]
    fn restart_never_resets_budget_or_deadline_and_old_worker_is_fenced() {
        let t = task();
        let mut s = TaskState::default();
        s.acquire("first", &t, at(1000)).unwrap();
        s.reserve("first", 1, &t, &Charge::Tool, at(1001)).unwrap();
        assert_eq!(s.acquire("next", &t, at(1002)), Err(Fault::Conflict));
        let w = s.acquire("next", &t, at(1031)).unwrap();
        assert_eq!(w.generation, 2);
        assert_eq!(s.spent.tool_admissions, 1);
        assert!(s.reserve("first", 1, &t, &Charge::Tool, at(1032)).is_err());
        s.acquire("third", &t, at(1062)).unwrap();
        s.acquire("fourth", &t, at(1093)).unwrap();
        assert_eq!(s.acquire("fifth", &t, at(1124)), Err(Fault::Exhausted));
        assert_eq!(s.acquire("fourth", &t, at(1600)), Err(Fault::Exhausted));
    }
    #[test]
    fn revocation_and_unknown_do_not_refund() {
        let t = task();
        let mut s = TaskState::default();
        s.acquire("w", &t, at(1000)).unwrap();
        s.reserve("w", 1, &t, &Charge::Tool, at(1001)).unwrap();
        s.fence(true, false).unwrap();
        assert_eq!(s.phase, Execution::EffectUnknown);
        assert_eq!(s.spent.tool_admissions, 1);
        assert!(s.acquire("fresh", &t, at(1002)).is_err());
        assert!(s.complete(true, true).is_err());
        s.complete(true, false).unwrap();
        assert_eq!(s.phase, Execution::Completed);
    }
    #[test]
    fn cumulative_model_limits_include_outstanding_reservations() {
        let t = task();
        let mut s = TaskState::default();
        s.acquire("w", &t, at(1000)).unwrap();
        for _ in 0..4 {
            s.reserve(
                "w",
                1,
                &t,
                &Charge::Model {
                    input_tokens: 32_000,
                    output_tokens: 4_000,
                    usd_micros: 250_000,
                },
                at(1001),
            )
            .unwrap();
        }
        let before = s.spent.clone();
        assert!(s
            .reserve(
                "w",
                1,
                &t,
                &Charge::Model {
                    input_tokens: 1,
                    output_tokens: 1,
                    usd_micros: 1
                },
                at(1002)
            )
            .is_err());
        assert_eq!(s.spent, before);
    }
    #[test]
    fn fence_preserves_completed_and_partial_effect_truth() {
        let mut s = TaskState::default();
        s.fence(false, true).unwrap();
        assert_eq!(s.phase, Execution::Pending);
        assert!(s.stop_new_work);
        s.complete(true, false).unwrap();
        s.fence(false, true).unwrap();
        assert_eq!(s.phase, Execution::Completed);
    }
    #[test]
    fn revision_overflow_cannot_partially_change_worker_or_counters() {
        let t = task();
        let mut s = TaskState {
            revision: MAX_SAFE_INTEGER as u64,
            ..TaskState::default()
        };
        let before = crate::canonical(&s).unwrap();
        assert!(s.acquire("w", &t, at(1000)).is_err());
        assert_eq!(crate::canonical(&s).unwrap(), before);
        assert!(s.fence(true, false).is_err());
        assert_eq!(crate::canonical(&s).unwrap(), before);
        assert!(s.complete(true, false).is_err());
        assert_eq!(crate::canonical(&s).unwrap(), before);
    }
}
