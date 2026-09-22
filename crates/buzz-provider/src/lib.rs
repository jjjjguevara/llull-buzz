//! Trusted provider control plane. This crate must never be linked into or mounted
//! inside the restricted model runtime. PostgreSQL is the sole production ledger.
#![forbid(unsafe_code)]
pub mod api;
pub mod auth;
pub mod budget;
mod db;
mod discovery;
mod effects;
mod identity;
pub mod native;
mod observations;
pub mod ports;
mod tasks;
pub use db::{CommandResult, Provider, ProviderError, Result};
pub use discovery::ProfileView;
pub use effects::{AttemptView, DispatchPermit, RecoverEffect, ToolAdmission};
pub use identity::{Binding, EnrollmentChallenge};
pub use llull_buzz_wire as wire;
pub use observations::{Observation, ObservationPage, ObservationQuery};
pub use tasks::{CompleteTask, CompletedEffect, TaskView, WorkerRequest};
