//! Trusted provider control plane. This crate must never be linked into or mounted
//! inside the restricted model runtime. PostgreSQL is the sole production ledger.
#![forbid(unsafe_code)]
pub mod auth;
pub mod native;
pub mod ports;
pub mod api;
pub mod budget;
mod db;
mod identity;
mod tasks;
mod effects;
pub use db::{Provider, ProviderError, CommandResult, Result};
pub use identity::{Binding, EnrollmentChallenge};
pub use tasks::{TaskView, WorkerRequest, CompleteTask, CompletedEffect};
pub use effects::{AttemptView, ToolAdmission, DispatchPermit, RecoverEffect};
pub use llull_buzz_wire as wire;
