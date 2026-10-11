//! Trusted provider control plane. This crate must never be linked into or mounted
//! inside the restricted model runtime. PostgreSQL is the sole production ledger.
#![forbid(unsafe_code)]
pub mod api;
mod attachments;
pub mod auth;
pub mod budget;
mod db;
mod discovery;
mod effects;
mod identity;
mod intake;
mod model_dispatch;
pub mod native;
mod native_media;
mod native_origin;
mod observations;
pub mod ports;
mod publication;
mod snapshots;
mod tasks;
pub use attachments::{NativeAttachmentSource, RetainAttachment, MAX_ATTACHMENT_BYTES};
pub use db::{CommandResult, Provider, ProviderError, Result};
pub use discovery::ProfileView;
pub use effects::{AttemptView, DispatchPermit, RecoverEffect, ToolAdmission};
pub use identity::{Binding, EnrollmentChallenge};
pub use intake::{Intake, NativeEventSource, RetainedEvidence};
pub use llull_buzz_wire as wire;
pub use model_dispatch::ModelDispatchView;
pub use native_media::{NativeAttachmentLease, NativeMedia};
pub use native_origin::HttpNativeOrigin;
pub use observations::{Observation, ObservationPage, ObservationQuery};
pub use publication::{Audience, PublicationPort, PublicationView, PublishResult, Publisher};
pub use snapshots::{SnapshotPage, SnapshotQuery};
pub use tasks::{CompleteTask, CompletedEffect, TaskView, WorkerRequest};
