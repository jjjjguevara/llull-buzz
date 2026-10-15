//! Private operator metadata custody. No HTTP, admission or standing certificate.
pub mod clock;
pub mod json;
pub mod relations;
#[derive(Debug, thiserror::Error)]
pub enum InspectionError {
    #[error("inspection refused: {0}")]
    Denied(&'static str),
    #[error("inspection outcome unknown: {code}")]
    Unknown {
        code: &'static str,
        first: Option<Box<InspectionError>>,
        cleanup: Vec<&'static str>,
    },
}
pub type Result<T> = std::result::Result<T, InspectionError>;
pub(crate) fn deny(code: &'static str) -> InspectionError {
    InspectionError::Denied(code)
}
pub const UNRESOLVED: [&str; 4] = [
    "native-owner-incarnation-unobserved",
    "credential-exposure-unobserved",
    "credential-channel-unobserved",
    "external-authority-unverified",
];
pub(crate) mod authority;

pub(crate) mod files;

pub(crate) mod acquire;
pub(crate) mod catalog;
pub mod history;
pub mod port;
