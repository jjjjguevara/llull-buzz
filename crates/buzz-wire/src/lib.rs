//! Consumer-neutral wire definitions and deterministic admission rules.
//! No clock, network, credentials, persistence or model loop lives here.
#![forbid(unsafe_code)]
pub mod json;
pub mod task;
pub mod wire;
pub use json::{canonical, digest, parse, sha256};
pub use task::*;
pub use wire::*;

pub const CONTRACT: &str = "llull-buzz integration v0.2";
pub const PROFILE: &str = "bz-restricted-2026-09/v1";
pub const UPSTREAM: &str = "01b6174a1cbad249e93f31df97d4b2ed1d0e8638";
pub const MAX_BYTES: usize = 1_048_576;
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Fault {
    #[error("invalid request")]
    Invalid,
    #[error("request exceeds limit")]
    TooLarge,
    #[error("authentication or authority denied")]
    Denied,
    #[error("immutable intent or generation conflict")]
    Conflict,
    #[error("surface unavailable in this implementation slice")]
    Unavailable,
    #[error("budget or lifetime exhausted")]
    Exhausted,
    #[error("operation requires original-owner recovery")]
    Unknown,
}
pub type Result<T> = std::result::Result<T, Fault>;

pub fn id(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 255 || s.chars().any(char::is_control) {
        return Err(Fault::Invalid);
    }
    Ok(())
}
pub fn hash(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Fault::Invalid);
    }
    Ok(())
}
