//! Pinned upstream native verification, with provider-specific closed parsing.
use llull_buzz_wire::{hash, parse, Fault};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}
pub fn event(bytes: &[u8]) -> std::result::Result<nostr::Event, Fault> {
    let raw: NativeEvent = parse(bytes)?;
    hash(&raw.id)?;
    hash(&raw.pubkey)?;
    if raw.sig.len() != 128
        || !raw
            .sig
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || raw.content.chars().count() > 16_384
        || raw.tags.len() > 128
        || raw
            .tags
            .iter()
            .any(|t| t.len() > 16 || t.iter().any(|v| v.len() > 4096))
    {
        return Err(Fault::Invalid);
    }
    let event: nostr::Event =
        serde_json::from_value(serde_json::to_value(raw).map_err(|_| Fault::Invalid)?)
            .map_err(|_| Fault::Invalid)?;
    buzz_core::verify_event(&event).map_err(|_| Fault::Denied)?;
    Ok(event)
}
pub(crate) fn tag<'a>(event: &'a nostr::Event, name: &str) -> std::result::Result<&'a str, Fault> {
    let tags: Vec<_> = event
        .tags
        .iter()
        .filter(|t| t.as_slice().first().is_some_and(|v| v == name))
        .collect();
    if tags.len() != 1 || tags[0].as_slice().len() != 2 {
        return Err(Fault::Denied);
    }
    Ok(tags[0].as_slice()[1].as_str())
}

/// An ordinary signed channel message can carry this text without client changes.
/// The content binds the community even though an NIP-29 h tag names the channel.
pub fn enrollment_text(
    consumer: &str,
    community: &str,
    enrollment: &str,
    challenge: &str,
) -> String {
    // JSON strings avoid delimiter/Unicode ambiguity while remaining ordinary message text.
    serde_json::json!({"llull_buzz_enrollment":1,"consumer":consumer,"community":community,"enrollment":enrollment,"challenge":challenge}).to_string()
}
pub(crate) fn verify_enrollment_proof(
    proof: &nostr::Event,
    intended: &str,
    bot: &str,
    channel: &str,
    expected_content: &str,
    issued_at: i64,
    expires_at: i64,
    now: i64,
) -> std::result::Result<(), Fault> {
    if proof.pubkey.to_hex() != intended
        || proof.kind.as_u16() as u32 != buzz_core::kind::KIND_STREAM_MESSAGE
        || tag(proof, "p")? != bot
        || tag(proof, "h")? != channel
        || proof.content != expected_content
        || now >= expires_at
        || (proof.created_at.as_secs() as i64) < issued_at
        || (proof.created_at.as_secs() as i64) > now + 30
        || (proof.created_at.as_secs() as i64) >= expires_at
    {
        return Err(Fault::Denied);
    }
    Ok(())
}

/// One canonical, percent-encoded path segment; never a caller-provided route.
pub fn segment(value: &str) -> llull_buzz_wire::Result<String> {
    llull_buzz_wire::id(value)?;
    if matches!(value, "." | "..") {
        return Err(llull_buzz_wire::Fault::Invalid);
    }
    let mut result = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            result.push(b as char);
        } else {
            use std::fmt::Write;
            write!(&mut result, "%{b:02X}").map_err(|_| llull_buzz_wire::Fault::Invalid)?;
        }
    }
    Ok(result)
}
