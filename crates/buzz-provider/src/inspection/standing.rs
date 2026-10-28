//! Read-only, bounded acquisition of original native credential custody.
//! The inspector does not load credentials, stop owners, close their channels,
//! revoke tokens, or convert local process absence into remote authority facts.
use super::{authority::Authenticated, clock::Budget, deny, Result};
use crate::native_custody::{
    self, CustodyEvent, CustodyRecord, NativeCustodyScope, ProcessIncarnation,
};
use rustix::fs::{fstat, openat, statat, AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingProfile {
    pub kind: String,
    pub scopes: Vec<NativeCustodyScope>,
    pub retained_anchors: BTreeMap<String, HistoryAnchor>,
}
/// Independently signed profile commitment to an already-observed original
/// acquisition and retained prefix. Runtime signing authority cannot replace
/// the request/profile root or rebase a missing original exposure history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryAnchor {
    pub acquisition_sha256: String,
    pub prefix_records: u64,
    pub prefix_head_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerObservation {
    pub scope: NativeCustodyScope,
    pub original_process: ProcessIncarnation,
    pub current_process: Option<ProcessIncarnation>,
    pub process_status: String,
    pub credential_file_status: String,
    pub socket_inodes: Option<Vec<String>>,
    pub history_sha256: String,
    pub head_sha256: String,
    pub history: Vec<CustodyRecord>,
    pub open_capabilities: BTreeMap<String, u64>,
    pub local_status: String,
    pub unresolved: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingObservation {
    pub kind: String,
    pub status: String,
    pub request_sha256: String,
    pub challenge: String,
    pub observed_us: i64,
    pub scopes: Vec<OwnerObservation>,
    pub unresolved: Vec<String>,
}
impl StandingProfile {
    pub(crate) fn authenticate(&self, auth: &Authenticated) -> Result<()> {
        if self.kind != "llull-buzz-native-standing-profile/v1" || self.scopes.is_empty() {
            return Err(deny("native_standing_profile"));
        }
        if self.retained_anchors.len() != self.scopes.len() {
            return Err(deny("native_standing_history_anchor"));
        }
        let mut ids = BTreeSet::new();
        for scope in &self.scopes {
            scope.validate()?;
            let anchor = self
                .retained_anchors
                .get(&scope.custody_id)
                .ok_or_else(|| deny("native_standing_history_anchor"))?;
            if anchor.prefix_records == 0 {
                return Err(deny("native_standing_history_anchor"));
            }
            llull_buzz_wire::hash(&anchor.acquisition_sha256)
                .map_err(|_| deny("native_standing_history_anchor"))?;
            llull_buzz_wire::hash(&anchor.prefix_head_sha256)
                .map_err(|_| deny("native_standing_history_anchor"))?;
            let r = auth.request();
            if !ids.insert(&scope.custody_id)
                || scope.installation != auth.profile().installation
                || scope.source_revision != auth.source_revision()
                || scope.implementation_sha256 != auth.profile().implementation_sha256
                || scope.membership_sha256 != auth.profile().membership_sha256
                || scope.operation_ref != r.operation_ref
                || scope.operation_sha256 != r.operation_sha256
                || scope.configuration_sha256 != r.configuration_sha256
                || scope.configuration_generation != r.configuration_generation
                || scope.source_copy_sha256 != r.source_copy_sha256
                || scope.target_copy_sha256 != r.target_copy_sha256
            {
                return Err(deny("native_standing_original_scope"));
            }
            if !Path::new(&scope.credential_file).is_absolute()
                || Path::new(&scope.credential_file)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(deny("native_standing_credential_path"));
            }
        }
        Ok(())
    }
}
fn fold(
    scope: &NativeCustodyScope,
    anchor: &HistoryAnchor,
    raw: &[u8],
    now: i64,
) -> Result<OwnerObservation> {
    if raw.is_empty() || raw.len() as u64 > native_custody::MAX_LOG_BYTES || !raw.ends_with(b"\n") {
        return Err(deny("native_standing_history_bound_or_partial"));
    }
    let mut history = Vec::new();
    let mut previous = native_custody::ZERO.to_owned();
    let expected_scope = scope.digest()?;
    let mut original = None;
    let mut capabilities = BTreeMap::<String, u64>::new();
    let mut released = false;
    let mut legacy_issuance = false;
    let mut last_us = 0;
    for (sequence, line) in raw[..raw.len() - 1].split(|b| *b == b'\n').enumerate() {
        let record: CustodyRecord =
            llull_buzz_wire::parse(line).map_err(|_| deny("native_standing_history_encoding"))?;
        if record.kind != "llull-buzz-native-custody-record/v1"
            || record.sequence != sequence as u64
            || record.previous_sha256 != previous
            || record.scope_sha256 != expected_scope
            || record.observed_us < last_us
            || record.observed_us > now
            || released
            || llull_buzz_wire::canonical(&record)
                .map_err(|_| deny("native_standing_history_encoding"))?
                != line
        {
            return Err(deny("native_standing_history_chain"));
        }
        match &record.event {
            CustodyEvent::Acquire {
                scope: acquired,
                process,
                key_file_sha256,
            } => {
                if sequence != 0 || acquired.as_ref() != scope || original.is_some() {
                    return Err(deny("native_standing_history_origin"));
                }
                llull_buzz_wire::hash(key_file_sha256)
                    .map_err(|_| deny("native_standing_key_identity"))?;
                process.validate()?;
                original = Some(process.clone());
            }
            CustodyEvent::CapabilityOpen { capability } => {
                if original.is_none()
                    || !matches!(
                        capability.as_str(),
                        "native-http" | "native-publication" | "consumer-http"
                    )
                {
                    return Err(deny("native_standing_capability"));
                }
                let count = capabilities.entry(capability.clone()).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| deny("native_standing_capability"))?;
            }
            CustodyEvent::CredentialIssued {
                capability,
                event_id,
                token_sha256,
                kind,
                explicit_expiration,
            } => {
                if capabilities.get(capability).copied().unwrap_or(0) == 0
                    || !matches!(
                        (capability.as_str(), *kind),
                        ("native-http", 27235 | 24242)
                            | ("native-publication", 9)
                            | ("consumer-http", 27235)
                    )
                    || (*kind == 24242 && explicit_expiration.is_none())
                {
                    return Err(deny("native_standing_issuance"));
                }
                llull_buzz_wire::hash(event_id).map_err(|_| deny("native_standing_issuance"))?;
                llull_buzz_wire::hash(token_sha256)
                    .map_err(|_| deny("native_standing_issuance"))?;
                legacy_issuance = true;
            }
            CustodyEvent::CredentialIssuedV2 {
                capability,
                event_id,
                token_sha256,
                kind,
                public_claims,
            } => {
                if capabilities.get(capability).copied().unwrap_or(0) == 0 {
                    return Err(deny("native_standing_issuance"));
                }
                llull_buzz_wire::hash(event_id).map_err(|_| deny("native_standing_issuance"))?;
                llull_buzz_wire::hash(token_sha256)
                    .map_err(|_| deny("native_standing_issuance"))?;
                public_claims.validate(scope, capability, *kind)?;
            }
            CustodyEvent::CapabilityClosed { capability } => {
                let count = capabilities
                    .get_mut(capability)
                    .ok_or_else(|| deny("native_standing_release"))?;
                *count = count
                    .checked_sub(1)
                    .ok_or_else(|| deny("native_standing_release"))?;
            }
            CustodyEvent::Released => {
                if original.is_none() || capabilities.values().any(|count| *count != 0) {
                    return Err(deny("native_standing_release"));
                }
                released = true;
            }
        }
        previous = llull_buzz_wire::sha256(line);
        if (sequence == 0 && previous != anchor.acquisition_sha256)
            || (sequence as u64 + 1 == anchor.prefix_records
                && previous != anchor.prefix_head_sha256)
        {
            return Err(deny("native_standing_history_anchor"));
        }
        last_us = record.observed_us;
        history.push(record);
    }
    if (history.len() as u64) < anchor.prefix_records {
        return Err(deny("native_standing_history_anchor"));
    }
    capabilities.retain(|_, count| *count > 0);
    Ok(OwnerObservation {
        scope: scope.clone(),
        original_process: original.ok_or_else(|| deny("native_standing_history_origin"))?,
        current_process: None,
        process_status: "UNKNOWN".into(),
        credential_file_status: "UNKNOWN".into(),
        socket_inodes: None,
        history_sha256: llull_buzz_wire::sha256(raw),
        head_sha256: previous,
        history,
        open_capabilities: capabilities,
        local_status: "UNKNOWN".into(),
        // NIP98 does not prove remote invalidation. Even an expired explicit
        // token is not a remote server configuration or key-revocation readback.
        unresolved: if legacy_issuance {
            vec![
                "external-authority-unverified".into(),
                "credential-public-claims-unavailable".into(),
            ]
        } else {
            vec!["external-authority-unverified".into()]
        },
    })
}
fn process_state(original: &ProcessIncarnation) -> Result<(String, Option<ProcessIncarnation>)> {
    let here = ProcessIncarnation::current()?;
    if original.machine_id != here.machine_id
        || original.boot_id != here.boot_id
        || original.namespaces.get("pid") != here.namespaces.get("pid")
    {
        return Ok(("UNKNOWN".into(), None));
    }
    let path = format!("/proc/{}", original.pid);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(("ABSENT".into(), None)),
        Err(_) => Ok(("UNKNOWN".into(), None)),
        Ok(_) => match ProcessIncarnation::read(original.pid) {
            Ok(current) if current == *original => Ok(("LIVE".into(), Some(current))),
            Ok(current) if current.start_ticks != original.start_ticks => {
                Ok(("REPLACED".into(), Some(current)))
            }
            _ => Ok(("UNKNOWN".into(), None)),
        },
    }
}
struct SocketInventory {
    inodes: BTreeSet<String>,
    encoded_bytes: usize,
}
impl SocketInventory {
    fn new() -> Self {
        Self {
            inodes: BTreeSet::new(),
            encoded_bytes: 2,
        }
    }
    fn admit(&mut self, inode: &str) -> Result<()> {
        let number = inode
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| deny("native_standing_channel_inventory"))?;
        if inode != number.to_string() {
            return Err(deny("native_standing_channel_inventory"));
        }
        if self.inodes.contains(inode) {
            return Ok(());
        }
        // Decimal kernel inode strings need no JSON escaping. Account for both
        // quotes and a separator before allocating the new retained entry. This
        // is the existing response-composition bound, not a smaller supported
        // business channel count or a permission to return a trimmed prefix.
        let encoded_bytes = self
            .encoded_bytes
            .checked_add(inode.len() + 3)
            .filter(|bytes| *bytes <= llull_buzz_wire::MAX_BYTES)
            .ok_or_else(|| deny("native_standing_channel_bound"))?;
        self.inodes.insert(inode.to_owned());
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }
}
fn scan_socket_directory(path: &Path, budget: &mut Budget) -> Result<Vec<String>> {
    budget.sample(super::clock::now())?;
    let mut inventory = SocketInventory::new();
    let entries = std::fs::read_dir(path).map_err(|_| deny("native_standing_channel_inventory"))?;
    for entry in entries {
        budget.sample(super::clock::now())?;
        let entry = entry.map_err(|_| deny("native_standing_channel_inventory"))?;
        let link = std::fs::read_link(entry.path())
            .map_err(|_| deny("native_standing_channel_inventory"))?;
        let text = link
            .to_str()
            .ok_or_else(|| deny("native_standing_channel_inventory"))?;
        if let Some(inode) = text
            .strip_prefix("socket:[")
            .and_then(|text| text.strip_suffix(']'))
        {
            inventory.admit(inode)?;
        }
        budget.sample(super::clock::now())?;
    }
    budget.sample(super::clock::now())?;
    Ok(inventory.inodes.into_iter().collect())
}
fn socket_owners(
    original: &ProcessIncarnation,
    state: &str,
    budget: &mut Budget,
) -> Result<Option<Vec<String>>> {
    budget.sample(super::clock::now())?;
    if matches!(state, "ABSENT" | "REPLACED") {
        return Ok(Some(Vec::new()));
    }
    if state != "LIVE" {
        return Ok(None);
    }
    if ProcessIncarnation::read(original.pid)? != *original {
        return Err(deny("native_standing_owner_changed"));
    }
    let sockets = scan_socket_directory(Path::new(&format!("/proc/{}/fd", original.pid)), budget)?;
    if ProcessIncarnation::read(original.pid)? != *original {
        return Err(deny("native_standing_owner_changed"));
    }
    budget.sample(super::clock::now())?;
    Ok(Some(sockets))
}

fn credential_file_state(scope: &NativeCustodyScope) -> Result<String> {
    let path = Path::new(&scope.credential_file);
    let parent = native_custody::private_directory(
        path.parent()
            .ok_or_else(|| deny("native_standing_credential_path"))?,
    )?;
    let result = match statat(
        parent.native_descriptor()?,
        path.file_name()
            .ok_or_else(|| deny("native_standing_credential_path"))?,
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => Ok("PRESENT".to_owned()),
        Err(rustix::io::Errno::NOENT) => Ok("ABSENT".to_owned()),
        Err(_) => Ok("UNKNOWN".to_owned()),
    };
    super::files::native_cleanup(result, parent.close())
}
fn read_log(
    directory: &impl std::os::fd::AsFd,
    name: &str,
    budget: &mut Budget,
) -> Result<Vec<u8>> {
    budget.sample(super::clock::now())?;
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| deny("native_standing_history_file"))?;
    let mut file = File::from(fd);
    let result = (|| {
        let before = file
            .metadata()
            .map_err(|_| deny("native_standing_history_file"))?;
        if !before.is_file()
            || before.uid() != rustix::process::geteuid().as_raw()
            || before.mode() & 0o777 != 0o600
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > native_custody::MAX_LOG_BYTES
        {
            return Err(deny("native_standing_history_custody"));
        }
        let mut raw = Vec::with_capacity(before.len() as usize);
        let mut chunk = [0u8; 8192];
        loop {
            budget.sample(super::clock::now())?;
            let count = file
                .read(&mut chunk)
                .map_err(|_| deny("native_standing_history_read"))?;
            if count == 0 {
                break;
            }
            if raw.len() + count > before.len() as usize {
                return Err(deny("native_standing_history_changed"));
            }
            raw.extend_from_slice(&chunk[..count]);
        }
        let after = file
            .metadata()
            .map_err(|_| deny("native_standing_history_file"))?;
        let named = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| deny("native_standing_history_file"))?;
        if (
            before.dev(),
            before.ino(),
            before.uid(),
            before.mode(),
            before.nlink(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.uid(),
            after.mode(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) || after.ino() != named.st_ino as u64
            || after.dev() != named.st_dev as u64
            || raw.len() as u64 != before.len()
        {
            return Err(deny("native_standing_history_changed"));
        }
        Ok(raw)
    })();
    let faults = nix::unistd::close(file)
        .err()
        .map(|_| "native_standing_log_close")
        .into_iter()
        .collect();
    super::files::native_cleanup(result, faults)
}
fn inventory(
    directory: &impl std::os::fd::AsFd,
    expected_count: usize,
    budget: &mut Budget,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    // rustix obtains an independent iterator from our held descriptor. No path
    // lookup, /proc dependency, symlink or namespace escape chooses the root.
    let entries =
        rustix::fs::Dir::read_from(directory).map_err(|_| deny("native_standing_inventory"))?;
    for entry in entries {
        budget.sample(super::clock::now())?;
        let entry = entry.map_err(|_| deny("native_standing_inventory"))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| deny("native_standing_inventory"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        if name.len() != 38
            || !name.ends_with(".jsonl")
            || !name[..32]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !names.insert(name.to_owned())
            || names.len() > expected_count
        {
            return Err(deny("native_standing_inventory"));
        }
    }
    Ok(names)
}

trait OwnerProbe {
    fn process(
        &self,
        original: &ProcessIncarnation,
    ) -> Result<(String, Option<ProcessIncarnation>)>;
    fn sockets(
        &self,
        original: &ProcessIncarnation,
        state: &str,
        budget: &mut Budget,
    ) -> Result<Option<Vec<String>>>;
}
struct LinuxOwnerProbe;
impl OwnerProbe for LinuxOwnerProbe {
    fn process(
        &self,
        original: &ProcessIncarnation,
    ) -> Result<(String, Option<ProcessIncarnation>)> {
        process_state(original)
    }
    fn sockets(
        &self,
        original: &ProcessIncarnation,
        state: &str,
        budget: &mut Budget,
    ) -> Result<Option<Vec<String>>> {
        socket_owners(original, state, budget)
    }
}
pub(crate) fn collect(
    profile: &StandingProfile,
    auth: &Authenticated,
    budget: &mut Budget,
) -> Result<StandingObservation> {
    profile.authenticate(auth)?;
    let directory = native_custody::private_directory(Path::new(native_custody::ROOT))?;
    collect_owned(profile, auth, budget, directory, &LinuxOwnerProbe)
}
// Source controls substitute only the final kernel observation boundary. File
// custody, scope authentication, complete reads/folding and cleanup stay real.
fn collect_owned(
    profile: &StandingProfile,
    auth: &Authenticated,
    budget: &mut Budget,
    directory: super::files::PrivateDirectory,
    probe: &impl OwnerProbe,
) -> Result<StandingObservation> {
    profile.authenticate(auth)?;
    let result = (|| {
        let original_directory =
            fstat(directory.native_descriptor()?).map_err(|_| deny("native_standing_directory"))?;
        let expected = profile
            .scopes
            .iter()
            .map(|scope| format!("{}.jsonl", scope.custody_id))
            .collect::<BTreeSet<_>>();
        if inventory(directory.native_descriptor()?, expected.len(), budget)? != expected {
            return Err(deny("native_standing_incomplete_inventory"));
        }
        let mut scopes = Vec::new();
        for scope in &profile.scopes {
            auth.current(budget.sample(super::clock::now())?)?;
            let name = format!("{}.jsonl", scope.custody_id);
            let raw = read_log(directory.native_descriptor()?, &name, budget)?;
            let mut observation = fold(
                scope,
                &profile.retained_anchors[&scope.custody_id],
                &raw,
                budget.sample(super::clock::now())?,
            )?;
            let before = probe.process(&observation.original_process)?;
            let sockets_before = probe.sockets(&observation.original_process, &before.0, budget)?;
            observation.credential_file_status = credential_file_state(scope)?;
            let after = probe.process(&observation.original_process)?;
            let sockets_after = probe.sockets(&observation.original_process, &after.0, budget)?;
            if before != after || sockets_before != sockets_after {
                return Err(deny("native_standing_owner_changed"));
            }
            observation.socket_inodes = sockets_after;
            (observation.process_status, observation.current_process) = after;
            if observation.process_status == "LIVE"
                || observation.credential_file_status == "PRESENT"
            {
                observation.local_status = "LIVE".into();
            } else if matches!(observation.process_status.as_str(), "ABSENT" | "REPLACED")
                && observation.credential_file_status == "ABSENT"
                && observation.open_capabilities.is_empty()
                && matches!(
                    observation.history.last().map(|r| &r.event),
                    Some(CustodyEvent::Released)
                )
            {
                observation.local_status = "RETIRED".into();
            }
            if observation.local_status == "UNKNOWN" {
                observation
                    .unresolved
                    .push("native-owner-or-credential-custody-unknown".into());
            }
            if read_log(directory.native_descriptor()?, &name, budget)? != raw {
                return Err(deny("native_standing_history_changed"));
            }
            scopes.push(observation);
        }
        if inventory(directory.native_descriptor()?, expected.len(), budget)? != expected {
            return Err(deny("native_standing_incomplete_inventory"));
        }
        let after =
            fstat(directory.native_descriptor()?).map_err(|_| deny("native_standing_directory"))?;
        if (
            original_directory.st_dev,
            original_directory.st_ino,
            original_directory.st_uid,
            original_directory.st_mode,
        ) != (after.st_dev, after.st_ino, after.st_uid, after.st_mode)
        {
            return Err(deny("native_standing_directory"));
        }
        auth.current(budget.sample(super::clock::now())?)?;
        Ok(StandingObservation {
            kind: "llull-buzz-private-native-standing/v1".into(),
            status: "PARTIAL".into(),
            request_sha256: auth.request_hash().into(),
            challenge: auth.request().challenge.clone(),
            observed_us: budget.sample(super::clock::now())?,
            scopes,
            unresolved: vec!["external-authority-unverified".into()],
        })
    })();
    super::files::native_cleanup(result, directory.close())
}

#[cfg(test)]
pub(super) fn synthetic_receiver_owner() -> OwnerObservation {
    tests::receiver_owner(0)
}
#[cfg(test)]
pub(super) fn synthetic_receiver_owner_at_age(age: u64) -> OwnerObservation {
    tests::receiver_owner(age)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> NativeCustodyScope {
        NativeCustodyScope {
            kind: "llull-buzz-native-custody-scope/v1".into(),
            custody_id: "a".repeat(32),
            installation: "test-installation".into(),
            source_revision: "b244ba7560112e498ee6d68a48d035c99cb0b8c2".into(),
            implementation_sha256: super::super::relations::implementation_sha256(),
            membership_sha256: "a".repeat(64),
            operation_ref: "original-operation".into(),
            operation_sha256: "b".repeat(64),
            configuration_sha256: "c".repeat(64),
            configuration_generation: 1,
            source_copy_sha256: "d".repeat(64),
            target_copy_sha256: "e".repeat(64),
            community_id: "community-a".into(),
            private_origin: "http://127.0.0.1:18443/".into(),
            public_origin: "https://native.synthetic.invalid/".into(),
            relay_public_key: "f".repeat(64),
            credential_public_key: nostr::Keys::generate().public_key().to_hex(),
            credential_file: "/var/lib/llull-buzz/native-keys/original.key".into(),
        }
    }
    fn process() -> ProcessIncarnation {
        ProcessIncarnation {
            machine_id: "a".repeat(32),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            pid: 1001,
            start_ticks: 12345,
            uid: 1001,
            namespaces: ["net", "mnt", "user", "pid"]
                .into_iter()
                .map(|n| (n.into(), format!("{n}:[1001]")))
                .collect(),
        }
    }
    fn encode(scope: &NativeCustodyScope, events: &[CustodyEvent]) -> Vec<u8> {
        let mut raw = Vec::new();
        let mut previous = native_custody::ZERO.to_owned();
        for (sequence, event) in events.iter().enumerate() {
            let record = CustodyRecord {
                kind: "llull-buzz-native-custody-record/v1".into(),
                sequence: sequence as u64,
                previous_sha256: previous,
                scope_sha256: scope.digest().unwrap(),
                observed_us: 1000 + sequence as i64,
                event: event.clone(),
            };
            let line = llull_buzz_wire::canonical(&record).unwrap();
            previous = llull_buzz_wire::sha256(&line);
            raw.extend(line);
            raw.push(b'\n');
        }
        raw
    }
    fn anchor(scope: &NativeCustodyScope) -> HistoryAnchor {
        let raw = encode(scope, &events(scope));
        let lines = raw[..raw.len() - 1]
            .split(|b| *b == b'\n')
            .collect::<Vec<_>>();
        HistoryAnchor {
            acquisition_sha256: llull_buzz_wire::sha256(lines[0]),
            prefix_records: lines.len() as u64,
            prefix_head_sha256: llull_buzz_wire::sha256(lines[lines.len() - 1]),
        }
    }
    fn events(scope: &NativeCustodyScope) -> Vec<CustodyEvent> {
        vec![
            CustodyEvent::Acquire {
                scope: Box::new(scope.clone()),
                process: process(),
                key_file_sha256: "0".repeat(64),
            },
            CustodyEvent::CapabilityOpen {
                capability: "native-http".into(),
            },
            CustodyEvent::CredentialIssued {
                capability: "native-http".into(),
                event_id: "1".repeat(64),
                token_sha256: "2".repeat(64),
                kind: 24242,
                explicit_expiration: Some(30),
            },
            CustodyEvent::CapabilityClosed {
                capability: "native-http".into(),
            },
            CustodyEvent::Released,
        ]
    }
    #[test]
    fn native_standing_complete_original_history_retains_remote_uncertainty() {
        let scope = scope();
        scope.validate().unwrap();
        let raw = encode(&scope, &events(&scope));
        let view = fold(&scope, &anchor(&scope), &raw, 2000).unwrap();
        assert_eq!(view.history.len(), 5);
        assert_eq!(view.history_sha256, llull_buzz_wire::sha256(&raw));
        assert!(view.open_capabilities.is_empty());
        assert_eq!(view.local_status, "UNKNOWN"); // folding is not kernel observation.
        assert_eq!(
            view.unresolved,
            [
                "external-authority-unverified",
                "credential-public-claims-unavailable"
            ]
        );
        assert_eq!(view.original_process, process());
    }
    #[test]
    fn native_standing_missing_extra_or_reordered_exposures_never_form_a_complete_history() {
        let scope = scope();
        let original = events(&scope);
        for events in [
            original[1..].to_vec(),
            original[..2]
                .iter()
                .cloned()
                .chain(original[3..].iter().cloned())
                .collect(),
            vec![original[0].clone(), original[0].clone()],
            vec![original[0].clone(), original[3].clone()],
            vec![
                original[0].clone(),
                original[1].clone(),
                original[4].clone(),
            ],
            original
                .iter()
                .cloned()
                .chain([original[1].clone()])
                .collect(),
        ] {
            assert!(fold(&scope, &anchor(&scope), &encode(&scope, &events), 2000).is_err());
        }
        let raw = encode(&scope, &original);
        assert!(fold(&scope, &anchor(&scope), &raw[..raw.len() - 1], 2000).is_err());
        let second_line = raw.split(|b| *b == b'\n').nth(1).unwrap();
        let mut prefix_lost = second_line.to_vec();
        prefix_lost.push(b'\n');
        assert!(fold(&scope, &anchor(&scope), &prefix_lost, 2000).is_err());
    }
    #[test]
    fn native_standing_wrong_original_action_configuration_copy_and_incarnation_deny() {
        let original = scope();
        let raw = encode(&original, &events(&original));
        for field in [
            "operation_ref",
            "operation_sha256",
            "configuration_sha256",
            "configuration_generation",
            "source_copy_sha256",
            "target_copy_sha256",
            "credential_public_key",
            "custody_id",
        ] {
            let mut value = serde_json::to_value(&original).unwrap();
            value[field] = if field == "configuration_generation" {
                2.into()
            } else {
                "0".repeat(if field == "custody_id" { 32 } else { 64 })
                    .into()
            };
            let changed: NativeCustodyScope = serde_json::from_value(value).unwrap();
            assert!(
                fold(&changed, &anchor(&original), &raw, 2000).is_err(),
                "{field}"
            );
        }
        let mut forged = raw.clone();
        let at = forged.windows(5).position(|w| w == b"12345").unwrap();
        forged[at] = b'9';
        assert!(fold(&original, &anchor(&original), &forged, 2000).is_err());
    }
    #[test]
    fn native_standing_live_capability_and_future_or_duplicate_issuance_refuse_retirement() {
        let scope = scope();
        let events = events(&scope);
        let mut initial_anchor = anchor(&scope);
        initial_anchor.prefix_records = 1;
        initial_anchor.prefix_head_sha256 = initial_anchor.acquisition_sha256.clone();
        let view = fold(&scope, &initial_anchor, &encode(&scope, &events[..3]), 2000).unwrap();
        assert_eq!(view.open_capabilities["native-http"], 1);
        assert_eq!(view.local_status, "UNKNOWN");
        assert!(fold(&scope, &anchor(&scope), &encode(&scope, &events), 1002).is_err());
        let mut bad = events.clone();
        bad[2] = CustodyEvent::CredentialIssued {
            capability: "native-publication".into(),
            event_id: "a".repeat(64),
            token_sha256: "b".repeat(64),
            kind: 24242,
            explicit_expiration: None,
        };
        assert!(fold(&scope, &anchor(&scope), &encode(&scope, &bad), 2000).is_err());
        assert!(super::super::clock::Budget::new(2000, 2000).is_err());
    }
    #[test]
    fn native_standing_real_signer_legacy_preserves_signed_event_contract() {
        let key = nostr::Keys::generate();
        let public = key.public_key();
        let signer: crate::native_custody::NativeSigner = key.into();
        let event = signer
            .sign(nostr::EventBuilder::new(
                nostr::Kind::Custom(24242),
                "synthetic",
            ))
            .unwrap();
        assert_eq!(event.pubkey, public);
        event.verify().unwrap();
    }
    #[test]
    fn native_standing_profile_exact_signed_original_scope_and_membership() {
        let (trust, profile, request, _, now) = super::super::authority::synthetic_port_inputs();
        let mut budget = Budget::new(now, now + 20_000_000).unwrap();
        let auth = Authenticated::admit(&trust, &profile, &request, &mut budget, now).unwrap();
        let mut scope = scope();
        let r = auth.request();
        scope.membership_sha256 = auth.profile().membership_sha256.clone();
        scope.operation_ref = r.operation_ref.clone();
        scope.operation_sha256 = r.operation_sha256.clone();
        scope.configuration_sha256 = r.configuration_sha256.clone();
        scope.configuration_generation = r.configuration_generation;
        scope.source_copy_sha256 = r.source_copy_sha256.clone();
        scope.target_copy_sha256 = r.target_copy_sha256.clone();
        let profile = StandingProfile {
            kind: "llull-buzz-native-standing-profile/v1".into(),
            retained_anchors: BTreeMap::from([(scope.custody_id.clone(), anchor(&scope))]),
            scopes: vec![scope],
        };
        profile.authenticate(&auth).unwrap();
        let mut duplicated = profile.clone();
        duplicated.scopes.push(profile.scopes[0].clone());
        assert!(duplicated.authenticate(&auth).is_err());
        let mut copied = profile;
        copied.scopes[0].membership_sha256 = "0".repeat(64);
        assert!(copied.authenticate(&auth).is_err());
    }
    struct Fixture {
        root: std::path::PathBuf,
        logs: std::path::PathBuf,
        keys: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("buzz-native-custody-{}", uuid::Uuid::new_v4()));
            let logs = root.join("logs");
            let keys = root.join("keys");
            for path in [&root, &logs, &keys] {
                std::fs::create_dir(path).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self { root, logs, keys }
        }
        fn file(&self, path: &Path, raw: &[u8]) {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(raw).unwrap();
            file.sync_all().unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }
    fn inert_process() -> Result<ProcessIncarnation> {
        let mut p = process();
        p.uid = rustix::process::geteuid().as_raw();
        Ok(p)
    }
    enum InertState {
        Absent,
        Live,
        Changed,
        Unknown,
    }
    struct InertProbe(InertState);
    impl OwnerProbe for InertProbe {
        fn process(
            &self,
            original: &ProcessIncarnation,
        ) -> Result<(String, Option<ProcessIncarnation>)> {
            Ok(match self.0 {
                InertState::Absent => ("ABSENT".into(), None),
                InertState::Live => ("LIVE".into(), Some(original.clone())),
                InertState::Changed => {
                    let mut p = original.clone();
                    p.start_ticks += 1;
                    ("REPLACED".into(), Some(p))
                }
                InertState::Unknown => ("UNKNOWN".into(), None),
            })
        }
        fn sockets(
            &self,
            _: &ProcessIncarnation,
            state: &str,
            budget: &mut Budget,
        ) -> Result<Option<Vec<String>>> {
            budget.sample(super::super::clock::now())?;
            Ok(match state {
                "LIVE" => Some(vec!["123456".into()]),
                "ABSENT" | "REPLACED" => Some(Vec::new()),
                _ => None,
            })
        }
    }
    fn fixture_scope(f: &Fixture, public_key: &str) -> NativeCustodyScope {
        let (trust, profile, request, _, now) = super::super::authority::synthetic_port_inputs();
        let mut budget = Budget::new(now, now + 20_000_000).unwrap();
        let auth = Authenticated::admit(&trust, &profile, &request, &mut budget, now).unwrap();
        let mut scope = scope();
        let r = auth.request();
        scope.membership_sha256 = auth.profile().membership_sha256.clone();
        scope.operation_ref = r.operation_ref.clone();
        scope.operation_sha256 = r.operation_sha256.clone();
        scope.configuration_sha256 = r.configuration_sha256.clone();
        scope.configuration_generation = r.configuration_generation;
        scope.source_copy_sha256 = r.source_copy_sha256.clone();
        scope.target_copy_sha256 = r.target_copy_sha256.clone();
        scope.credential_public_key = public_key.into();
        scope.credential_file = f.keys.join("synthetic.key").to_str().unwrap().into();
        scope
    }
    fn actual_history(f: &Fixture) -> (NativeCustodyScope, Vec<u8>) {
        actual_history_with_native(f, false, 0)
    }
    fn actual_history_with_native(
        f: &Fixture,
        with_native_http: bool,
        age: u64,
    ) -> (NativeCustodyScope, Vec<u8>) {
        let key = nostr::Keys::generate();
        let scope = fixture_scope(f, &key.public_key().to_hex());
        f.file(
            Path::new(&scope.credential_file),
            key.secret_key().to_secret_hex().as_bytes(),
        );
        let credential = crate::native_custody::NativeCredential::acquire_synthetic_fixture(
            scope.clone(),
            Path::new(&scope.credential_file),
            &f.logs,
            inert_process,
        )
        .unwrap();
        let http = credential.signer("native-http").unwrap();
        let publisher = credential.signer("native-publication").unwrap();
        let consumer = credential.signer("consumer-http").unwrap();
        if with_native_http {
            http.sign(
                nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
                    .custom_created_at(nostr::Timestamp::from_secs(
                        nostr::Timestamp::now().as_secs().saturating_sub(age),
                    ))
                    .tags([
                        nostr::Tag::parse(["u", "https://native.synthetic.invalid/query"]).unwrap(),
                        nostr::Tag::parse(["method", "POST"]).unwrap(),
                        nostr::Tag::parse([
                            "payload",
                            &llull_buzz_wire::sha256(b"synthetic original request"),
                        ])
                        .unwrap(),
                    ]),
            )
            .unwrap()
            .verify()
            .unwrap();
        }
        assert!(credential.signer("unregistered-channel").is_err());
        let event = http
            .sign(
                nostr::EventBuilder::new(nostr::Kind::Custom(24242), "synthetic read").tags([
                    nostr::Tag::parse([
                        "expiration",
                        &(nostr::Timestamp::now().as_secs() + 30).to_string(),
                    ])
                    .unwrap(),
                    nostr::Tag::parse(["t", "get"]).unwrap(),
                    nostr::Tag::parse(["x", &"b".repeat(64)]).unwrap(),
                ]),
            )
            .unwrap();
        event.verify().unwrap();
        let publication = publisher
            .sign(
                buzz_sdk::build_message(
                    uuid::Uuid::nil(),
                    "synthetic text",
                    None,
                    &[],
                    false,
                    &[],
                    &[],
                )
                .unwrap()
                .tag(
                    nostr::Tag::parse(["llull-publication", &uuid::Uuid::nil().to_string()])
                        .unwrap(),
                ),
            )
            .unwrap();
        publication.verify().unwrap();
        consumer
            .bind_public_origin("https://native.synthetic.invalid/command")
            .unwrap();
        assert!(consumer
            .bind_public_origin("https://foreign.invalid/command")
            .is_err());
        let invocation = consumer
            .sign(nostr::EventBuilder::new(nostr::Kind::HttpAuth, "").tags([
                nostr::Tag::parse(["u", "https://native.synthetic.invalid/command"]).unwrap(),
                nostr::Tag::parse(["method", "POST"]).unwrap(),
                nostr::Tag::parse(["payload", &"a".repeat(64)]).unwrap(),
            ]))
            .unwrap();
        invocation.verify().unwrap();
        assert!(consumer
            .sign(nostr::EventBuilder::new(
                nostr::Kind::Custom(9),
                "foreign capability"
            ))
            .is_err());
        drop(consumer);
        drop(http);
        drop(publisher);
        drop(credential);
        let raw = std::fs::read(f.logs.join(format!("{}.jsonl", scope.custody_id))).unwrap();
        (scope, raw)
    }
    pub(super) fn receiver_owner(age: u64) -> OwnerObservation {
        let f = Fixture::new();
        let (scope, raw) = actual_history_with_native(&f, true, age);
        let (auth, _, _) = signed_profile(scope.clone(), &raw);
        fold(
            &scope,
            &auth
                .profile()
                .native_standing
                .as_ref()
                .unwrap()
                .retained_anchors[&scope.custody_id],
            &raw,
            super::super::clock::now(),
        )
        .unwrap()
    }
    fn signed_profile(scope: NativeCustodyScope, raw: &[u8]) -> (Authenticated, Budget, Vec<u8>) {
        let lines = raw[..raw.len() - 1]
            .split(|b| *b == b'\n')
            .collect::<Vec<_>>();
        let anchor = HistoryAnchor {
            acquisition_sha256: llull_buzz_wire::sha256(lines[0]),
            prefix_records: lines.len() as u64,
            prefix_head_sha256: llull_buzz_wire::sha256(lines[lines.len() - 1]),
        };
        let profile = StandingProfile {
            kind: "llull-buzz-native-standing-profile/v1".into(),
            retained_anchors: BTreeMap::from([(scope.custody_id.clone(), anchor)]),
            scopes: vec![scope],
        };
        let (trust, profile, request, key, now) =
            super::super::authority::synthetic_native_standing_inputs(profile);
        let mut budget = Budget::new(now, now + 20_000_000).unwrap();
        let auth = Authenticated::admit(&trust, &profile, &request, &mut budget, now).unwrap();
        (auth, budget, key)
    }
    #[test]
    fn native_standing_real_acquisition_sign_release_and_protected_collector_positive() {
        let f = Fixture::new();
        let (scope, raw) = actual_history(&f);
        std::fs::remove_file(&scope.credential_file).unwrap(); // only the owned synthetic fixture credential.
        let (auth, mut budget, signer) = signed_profile(scope, &raw);
        let directory = native_custody::private_directory(&f.logs).unwrap();
        let observation = collect_owned(
            auth.profile().native_standing.as_ref().unwrap(),
            &auth,
            &mut budget,
            directory,
            &InertProbe(InertState::Absent),
        )
        .unwrap();
        assert_eq!(observation.scopes[0].local_status, "RETIRED");
        assert_eq!(observation.scopes[0].history.len(), 11);
        assert_eq!(observation.scopes[0].socket_inodes, Some(vec![]));
        assert_eq!(observation.status, "PARTIAL");
        assert_eq!(observation.unresolved, ["external-authority-unverified"]);
        let raw_body = serde_json::to_value(&observation).unwrap();
        let body_digest = llull_buzz_wire::sha256(&serde_json::to_vec(&raw_body).unwrap());
        let signed = auth
            .sign(
                observation,
                &signer,
                super::super::clock::now(),
                auth.expires(),
            )
            .unwrap();
        auth.verify_response(&signed, &body_digest, super::super::clock::now())
            .unwrap();
        assert!(!String::from_utf8(signed).unwrap().contains("PRIVATE KEY"));
    }
    #[test]
    fn native_standing_public_claims_capture_actual_signed_scope_without_reusable_event() {
        use crate::native_custody::{NativeCredential, PublicCredentialScope};
        let f = Fixture::new();
        let key = nostr::Keys::generate();
        let secret = key.secret_key().to_secret_hex();
        let scope = fixture_scope(&f, &key.public_key().to_hex());
        f.file(Path::new(&scope.credential_file), secret.as_bytes());
        let credential = NativeCredential::acquire_synthetic_fixture(
            scope.clone(),
            Path::new(&scope.credential_file),
            &f.logs,
            inert_process,
        )
        .unwrap();
        let channel = uuid::Uuid::new_v4();
        let publication_id = uuid::Uuid::new_v4();
        let expiration = nostr::Timestamp::now().as_secs() + 30;
        let thread = buzz_sdk::ThreadRef {
            root_event_id: nostr::EventId::from_hex(&"a".repeat(64)).unwrap(),
            parent_event_id: nostr::EventId::from_hex(&"b".repeat(64)).unwrap(),
        };
        let http = |url| {
            nostr::EventBuilder::new(nostr::Kind::HttpAuth, "").tags([
                nostr::Tag::parse(["u", url]).unwrap(),
                nostr::Tag::parse(["method", "POST"]).unwrap(),
                nostr::Tag::parse(["payload", &llull_buzz_wire::sha256(b"original body")]).unwrap(),
                nostr::Tag::parse(["nonce", "synthetic-public-nonce"]).unwrap(),
            ])
        };
        let builders = [
            (
                "native-http",
                http("https://native.synthetic.invalid/query"),
            ),
            (
                "consumer-http",
                http("https://native.synthetic.invalid/command"),
            ),
            (
                "native-http",
                nostr::EventBuilder::new(nostr::Kind::Custom(24242), "Read original attachment")
                    .tags([
                        nostr::Tag::parse(["t", "get"]).unwrap(),
                        nostr::Tag::parse(["x", &"c".repeat(64)]).unwrap(),
                        nostr::Tag::parse(["expiration", &expiration.to_string()]).unwrap(),
                    ]),
            ),
            (
                "native-publication",
                buzz_sdk::build_message(
                    channel,
                    "original publication text",
                    Some(&thread),
                    &[],
                    false,
                    &[],
                    &[],
                )
                .unwrap()
                .tag(
                    nostr::Tag::parse(["llull-publication", &publication_id.to_string()]).unwrap(),
                ),
            ),
        ];
        let mut signed = Vec::new();
        for (capability, builder) in builders {
            let signer = credential.signer(capability).unwrap();
            let event = signer.sign(builder).unwrap();
            event.verify().unwrap();
            signed.push(event);
        }
        drop(credential);
        let raw = std::fs::read(f.logs.join(format!("{}.jsonl", scope.custody_id))).unwrap();
        let lines = raw[..raw.len() - 1]
            .split(|b| *b == b'\n')
            .collect::<Vec<_>>();
        let anchor = HistoryAnchor {
            acquisition_sha256: llull_buzz_wire::sha256(lines[0]),
            prefix_records: lines.len() as u64,
            prefix_head_sha256: llull_buzz_wire::sha256(lines[lines.len() - 1]),
        };
        let observation = fold(&scope, &anchor, &raw, super::super::clock::now()).unwrap();
        let issued = observation
            .history
            .iter()
            .filter_map(|r| match &r.event {
                CustodyEvent::CredentialIssuedV2 {
                    capability,
                    event_id,
                    token_sha256,
                    kind,
                    public_claims,
                } => Some((capability, event_id, token_sha256, kind, public_claims)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(issued.len(), 4);
        for ((_, id, token, kind, claims), event) in issued.iter().zip(&signed) {
            assert_eq!(**id, event.id.to_hex());
            assert_eq!(
                **token,
                llull_buzz_wire::sha256(&serde_json::to_vec(event).unwrap())
            );
            assert_eq!(**kind, event.kind.as_u16());
            assert_eq!(claims.public_key, event.pubkey.to_hex());
            assert_eq!(claims.created_at, event.created_at.as_secs());
            assert_eq!(
                claims.content_sha256,
                llull_buzz_wire::sha256(event.content.as_bytes())
            );
            assert_eq!(
                claims.tags_sha256,
                llull_buzz_wire::digest(
                    &event
                        .tags
                        .iter()
                        .map(|t| t.as_slice().to_vec())
                        .collect::<Vec<_>>()
                )
                .unwrap()
            );
            let claims_raw = llull_buzz_wire::canonical(claims).unwrap();
            assert!(!String::from_utf8_lossy(&claims_raw).contains(&event.sig.to_string()));
        }
        for (event, url) in signed[..2].iter().zip([
            "https://native.synthetic.invalid/query",
            "https://native.synthetic.invalid/command",
        ]) {
            assert_eq!(
                buzz_auth::verify_nip98_event(
                    &serde_json::to_string(event).unwrap(),
                    url,
                    "POST",
                    Some(b"original body")
                )
                .unwrap(),
                key.public_key()
            );
            assert!(buzz_auth::verify_nip98_event(
                &serde_json::to_string(event).unwrap(),
                url,
                "POST",
                Some(b"changed body")
            )
            .is_err());
        }
        assert!(
            matches!(&issued[0].4.scope, PublicCredentialScope::Nip98 { url, method, payload_sha256, nonce_sha256 } if url.ends_with("/query") && method == "POST" && payload_sha256 == &llull_buzz_wire::sha256(b"original body") && nonce_sha256.as_deref() == Some(llull_buzz_wire::sha256(b"synthetic-public-nonce").as_str()))
        );
        assert!(
            matches!(&issued[2].4.scope, PublicCredentialScope::MediaGet { blob_sha256, expiration: actual } if blob_sha256 == &"c".repeat(64) && *actual == expiration)
        );
        assert!(
            matches!(&issued[3].4.scope, PublicCredentialScope::Publication { channel_id, publication_id: id, thread: actual } if channel_id == &channel.to_string() && id == &publication_id.to_string() && actual["root"] == thread.root_event_id.to_hex() && actual["reply"] == thread.parent_event_id.to_hex())
        );
        let text = String::from_utf8(raw).unwrap();
        assert!(!text.contains(&secret));
        assert!(!text.contains("original publication text"));
        assert!(!text.contains("synthetic-public-nonce"));
        assert_eq!(observation.unresolved, ["external-authority-unverified"]);
        // Expiration is retained verbatim, not turned into remote retirement.
        assert_eq!(observation.local_status, "UNKNOWN");
    }
    #[test]
    fn native_standing_public_claims_refuse_ambiguous_unbound_and_unaccounted_signatures() {
        let f = Fixture::new();
        let key = nostr::Keys::generate();
        let scope = fixture_scope(&f, &key.public_key().to_hex());
        f.file(
            Path::new(&scope.credential_file),
            key.secret_key().to_secret_hex().as_bytes(),
        );
        let credential = crate::native_custody::NativeCredential::acquire_synthetic_fixture(
            scope.clone(),
            Path::new(&scope.credential_file),
            &f.logs,
            inert_process,
        )
        .unwrap();
        let signer = credential.signer("native-http").unwrap();
        let http = |url: &str, method: &str, payload: &str| {
            nostr::EventBuilder::new(nostr::Kind::HttpAuth, "").tags([
                nostr::Tag::parse(["u", url]).unwrap(),
                nostr::Tag::parse(["method", method]).unwrap(),
                nostr::Tag::parse(["payload", payload]).unwrap(),
            ])
        };
        for bad in [
            nostr::EventBuilder::new(nostr::Kind::HttpAuth, ""),
            http("https://foreign.invalid/query", "POST", &"a".repeat(64)),
            http(
                "https://native.synthetic.invalid/unregistered",
                "POST",
                &"a".repeat(64),
            ),
            http(
                "https://native.synthetic.invalid/query",
                "GET",
                &"a".repeat(64),
            ),
            http(
                "https://native.synthetic.invalid/query",
                "POST",
                "not-a-sha256",
            ),
            http(
                "https://native.synthetic.invalid/query",
                "POST",
                &"a".repeat(64),
            )
            .tag(nostr::Tag::parse(["u", "https://native.synthetic.invalid/events"]).unwrap()),
            http(
                "https://native.synthetic.invalid/query",
                "POST",
                &"a".repeat(64),
            )
            .tag(nostr::Tag::parse(["expiration", "9000"]).unwrap()),
            nostr::EventBuilder::new(nostr::Kind::Custom(24242), "Read").tags([
                nostr::Tag::parse(["t", "get"]).unwrap(),
                nostr::Tag::parse(["server", "native.synthetic.invalid"]).unwrap(),
                nostr::Tag::parse(["expiration", "1234"]).unwrap(),
            ]),
            nostr::EventBuilder::new(nostr::Kind::Custom(24242), "Read").tags([
                nostr::Tag::parse(["t", "get"]).unwrap(),
                nostr::Tag::parse(["x", &"a".repeat(64)]).unwrap(),
                nostr::Tag::parse(["expiration", "01234"]).unwrap(),
            ]),
        ] {
            assert!(signer.sign(bad).is_err());
        }
        drop(signer);
        drop(credential);
        let raw = std::fs::read(f.logs.join(format!("{}.jsonl", scope.custody_id))).unwrap();
        for line in raw[..raw.len() - 1].split(|b| *b == b'\n') {
            let record: CustodyRecord = llull_buzz_wire::parse(line).unwrap();
            assert!(!matches!(
                record.event,
                CustodyEvent::CredentialIssuedV2 { .. }
            ));
        }
    }
    #[test]
    fn native_standing_public_claims_fold_rechecks_original_key_capability_and_closed_shape() {
        let f = Fixture::new();
        let (scope, raw) = actual_history(&f);
        let events = raw[..raw.len() - 1]
            .split(|b| *b == b'\n')
            .map(|line| llull_buzz_wire::parse::<CustodyRecord>(line).unwrap().event)
            .collect::<Vec<_>>();
        let issuance_index = events
            .iter()
            .position(|event| matches!(event, CustodyEvent::CredentialIssuedV2 { .. }))
            .unwrap();
        let original = encode(&scope, &events);
        let first = original.split(|b| *b == b'\n').next().unwrap();
        let anchor = HistoryAnchor {
            acquisition_sha256: llull_buzz_wire::sha256(first),
            prefix_records: 1,
            prefix_head_sha256: llull_buzz_wire::sha256(first),
        };
        fold(&scope, &anchor, &original, 2000).unwrap();
        for (field, value) in [
            ("public_key", serde_json::json!("f".repeat(64))),
            ("kind", serde_json::json!("future-unregistered-contract/v2")),
            ("tags_sha256", serde_json::json!("not-a-hash")),
            (
                "scope",
                serde_json::json!({"type":"media-get", "blob_sha256":"bad", "expiration":30}),
            ),
            (
                "scope",
                serde_json::json!({"type":"publication", "channel_id":uuid::Uuid::nil(), "publication_id":uuid::Uuid::nil(), "thread":{}}),
            ),
        ] {
            let mut altered = events.clone();
            let CustodyEvent::CredentialIssuedV2 { public_claims, .. } =
                &mut altered[issuance_index]
            else {
                panic!("actual signed issuance missing")
            };
            let mut body = serde_json::to_value(&*public_claims).unwrap();
            body[field] = value;
            *public_claims = serde_json::from_value(body).unwrap();
            assert!(
                fold(&scope, &anchor, &encode(&scope, &altered), 2000).is_err(),
                "{field}"
            );
        }
        let mut widened = serde_json::to_value(&events[issuance_index]).unwrap();
        widened["public_claims"]["scope"]["server"] = "foreign.invalid".into();
        assert!(serde_json::from_value::<CustodyEvent>(widened).is_err());
        let CustodyEvent::CredentialIssuedV2 {
            public_claims,
            capability,
            kind,
            ..
        } = &events[issuance_index]
        else {
            unreachable!()
        };
        let mut unsafe_number = public_claims.clone();
        unsafe_number.created_at = 9_007_199_254_740_992;
        assert!(unsafe_number.validate(&scope, capability, *kind).is_err());
        assert!(llull_buzz_wire::canonical(&unsafe_number).is_err());
    }
    #[test]
    fn native_standing_actual_credential_file_and_live_or_unknown_process_never_retire() {
        for state in [
            InertState::Absent,
            InertState::Live,
            InertState::Changed,
            InertState::Unknown,
        ] {
            let f = Fixture::new();
            let (scope, raw) = actual_history(&f);
            let (auth, mut budget, _) = signed_profile(scope, &raw);
            let directory = native_custody::private_directory(&f.logs).unwrap();
            let view = collect_owned(
                auth.profile().native_standing.as_ref().unwrap(),
                &auth,
                &mut budget,
                directory,
                &InertProbe(state),
            )
            .unwrap();
            assert_eq!(view.scopes[0].credential_file_status, "PRESENT");
            assert_eq!(view.scopes[0].local_status, "LIVE");
        }
        let f = Fixture::new();
        let (scope, raw) = actual_history(&f);
        std::fs::remove_file(&scope.credential_file).unwrap();
        let (auth, mut budget, _) = signed_profile(scope, &raw);
        let directory = native_custody::private_directory(&f.logs).unwrap();
        let view = collect_owned(
            auth.profile().native_standing.as_ref().unwrap(),
            &auth,
            &mut budget,
            directory,
            &InertProbe(InertState::Unknown),
        )
        .unwrap();
        assert_eq!(view.scopes[0].local_status, "UNKNOWN");
        assert!(view.scopes[0]
            .unresolved
            .contains(&"native-owner-or-credential-custody-unknown".into()));
    }
    #[test]
    fn native_standing_missing_extra_replaced_and_truncated_physical_history_refuse() {
        use std::os::unix::fs::PermissionsExt;
        for fault in ["missing", "extra", "truncated", "mode", "symlink"] {
            let f = Fixture::new();
            let (scope, raw) = actual_history(&f);
            let path = f.logs.join(format!("{}.jsonl", scope.custody_id));
            let (auth, mut budget, _) = signed_profile(scope, &raw);
            match fault {
                "missing" => std::fs::remove_file(&path).unwrap(),
                "extra" => f.file(&f.logs.join(format!("{}.jsonl", "b".repeat(32))), &raw),
                "truncated" => std::fs::write(&path, &raw[..raw.len() - 1]).unwrap(),
                "mode" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "symlink" => {
                    std::fs::rename(&path, f.keys.join("held.jsonl")).unwrap();
                    std::os::unix::fs::symlink(f.keys.join("held.jsonl"), &path).unwrap();
                }
                _ => unreachable!(),
            }
            let directory = native_custody::private_directory(&f.logs).unwrap();
            assert!(
                collect_owned(
                    auth.profile().native_standing.as_ref().unwrap(),
                    &auth,
                    &mut budget,
                    directory,
                    &InertProbe(InertState::Absent)
                )
                .is_err(),
                "{fault}"
            );
        }
    }
    #[test]
    fn native_standing_duplicate_original_acquisition_and_cancelled_deadline_refuse() {
        use futures_util::FutureExt;
        let f = Fixture::new();
        let (scope, raw) = actual_history(&f);
        assert!(
            crate::native_custody::NativeCredential::acquire_synthetic_fixture(
                scope.clone(),
                Path::new(&scope.credential_file),
                &f.logs,
                inert_process
            )
            .is_err()
        );
        let (auth, mut budget, _) = signed_profile(scope, &raw);
        budget.watch(async {}.boxed().shared());
        let directory = native_custody::private_directory(&f.logs).unwrap();
        assert!(collect_owned(
            auth.profile().native_standing.as_ref().unwrap(),
            &auth,
            &mut budget,
            directory,
            &InertProbe(InertState::Absent)
        )
        .is_err());
        assert!(auth.current(auth.expires()).is_err());
        assert!(budget.sample(super::super::clock::now()).is_err());
    }
    #[test]
    fn native_standing_cleanup_failure_after_real_close_stays_unknown() {
        let f = Fixture::new();
        let (scope, raw) = actual_history(&f);
        std::fs::remove_file(&scope.credential_file).unwrap();
        let (auth, mut budget, _) = signed_profile(scope, &raw);
        let directory = native_custody::private_directory(&f.logs).unwrap();
        super::super::files::set_test_fault("native-close");
        let result = collect_owned(
            auth.profile().native_standing.as_ref().unwrap(),
            &auth,
            &mut budget,
            directory,
            &InertProbe(InertState::Absent),
        );
        super::super::files::set_test_fault("");
        assert!(matches!(
            result,
            Err(super::super::InspectionError::Unknown { .. })
        ));
    }
    #[test]
    fn native_standing_malformed_original_incarnation_is_not_a_qualified_owner() {
        for fault in [
            "pid",
            "start",
            "boot",
            "machine",
            "namespace",
            "missing_namespace",
        ] {
            let scope = scope();
            let mut events = events(&scope);
            if let CustodyEvent::Acquire { process, .. } = &mut events[0] {
                match fault {
                    "pid" => process.pid = 0,
                    "start" => process.start_ticks = 0,
                    "boot" => process.boot_id = "unobserved".into(),
                    "machine" => process.machine_id = "G".repeat(32),
                    "namespace" => {
                        process.namespaces.insert("net".into(), "net:[000]".into());
                    }
                    "missing_namespace" => {
                        process.namespaces.remove("user");
                    }
                    _ => unreachable!(),
                }
            }
            let raw = encode(&scope, &events);
            let lines = raw[..raw.len() - 1]
                .split(|b| *b == b'\n')
                .collect::<Vec<_>>();
            let anchor = HistoryAnchor {
                acquisition_sha256: llull_buzz_wire::sha256(lines[0]),
                prefix_records: lines.len() as u64,
                prefix_head_sha256: llull_buzz_wire::sha256(lines[lines.len() - 1]),
            };
            assert!(fold(&scope, &anchor, &raw, 2000).is_err(), "{fault}");
        }
    }
    #[test]
    #[ignore = "invoked only by bounded FIFO parent control with owned fixture environment"]
    fn native_standing_fifo_acquire_child() {
        let root = std::path::PathBuf::from(
            std::env::var_os("BUZZ_NATIVE_CUSTODY_FIFO_FIXTURE").expect("owned fixture only"),
        );
        let scope: NativeCustodyScope =
            llull_buzz_wire::parse(&std::fs::read(root.join("scope.json")).unwrap()).unwrap();
        let result = crate::native_custody::NativeCredential::acquire_synthetic_fixture(
            scope.clone(),
            Path::new(&scope.credential_file),
            &root.join("logs"),
            inert_process,
        );
        assert!(matches!(
            result,
            Err(super::super::InspectionError::Denied(
                "native_custody_key_file"
            ))
        ));
    }
    #[test]
    fn native_standing_fifo_keyleaf_is_refused_without_blocking() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let f = Fixture::new();
        let scope = fixture_scope(&f, &nostr::Keys::generate().public_key().to_hex());
        assert!(Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&scope.credential_file)
            .status()
            .unwrap()
            .success());
        f.file(
            &f.root.join("scope.json"),
            &llull_buzz_wire::canonical(&scope).unwrap(),
        );
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "inspection::standing::tests::native_standing_fifo_acquire_child",
                "--nocapture",
            ])
            .env("BUZZ_NATIVE_CUSTODY_FIFO_FIXTURE", &f.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut blocked = false;
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                blocked = true;
                let _ = child.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            !blocked,
            "owned acquisition child blocked on FIFO and was killed/reaped before any signing"
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn native_standing_socket_loop_actual_files_obeys_sticky_budget() {
        use futures_util::FutureExt;
        let f = Fixture::new();
        std::os::unix::fs::symlink("socket:[123]", f.keys.join("3")).unwrap();
        std::os::unix::fs::symlink("socket:[456]", f.keys.join("4")).unwrap();
        std::os::unix::fs::symlink("pipe:[789]", f.keys.join("5")).unwrap();
        let now = super::super::clock::now();
        let mut budget = Budget::new(now, now + 20_000_000).unwrap();
        assert_eq!(
            scan_socket_directory(&f.keys, &mut budget).unwrap(),
            ["123", "456"]
        );
        let mut expired = Budget::new(
            now - super::super::clock::MAX_ELAPSED_US - 1,
            now + 20_000_000,
        )
        .unwrap();
        assert!(scan_socket_directory(&f.keys, &mut expired).is_err());
        assert!(expired.sample(now).is_err());
        let mut cancelled = Budget::new(now, now + 20_000_000).unwrap();
        cancelled.watch(async {}.boxed().shared());
        assert!(scan_socket_directory(&f.keys, &mut cancelled).is_err());
        assert!(cancelled.sample(now).is_err());
    }
    #[test]
    fn native_standing_socket_inventory_refuses_before_compositional_overallocation() {
        let mut inventory = SocketInventory::new();
        let mut refused = false;
        for inode in 1..250_000_u64 {
            let before = (inventory.inodes.len(), inventory.encoded_bytes);
            if inventory.admit(&inode.to_string()).is_err() {
                assert_eq!((inventory.inodes.len(), inventory.encoded_bytes), before);
                assert!(inventory.encoded_bytes <= llull_buzz_wire::MAX_BYTES);
                refused = true;
                break;
            }
        }
        assert!(refused); // no trimmed inventory is emitted from a refused scan.
        for invalid in ["", "0", "01", "-1", "x", "18446744073709551616"] {
            assert!(SocketInventory::new().admit(invalid).is_err());
        }
    }
}
