//! Bounded local receiver observations. Source bytes and executable bytes are
//! measured separately: their presence never invents a source-to-image build
//! attestation, or a complete inventory of recipients of an original token.
use super::{authority::Authenticated, clock::Budget, deny, Result};
use crate::native_custody::{CustodyEvent, ProcessIncarnation, PublicCredentialScope};
use rustix::fs::{fstat, openat, statat, AtFlags, Mode, OFlags, CWD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    path::{Component, Path},
};

pub const UPSTREAM: &str = "01b6174a1cbad249e93f31df97d4b2ed1d0e8638";
pub const PROGRAM: &str = "/opt/llull/upstream/buzz-relay";
/// Exact read-only source observations at the selected upstream revision.
/// Full-file hashes cover the verifier and the actual relay call sites.
pub const POLICY_FILES: [(&str, &str); 4] = [
    (
        "crates/buzz-auth/src/nip98.rs",
        "2114a61c8d9f6607adac9cc4e1a1b2943b17459bcd3d043896a27bfcce4d13b0",
    ),
    (
        "crates/buzz-media/src/auth.rs",
        "18b23b08669366c5f62d3c6a3a06bea57b5c596c8b82b9197b23fb201739acda",
    ),
    (
        "crates/buzz-relay/src/api/bridge.rs",
        "12719eb8211f6ccefa196a4630433d08ae8548deb41b9bc3251fa536bc76dd6e",
    ),
    (
        "crates/buzz-relay/src/api/media.rs",
        "a3a054cfa08b3c5687b36ba44d7088b218d4bf6f8cdd94c3c186938f4d5c0cf1",
    ),
];
const MAX_SOURCE: u64 = 1024 * 1024;
const MAX_PROGRAM: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverProfile {
    pub kind: String,
    pub receivers: Vec<ReceiverSelection>,
}
/// Authenticated selection, not an installed source/image attestation. The
/// protected consumer must independently join the original build/image record
/// to these measured bytes before using any conditional rejection boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverSelection {
    pub receiver_id: String,
    pub custody_ids: Vec<String>,
    pub process: ProcessIncarnation,
    pub program: String,
    pub executable_sha256: String,
    pub source_root: String,
    pub upstream_revision: String,
    pub source_image_admission_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeasuredFile {
    /// Executable paths are absolute in receiver rootfs; policy source paths
    /// are absolute on the authenticated observer host. The admission joins
    /// these two distinct file domains; neither substitutes for the other.
    pub path: String,
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClockDomain {
    pub collector: ProcessIncarnation,
    pub receiver: ProcessIncarnation,
    pub time_namespace: String,
    pub time_offsets_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConditionalRejection {
    pub custody_id: String,
    pub event_id: String,
    pub token_sha256: String,
    pub capability: String,
    pub policy: String,
    /// First integer receiver-clock second at which the selected source rejects.
    /// This is NOT a claim that an installed receiver enforces that source.
    pub reject_at_secs: Option<u64>,
    pub elapsed_at_observation: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverObservation {
    pub receiver_id: String,
    pub custody_ids: Vec<String>,
    /// This receiver's historical bounded snapshot, never collection completion.
    pub observed_us: i64,
    pub status: String,
    pub source_image_admission_sha256: String,
    pub clock_domain: Option<ClockDomain>,
    pub executable: Option<MeasuredFile>,
    pub policy_files: Vec<MeasuredFile>,
    pub conditional_rejections: Vec<ConditionalRejection>,
    pub unresolved: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverObservations {
    pub kind: String,
    pub request_sha256: String,
    pub challenge: String,
    /// Collection completion only; individual facts retain their own timestamps.
    pub observed_us: i64,
    pub receivers: Vec<ReceiverObservation>,
    pub unresolved: Vec<String>,
}
fn absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && path.len() <= 4096
        && !path.chars().any(char::is_control)
}
impl ReceiverProfile {
    pub(crate) fn authenticate(&self, auth: &Authenticated) -> Result<()> {
        if self.kind != "llull-buzz-native-receiver-profile/v1" || self.receivers.is_empty() {
            return Err(deny("receiver_profile"));
        }
        let native = auth
            .profile()
            .native_standing
            .as_ref()
            .ok_or_else(|| deny("receiver_original_scopes"))?;
        let mut ids = BTreeSet::new();
        for r in &self.receivers {
            llull_buzz_wire::id(&r.receiver_id).map_err(|_| deny("receiver_identity"))?;
            r.process.validate()?;
            llull_buzz_wire::hash(&r.executable_sha256).map_err(|_| deny("receiver_executable"))?;
            llull_buzz_wire::hash(&r.source_image_admission_sha256)
                .map_err(|_| deny("receiver_admission"))?;
            if !ids.insert(&r.receiver_id)
                || r.program != PROGRAM
                || r.upstream_revision != UPSTREAM
                || !absolute(&r.source_root)
                || r.custody_ids.is_empty()
            {
                return Err(deny("receiver_selection"));
            }
            let mut selected = BTreeSet::new();
            for id in &r.custody_ids {
                if !selected.insert(id) || !native.scopes.iter().any(|s| s.custody_id == *id) {
                    return Err(deny("receiver_original_scopes"));
                }
            }
        }
        Ok(())
    }
}

use super::files::identity as file_identity;
/// Count the actual serialized DTO before retaining another vector member.
/// A counting writer never allocates a second large serialized body merely to
/// discover that this invocation cannot compose its existing wire envelope.
fn admit_composition(bytes: &mut usize, value: &impl Serialize) -> Result<()> {
    struct Counter {
        bytes: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(data.len())
                .filter(|n| *n <= llull_buzz_wire::MAX_BYTES)
                .ok_or_else(|| std::io::Error::other("receiver composition bound"))?;
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        bytes: bytes
            .checked_add(1)
            .ok_or_else(|| deny("receiver_composition"))?,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| deny("receiver_composition"))?;
    *bytes = counter.bytes;
    Ok(())
}
/// Retain every parent descriptor; no symlink traversal, path-only re-open,
/// unbounded allocation, FIFO blocking or unchecked descriptor close.
fn measure(root: &Path, relative: &str, maximum: u64, budget: &mut Budget) -> Result<MeasuredFile> {
    measure_owned(root, relative, maximum, budget, 0)
}
fn measure_owned(
    root: &Path,
    relative: &str,
    maximum: u64,
    budget: &mut Budget,
    owner: u32,
) -> Result<MeasuredFile> {
    budget.sample(super::clock::now())?;
    let mut held = Vec::new();
    let mut initial = Vec::new();
    let result = (|| {
        let rootfd = openat(
            CWD,
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| deny("receiver_root"))?;
        held.push(rootfd);
        let root_stat = fstat(held.last().ok_or_else(|| deny("receiver_root"))?)
            .map_err(|_| deny("receiver_root"))?;
        if root_stat.st_uid != owner || root_stat.st_mode & 0o022 != 0 {
            return Err(deny("receiver_root_custody"));
        }
        initial.push(file_identity(&root_stat));
        let parts = Path::new(relative).components().collect::<Vec<_>>();
        if parts.is_empty() || parts.iter().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(deny("receiver_file_path"));
        }
        for component in &parts[..parts.len() - 1] {
            budget.sample(super::clock::now())?;
            let fd = openat(
                held.last().ok_or_else(|| deny("receiver_root"))?,
                component.as_os_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| deny("receiver_file_parent"))?;
            held.push(fd);
            let s = fstat(held.last().ok_or_else(|| deny("receiver_root"))?)
                .map_err(|_| deny("receiver_file_parent"))?;
            if s.st_uid != owner || s.st_mode & 0o022 != 0 {
                return Err(deny("receiver_file_parent"));
            }
            initial.push(file_identity(&s));
        }
        let parent = held.last().ok_or_else(|| deny("receiver_root"))?;
        let leaf = parts
            .last()
            .ok_or_else(|| deny("receiver_file_path"))?
            .as_os_str();
        let fd = openat(
            parent,
            leaf,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| deny("receiver_file_open"))?;
        let mut file = File::from(fd);
        let first = (|| {
            let before = fstat(&file).map_err(|_| deny("receiver_file_stat"))?;
            if before.st_mode & 0o170000 != 0o100000
                || before.st_uid != owner
                || before.st_mode & 0o022 != 0
                || before.st_size <= 0
                || before.st_size as u64 > maximum
            {
                return Err(deny("receiver_file_custody"));
            }
            let mut bytes = 0u64;
            let mut hasher = Sha256::new();
            let mut chunk = [0u8; 8192];
            loop {
                budget.sample(super::clock::now())?;
                let count = file
                    .read(&mut chunk)
                    .map_err(|_| deny("receiver_file_read"))?;
                if count == 0 {
                    break;
                }
                bytes = bytes
                    .checked_add(count as u64)
                    .filter(|v| *v <= before.st_size as u64)
                    .ok_or_else(|| deny("receiver_file_changed"))?;
                hasher.update(&chunk[..count]);
            }
            let after = fstat(&file).map_err(|_| deny("receiver_file_stat"))?;
            let linked = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| deny("receiver_file_changed"))?;
            if file_identity(&before) != file_identity(&after)
                || file_identity(&before) != file_identity(&linked)
                || bytes != before.st_size as u64
            {
                return Err(deny("receiver_file_changed"));
            }
            for (index, fd) in held.iter().enumerate() {
                budget.sample(super::clock::now())?;
                let current = fstat(fd).map_err(|_| deny("receiver_file_parent_changed"))?;
                let linked = if index == 0 {
                    statat(CWD, root, AtFlags::empty())
                } else {
                    statat(
                        &held[index - 1],
                        parts[index - 1].as_os_str(),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )
                }
                .map_err(|_| deny("receiver_file_parent_changed"))?;
                if file_identity(&current) != initial[index]
                    || file_identity(&linked) != initial[index]
                {
                    return Err(deny("receiver_file_parent_changed"));
                }
            }
            let identity = file_identity(&before);
            if identity.dev > 9_007_199_254_740_991 || identity.inode > 9_007_199_254_740_991 {
                return Err(deny("receiver_file_wire_identity"));
            }
            Ok(MeasuredFile {
                path: format!("/{relative}"),
                device: identity.dev,
                inode: identity.inode,
                uid: before.st_uid,
                mode: identity.mode,
                bytes,
                sha256: hasher
                    .finalize()
                    .iter()
                    .flat_map(|byte| {
                        const HEX: &[u8; 16] = b"0123456789abcdef";
                        [
                            HEX[(byte >> 4) as usize] as char,
                            HEX[(byte & 15) as usize] as char,
                        ]
                    })
                    .collect(),
            })
        })();
        super::files::native_cleanup(
            first,
            nix::unistd::close(file)
                .err()
                .map(|_| "receiver_file_close")
                .into_iter()
                .collect(),
        )
    })();
    let faults = held
        .into_iter()
        .rev()
        .filter_map(|fd| {
            nix::unistd::close(fd)
                .err()
                .map(|_| "receiver_parent_close")
        })
        .collect();
    super::files::native_cleanup(result, faults)
}

fn rejection(
    owners: &[super::standing::OwnerObservation],
    selected: &ReceiverSelection,
    now_us: i64,
) -> Result<Vec<ConditionalRejection>> {
    if now_us < 0 {
        return Err(deny("receiver_clock"));
    }
    let now_secs = u64::try_from(now_us / 1_000_000).map_err(|_| deny("receiver_clock"))?;
    let mut result = Vec::new();
    let mut bytes = 2;
    for owner in owners
        .iter()
        .filter(|o| selected.custody_ids.contains(&o.scope.custody_id))
    {
        for record in &owner.history {
            if let CustodyEvent::CredentialIssuedV2 {
                capability,
                event_id,
                token_sha256,
                public_claims,
                ..
            } = &record.event
            {
                let (policy, cutoff) = match &public_claims.scope {
                    PublicCredentialScope::Nip98 { .. } if capability == "native-http" => (
                        "upstream-relay-nip98-plus-minus-60s",
                        public_claims.created_at.checked_add(61),
                    ),
                    PublicCredentialScope::MediaGet { expiration, .. } => (
                        "upstream-relay-media-get-expiration-or-age-3600s",
                        public_claims
                            .created_at
                            .checked_add(3601)
                            .map(|age| age.min(*expiration)),
                    ),
                    PublicCredentialScope::Publication { .. } => {
                        ("publication-has-no-proven-expiry", None)
                    }
                    _ => ("consumer-receiver-policy-unavailable", None),
                };
                let cutoff = cutoff.filter(|v| *v <= 9_007_199_254_740_991);
                let observation = ConditionalRejection {
                    custody_id: owner.scope.custody_id.clone(),
                    event_id: event_id.clone(),
                    token_sha256: token_sha256.clone(),
                    capability: capability.clone(),
                    policy: policy.into(),
                    reject_at_secs: cutoff,
                    elapsed_at_observation: cutoff.map(|v| now_secs >= v),
                };
                admit_composition(&mut bytes, &observation)?;
                result.push(observation);
            }
        }
    }
    Ok(result)
}

fn time_domain(pid: u32, budget: &mut Budget) -> Result<(String, String)> {
    budget.sample(super::clock::now())?;
    let link = std::fs::read_link(format!("/proc/{pid}/ns/time"))
        .map_err(|_| deny("receiver_time_namespace"))?;
    let name = link
        .to_str()
        .ok_or_else(|| deny("receiver_time_namespace"))?
        .to_owned();
    let inode = name
        .strip_prefix("time:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| deny("receiver_time_namespace"))?;
    if name != format!("time:[{inode}]") {
        return Err(deny("receiver_time_namespace"));
    }
    // Linux time namespaces virtualize monotonic/boottime, not CLOCK_REALTIME.
    // Retain the complete offsets anyway, so a future policy cannot silently
    // reuse a weaker domain or omit an independently observed discrepancy.
    let raw = crate::native_custody::bounded_read(
        Path::new(&format!("/proc/{pid}/timens_offsets")),
        4096,
    )?;
    if raw.is_empty() || raw.len() > 4096 {
        return Err(deny("receiver_time_offsets"));
    }
    budget.sample(super::clock::now())?;
    Ok((name, llull_buzz_wire::sha256(&raw)))
}
fn executable_matches(link: &Path, actual: &std::fs::Metadata, measured: &MeasuredFile) -> bool {
    use std::os::unix::fs::MetadataExt;
    link == Path::new(PROGRAM)
        && measured.path == PROGRAM
        && (
            actual.dev(),
            actual.ino(),
            actual.uid(),
            actual.mode(),
            actual.len(),
        ) == (
            measured.device,
            measured.inode,
            measured.uid,
            measured.mode,
            measured.bytes,
        )
}
fn verify_executable(pid: u32, measured: &MeasuredFile, budget: &mut Budget) -> Result<()> {
    budget.sample(super::clock::now())?;
    // This is a deliberate kernel magic-link read, qualified by exact process
    // birth/namespace checks around the full acquisition. Birth survives exec,
    // so this program-and-inode join must also run AFTER all source reads.
    let path = format!("/proc/{pid}/exe");
    let link = std::fs::read_link(&path).map_err(|_| deny("receiver_executable_link"))?;
    let metadata = std::fs::metadata(&path).map_err(|_| deny("receiver_executable_identity"))?;
    if !executable_matches(&link, &metadata, measured) {
        return Err(deny("receiver_executable_identity"));
    }
    budget.sample(super::clock::now())?;
    Ok(())
}
fn observe(
    selection: &ReceiverSelection,
    owners: &[super::standing::OwnerObservation],
    budget: &mut Budget,
) -> Result<ReceiverObservation> {
    let mut result = ReceiverObservation {
        receiver_id: selection.receiver_id.clone(),
        custody_ids: selection.custody_ids.clone(),
        observed_us: budget.sample(super::clock::now())?,
        status: "UNKNOWN".into(),
        source_image_admission_sha256: selection.source_image_admission_sha256.clone(),
        clock_domain: None,
        executable: None,
        policy_files: Vec::new(),
        conditional_rejections: Vec::new(),
        unresolved: vec![
            "receiver-source-image-admission-unverified".into(),
            "other-recipient-and-copied-token-domains-unobserved".into(),
        ],
    };
    let here = match ProcessIncarnation::current() {
        Ok(p) => p,
        Err(_) => {
            result
                .unresolved
                .push("receiver-linux-kernel-unavailable".into());
            return Ok(result);
        }
    };
    if selection.process.machine_id != here.machine_id
        || selection.process.boot_id != here.boot_id
        || selection.process.namespaces.get("pid") != here.namespaces.get("pid")
    {
        result
            .unresolved
            .push("receiver-remote-machine-boot-or-pid-domain-unsupported".into());
        return Ok(result);
    }
    let current = ProcessIncarnation::read(selection.process.pid)?;
    if current != selection.process {
        return Err(deny("receiver_incarnation_changed"));
    }
    let clock = time_domain(here.pid, budget)?;
    if clock != time_domain(current.pid, budget)? {
        return Err(deny("receiver_clock_domain"));
    }
    let root = std::path::PathBuf::from(format!("/proc/{}/root", current.pid));
    let executable = measure(&root, PROGRAM.trim_start_matches('/'), MAX_PROGRAM, budget)?;
    if executable.sha256 != selection.executable_sha256 || executable.mode & 0o111 == 0 {
        return Err(deny("receiver_executable_identity"));
    }
    verify_executable(current.pid, &executable, budget)?;
    for (path, expected) in POLICY_FILES {
        let name = format!(
            "{}/{path}",
            selection
                .source_root
                .trim_start_matches('/')
                .trim_end_matches('/')
        );
        let measured = measure(
            Path::new("/"),
            name.trim_start_matches('/'),
            MAX_SOURCE,
            budget,
        )?;
        if measured.sha256 != expected {
            return Err(deny("receiver_source_policy"));
        }
        result.policy_files.push(measured);
    }
    if measure(&root, PROGRAM.trim_start_matches('/'), MAX_PROGRAM, budget)? != executable {
        return Err(deny("receiver_executable_changed"));
    }
    for measured in &result.policy_files {
        if measure(
            Path::new("/"),
            measured.path.trim_start_matches('/'),
            MAX_SOURCE,
            budget,
        )? != *measured
        {
            return Err(deny("receiver_source_changed"));
        }
    }
    if ProcessIncarnation::read(current.pid)? != current
        || ProcessIncarnation::current()? != here
        || time_domain(here.pid, budget)? != clock
        || time_domain(current.pid, budget)? != clock
    {
        return Err(deny("receiver_observation_changed"));
    }
    verify_executable(current.pid, &executable, budget)?;
    result.status = "SOURCE_AND_PROGRAM_OBSERVED_BUILD_UNVERIFIED".into();
    result.clock_domain = Some(ClockDomain {
        collector: here,
        receiver: current,
        time_namespace: clock.0,
        time_offsets_sha256: clock.1,
    });
    result.executable = Some(executable);
    result.observed_us = budget.sample(super::clock::now())?;
    result.conditional_rejections = rejection(owners, selection, result.observed_us)?;
    Ok(result)
}
pub(crate) fn collect(
    profile: &ReceiverProfile,
    owners: &[super::standing::OwnerObservation],
    auth: &Authenticated,
    budget: &mut Budget,
) -> Result<ReceiverObservations> {
    collect_with(profile, owners, auth, budget, observe, super::clock::now)
}
// Only the final receiver snapshot/clock boundary is replaceable by inert
// source fixtures; production acquisition is always the fixed observe function.
fn collect_with(
    profile: &ReceiverProfile,
    owners: &[super::standing::OwnerObservation],
    auth: &Authenticated,
    budget: &mut Budget,
    mut acquire: impl FnMut(
        &ReceiverSelection,
        &[super::standing::OwnerObservation],
        &mut Budget,
    ) -> Result<ReceiverObservation>,
    mut clock: impl FnMut() -> i64,
) -> Result<ReceiverObservations> {
    profile.authenticate(auth)?;
    let mut receivers = Vec::new();
    let mut bytes = 2;
    for selection in &profile.receivers {
        auth.current(budget.sample(clock())?)?;
        let observation = acquire(selection, owners, budget)?;
        admit_composition(&mut bytes, &observation)?;
        receivers.push(observation);
    }
    let observed_us = budget.sample(clock())?;
    let observation = ReceiverObservations {
        kind: "llull-buzz-private-native-receivers/v1".into(),
        request_sha256: auth.request_hash().into(),
        challenge: auth.request().challenge.clone(),
        observed_us,
        receivers,
        unresolved: vec![
            "receiver-source-image-admission-unverified".into(),
            "provider-post-snapshot-authority-unverified".into(),
            "other-recipient-and-copied-token-domains-unobserved".into(),
        ],
    };
    admit_composition(&mut 0, &observation)?;
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspection::standing::{HistoryAnchor, OwnerObservation, StandingProfile};
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    fn selection(owner: &OwnerObservation) -> ReceiverSelection {
        ReceiverSelection {
            receiver_id: "original-native-relay".into(),
            custody_ids: vec![owner.scope.custody_id.clone()],
            process: owner.original_process.clone(),
            program: PROGRAM.into(),
            executable_sha256: "a".repeat(64),
            source_root: "/opt/llull/receiver-source".into(),
            upstream_revision: UPSTREAM.into(),
            source_image_admission_sha256: "b".repeat(64),
        }
    }
    fn inputs(
        owner: &OwnerObservation,
        receiver: ReceiverSelection,
    ) -> (Authenticated, Budget, Vec<u8>) {
        inputs_many(owner, vec![receiver])
    }
    fn inputs_many(
        owner: &OwnerObservation,
        selections: Vec<ReceiverSelection>,
    ) -> (Authenticated, Budget, Vec<u8>) {
        let native = StandingProfile {
            kind: "llull-buzz-native-standing-profile/v1".into(),
            scopes: vec![owner.scope.clone()],
            retained_anchors: std::collections::BTreeMap::from([(
                owner.scope.custody_id.clone(),
                HistoryAnchor {
                    acquisition_sha256: llull_buzz_wire::digest(&owner.history[0]).unwrap(),
                    prefix_records: owner.history.len() as u64,
                    prefix_head_sha256: owner.head_sha256.clone(),
                },
            )]),
        };
        let receivers = ReceiverProfile {
            kind: "llull-buzz-native-receiver-profile/v1".into(),
            receivers: selections,
        };
        let (trust, profile, request, signer, now) =
            super::super::authority::synthetic_receiver_inputs(native, receivers);
        let mut budget = Budget::new(now, now + 20_000_000).unwrap();
        let auth = Authenticated::admit(&trust, &profile, &request, &mut budget, now).unwrap();
        (auth, budget, signer)
    }
    #[test]
    fn receiver_actual_original_signatures_fold_to_exact_conditional_token_boundaries() {
        let owner = super::super::standing::synthetic_receiver_owner();
        let selected = selection(&owner);
        let now = super::super::clock::now() + 7200 * 1_000_000;
        let disposition = rejection(std::slice::from_ref(&owner), &selected, now).unwrap();
        assert_eq!(disposition.len(), 4);
        for observed in &disposition {
            let record = owner.history.iter().find(|record| matches!(&record.event, CustodyEvent::CredentialIssuedV2 { event_id, token_sha256, .. } if event_id == &observed.event_id && token_sha256 == &observed.token_sha256)).unwrap();
            let CustodyEvent::CredentialIssuedV2 {
                capability,
                public_claims,
                ..
            } = &record.event
            else {
                unreachable!()
            };
            assert_eq!(observed.custody_id, owner.scope.custody_id);
            assert_eq!(&observed.capability, capability);
            match &public_claims.scope {
                PublicCredentialScope::Nip98 { .. } if capability == "native-http" => {
                    assert_eq!(observed.reject_at_secs, Some(public_claims.created_at + 61));
                    assert_eq!(observed.elapsed_at_observation, Some(true));
                    let at_boundary = rejection(
                        std::slice::from_ref(&owner),
                        &selected,
                        (public_claims.created_at as i64 + 60) * 1_000_000,
                    )
                    .unwrap();
                    assert_eq!(
                        at_boundary
                            .iter()
                            .find(|r| r.event_id == observed.event_id)
                            .unwrap()
                            .elapsed_at_observation,
                        Some(false)
                    );
                    let after_boundary = rejection(
                        std::slice::from_ref(&owner),
                        &selected,
                        (public_claims.created_at as i64 + 61) * 1_000_000,
                    )
                    .unwrap();
                    assert_eq!(
                        after_boundary
                            .iter()
                            .find(|r| r.event_id == observed.event_id)
                            .unwrap()
                            .elapsed_at_observation,
                        Some(true)
                    );
                }
                PublicCredentialScope::MediaGet { expiration, .. } => {
                    assert_eq!(
                        observed.reject_at_secs,
                        Some((*expiration).min(public_claims.created_at + 3601))
                    );
                    assert_eq!(observed.elapsed_at_observation, Some(true));
                }
                _ => {
                    assert!(observed.reject_at_secs.is_none());
                    assert!(observed.elapsed_at_observation.is_none());
                }
            }
        }
        let mut foreign = selected;
        foreign.custody_ids = vec!["0".repeat(32)];
        assert!(rejection(&[owner], &foreign, now).unwrap().is_empty());
    }
    #[test]
    fn receiver_selected_pinned_nip98_guard_accepts_fresh_and_refuses_original_old_event() {
        let keys = nostr::Keys::generate();
        let now = nostr::Timestamp::now().as_secs();
        let url = "https://native.synthetic.invalid/query";
        let event = |created| {
            let event = nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
                .custom_created_at(nostr::Timestamp::from_secs(created))
                .tags([
                    nostr::Tag::parse(["u", url]).unwrap(),
                    nostr::Tag::parse(["method", "POST"]).unwrap(),
                    nostr::Tag::parse(["payload", &llull_buzz_wire::sha256(b"original")]).unwrap(),
                ])
                .sign_with_keys(&keys)
                .unwrap();
            serde_json::to_string(&event).unwrap()
        };
        assert!(buzz_auth::verify_nip98_event(&event(now), url, "POST", Some(b"original")).is_ok());
        assert!(
            buzz_auth::verify_nip98_event(&event(now - 62), url, "POST", Some(b"original"))
                .is_err()
        );
        assert!(
            buzz_auth::verify_nip98_event(&event(now), url, "POST", Some(b"substituted")).is_err()
        );
    }
    #[test]
    fn receiver_authenticated_remote_or_unsupported_domain_preserves_all_missing_authority() {
        let owner = super::super::standing::synthetic_receiver_owner();
        let (auth, mut budget, signer) = inputs(&owner, selection(&owner));
        let profile = auth.profile().native_receivers.as_ref().unwrap();
        let observation = collect(profile, &[owner], &auth, &mut budget).unwrap();
        assert_eq!(observation.receivers[0].status, "UNKNOWN");
        assert!(observation.receivers[0].clock_domain.is_none());
        assert!(observation.receivers[0].executable.is_none());
        assert!(observation.receivers[0].conditional_rejections.is_empty());
        assert!(observation
            .unresolved
            .contains(&"receiver-source-image-admission-unverified".into()));
        assert!(observation
            .unresolved
            .contains(&"other-recipient-and-copied-token-domains-unobserved".into()));
        let encoded = serde_json::to_vec(&serde_json::to_value(&observation).unwrap()).unwrap();
        let signed = auth
            .sign(
                observation,
                &signer,
                super::super::clock::now(),
                auth.expires(),
            )
            .unwrap();
        auth.verify_response(
            &signed,
            &llull_buzz_wire::sha256(&encoded),
            super::super::clock::now(),
        )
        .unwrap();
        let mut changed = profile.clone();
        changed.receivers[0].custody_ids = vec!["0".repeat(32)];
        assert!(changed.authenticate(&auth).is_err());
        changed = profile.clone();
        changed.receivers[0].upstream_revision = "0".repeat(40);
        assert!(changed.authenticate(&auth).is_err());
        changed = profile.clone();
        changed.receivers[0].program = "/opt/llull/upstream/buzz-agent".into();
        assert!(changed.authenticate(&auth).is_err());
        changed = profile.clone();
        changed.receivers[0].source_root = "/opt/llull/../receiver-source".into();
        assert!(changed.authenticate(&auth).is_err());
    }
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("buzz-receiver-source-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::create_dir(root.join("source")).unwrap();
            std::fs::set_permissions(root.join("source"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::write(
                root.join("source/policy.rs"),
                b"synthetic source bytes only",
            )
            .unwrap();
            std::fs::set_permissions(
                root.join("source/policy.rs"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            Self(root)
        }
        fn read(&self, path: &str, limit: u64) -> Result<MeasuredFile> {
            let now = super::super::clock::now();
            measure_owned(
                &self.0,
                path,
                limit,
                &mut Budget::new(now, now + 20_000_000).unwrap(),
                rustix::process::geteuid().as_raw(),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn receiver_real_held_files_stream_hash_and_refuse_links_modes_paths_and_bounds() {
        let f = Fixture::new();
        let measured = f.read("source/policy.rs", MAX_SOURCE).unwrap();
        assert_eq!(
            measured.sha256,
            llull_buzz_wire::sha256(b"synthetic source bytes only")
        );
        assert_eq!(measured.bytes, 27);
        assert!(f.read("source/policy.rs", 5).is_err());
        assert!(f.read("source/../source/policy.rs", MAX_SOURCE).is_err());
        std::os::unix::fs::symlink(f.0.join("source/policy.rs"), f.0.join("source/link.rs"))
            .unwrap();
        assert!(f.read("source/link.rs", MAX_SOURCE).is_err());
        std::os::unix::fs::symlink(f.0.join("source"), f.0.join("linked-source")).unwrap();
        assert!(f.read("linked-source/policy.rs", MAX_SOURCE).is_err());
        std::fs::set_permissions(
            f.0.join("source/policy.rs"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(f.read("source/policy.rs", MAX_SOURCE).is_err());
    }
    #[test]
    fn receiver_cancelled_budget_never_reads_a_source_prefix_as_complete() {
        let f = Fixture::new();
        let now = super::super::clock::now();
        let mut budget = Budget::new(now, now + 20_000_000).unwrap();
        assert!(budget.sample(now - 1).is_err());
        assert!(measure_owned(
            &f.0,
            "source/policy.rs",
            MAX_SOURCE,
            &mut budget,
            rustix::process::geteuid().as_raw()
        )
        .is_err());
        assert!(budget.sample(super::super::clock::now()).is_err());
    }
    #[test]
    fn receiver_final_kernel_program_join_refuses_exec_or_image_leaf_replacement() {
        let f = Fixture::new();
        let mut measured = f.read("source/policy.rs", MAX_SOURCE).unwrap();
        // Only the final /proc link/path tuple is an INERT fixture. File open,
        // metadata, streamed hash and identity guards use real owned files.
        measured.path = PROGRAM.into();
        let original = std::fs::metadata(f.0.join("source/policy.rs")).unwrap();
        assert!(executable_matches(Path::new(PROGRAM), &original, &measured));
        assert!(!executable_matches(
            Path::new("/opt/llull/upstream/buzz-agent"),
            &original,
            &measured
        ));
        std::fs::write(f.0.join("source/other.rs"), b"synthetic source bytes only").unwrap();
        let replaced = std::fs::metadata(f.0.join("source/other.rs")).unwrap();
        assert!(!executable_matches(
            Path::new(PROGRAM),
            &replaced,
            &measured
        ));
        measured.sha256 = POLICY_FILES[0].1.into();
        assert!(!executable_matches(
            Path::new(PROGRAM),
            &replaced,
            &measured
        ));
    }
    #[test]
    fn receiver_closed_dto_refuses_unknown_claims_and_unproved_authority_flags() {
        let owner = super::super::standing::synthetic_receiver_owner();
        let mut selected = serde_json::to_value(selection(&owner)).unwrap();
        selected["trusted"] = serde_json::json!(true);
        assert!(llull_buzz_wire::parse::<ReceiverSelection>(
            &serde_json::to_vec(&selected).unwrap()
        )
        .is_err());
        for (path, hash) in POLICY_FILES {
            assert!(path.starts_with("crates/"));
            llull_buzz_wire::hash(hash).unwrap();
        }
        assert_eq!(super::super::UNRESOLVED.len(), 4);
    }
    #[test]
    fn receiver_actual_serialized_composition_refuses_before_retaining_overflow() {
        let owner = super::super::standing::synthetic_receiver_owner();
        let value = selection(&owner);
        let mut bytes = 2;
        let mut admitted = 0;
        while admit_composition(&mut bytes, &value).is_ok() {
            admitted += 1;
        }
        assert!(admitted > 1);
        assert!(bytes <= llull_buzz_wire::MAX_BYTES);
        assert!(admit_composition(&mut bytes, &value).is_err());
        assert!(rejection(&[owner], &value, -1).is_err());
    }
    #[test]
    fn receiver_first_exec_or_exit_during_second_acquisition_never_freshens_its_snapshot() {
        use std::cell::Cell;
        for transition in ["exec", "exit"] {
            let owner = super::super::standing::synthetic_receiver_owner_at_age(55);
            let f = Fixture::new();
            std::fs::set_permissions(
                f.0.join("source/policy.rs"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let mut measured = f.read("source/policy.rs", MAX_SOURCE).unwrap();
            measured.path = PROGRAM.into();
            assert!(executable_matches(
                Path::new(PROGRAM),
                &std::fs::metadata(f.0.join("source/policy.rs")).unwrap(),
                &measured
            ));
            let mut first = selection(&owner);
            first.executable_sha256 = measured.sha256.clone();
            let mut second = first.clone();
            second.receiver_id = "second-native-relay".into();
            second.process.pid += 1;
            let (auth, mut budget, _) = inputs_many(&owner, vec![first, second]);
            let (event_id, cutoff) = owner
                .history
                .iter()
                .find_map(|record| match &record.event {
                    CustodyEvent::CredentialIssuedV2 {
                        event_id,
                        capability,
                        public_claims,
                        ..
                    } if capability == "native-http"
                        && matches!(public_claims.scope, PublicCredentialScope::Nip98 { .. }) =>
                    {
                        Some((event_id.clone(), public_claims.created_at + 61))
                    }
                    _ => None,
                })
                .unwrap();
            let first_us = (cutoff as i64 - 1) * 1_000_000;
            let second_us = (cutoff as i64 + 1) * 1_000_000;
            let now = Cell::new(first_us);
            let first_state = Cell::new("original");
            let stage = Cell::new(0);
            // Final kernel snapshots and elapsed clock are explicitly INERT.
            // Original acquisition/signatures/fold, ES256 root profile, held
            // file reads and final program identity guard remain real above.
            let result = collect_with(
                auth.profile().native_receivers.as_ref().unwrap(),
                std::slice::from_ref(&owner),
                &auth,
                &mut budget,
                |selected, owners, _| {
                    if stage.get() == 1 {
                        first_state.set(transition);
                        now.set(second_us);
                    }
                    let observed_us = now.get();
                    auth.current(observed_us)?;
                    stage.set(stage.get() + 1);
                    Ok(ReceiverObservation {
                        receiver_id: selected.receiver_id.clone(),
                        custody_ids: selected.custody_ids.clone(),
                        observed_us,
                        status: "SOURCE_AND_PROGRAM_OBSERVED_BUILD_UNVERIFIED".into(),
                        source_image_admission_sha256: selected
                            .source_image_admission_sha256
                            .clone(),
                        clock_domain: Some(ClockDomain {
                            collector: owner.original_process.clone(),
                            receiver: selected.process.clone(),
                            time_namespace: "time:[1]".into(),
                            time_offsets_sha256: "0".repeat(64),
                        }),
                        executable: Some(measured.clone()),
                        policy_files: Vec::new(),
                        conditional_rejections: rejection(owners, selected, observed_us)?,
                        unresolved: vec![
                            "receiver-source-image-admission-unverified".into(),
                            "other-recipient-and-copied-token-domains-unobserved".into(),
                        ],
                    })
                },
                || now.get(),
            )
            .unwrap();
            assert_eq!(first_state.get(), transition);
            assert_eq!(result.observed_us, second_us);
            assert_eq!(result.receivers[0].observed_us, first_us);
            assert_eq!(result.receivers[1].observed_us, second_us);
            let first_token = result.receivers[0]
                .conditional_rejections
                .iter()
                .find(|r| r.event_id == event_id)
                .unwrap();
            let second_token = result.receivers[1]
                .conditional_rejections
                .iter()
                .find(|r| r.event_id == event_id)
                .unwrap();
            assert_eq!(first_token.elapsed_at_observation, Some(false));
            assert_eq!(second_token.elapsed_at_observation, Some(true));
            assert!(result
                .unresolved
                .contains(&"provider-post-snapshot-authority-unverified".into()));
        }
    }
}
