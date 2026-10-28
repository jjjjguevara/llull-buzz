//! Native credential custody at the actual acquisition/signing/release sites.
//!
//! This log describes this provider's instrumented native key only. It cannot
//! revoke signed credentials, prove remote erasure or reconstruct earlier loads.
use crate::inspection::{deny, Result};
use llull_buzz_wire::{digest, hash, id, sha256};
use rustix::fs::{fstat, openat, AtFlags, Mode, OFlags, CWD};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
    sync::{Arc, Mutex},
};

pub(crate) const ROOT: &str = "/var/lib/llull-buzz/native-custody";
pub(crate) const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Provisioned before the original key load, independently retained by the
/// operator profile. A new invocation needs a new custody_id; no log is resumed,
/// truncated or manufactured from a current database membership observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCustodyScope {
    pub kind: String,
    pub custody_id: String,
    pub installation: String,
    pub source_revision: String,
    pub implementation_sha256: String,
    pub membership_sha256: String,
    pub operation_ref: String,
    pub operation_sha256: String,
    pub configuration_sha256: String,
    pub configuration_generation: u64,
    pub source_copy_sha256: String,
    pub target_copy_sha256: String,
    pub community_id: String,
    pub private_origin: String,
    pub public_origin: String,
    pub relay_public_key: String,
    pub credential_public_key: String,
    pub credential_file: String,
}
impl NativeCustodyScope {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.kind != "llull-buzz-native-custody-scope/v1"
            || self.custody_id.len() != 32
            || !self
                .custody_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.source_revision.len() != 40
            || !self
                .source_revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.configuration_generation == 0
            || self.implementation_sha256 != crate::inspection::relations::implementation_sha256()
        {
            return Err(deny("native_custody_scope"));
        }
        if !Path::new(&self.credential_file).is_absolute()
            || Path::new(&self.credential_file)
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(deny("native_custody_key_path"));
        }
        for value in [&self.installation, &self.operation_ref, &self.community_id] {
            id(value).map_err(|_| deny("native_custody_scope"))?;
        }
        for value in [
            &self.implementation_sha256,
            &self.membership_sha256,
            &self.operation_sha256,
            &self.configuration_sha256,
            &self.source_copy_sha256,
            &self.target_copy_sha256,
            &self.relay_public_key,
            &self.credential_public_key,
        ] {
            hash(value).map_err(|_| deny("native_custody_scope"))?;
        }
        for (text, public) in [(&self.private_origin, false), (&self.public_origin, true)] {
            let url = url::Url::parse(text).map_err(|_| deny("native_custody_origin"))?;
            if !(url.scheme() == "https" || !public && url.scheme() == "http")
                || url.host_str().is_none()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(deny("native_custody_origin"));
            }
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        digest(self).map_err(|_| deny("native_custody_encoding"))
    }
}

/// Linux facts read from the kernel, never accepted from an operator assertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessIncarnation {
    pub machine_id: String,
    pub boot_id: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub uid: u32,
    pub namespaces: BTreeMap<String, String>,
}
pub(crate) fn bounded_read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| deny("native_custody_kernel_read"))?;
    let mut bytes = Vec::new();
    let mut file = File::from(fd);
    let result = (&mut file).take(maximum + 1).read_to_end(&mut bytes);
    if nix::unistd::close(file).is_err() {
        return Err(deny("native_custody_kernel_close"));
    }
    result.map_err(|_| deny("native_custody_kernel_read"))?;
    if bytes.len() as u64 > maximum {
        return Err(deny("native_custody_kernel_bound"));
    }
    Ok(bytes)
}
fn kernel_text(path: &str, maximum: u64) -> Result<String> {
    String::from_utf8(bounded_read(Path::new(path), maximum)?)
        .map(|text| text.trim().to_owned())
        .map_err(|_| deny("native_custody_kernel_text"))
}
impl ProcessIncarnation {
    pub fn current() -> Result<Self> {
        Self::read(std::process::id())
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.machine_id.len() != 32
            || !self
                .machine_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || uuid::Uuid::parse_str(&self.boot_id).is_err()
            || uuid::Uuid::parse_str(&self.boot_id)
                .map(|v| v.to_string())
                .ok()
                .as_ref()
                != Some(&self.boot_id)
            || self.pid == 0
            || self.start_ticks == 0
            || self.namespaces.len() != 4
        {
            return Err(deny("native_custody_incarnation"));
        }
        for name in ["net", "mnt", "user", "pid"] {
            let text = self
                .namespaces
                .get(name)
                .ok_or_else(|| deny("native_custody_incarnation"))?;
            let inode = text
                .strip_prefix(&format!("{name}:["))
                .and_then(|v| v.strip_suffix(']'))
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .ok_or_else(|| deny("native_custody_incarnation"))?;
            if text != &format!("{name}:[{inode}]") {
                return Err(deny("native_custody_incarnation"));
            }
        }
        Ok(())
    }
    pub(crate) fn read(pid: u32) -> Result<Self> {
        if cfg!(not(target_os = "linux")) {
            return Err(deny("native_custody_linux_required"));
        }
        let stat = kernel_text(&format!("/proc/{pid}/stat"), 16384)?;
        let rest = stat
            .rsplit_once(") ")
            .ok_or_else(|| deny("native_custody_stat"))?
            .1;
        // rest starts at field 3 (state); starttime is field 22.
        let start_ticks = rest
            .split_whitespace()
            .nth(19)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| deny("native_custody_stat"))?;
        let status = kernel_text(&format!("/proc/{pid}/status"), 65536)?;
        let uids = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .ok_or_else(|| deny("native_custody_uid"))?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| deny("native_custody_uid"))?;
        if uids.len() != 4 || uids.iter().any(|v| *v != uids[0]) {
            return Err(deny("native_custody_uid"));
        }
        let mut namespaces = BTreeMap::new();
        for name in ["net", "mnt", "user", "pid"] {
            let link = std::fs::read_link(format!("/proc/{pid}/ns/{name}"))
                .map_err(|_| deny("native_custody_namespace"))?;
            namespaces.insert(
                name.into(),
                link.to_str()
                    .ok_or_else(|| deny("native_custody_namespace"))?
                    .into(),
            );
        }
        let result = Self {
            machine_id: kernel_text("/etc/machine-id", 128)?,
            boot_id: kernel_text("/proc/sys/kernel/random/boot_id", 128)?,
            pid,
            start_ticks,
            uid: uids[0],
            namespaces,
        };
        result.validate()?;
        let after = kernel_text(&format!("/proc/{pid}/stat"), 16384)?;
        let after_start = after
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split_whitespace().nth(19))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| deny("native_custody_stat"))?;
        if after_start != result.start_ticks {
            return Err(deny("native_custody_incarnation_changed"));
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", deny_unknown_fields)]
pub enum CustodyEvent {
    Acquire {
        scope: Box<NativeCustodyScope>,
        process: ProcessIncarnation,
        key_file_sha256: String,
    },
    CapabilityOpen {
        capability: String,
    },
    CredentialIssued {
        capability: String,
        event_id: String,
        token_sha256: String,
        kind: u16,
        explicit_expiration: Option<u64>,
    },
    /// Public claims captured from the actual signed event before transport.
    /// The separate variant never upgrades older, incomplete journal records.
    CredentialIssuedV2 {
        capability: String,
        event_id: String,
        token_sha256: String,
        kind: u16,
        public_claims: Box<PublicCredentialClaims>,
    },
    CapabilityClosed {
        capability: String,
    },
    Released,
}
/// A non-reusable description, not the signed event or a bearer credential.
/// Lifetime is a signed claim; receiver enforcement remains independently unknown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicCredentialClaims {
    pub kind: String,
    pub public_key: String,
    pub created_at: u64,
    pub content_sha256: String,
    pub tags_sha256: String,
    pub scope: PublicCredentialScope,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PublicCredentialScope {
    Nip98 {
        url: String,
        method: String,
        payload_sha256: String,
        nonce_sha256: Option<String>,
    },
    MediaGet {
        blob_sha256: String,
        expiration: u64,
    },
    Publication {
        channel_id: String,
        publication_id: String,
        thread: BTreeMap<String, String>,
    },
}
impl PublicCredentialClaims {
    fn from_event(event: &nostr::Event) -> Result<Self> {
        let tags = event
            .tags
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect::<Vec<_>>();
        let one = |name: &str| -> Result<String> {
            let matches = tags
                .iter()
                .filter(|t| t.first().is_some_and(|v| v == name))
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [tag] if tag.len() == 2 => Ok(tag[1].clone()),
                _ => Err(deny("native_custody_public_claims")),
            }
        };
        let allowed = |names: &[&str]| {
            tags.iter()
                .all(|t| t.first().is_some_and(|n| names.contains(&n.as_str())))
        };
        let scope = match event.kind.as_u16() {
            27235 if event.content.is_empty() && allowed(&["u", "method", "payload", "nonce"]) => {
                let nonce_sha256 = if tags.iter().any(|t| t.first().is_some_and(|v| v == "nonce")) {
                    Some(sha256(one("nonce")?.as_bytes()))
                } else {
                    None
                };
                PublicCredentialScope::Nip98 {
                    url: one("u")?,
                    method: one("method")?,
                    payload_sha256: one("payload")?,
                    nonce_sha256,
                }
            }
            24242
                if !event.content.trim().is_empty()
                    && allowed(&["t", "x", "expiration"])
                    && one("t")? == "get" =>
            {
                let expiration = one("expiration")?;
                let parsed = expiration
                    .parse::<u64>()
                    .map_err(|_| deny("native_custody_public_claims"))?;
                if parsed.to_string() != expiration {
                    return Err(deny("native_custody_public_claims"));
                }
                PublicCredentialScope::MediaGet {
                    blob_sha256: one("x")?,
                    expiration: parsed,
                }
            }
            9 if allowed(&["h", "llull-publication", "e"]) => {
                let mut thread = BTreeMap::new();
                for tag in tags.iter().filter(|t| t.first().is_some_and(|v| v == "e")) {
                    if tag.len() != 4
                        || !tag[2].is_empty()
                        || !matches!(tag[3].as_str(), "root" | "reply")
                        || thread.insert(tag[3].clone(), tag[1].clone()).is_some()
                    {
                        return Err(deny("native_custody_public_claims"));
                    }
                }
                PublicCredentialScope::Publication {
                    channel_id: one("h")?,
                    publication_id: one("llull-publication")?,
                    thread,
                }
            }
            _ => return Err(deny("native_custody_public_claims")),
        };
        Ok(Self {
            kind: "llull-buzz-native-public-claims/v1".into(),
            public_key: event.pubkey.to_hex(),
            created_at: event.created_at.as_secs(),
            content_sha256: sha256(event.content.as_bytes()),
            tags_sha256: digest(&tags).map_err(|_| deny("native_custody_public_claims"))?,
            scope,
        })
    }
    pub(crate) fn validate(
        &self,
        scope: &NativeCustodyScope,
        capability: &str,
        kind: u16,
    ) -> Result<()> {
        if self.kind != "llull-buzz-native-public-claims/v1"
            || self.public_key != scope.credential_public_key
            || self.created_at > 9_007_199_254_740_991
        {
            return Err(deny("native_custody_public_claims"));
        }
        for value in [&self.public_key, &self.content_sha256, &self.tags_sha256] {
            hash(value).map_err(|_| deny("native_custody_public_claims"))?;
        }
        match &self.scope {
            PublicCredentialScope::Nip98 {
                url,
                method,
                payload_sha256,
                nonce_sha256,
            } => {
                let actual =
                    url::Url::parse(url).map_err(|_| deny("native_custody_public_claims"))?;
                let origin = url::Url::parse(&scope.public_origin)
                    .map_err(|_| deny("native_custody_public_claims"))?;
                if kind != 27235
                    || !matches!(capability, "native-http" | "consumer-http")
                    || method != "POST"
                    || self.content_sha256 != sha256(b"")
                    || actual.origin() != origin.origin()
                    || !actual.username().is_empty()
                    || actual.password().is_some()
                    || actual.query().is_some()
                    || actual.fragment().is_some()
                    || (capability == "native-http"
                        && !matches!(actual.path(), "/query" | "/events"))
                {
                    return Err(deny("native_custody_public_claims"));
                }
                hash(payload_sha256).map_err(|_| deny("native_custody_public_claims"))?;
                if let Some(nonce) = nonce_sha256 {
                    hash(nonce).map_err(|_| deny("native_custody_public_claims"))?;
                }
            }
            PublicCredentialScope::MediaGet {
                blob_sha256,
                expiration,
            } => {
                if kind != 24242
                    || capability != "native-http"
                    || *expiration > 9_007_199_254_740_991
                    || self.content_sha256 == sha256(b"")
                {
                    return Err(deny("native_custody_public_claims"));
                }
                hash(blob_sha256).map_err(|_| deny("native_custody_public_claims"))?;
            }
            PublicCredentialScope::Publication {
                channel_id,
                publication_id,
                thread,
            } => {
                if kind != 9
                    || capability != "native-publication"
                    || thread.len() > 2
                    || (thread.contains_key("root") && !thread.contains_key("reply"))
                {
                    return Err(deny("native_custody_public_claims"));
                }
                for value in [channel_id, publication_id] {
                    if uuid::Uuid::parse_str(value)
                        .map_err(|_| deny("native_custody_public_claims"))?
                        .to_string()
                        != *value
                    {
                        return Err(deny("native_custody_public_claims"));
                    }
                }
                for (marker, event_id) in thread {
                    if !matches!(marker.as_str(), "root" | "reply") {
                        return Err(deny("native_custody_public_claims"));
                    }
                    hash(event_id).map_err(|_| deny("native_custody_public_claims"))?;
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyRecord {
    pub kind: String,
    pub sequence: u64,
    pub previous_sha256: String,
    pub scope_sha256: String,
    pub observed_us: i64,
    pub event: CustodyEvent,
}
struct Journal {
    directory: crate::inspection::files::PrivateDirectory,
    file: Option<File>,
    file_name: String,
    scope_sha256: String,
    process: ProcessIncarnation,
    process_reader: fn() -> Result<ProcessIncarnation>,
    sequence: u64,
    previous_sha256: String,
    bytes: u64,
    failed: bool,
}
/// Walk every parent with held no-follow descriptors. Neither a symlink parent,
/// a group-writable ancestor nor a replaced leaf is an admitted custody root.
pub(crate) fn private_directory(path: &Path) -> Result<crate::inspection::files::PrivateDirectory> {
    crate::inspection::files::PrivateDirectory::open_native_custody(path)
}
impl Journal {
    fn append(&mut self, event: CustodyEvent) -> Result<()> {
        if self.failed {
            return Err(deny("native_custody_failed"));
        }
        let result = (|| {
            if (self.process_reader)()? != self.process {
                return Err(deny("native_custody_incarnation_changed"));
            }
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| deny("native_custody_closed"))?;
            let held = file.metadata().map_err(|_| deny("native_custody_file"))?;
            use std::os::unix::fs::MetadataExt;
            let named = rustix::fs::statat(
                self.directory.native_descriptor()?,
                self.file_name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| deny("native_custody_file"))?;
            if held.dev() != named.st_dev as u64
                || held.ino() != named.st_ino as u64
                || held.len() != self.bytes
                || held.nlink() != 1
                || held.mode() & 0o777 != 0o600
                || held.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(deny("native_custody_file"));
            }
            let record = CustodyRecord {
                kind: "llull-buzz-native-custody-record/v1".into(),
                sequence: self.sequence,
                previous_sha256: self.previous_sha256.clone(),
                scope_sha256: self.scope_sha256.clone(),
                observed_us: chrono::Utc::now().timestamp_micros(),
                event,
            };
            let mut raw =
                llull_buzz_wire::canonical(&record).map_err(|_| deny("native_custody_encoding"))?;
            let next_hash = sha256(&raw);
            raw.push(b'\n');
            if self.bytes + raw.len() as u64 > MAX_LOG_BYTES {
                return Err(deny("native_custody_bound"));
            }
            file.write_all(&raw)
                .and_then(|()| file.sync_data())
                .map_err(|_| deny("native_custody_write"))?;
            self.sequence += 1;
            self.bytes += raw.len() as u64;
            self.previous_sha256 = next_hash;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

/// One in-memory key allocation. Aliases are capability-scoped and journaled;
/// raw private key material cannot be exported through this API.
pub struct NativeCredential {
    key: nostr::Keys,
    scope: NativeCustodyScope,
    journal: Arc<Mutex<Journal>>,
}
impl NativeCredential {
    pub fn acquire(scope: NativeCustodyScope, key_file: &Path) -> Result<Arc<Self>> {
        Self::acquire_at(scope, key_file, Path::new(ROOT))
    }
    fn acquire_at(scope: NativeCustodyScope, key_file: &Path, root: &Path) -> Result<Arc<Self>> {
        Self::acquire_owned(scope, key_file, root, ProcessIncarnation::current)
    }
    fn acquire_owned(
        scope: NativeCustodyScope,
        key_file: &Path,
        root: &Path,
        process_reader: fn() -> Result<ProcessIncarnation>,
    ) -> Result<Arc<Self>> {
        scope.validate()?;
        if key_file != Path::new(&scope.credential_file) {
            return Err(deny("native_custody_key_path"));
        }
        let process = process_reader()?;
        let directory = private_directory(root)?;
        let file_name = format!("{}.jsonl", scope.custody_id);
        let fd = openat(
            directory.native_descriptor()?,
            file_name.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::APPEND
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| deny("native_custody_original_history"))?;
        let mut journal = Journal {
            directory,
            file: Some(File::from(fd)),
            file_name,
            scope_sha256: scope.digest()?,
            process: process.clone(),
            process_reader,
            sequence: 0,
            previous_sha256: ZERO.into(),
            bytes: 0,
            failed: false,
        };
        let key_parent = private_directory(
            key_file
                .parent()
                .ok_or_else(|| deny("native_custody_key_path"))?,
        )?;
        let fd = openat(
            key_parent.native_descriptor()?,
            key_file
                .file_name()
                .ok_or_else(|| deny("native_custody_key_path"))?,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| deny("native_custody_key_file"))?;
        let s = fstat(&fd).map_err(|_| deny("native_custody_key_file"))?;
        if s.st_mode & 0o170000 != 0o100000
            || s.st_mode & 0o077 != 0
            || s.st_nlink != 1
            || s.st_uid != process.uid
            || s.st_size <= 0
            || s.st_size > 1024
        {
            return Err(deny("native_custody_key_file"));
        }
        let mut secret = String::new();
        let mut file = File::from(fd);
        let read_result = (&mut file).take(1025).read_to_string(&mut secret);
        let after = fstat(&file).map_err(|_| deny("native_custody_key_file"))?;
        let named = rustix::fs::statat(
            key_parent.native_descriptor()?,
            key_file
                .file_name()
                .ok_or_else(|| deny("native_custody_key_path"))?,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| deny("native_custody_key_file"))?;
        let stable = (
            s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_size, s.st_mtime, s.st_ctime,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_mode,
            after.st_size,
            after.st_mtime,
            after.st_ctime,
        ) && (s.st_dev, s.st_ino) == (named.st_dev, named.st_ino);
        let close_failed = nix::unistd::close(file).is_err();
        let parent_faults = key_parent.close();
        if close_failed || !parent_faults.is_empty() {
            return Err(deny("native_custody_key_cleanup"));
        }
        read_result.map_err(|_| deny("native_custody_key_file"))?;
        if !stable || secret.len() != s.st_size as usize {
            return Err(deny("native_custody_key_file_changed"));
        }
        let key_file_sha256 = sha256(secret.as_bytes());
        let key = nostr::Keys::parse(secret.trim()).map_err(|_| deny("native_custody_key"))?;
        // Drop/overwrite input before returning any capability. The Nostr key
        // implementation owns its own secret allocation until process retirement.
        let mut bytes = secret.into_bytes();
        bytes.fill(0);
        if key.public_key().to_hex() != scope.credential_public_key {
            return Err(deny("native_custody_key_identity"));
        }
        let credential_scope = scope.clone();
        journal.append(CustodyEvent::Acquire {
            scope: Box::new(scope),
            process,
            key_file_sha256,
        })?;
        Ok(Arc::new(Self {
            key,
            scope: credential_scope,
            journal: Arc::new(Mutex::new(journal)),
        }))
    }
    #[cfg(test)]
    pub(crate) fn acquire_synthetic_fixture(
        scope: NativeCustodyScope,
        key_file: &Path,
        root: &Path,
        process_reader: fn() -> Result<ProcessIncarnation>,
    ) -> Result<Arc<Self>> {
        Self::acquire_owned(scope, key_file, root, process_reader)
    }
    pub fn signer(self: &Arc<Self>, capability: &str) -> Result<NativeSigner> {
        if !matches!(
            capability,
            "native-http" | "native-publication" | "consumer-http"
        ) {
            return Err(deny("native_custody_capability"));
        }
        self.journal
            .lock()
            .map_err(|_| deny("native_custody_lock"))?
            .append(CustodyEvent::CapabilityOpen {
                capability: capability.into(),
            })?;
        Ok(NativeSigner {
            inner: Signer::Tracked {
                owner: self.clone(),
                capability: capability.into(),
            },
        })
    }
}
impl Drop for NativeCredential {
    fn drop(&mut self) {
        if let Ok(mut journal) = self.journal.lock() {
            let _ = journal.append(CustodyEvent::Released);
            // No release result is asserted by Drop: collectors require the
            // durable event plus independent absence of this process incarnation.
            journal.file.take();
        }
    }
}
enum Signer {
    Legacy(nostr::Keys),
    Tracked {
        owner: Arc<NativeCredential>,
        capability: String,
    },
}
pub struct NativeSigner {
    inner: Signer,
}
impl From<nostr::Keys> for NativeSigner {
    fn from(key: nostr::Keys) -> Self {
        Self {
            inner: Signer::Legacy(key),
        }
    }
}
impl NativeSigner {
    pub fn public_key(&self) -> nostr::PublicKey {
        match &self.inner {
            Signer::Legacy(key) => key.public_key(),
            Signer::Tracked { owner, .. } => owner.key.public_key(),
        }
    }
    pub(crate) fn bind_public_origin(
        &self,
        origin: &str,
    ) -> std::result::Result<(), crate::ports::PortError> {
        if let Signer::Tracked { owner, .. } = &self.inner {
            let actual = url::Url::parse(origin).map_err(|_| crate::ports::PortError)?;
            let expected =
                url::Url::parse(&owner.scope.public_origin).map_err(|_| crate::ports::PortError)?;
            if actual.origin() != expected.origin() {
                return Err(crate::ports::PortError);
            }
        }
        Ok(())
    }
    pub(crate) fn bind_native(
        &self,
        community: &str,
        private: &str,
        public: &str,
        relay: &str,
    ) -> std::result::Result<(), crate::ports::PortError> {
        if let Signer::Tracked { owner, .. } = &self.inner {
            let scope = &owner.scope;
            if scope.community_id != community
                || scope.private_origin != private
                || scope.public_origin != public
                || scope.relay_public_key != relay
            {
                return Err(crate::ports::PortError);
            }
        }
        Ok(())
    }
    pub(crate) fn sign(
        &self,
        builder: nostr::EventBuilder,
    ) -> std::result::Result<nostr::Event, crate::ports::PortError> {
        let (key, custody) = match &self.inner {
            Signer::Legacy(key) => (key, None),
            Signer::Tracked { owner, capability } => (&owner.key, Some((owner, capability))),
        };
        let event = builder
            .sign_with_keys(key)
            .map_err(|_| crate::ports::PortError)?;
        if let Some((owner, capability)) = custody {
            if !matches!(
                (capability.as_str(), event.kind.as_u16()),
                ("native-http", 27235 | 24242)
                    | ("native-publication", 9)
                    | ("consumer-http", 27235)
            ) {
                return Err(crate::ports::PortError);
            }
            let public_claims =
                PublicCredentialClaims::from_event(&event).map_err(|_| crate::ports::PortError)?;
            public_claims
                .validate(&owner.scope, capability, event.kind.as_u16())
                .map_err(|_| crate::ports::PortError)?;
            owner
                .journal
                .lock()
                .map_err(|_| crate::ports::PortError)?
                .append(CustodyEvent::CredentialIssuedV2 {
                    capability: capability.clone(),
                    event_id: event.id.to_hex(),
                    token_sha256: sha256(
                        &serde_json::to_vec(&event).map_err(|_| crate::ports::PortError)?,
                    ),
                    kind: event.kind.as_u16(),
                    public_claims: Box::new(public_claims),
                })
                .map_err(|_| crate::ports::PortError)?;
        }
        Ok(event)
    }
}
impl Drop for NativeSigner {
    fn drop(&mut self) {
        if let Signer::Tracked { owner, capability } = &self.inner {
            if let Ok(mut journal) = owner.journal.lock() {
                let _ = journal.append(CustodyEvent::CapabilityClosed {
                    capability: capability.clone(),
                });
            }
        }
    }
}
