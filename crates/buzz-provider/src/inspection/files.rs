//! Held-directory, no-follow private-file custody. No caller-chosen credential path.
use super::{clock::Budget, deny, InspectionError, Result};
use rustix::fs::{fstat, openat, statat, unlinkat, AtFlags, Mode, OFlags, Stat, CWD};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
};
const ROOT: &str = "/etc/llull-buzz/inspection";
const MAX_FILE: usize = llull_buzz_wire::MAX_BYTES;

/// Private bytes have no Debug/Clone/accessor returning owned aliases.
pub(crate) struct PrivateBytes(Vec<u8>);
impl PrivateBytes {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for PrivateBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
#[derive(Clone, PartialEq, Eq)]
struct Identity {
    dev: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    size: i64,
    modified: (i64, i64),
    changed: (i64, i64),
}
// The selected Linux arm64 Stat already has these canonical widths. Other
// Unix ABIs (including Darwin dev/mode) retain the original conversions below.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn identity(s: &Stat) -> Identity {
    Identity {
        dev: s.st_dev,
        inode: s.st_ino,
        owner: s.st_uid,
        mode: s.st_mode,
        links: s.st_nlink as u64,
        size: s.st_size,
        modified: (s.st_mtime, s.st_mtime_nsec as i64),
        changed: (s.st_ctime, s.st_ctime_nsec as i64),
    }
}
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn identity(s: &Stat) -> Identity {
    Identity {
        dev: s.st_dev as u64,
        inode: s.st_ino as u64,
        owner: s.st_uid,
        mode: s.st_mode as u32,
        links: s.st_nlink as u64,
        size: s.st_size as i64,
        modified: (s.st_mtime as i64, s.st_mtime_nsec as i64),
        changed: (s.st_ctime as i64, s.st_ctime_nsec as i64),
    }
}
struct PrivateChunk([u8; 8192]);
impl Drop for PrivateChunk {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct Directory {
    name: String,
    fd: Option<OwnedFd>,
    initial: Identity,
}
pub(crate) struct CleanupAnchor(Vec<(String, u64, u64, u32, u32)>);
pub(crate) struct PrivateDirectory {
    chain: Vec<Directory>,
    owner: u32,
}
/// Consume exactly once, including EINTR; never retry a possibly reused FD.
fn checked_close(fd: impl std::os::fd::IntoRawFd) -> std::result::Result<(), &'static str> {
    nix::unistd::close(fd).map_err(|_| "private_fd_close")
}
fn with_cleanup<T>(first: Result<T>, faults: Vec<&'static str>) -> Result<T> {
    if faults.is_empty() {
        first
    } else {
        Err(InspectionError::Unknown {
            code: "private_cleanup",
            first: first.err().map(Box::new),
            cleanup: faults,
        })
    }
}
impl PrivateDirectory {
    pub(crate) fn open(budget: &mut Budget) -> Result<Self> {
        Self::open_path(Path::new(ROOT), budget)
    }
    #[cfg(test)]
    pub(super) fn open_synthetic_fixture(path: &Path, budget: &mut Budget) -> Result<Self> {
        Self::open_path(path, budget)
    }
    fn open_path(path: &Path, budget: &mut Budget) -> Result<Self> {
        Self::open_checked(path, || budget.sample(super::clock::now()).map(|_| ()))
    }
    // Cleanup-only fixed path: never admits an acquisition/accepted response or
    // resets its failed invocation budget. The caller already holds a refusal.
    pub(crate) fn cleanup_anchor(&self) -> CleanupAnchor {
        CleanupAnchor(
            self.chain
                .iter()
                .map(|d| {
                    (
                        d.name.clone(),
                        d.initial.dev,
                        d.initial.inode,
                        d.initial.owner,
                        d.initial.mode,
                    )
                })
                .collect(),
        )
    }
    pub(crate) fn open_for_cleanup(expected: &CleanupAnchor) -> Result<Self> {
        let mut reopened = Self::open_checked(Path::new(ROOT), || Ok(()))?;
        if reopened.cleanup_anchor().0 != expected.0 {
            let faults = reopened.close_faults();
            return with_cleanup(Err(deny("private_cleanup_parent_replaced")), faults);
        }
        Ok(reopened)
    }
    fn open_checked(path: &Path, mut tick: impl FnMut() -> Result<()>) -> Result<Self> {
        if !path.is_absolute() {
            return Err(deny("private_root"));
        }
        let owner = rustix::process::geteuid().as_raw();
        let mut result = Self {
            chain: Vec::new(),
            owner,
        };
        let admitted = (|| {
            tick()?;
            let fd = openat(
                CWD,
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| deny("private_root"))?;
            result.push_directory("/".into(), fd, false)?;
            let components = path.components().collect::<Vec<_>>();
            for (i, component) in components.iter().enumerate().skip(1) {
                let Component::Normal(name) = component else {
                    return Err(deny("private_root"));
                };
                tick()?;
                let fd = openat(
                    result.leaf()?,
                    *name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| deny("private_root"))?;
                result.push_directory(
                    name.to_str().ok_or_else(|| deny("private_root"))?.into(),
                    fd,
                    i + 1 == components.len(),
                )?;
                result.check_chain()?;
            }
            if result.chain.len() < 2 {
                return Err(deny("private_root"));
            }
            tick()?;
            Ok(())
        })();
        match admitted {
            Ok(()) => Ok(result),
            Err(first) => with_cleanup(Err(first), result.close_faults()),
        }
    }
    fn push_directory(&mut self, name: String, fd: OwnedFd, leaf: bool) -> Result<()> {
        let checked = (|| {
            let s = fstat(&fd).map_err(|_| deny("private_directory_stat"))?;
            let i = identity(&s);
            if i.mode & 0o170000 != 0o040000
                || (i.owner != 0 && i.owner != self.owner)
                || i.mode & 0o022 != 0
                || (leaf && (i.owner != self.owner || i.mode & 0o777 != 0o700))
            {
                return Err(deny("private_directory_mode"));
            }
            Ok(i)
        })();
        match checked {
            Ok(initial) => {
                self.chain.push(Directory {
                    name,
                    fd: Some(fd),
                    initial,
                });
                Ok(())
            }
            Err(first) => with_cleanup(Err(first), checked_close(fd).err().into_iter().collect()),
        }
    }
    fn leaf(&self) -> Result<&OwnedFd> {
        self.chain
            .last()
            .and_then(|d| d.fd.as_ref())
            .ok_or_else(|| deny("private_closed"))
    }
    fn check_chain(&self) -> Result<()> {
        for (index, d) in self.chain.iter().enumerate() {
            let current = identity(
                &fstat(d.fd.as_ref().ok_or_else(|| deny("private_closed"))?)
                    .map_err(|_| deny("private_directory_stat"))?,
            );
            if (current.dev, current.inode, current.owner, current.mode)
                != (
                    d.initial.dev,
                    d.initial.inode,
                    d.initial.owner,
                    d.initial.mode,
                )
            {
                return Err(deny("private_directory_replaced"));
            }
            if index > 0 {
                let linked = identity(
                    &statat(
                        self.chain[index - 1]
                            .fd
                            .as_ref()
                            .ok_or_else(|| deny("private_closed"))?,
                        d.name.as_str(),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .map_err(|_| deny("private_directory_link"))?,
                );
                if (linked.dev, linked.inode, linked.owner, linked.mode)
                    != (current.dev, current.inode, current.owner, current.mode)
                {
                    return Err(deny("private_directory_replaced"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn read(&self, name: &str, budget: &mut Budget) -> Result<PrivateBytes> {
        if !matches!(
            name,
            "trust.json"
                | "profile.jws"
                | "request.jws"
                | "response-key.pem"
                | "sql-password"
                | "sql-root.pem"
                | "schema-manifest.json"
        ) {
            return Err(deny("private_file_selector"));
        }
        self.check_chain()?;
        budget.sample(super::clock::now())?;
        let fd = openat(
            self.leaf()?,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| deny("private_file_open"))?;
        let mut file = File::from(fd);
        let first = (|| {
            let before = identity(&fstat(&file).map_err(|_| deny("private_file_stat"))?);
            if before.mode & 0o170000 != 0o100000
                || before.owner != self.owner
                || before.mode & 0o777 != 0o600
                || before.links != 1
                || before.size <= 0
                || before.size > MAX_FILE as i64
            {
                return Err(deny("private_file_mode_size"));
            }
            let mut bytes = PrivateBytes(Vec::with_capacity(before.size as usize));
            let mut chunk = PrivateChunk([0u8; 8192]);
            loop {
                budget.sample(super::clock::now())?;
                let count = file
                    .read(&mut chunk.0)
                    .map_err(|_| deny("private_file_read"))?;
                if count == 0 {
                    break;
                }
                if bytes
                    .0
                    .len()
                    .checked_add(count)
                    .filter(|n| *n <= before.size as usize)
                    .is_none()
                {
                    chunk.0.fill(0);
                    return Err(deny("private_file_grew"));
                }
                bytes.0.extend_from_slice(&chunk.0[..count]);
                chunk.0.fill(0);
            }
            chunk.0.fill(0);
            let after = identity(&fstat(&file).map_err(|_| deny("private_file_stat"))?);
            let linked = identity(
                &statat(self.leaf()?, name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| deny("private_file_link"))?,
            );
            self.check_chain()?;
            if before != after || before != linked || bytes.0.len() != before.size as usize {
                return Err(deny("private_file_changed"));
            }
            budget.sample(super::clock::now())?;
            Ok(bytes)
        })();
        with_cleanup(first, checked_close(file).err().into_iter().collect())
    }
    pub(crate) fn current(&self, name: &str, expected: &str, budget: &mut Budget) -> Result<()> {
        let bytes = self.read(name, budget)?;
        let hash = llull_buzz_wire::sha256(bytes.bytes());
        drop(bytes);
        budget.sample(super::clock::now())?;
        if hash != expected {
            return Err(deny("private_generation_changed"));
        }
        Ok(())
    }
    pub(crate) fn write_response(
        &self,
        name: &str,
        bytes: &[u8],
        budget: &mut Budget,
    ) -> Result<Output> {
        if name.len() != 68
            || !name.ends_with(".jws")
            || llull_buzz_wire::hash(&name[..64]).is_err()
            || bytes.is_empty()
            || bytes.len() > MAX_FILE
        {
            return Err(deny("private_output_selector"));
        }
        self.check_chain()?;
        budget.sample(super::clock::now())?;
        let fd = openat(
            self.leaf()?,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| deny("private_output_create"))?;
        let mut file = File::from(fd);
        let initial = fstat(&file)
            .map(|s| identity(&s))
            .map_err(|_| deny("private_output_stat"));
        let first = (|| {
            let initial = initial.as_ref().map_err(|_| deny("private_output_stat"))?;
            if initial.owner != self.owner
                || initial.mode & 0o777 != 0o600
                || initial.links != 1
                || initial.size != 0
            {
                return Err(deny("private_output_mode"));
            }
            for chunk in bytes.chunks(8192) {
                budget.sample(super::clock::now())?;
                file.write_all(chunk)
                    .map_err(|_| deny("private_output_write"))?;
            }
            file.sync_all().map_err(|_| deny("private_output_sync"))?;
            let written = identity(&fstat(&file).map_err(|_| deny("private_output_stat"))?);
            let linked = identity(
                &statat(self.leaf()?, name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| deny("private_output_link"))?,
            );
            self.check_chain()?;
            if written != linked
                || written.inode != initial.inode
                || written.dev != initial.dev
                || written.size != bytes.len() as i64
                || written.links != 1
                || written.owner != initial.owner
                || written.mode != initial.mode
            {
                return Err(deny("private_output_changed"));
            }
            rustix::fs::fsync(self.leaf()?).map_err(|_| deny("private_directory_sync"))?;
            budget.sample(super::clock::now())?;
            Ok(Output {
                name: name.into(),
                identity: written,
                sha256: llull_buzz_wire::sha256(bytes),
                body_sha256: String::new(),
            })
        })();
        let mut faults = checked_close(file).err().into_iter().collect::<Vec<_>>();
        if first.is_err() || !faults.is_empty() {
            match initial {
                Ok(initial) => {
                    if self.unlink_owned(name, &initial).is_err() {
                        faults.push("private_output_remove");
                    }
                }
                Err(_) => faults.push("private_output_identity_unknown"),
            }
        }
        with_cleanup(first, faults)
    }
    /// Reacquire only an output created by this invocation under the held
    /// parent. Content, original identity and private protection all bind before
    /// and after the bounded read; close uncertainty can never return bytes.
    pub(crate) fn read_response(
        &self,
        output: &Output,
        budget: &mut Budget,
    ) -> Result<PrivateBytes> {
        #[cfg(test)]
        if test_fault("output-read") {
            return Err(deny("inert_output_read"));
        }
        self.check_chain()?;
        budget.sample(super::clock::now())?;
        let fd = openat(
            self.leaf()?,
            output.name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| deny("private_output_read_open"))?;
        let mut file = File::from(fd);
        let first = (|| {
            let before = identity(&fstat(&file).map_err(|_| deny("private_output_stat"))?);
            #[cfg(test)]
            let before = {
                let mut before = before;
                if test_fault("output-owner") {
                    before.owner = before.owner.wrapping_add(1);
                }
                before
            };
            if before != output.identity
                || before.owner != self.owner
                || before.mode & 0o777 != 0o600
                || before.mode & 0o170000 != 0o100000
                || before.links != 1
                || before.size <= 0
                || before.size > MAX_FILE as i64
            {
                return Err(deny("private_output_generation"));
            }
            let mut bytes = PrivateBytes(Vec::with_capacity(before.size as usize));
            let mut chunk = PrivateChunk([0; 8192]);
            loop {
                budget.sample(super::clock::now())?;
                let count = file
                    .read(&mut chunk.0)
                    .map_err(|_| deny("private_output_read"))?;
                if count == 0 {
                    break;
                }
                if bytes
                    .0
                    .len()
                    .checked_add(count)
                    .is_none_or(|len| len > before.size as usize)
                {
                    return Err(deny("private_output_read_bound"));
                }
                bytes.0.extend_from_slice(&chunk.0[..count]);
                chunk.0.fill(0);
            }
            let after = identity(&fstat(&file).map_err(|_| deny("private_output_stat"))?);
            let linked = identity(
                &statat(
                    self.leaf()?,
                    output.name.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|_| deny("private_output_link"))?,
            );
            self.check_chain()?;
            if before != after
                || before != linked
                || bytes.0.len() != before.size as usize
                || llull_buzz_wire::sha256(bytes.bytes()) != output.sha256
            {
                return Err(deny("private_output_generation"));
            }
            budget.sample(super::clock::now())?;
            Ok(bytes)
        })();
        let faults = checked_close(file).err().into_iter().collect::<Vec<_>>();
        #[cfg(test)]
        let faults = {
            let mut faults = faults;
            if test_fault("output-close") {
                faults.push("inert_output_close");
            }
            faults
        };
        let result = with_cleanup(first, faults);
        #[cfg(test)]
        if test_fault("final-hash-clock") {
            let _ = budget.sample(0);
        }
        // Even a late close/hash cannot become accepted persisted custody.
        let terminal = budget.sample(super::clock::now());
        match result {
            Ok(bytes) => {
                terminal?;
                Ok(bytes)
            }
            Err(error) => Err(error),
        }
    }
    fn unlink_owned(&self, name: &str, expected: &Identity) -> Result<()> {
        self.check_chain()?;
        let actual = identity(
            &statat(self.leaf()?, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| deny("private_output_link"))?,
        );
        if (actual.dev, actual.inode, actual.owner)
            != (expected.dev, expected.inode, expected.owner)
        {
            return Err(deny("private_output_replaced"));
        }
        unlinkat(self.leaf()?, name, AtFlags::empty())
            .map_err(|_| deny("private_output_remove"))?;
        rustix::fs::fsync(self.leaf()?).map_err(|_| deny("private_directory_sync"))?;
        Ok(())
    }
    pub(crate) fn check_response_generation(&self, output: &Output) -> Result<()> {
        self.check_chain()?;
        let linked = identity(
            &statat(
                self.leaf()?,
                output.name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| deny("private_output_link"))?,
        );
        if linked != output.identity
            || linked.owner != self.owner
            || linked.mode & 0o777 != 0o600
            || linked.links != 1
        {
            return Err(deny("private_output_generation"));
        }
        Ok(())
    }
    pub(crate) fn remove_output(&self, output: &Output) -> Result<()> {
        #[cfg(test)]
        if test_fault("remove") {
            return Err(deny("inert_file_remove"));
        }
        self.unlink_owned(&output.name, &output.identity)
    }
    fn close_faults(&mut self) -> Vec<&'static str> {
        let mut faults = Vec::new();
        for d in self.chain.iter_mut().rev() {
            if let Some(fd) = d.fd.take() {
                if let Err(code) = checked_close(fd) {
                    faults.push(code);
                }
            }
        }
        faults
    }
    pub(crate) fn close(mut self) -> Vec<&'static str> {
        self.close_faults()
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = self.close_faults();
    }
}
pub(crate) struct Output {
    name: String,
    identity: Identity,
    pub(crate) sha256: String,
    pub(crate) body_sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir().unwrap().join(format!(
                "owned-private-file-test-{}-{}",
                std::process::id(),
                super::super::clock::now()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, body: &[u8]) {
            let path = self.0.join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only the exact unique fixture directory and entries authored by this test.
            if let Ok(entries) = std::fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    fn budget() -> Budget {
        let now = super::super::clock::now();
        Budget::new(now, now + 30_000_000).unwrap()
    }
    #[test]
    fn actual_held_directory_private_read_and_generation_binding() {
        let fixture = Fixture::new();
        fixture.file("trust.json", b"{\"generation\":1}");
        let mut b = budget();
        let dir = PrivateDirectory::open_path(&fixture.0, &mut b).unwrap();
        let bytes = dir.read("trust.json", &mut b).unwrap();
        assert_eq!(bytes.bytes(), b"{\"generation\":1}");
        let hash = llull_buzz_wire::sha256(bytes.bytes());
        drop(bytes);
        dir.current("trust.json", &hash, &mut b).unwrap();
        fixture.file("trust.json", b"{\"generation\":2}");
        assert!(dir.current("trust.json", &hash, &mut b).is_err());
        assert!(dir.read("../trust.json", &mut b).is_err());
        assert!(dir.close().is_empty());
    }
    #[test]
    fn genuine_symlink_hardlink_and_world_readable_inputs_refuse() {
        let fixture = Fixture::new();
        fixture.file("original", b"synthetic-private-fixture");
        symlink("original", fixture.0.join("response-key.pem")).unwrap();
        std::fs::hard_link(fixture.0.join("original"), fixture.0.join("sql-password")).unwrap();
        fixture.file("trust.json", b"{}");
        std::fs::set_permissions(
            fixture.0.join("trust.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let mut b = budget();
        let dir = PrivateDirectory::open_path(&fixture.0, &mut b).unwrap();
        for name in ["response-key.pem", "sql-password", "trust.json"] {
            assert!(dir.read(name, &mut b).is_err());
        }
        assert!(dir.close().is_empty());
        std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(PrivateDirectory::open_path(&fixture.0, &mut b).is_err());
    }
    #[test]
    fn exclusive_private_output_custody_and_no_overwrite() {
        let fixture = Fixture::new();
        let mut b = budget();
        let dir = PrivateDirectory::open_path(&fixture.0, &mut b).unwrap();
        let name = format!("{}.jws", "a".repeat(64));
        let output = dir
            .write_response(&name, b"synthetic-signed-output", &mut b)
            .unwrap();
        assert_eq!(
            output.sha256,
            llull_buzz_wire::sha256(b"synthetic-signed-output")
        );
        assert_eq!(
            std::fs::metadata(fixture.0.join(&name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(dir.write_response(&name, b"replacement", &mut b).is_err());
        assert_eq!(
            std::fs::read(fixture.0.join(&name)).unwrap(),
            b"synthetic-signed-output"
        );
        dir.remove_output(&output).unwrap();
        assert!(!fixture.0.join(&name).exists());
        assert!(dir.close().is_empty());
    }
}

#[cfg(test)]
thread_local! { static FILE_FAULT: std::cell::RefCell<&'static str> = const { std::cell::RefCell::new("") }; }
#[cfg(test)]
pub(super) fn set_test_fault(fault: &'static str) {
    FILE_FAULT.with(|slot| *slot.borrow_mut() = fault);
}
#[cfg(test)]
fn test_fault(fault: &str) -> bool {
    FILE_FAULT.with(|slot| *slot.borrow() == fault)
}
