//! Consume exact verification removal facts; only the locked Python authority deletes DB payload.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileBinding {
    identity: [u64; 3],
    size: u64,
    sha256: String,
}
fn binding(path: &Path) -> anyhow::Result<FileBinding> {
    let before = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        before.is_file() && before.uid() == uid && before.mode() & 0o022 == 0,
        "verification foreign/symlink payload retained"
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    anyhow::ensure!(
        (before.dev(), before.ino()) == (opened.dev(), opened.ino()),
        "verification file replaced before read"
    );
    let mut hash = Sha256::new();
    let mut chunk = [0_u8; 65536];
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
    }
    let after = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let signature = |v: &fs::Metadata| {
        (
            v.dev(),
            v.ino(),
            v.len(),
            v.mtime(),
            v.mtime_nsec(),
            v.ctime(),
            v.ctime_nsec(),
        )
    };
    anyhow::ensure!(
        signature(&before) == signature(&after) && signature(&before) == signature(&current),
        "verification payload changed during read"
    );
    Ok(FileBinding {
        identity: [before.dev(), before.ino(), u64::from(before.uid())],
        size: before.len(),
        sha256: format!("{:x}", hash.finalize()),
    })
}
fn file_hash(path: &Path) -> anyhow::Result<String> {
    anyhow::ensure!(
        fs::symlink_metadata(path)?.nlink() == 1,
        "verification authority hardlink refused"
    );
    Ok(binding(path)?.sha256)
}

/// Cache root/content rights are already held by preparation. Reuse the
/// verification namespace only with its own root SH then stable target EX.
pub(super) fn reuse_directory(path: &Path) -> anyhow::Result<Option<(fs::File, fs::File)>> {
    let parent = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        parent.is_dir() && parent.uid() == uid && parent.mode() & 0o077 == 0,
        "verification reuse directory identity refused"
    );
    let entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    if entries.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(
        entries.len() == 1,
        "verification reuse has pending payload/unknown namespace; retained"
    );
    let coord = entries[0].path();
    let coord_identity = fs::symlink_metadata(&coord)?;
    anyhow::ensure!(
        entries[0]
            .file_name()
            .to_string_lossy()
            .starts_with(".ida-cli-txn-")
            && fs::symlink_metadata(&coord)?.is_dir(),
        "verification reuse coordination refused"
    );
    let open_lock = |name: &str, mode: libc::c_int| -> anyhow::Result<fs::File> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(coord.join(name))?;
        let meta = file.metadata()?;
        anyhow::ensure!(
            meta.is_file() && meta.nlink() == 1 && meta.uid() == uid && meta.mode() & 0o022 == 0,
            "verification reuse lock refused"
        );
        // SAFETY: live owned descriptor; independent nonblocking flock.
        anyhow::ensure!(
            unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } == 0,
            "verification reuse writer active; retained"
        );
        let current = fs::symlink_metadata(coord.join(name))?;
        anyhow::ensure!(
            (meta.dev(), meta.ino()) == (current.dev(), current.ino()),
            "verification reuse lock replaced"
        );
        Ok(file)
    };
    let root = open_lock("root.lock", libc::LOCK_SH)?;
    let lock = open_lock("lock", libc::LOCK_EX)?;
    let target: serde_json::Value =
        serde_json::from_slice(&read_small(&coord.join("target.json"), uid)?)?;
    let lock_meta = lock.metadata()?;
    anyhow::ensure!(
        target["schema"] == 1
            && target["target"] == serde_json::json!(path.canonicalize()?.join("probe.i64"))
            && target["coord_key"]["parent"]
                == serde_json::json!([parent.dev(), parent.ino(), uid])
            && target["lock_identity"]
                == serde_json::json!([lock_meta.dev(), lock_meta.ino(), uid]),
        "verification reuse target binding changed"
    );
    let journal: serde_json::Value =
        serde_json::from_slice(&read_small(&coord.join("custody.json"), uid)?)?;
    anyhow::ensure!(
        journal["schema"] == 1
            && journal["coord_key"] == target["coord_key"]
            && journal["verification_scope"].is_object()
            && journal["entries"].as_object().is_some_and(|v| v.is_empty())
            && journal["compaction"].is_null()
            && (journal["file_intents"].is_null()
                || journal["file_intents"]
                    .as_object()
                    .is_some_and(|v| v.is_empty()))
            && journal["closed_after_holes"]
                .as_array()
                .is_some_and(|v| v.is_empty())
            && journal["next_epoch"]
                .as_u64()
                .is_some_and(|v| v > 0 && journal["closed_through"].as_u64() == Some(v - 1))
            && journal["verification_cleanup_conflict"] != true,
        "verification reuse has unsettled obligations; retained"
    );
    for entry in fs::read_dir(&coord)? {
        let entry = entry?;
        let name = entry.file_name();
        let meta = fs::symlink_metadata(entry.path())?;
        if ["observations", "proofs", "retained"]
            .iter()
            .any(|n| name == *n)
        {
            anyhow::ensure!(
                meta.is_dir() && fs::read_dir(entry.path())?.next().is_none(),
                "verification reuse has producer/evidence/scratch references; retained"
            );
        } else {
            anyhow::ensure!(
                [
                    "lock",
                    "root.lock",
                    "target.json",
                    "custody.json",
                    "volume.json"
                ]
                .iter()
                .any(|n| name == *n)
                    && meta.is_file()
                    && meta.uid() == uid
                    && meta.nlink() == 1,
                "verification reuse unknown/pending evidence retained"
            );
        }
    }
    anyhow::ensure!(
        fs::read_dir(path)?.count() == 1,
        "verification reuse namespace changed"
    );
    let current = fs::symlink_metadata(path)?;
    let coord_current = fs::symlink_metadata(&coord)?;
    anyhow::ensure!(
        (current.dev(), current.ino()) == (parent.dev(), parent.ino())
            && (coord_current.dev(), coord_current.ino())
                == (coord_identity.dev(), coord_identity.ino()),
        "verification reuse directory replaced"
    );
    Ok(Some((root, lock)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Removed {
    name: String,
    file: FileBinding,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    kind: String,
    directory: [u64; 3],
    target: PathBuf,
    coord_key: serde_json::Value,
    target_sha256: String,
    journal_sha256: String,
    input: Option<FileBinding>,
    removed: Vec<Removed>,
}

pub(crate) struct Cleanup {
    path: PathBuf,
    identity: (u64, u64),
    published_input: Option<PathBuf>,
    created: std::sync::Mutex<BTreeMap<String, FileBinding>>,
    done: std::sync::atomic::AtomicBool,
    error: std::sync::Mutex<Option<String>>,
}
impl Cleanup {
    pub(super) fn new(
        path: PathBuf,
        identity: (u64, u64),
        published_input: Option<PathBuf>,
    ) -> Self {
        let cleanup = Self {
            path,
            identity,
            published_input,
            created: std::sync::Mutex::new(BTreeMap::new()),
            done: std::sync::atomic::AtomicBool::new(false),
            error: std::sync::Mutex::new(None),
        };
        if let Err(error) = cleanup.bind_created() {
            *cleanup.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
        }
        cleanup
    }
    /// Called after our copy/rename succeeds and before any SDK handoff.
    pub(super) fn bind_created(&self) -> anyhow::Result<()> {
        let mut created = BTreeMap::new();
        for name in ["probe.i64", "input"] {
            match fs::symlink_metadata(self.path.join(name)) {
                Ok(_) => {
                    created.insert(name.into(), binding(&self.path.join(name))?);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        *self.created.lock().unwrap_or_else(|e| e.into_inner()) = created;
        Ok(())
    }
    pub(crate) fn complete(&self, handed_off: bool) -> anyhow::Result<bool> {
        if self.done.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(true);
        }
        let mut error = self.error.lock().unwrap_or_else(|e| e.into_inner());
        if self.done.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(true);
        }
        if handed_off {
            match fs::symlink_metadata(self.path.join("closed")) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(e) => {
                    *error = Some(e.to_string());
                    return Err(e.into());
                }
                Ok(_) => {}
            }
        }
        let result = self.consume_with(handed_off, true, || Ok(()));
        match result {
            Ok(()) => {
                self.done.store(true, std::sync::atomic::Ordering::Release);
                *error = None;
                Ok(true)
            }
            Err(e) => {
                *error = Some(format!("{e:#}"));
                Err(e)
            }
        }
    }
    #[cfg(test)]
    pub(super) fn validate_closure(&self) -> anyhow::Result<()> {
        self.consume_with(true, false, || Ok(()))
    }
    /// Validate, publish, and retire the immutable input while the same target
    /// EX remains owned. Normal target admission cannot enter between them.
    pub(super) fn publish_with_closure(
        &self,
        publish: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let mut error = self.error.lock().unwrap_or_else(|e| e.into_inner());
        if self.done.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        let result = self.consume_with(true, true, publish);
        match &result {
            Ok(()) => {
                self.done.store(true, std::sync::atomic::Ordering::Release);
                *error = None;
            }
            Err(failure) => *error = Some(format!("{failure:#}")),
        }
        result
    }
    fn consume_with(
        &self,
        handed_off: bool,
        remove: bool,
        publish: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let parent = fs::symlink_metadata(&self.path)?;
        anyhow::ensure!(
            parent.is_dir() && (parent.dev(), parent.ino()) == self.identity,
            "verification directory identity changed; retained"
        );
        let entries = fs::read_dir(&self.path)?
            .take(33)
            .collect::<Result<Vec<_>, _>>()?;
        anyhow::ensure!(
            entries.len() <= 32,
            "verification namespace exceeds manifest bound"
        );
        let mut coordinate = None;
        let mut payload = Vec::new();
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("unknown verification name"))?;
            let meta = fs::symlink_metadata(entry.path())?;
            if name.starts_with(".ida-cli-txn-") && meta.is_dir() {
                anyhow::ensure!(coordinate.is_none(), "ambiguous verification coordination");
                coordinate = Some(entry.path());
            } else {
                anyhow::ensure!(
                    matches!(name.as_str(), "probe.i64" | "input" | "closed")
                        && meta.is_file()
                        && meta.uid() == parent.uid(),
                    "unknown/foreign verification component retained"
                );
                if handed_off {
                    anyhow::ensure!(
                        name != "probe.i64",
                        "verification probe appeared after completed removal; retained"
                    );
                }
                payload.push((name, entry.path(), meta.nlink()));
            }
        }
        let mut target_binding = None;
        let _lock = if let Some(coord) = coordinate.as_ref() {
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(coord.join("lock"))?;
            let meta = lock.metadata()?;
            anyhow::ensure!(
                meta.is_file() && meta.nlink() == 1 && meta.uid() == parent.uid(),
                "verification lock identity refused"
            );
            // SAFETY: a live owned descriptor; independent nonblocking flock.
            anyhow::ensure!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "verification target writer active; retained"
            );
            let bytes = read_small(&coord.join("target.json"), parent.uid())?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                value["schema"] == 1
                    && value["lock_identity"]
                        == serde_json::json!([meta.dev(), meta.ino(), meta.uid()])
                    && value["target"]
                        == serde_json::json!(self.path.canonicalize()?.join("probe.i64")),
                "verification target binding changed"
            );
            target_binding = Some((value, format!("{:x}", Sha256::digest(bytes))));
            Some(lock)
        } else {
            None
        };
        // Recheck the complete namespace after acquiring stable target EX.
        // A producer may have admitted a new component while we waited.
        let current = fs::read_dir(&self.path)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let expected = payload
            .iter()
            .map(|(_, path, _)| path.clone())
            .chain(coordinate.iter().cloned())
            .collect();
        anyhow::ensure!(
            current == expected,
            "verification namespace changed before target lock; retained"
        );
        let closure_binding = if handed_off {
            Some(binding(&self.path.join("closed"))?)
        } else {
            None
        };
        let created = self.created.lock().unwrap_or_else(|e| e.into_inner());
        if handed_off {
            let coord = coordinate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("verification coordination missing"))?;
            let (target, target_hash) = target_binding
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("verification target missing"))?;
            let marker = read_small(&self.path.join("closed"), parent.uid())?;
            let receipt: Receipt = serde_json::from_slice(&marker)?;
            anyhow::ensure!(
                receipt.schema == 1
                    && receipt.kind == "verification_probe_cleanup"
                    && receipt.directory == [parent.dev(), parent.ino(), u64::from(parent.uid())]
                    && receipt.target == self.path.canonicalize()?.join("probe.i64")
                    && receipt.coord_key == target["coord_key"]
                    && receipt.target_sha256 == *target_hash,
                "verification closure scope/target changed; retained"
            );
            anyhow::ensure!(
                file_hash(&coord.join("custody.json"))? == receipt.journal_sha256,
                "verification journal changed after issuer; newer responsibility retained"
            );
            anyhow::ensure!(
                receipt.input.as_ref() == created.get("input"),
                "verification input ownership receipt changed"
            );
            for removed in receipt.removed {
                anyhow::ensure!(
                    [
                        "probe.i64",
                        "probe.id0",
                        "probe.id1",
                        "probe.id2",
                        "probe.nam",
                        "probe.til"
                    ]
                    .contains(&removed.name.as_str())
                        && removed.file.identity[2] == u64::from(parent.uid())
                        && removed.file.sha256.len() == 64,
                    "verification removed-payload receipt malformed"
                );
                anyhow::ensure!(
                    !self.path.join(removed.name).exists(),
                    "verification removed payload reappeared; retained"
                );
            }
        } else if let Some(coord) = coordinate.as_ref() {
            if coord.join("custody.json").exists() {
                let journal: serde_json::Value = serde_json::from_slice(&read_small(
                    &coord.join("custody.json"),
                    parent.uid(),
                )?)?;
                anyhow::ensure!(
                    journal["entries"].as_object().is_some_and(|m| m.is_empty())
                        && journal["file_intents"]
                            .as_object()
                            .is_none_or(|m| m.is_empty()),
                    "unpublished copy has another responsibility; retained"
                );
            }
        }
        // Only an immutable input snapshot is removed after handoff. Database
        // files were already deleted by the current Python authority under EX.
        for (name, path, _) in &payload {
            let links = fs::symlink_metadata(path)?.nlink();
            if name == "closed" {
                anyhow::ensure!(handed_off && links == 1, "unowned closure receipt retained");
                continue;
            }
            let expected = created
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("unowned verification payload retained"))?;
            anyhow::ensure!(
                binding(path)? == *expected,
                "verification payload identity/content changed; retained"
            );
            let published = name == "input"
                && links == 2
                && self.published_input.as_ref().is_some_and(|p| {
                    fs::symlink_metadata(p).is_ok_and(|m| {
                        m.is_file() && [m.dev(), m.ino(), u64::from(m.uid())] == expected.identity
                    })
                });
            anyhow::ensure!(
                links == 1 || published,
                "verification payload has foreign hardlink; retained"
            );
        }
        if !remove {
            return Ok(());
        }
        publish()?;
        payload.sort_by_key(|(name, _, _)| name == "closed");
        for (name, path, _) in payload {
            if name == "closed" {
                anyhow::ensure!(
                    closure_binding.as_ref() == Some(&binding(&path)?),
                    "verification closure replaced at unlink; retained"
                );
            } else {
                anyhow::ensure!(
                    created.get(&name) == Some(&binding(&path)?),
                    "verification payload replaced at unlink; retained"
                );
            }
            let links = fs::symlink_metadata(&path)?.nlink();
            let published = name == "input"
                && links == 2
                && self.published_input.as_ref().is_some_and(|published| {
                    fs::symlink_metadata(published).is_ok_and(|v| {
                        v.is_file()
                            && created.get("input").is_some_and(|b| {
                                b.identity == [v.dev(), v.ino(), u64::from(v.uid())]
                            })
                    })
                });
            anyhow::ensure!(
                links == 1 || published,
                "verification hardlink appeared at unlink; retained"
            );
            fs::remove_file(path)?;
        }
        if fs::read_dir(&self.path)?.next().is_none() {
            fs::remove_dir(&self.path)?;
        }
        Ok(())
    }
    pub(crate) fn status(&self) -> serde_json::Value {
        serde_json::json!({"path":self.path,"cleanup_complete":self.done.load(std::sync::atomic::Ordering::Acquire),
            "cleanup_error":*self.error.lock().unwrap_or_else(|e|e.into_inner()),"next_action":"wait_exact_probe_removal_and_unchanged_target_journal"})
    }
}
fn read_small(path: &Path, uid: u32) -> anyhow::Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    anyhow::ensure!(
        meta.is_file()
            && meta.uid() == uid
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= 65536,
        "verification receipt identity/size refused"
    );
    let mut bytes = Vec::new();
    file.by_ref().take(65537).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let signature = |v: &fs::Metadata| {
        (
            v.dev(),
            v.ino(),
            v.len(),
            v.mtime(),
            v.mtime_nsec(),
            v.ctime(),
            v.ctime_nsec(),
        )
    };
    anyhow::ensure!(
        bytes.len() as u64 == meta.len()
            && signature(&meta) == signature(&after)
            && signature(&meta) == signature(&current),
        "verification receipt changed during read"
    );
    Ok(bytes)
}

/// File-consumer fixture only. It does not issue or model an owner proof.
#[cfg(test)]
pub(super) fn issue_unit_receipt(root: &Path) {
    let coord = root.join(".ida-cli-txn-unit");
    fs::create_dir_all(&coord).expect("private coordinate");
    if !coord.join("lock").exists() {
        fs::write(coord.join("lock"), b"").expect("stable lock");
    }
    if !coord.join("root.lock").exists() {
        fs::write(coord.join("root.lock"), b"").expect("stable root lock");
    }
    fs::write(coord.join("proof"), b"retained exact proof").expect("proof bytes");
    let lock = fs::metadata(coord.join("lock")).expect("lock identity");
    let parent = fs::metadata(root).expect("copy identity");
    let key = serde_json::json!({"kind":"unit-file-consumer","parent":[parent.dev(),parent.ino(),parent.uid()]});
    let journal = serde_json::json!({"schema":1,"coord_key":key,"entries":{},"file_intents":{},"compaction":null,
        "next_epoch":1,"closed_through":0,"closed_after_holes":[],"verification_scope":{}});
    fs::write(
        coord.join("custody.json"),
        serde_json::to_vec(&journal).expect("journal JSON"),
    )
    .expect("closed fixture journal");
    let target = serde_json::json!({"schema":1,"target":root.canonicalize().expect("canonical").join("probe.i64"),
        "lock_identity":[lock.dev(),lock.ino(),lock.uid()],"coord_key":key});
    fs::write(
        coord.join("target.json"),
        serde_json::to_vec(&target).expect("target JSON"),
    )
    .expect("target");
    let removed = binding(&root.join("probe.i64")).expect("fixture probe binding");
    fs::remove_file(root.join("probe.i64")).expect("fixture issuer removes its probe");
    let marker = serde_json::json!({"schema":1,"kind":"verification_probe_cleanup",
        "directory":[parent.dev(),parent.ino(),parent.uid()],"target":root.canonicalize().expect("canonical").join("probe.i64"),
        "coord_key":key,"target_sha256":file_hash(&coord.join("target.json")).expect("target hash"),
        "journal_sha256":file_hash(&coord.join("custody.json")).expect("journal hash"),
        "input":binding(&root.join("input")).expect("fixture input"),"removed":[{"name":"probe.i64","file":removed}]});
    fs::write(
        root.join("closed"),
        serde_json::to_vec(&marker).expect("marker JSON"),
    )
    .expect("fixture completed-removal record");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    static IDS: AtomicU64 = AtomicU64::new(1);
    fn directory() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "r3b-copy-{}-{}",
            std::process::id(),
            IDS.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fresh private copy");
        fs::write(root.join("input"), b"owned input").expect("input");
        fs::write(root.join("probe.i64"), b"owned packed copy").expect("copy");
        root
    }
    #[test]
    fn copy_cleanup_requires_closure_and_rejects_unknown_files_or_symlinks() {
        let root = directory();
        let info = fs::metadata(&root).expect("directory");
        let receipt = Cleanup::new(root.clone(), (info.dev(), info.ino()), None);
        assert!(!receipt.complete(true).expect("wait for closure"));
        fs::write(root.join("closed"), b"").expect("synthetic file-cleanup receipt, not N1 proof");
        fs::write(root.join("foreign"), b"must remain").expect("unknown component");
        assert!(receipt.complete(true).is_err());
        assert!(root.join("input").exists() && root.join("probe.i64").exists());
        fs::remove_file(root.join("foreign")).expect("remove only test input");
        fs::remove_file(root.join("closed")).expect("replace receipt");
        symlink(root.join("input"), root.join("closed")).expect("negative symlink");
        assert!(receipt.complete(true).is_err());
        assert_eq!(
            fs::read(root.join("input")).expect("input retained"),
            b"owned input"
        );
        fs::remove_dir_all(root).expect("own unit fixture");
    }
    #[test]
    fn completed_removal_rejects_new_journal_even_without_a_reappeared_probe() {
        let root = directory();
        let info = fs::metadata(&root).expect("directory");
        let cleanup = Cleanup::new(root.clone(), (info.dev(), info.ino()), None);
        issue_unit_receipt(&root);
        fs::write(
            root.join(".ida-cli-txn-unit/custody.json"),
            b"{\"revision\":2,\"entries\":{}}",
        )
        .expect("new journal bytes");
        assert!(
            cleanup.validate_closure().is_err(),
            "new responsibility must block publication"
        );
        assert!(
            cleanup.complete(true).is_err(),
            "changed journal cannot authorize input deletion"
        );
        assert_eq!(
            fs::read(root.join("input")).expect("input retained"),
            b"owned input"
        );
        assert_eq!(cleanup.status()["cleanup_complete"], false);
        fs::remove_dir_all(root).expect("own unit fixture");
    }

    #[test]
    fn copy_payload_cleanup_preserves_stable_lock_and_proof_bytes() {
        let root = directory();
        let info = fs::metadata(&root).expect("directory");
        let receipt = Cleanup::new(root.clone(), (info.dev(), info.ino()), None);
        issue_unit_receipt(&root);
        let coord = root.join(".ida-cli-txn-unit");
        let lock_info = fs::metadata(coord.join("lock")).expect("lock identity");
        assert!(receipt.complete(true).expect("proved file cleanup"));
        assert!(receipt.complete(true).expect("idempotent completion"));
        assert!(!root.join("input").exists() && !root.join("probe.i64").exists());
        assert_eq!(
            fs::metadata(coord.join("lock"))
                .expect("same stable lock")
                .ino(),
            lock_info.ino()
        );
        assert_eq!(
            fs::read(coord.join("proof")).expect("proof retained"),
            b"retained exact proof"
        );
        fs::remove_dir_all(root).expect("own unit fixture");
    }
}
