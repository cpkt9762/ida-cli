//! Dispose only proved verification payload; stable coordination is never removed.
use std::{
    fs,
    io::Read,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(crate) struct Cleanup {
    path: std::path::PathBuf,
    identity: (u64, u64),
    published_input: Option<std::path::PathBuf>,
    done: std::sync::atomic::AtomicBool,
    error: std::sync::Mutex<Option<String>>,
}
impl Cleanup {
    pub(super) fn new(
        path: std::path::PathBuf,
        identity: (u64, u64),
        published_input: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            path,
            identity,
            published_input,
            done: std::sync::atomic::AtomicBool::new(false),
            error: std::sync::Mutex::new(None),
        }
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
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(failure) => {
                    *error = Some(failure.to_string());
                    return Err(failure.into());
                }
                Ok(_) => {}
            }
        }
        match cleanup(
            &self.path,
            self.identity,
            handed_off,
            self.published_input.as_deref(),
        ) {
            Ok(()) => {
                self.done.store(true, std::sync::atomic::Ordering::Release);
                Ok(true)
            }
            Err(failure) => {
                *error = Some(format!("{failure:#}"));
                Err(failure)
            }
        }
    }
    pub(crate) fn status(&self) -> serde_json::Value {
        serde_json::json!({"path":self.path,"cleanup_complete":self.done.load(std::sync::atomic::Ordering::Acquire),
            "cleanup_error":*self.error.lock().unwrap_or_else(|e|e.into_inner()),"next_action":"wait_exact_proof_and_verify_copy_gate"})
    }
}

pub(super) fn cleanup(
    directory: &Path,
    expected: (u64, u64),
    handed_off: bool,
    published_input: Option<&Path>,
) -> anyhow::Result<()> {
    let parent = fs::symlink_metadata(directory)?;
    anyhow::ensure!(
        parent.is_dir() && (parent.dev(), parent.ino()) == expected,
        "verification directory identity changed; copy retained"
    );
    let entries = fs::read_dir(directory)?
        .take(33)
        .collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        entries.len() <= 32,
        "verification namespace exceeds cleanup manifest bound"
    );
    let mut payload = Vec::new();
    let mut coordination = None;
    for entry in &entries {
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("unknown verification name"))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if name.starts_with(".ida-cli-txn-") && metadata.is_dir() {
            anyhow::ensure!(
                coordination.is_none(),
                "ambiguous verification coordination"
            );
            coordination = Some(entry.path());
        } else {
            anyhow::ensure!(
                matches!(name, "probe.i64" | "input" | "closed")
                    && metadata.is_file()
                    && metadata.uid() == parent.uid(),
                "unknown verification component; all payload retained"
            );
            let published = name == "input"
                && metadata.nlink() == 2
                && published_input
                    .and_then(|p| fs::symlink_metadata(p).ok())
                    .is_some_and(|m| {
                        m.is_file() && (m.dev(), m.ino()) == (metadata.dev(), metadata.ino())
                    });
            anyhow::ensure!(
                metadata.nlink() == 1 || published,
                "verification payload has an unknown hard link; retained"
            );
            payload.push((entry.path(), metadata.dev(), metadata.ino()));
        }
    }
    let _lock = if let Some(coordination) = coordination {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(coordination.join("lock"))?;
        let metadata = file.metadata()?;
        let mut source = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(coordination.join("target.json"))?;
        let binding_metadata = source.metadata()?;
        anyhow::ensure!(
            binding_metadata.is_file()
                && binding_metadata.nlink() == 1
                && binding_metadata.uid() == parent.uid()
                && binding_metadata.len() <= 16384,
            "verification binding file identity refused"
        );
        let mut bytes = Vec::new();
        source.by_ref().take(16385).read_to_end(&mut bytes)?;
        let binding: serde_json::Value = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            binding["schema"] == 1
                && binding["lock_identity"]
                    == serde_json::json!([metadata.dev(), metadata.ino(), metadata.uid()])
                && binding["target"]
                    == serde_json::json!(directory.canonicalize()?.join("probe.i64")),
            "verification target lock binding changed"
        );
        // SAFETY: the owned file remains open; this is an independent, nonblocking OFD.
        anyhow::ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "verification target writer still active; payload retained"
        );
        Some(file)
    } else {
        None
    };
    if handed_off {
        let marker = fs::symlink_metadata(directory.join("closed"))?;
        anyhow::ensure!(
            marker.is_file()
                && marker.uid() == parent.uid()
                && marker.nlink() == 1
                && marker.len() == 0,
            "verification closure is not confirmed; payload retained"
        );
    }
    for (path, device, inode) in &payload {
        let current = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            current.is_file() && (current.dev(), current.ino()) == (*device, *inode),
            "verification component changed before cleanup; payload retained"
        );
    }
    // Remove the receipt last. An I/O error retains the authorization needed
    // to diagnose/continue removal of the still present exact payload.
    payload.sort_by_key(|(path, _, _)| path.file_name().is_some_and(|n| n == "closed"));
    for (path, _, _) in payload {
        fs::remove_file(path)?;
    }
    // A verification CoordKey has the same permanent lock/identity rules as
    // other targets. Empty directories without coordination can be removed.
    if fs::read_dir(directory)?.next().is_none() {
        fs::remove_dir(directory)?;
    }
    Ok(())
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
    fn copy_payload_cleanup_preserves_stable_lock_and_proof_bytes() {
        let root = directory();
        let info = fs::metadata(&root).expect("directory");
        let coord = root.join(".ida-cli-txn-unit");
        fs::create_dir(&coord).expect("coordination");
        fs::write(coord.join("lock"), b"").expect("stable lock");
        let lock_info = fs::metadata(coord.join("lock")).expect("lock identity");
        let binding = serde_json::json!({"schema":1,"target":root.canonicalize().expect("target parent").join("probe.i64"),
            "lock_identity":[lock_info.dev(),lock_info.ino(),lock_info.uid()]});
        fs::write(
            coord.join("target.json"),
            serde_json::to_vec(&binding).expect("binding"),
        )
        .expect("target identity");
        fs::write(coord.join("proof"), b"retained exact proof").expect("proof evidence");
        fs::write(root.join("closed"), b"").expect("unit closure input");
        let receipt = Cleanup::new(root.clone(), (info.dev(), info.ino()), None);
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
