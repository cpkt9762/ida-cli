//! Versioned native cache inputs. Existing IDBs are never replaced by refresh.
use crate::{
    error::ToolError,
    preprocess::{Preparation, StagedArtifact},
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub fn current(root: &Path, key: &str) -> anyhow::Result<Option<PathBuf>> {
    let index = read_index(root)?;
    let Some(relative) = index.get(key) else {
        return Ok(None);
    };
    let path = Path::new(relative);
    anyhow::ensure!(
        path.components().count() == 3
            && path.starts_with("generations")
            && path.file_name().is_some_and(|n| n == "input.i64")
            && path
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
        "invalid generation index path"
    );
    let path = root.join(path);
    for candidate in [&path, &path.with_extension("")] {
        if let Ok(meta) = candidate.symlink_metadata() {
            anyhow::ensure!(
                !meta.file_type().is_symlink(),
                "symlink generation file refused"
            );
        }
    }
    if !path.parent().is_some_and(Path::is_dir) {
        return Ok(None);
    }
    anyhow::ensure!(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("generation parent missing"))?
            .canonicalize()?
            .starts_with(root.canonicalize()?),
        "generation escapes cache"
    );
    Ok(Some(path))
}
pub(crate) fn read_index(root: &Path) -> anyhow::Result<BTreeMap<String, String>> {
    match std::fs::read(root.join("nexus-index.json")) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error.into()),
    }
}
pub fn publish_index(
    root: &Path,
    key: &str,
    idb: &Path,
    preparation: &Preparation,
) -> anyhow::Result<()> {
    // A separate short index lock serializes publishers holding shared root locks.
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join(".index.lock"))?;
    // SAFETY: the descriptor remains owned until the function returns.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        anyhow::bail!(
            "cache index publication busy: {}",
            std::io::Error::last_os_error()
        );
    }
    let result = (|| {
        preparation.check()?;
        let mut index = read_index(root)?;
        index.insert(
            key.into(),
            idb.strip_prefix(root)?.to_string_lossy().into_owned(),
        );
        let stage = StagedArtifact::create(&root.join("nexus-index.json"))?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage.output)?;
        use std::io::Write;
        output.write_all(&serde_json::to_vec(&index)?)?;
        output.sync_all()?;
        // Only the index pointer is replaceable; generation contents never are.
        stage.commit(preparation, || {
            #[cfg(any(test, feature = "nexus-test-support"))]
            {
                // A real blocking syscall after the artifact commit point. Only
                // the protocol regression creates this private FIFO.
                let fifo = root.join(".n7-publish-fifo");
                if fifo.exists() {
                    std::fs::read(fifo)?;
                }
            }
            std::fs::rename(&stage.output, root.join("nexus-index.json"))
        })?;
        std::fs::File::open(root)?.sync_all()?;
        Ok::<_, anyhow::Error>(())
    })();
    // SAFETY: explicitly release before close to avoid fork/exec lock inheritance.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) } != 0 {
        anyhow::bail!(
            "cache index unlock failed: {}",
            std::io::Error::last_os_error()
        );
    }
    result
}

fn unique() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}
pub fn create(
    root: &Path,
    key: &str,
    snapshot: &Path,
    preparation: &Preparation,
) -> anyhow::Result<PathBuf> {
    let container = root.join("generations");
    anyhow::ensure!(
        !container
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink()),
        "symlink generation container refused"
    );
    std::fs::create_dir_all(&container)?;
    let destination = container.join(unique());
    let stage = StagedArtifact::create(&destination)?;
    std::fs::create_dir(&stage.output)?;
    std::fs::hard_link(snapshot, stage.output.join("input"))?;
    std::fs::write(
        stage.output.join("generation.json"),
        serde_json::to_vec(&serde_json::json!({"version":1,"key":key}))?,
    )?;
    std::fs::File::open(stage.output.join("input"))?.sync_all()?;
    std::fs::File::open(stage.output.join("generation.json"))?.sync_all()?;
    stage.publish_directory(preparation)?;
    std::fs::File::open(container)?.sync_all()?;
    Ok(destination.join("input"))
}

pub async fn preprocess(
    path: PathBuf,
    root: PathBuf,
    preparation: &Preparation,
) -> Result<Option<StagedArtifact>, ToolError> {
    let Some(command) = std::env::var_os("IDA_NEXUS_INPUT_PREPROCESSOR") else {
        return Ok(None);
    };
    // Local trusted executable: receives input and a task-owned staging output.
    let stage = StagedArtifact::create(&root.join(".preprocessed-input"))
        .map_err(|e| ToolError::IdaError(format!("input processor staging: {e}")))?;
    let receipt = stage.cleanup_receipt();
    let mut child = tokio::process::Command::new(command);
    child.arg(&path).arg(&stage.output);
    let result = crate::preprocess::run(child, preparation.clone()).await;
    if let Err(error) = result {
        drop(stage);
        receipt.wait().await?;
        return Err(error);
    }
    let output = result.map_err(|e| ToolError::IdaError(e.to_string()))?;
    if !output.status.success() {
        drop(stage);
        receipt.wait().await?;
        return Err(ToolError::IdaError(format!(
            "input processor failed: {}",
            output.status
        )));
    }
    Ok(Some(stage))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_index_publication_keeps_previous_generation() {
        let root = std::env::temp_dir().join(format!(
            "n7-index-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir(&root).expect("private test root");
        let old = root.as_path().join("generations/old/input.i64");
        let new = root.as_path().join("generations/new/input.i64");
        let prep = Preparation::new(std::time::Duration::from_secs(5));
        publish_index(root.as_path(), "key", &old, &prep).expect("initial index");
        let before = std::fs::read(root.as_path().join("nexus-index.json")).unwrap();
        prep.cancel.cancel();
        assert!(publish_index(root.as_path(), "key", &new, &prep).is_err());
        assert_eq!(
            std::fs::read(root.as_path().join("nexus-index.json")).unwrap(),
            before
        );
        std::fs::remove_dir_all(root).expect("remove private index root");
    }
}
