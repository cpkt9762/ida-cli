//! Prepare a canonical cache input before acquiring any Nexus lease.
use crate::{blocking, error::ToolError, idb_store::IdbStore, preprocess::Preparation};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Existing IDBs retain their canonical identity. Raw input is published without
/// replacement beside the content-addressed IDB, so its default Nexus output is
/// the central cache destination, including recovery without a packed base.
pub async fn prepare_open(
    path: PathBuf,
    cache: PathBuf,
    preparation: &Preparation,
) -> Result<PathBuf, ToolError> {
    let preparing = preparation.clone();
    preparation
        .wait(blocking::run(blocking::WorkClass::Prepare, move || {
            prepare(path, cache, &preparing)
        }))
        .await?
        .map_err(|e| ToolError::IdaError(format!("Nexus cache preparation: {e:#}")))
}

fn digest(path: &std::path::Path, preparation: &Preparation) -> anyhow::Result<blake3::Hash> {
    let mut input = std::fs::File::open(path)?;
    let mut hash = blake3::Hasher::new();
    let mut buffer = [0; 65536];
    loop {
        preparation.check()?;
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(hash.finalize())
}

fn prepare(path: PathBuf, cache: PathBuf, preparation: &Preparation) -> anyhow::Result<PathBuf> {
    preparation.check()?;
    let path = path.canonicalize()?;
    if path.extension().is_some_and(|x| x == "i64" || x == "idb") {
        return Ok(path);
    }
    std::fs::create_dir_all(&cache)?;
    let store = IdbStore::with_root(cache.clone());
    let hash = digest(&path, preparation)?;
    let (cached, destination) = store.prepared_paths(&path)?;
    let input = cached.unwrap_or(destination).with_extension("");
    if input.exists() {
        if digest(&input, preparation)? != hash {
            anyhow::bail!("central cache input collision; refusing replacement");
        }
        return Ok(input);
    }
    static IDS: AtomicU64 = AtomicU64::new(1);
    let staging = cache.join(format!(
        ".nexus-input-{}-{}",
        std::process::id(),
        IDS.fetch_add(1, Ordering::Relaxed)
    ));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)?;
    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_file(&self.0) {
                tracing::warn!(%error, "cache input staging cleanup failed");
            }
        }
    }
    let _remove = Remove(staging.clone());
    let mut source = std::fs::File::open(path)?;
    let mut copied = blake3::Hasher::new();
    let mut buffer = [0; 65536];
    loop {
        preparation.check()?;
        let size = source.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        output.write_all(&buffer[..size])?;
        copied.update(&buffer[..size]);
    }
    if copied.finalize() != hash {
        anyhow::bail!("source changed during cache preparation");
    }
    output.sync_all()?;
    preparation.check()?;
    match std::fs::hard_link(&staging, &input) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if digest(&input, preparation)? != hash {
                anyhow::bail!("concurrent central cache input collision");
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(input)
}
