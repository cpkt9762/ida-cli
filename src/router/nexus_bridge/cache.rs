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
    #[cfg(test)]
    hook("snapshot_hashed");
    let (cached, destination) = store.prepared_paths(&path)?;
    let input = cached.unwrap_or(destination).with_extension("");
    #[cfg(test)]
    hook("path_selected");
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
    #[cfg(test)]
    hook("before_publish");
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

#[cfg(test)]
type CacheHook = Box<dyn FnMut(&str)>;
#[cfg(test)]
thread_local! { static HOOK: std::cell::RefCell<Option<CacheHook>> = std::cell::RefCell::new(None); }
#[cfg(test)]
fn hook(phase: &str) {
    HOOK.with(|h| {
        if let Some(f) = h.borrow_mut().as_mut() {
            f(phase);
        }
    });
}
#[cfg(test)]
mod f1_regressions {
    use super::*;
    use std::time::Duration;
    fn root(label: &str) -> PathBuf {
        let root = PathBuf::from(std::env::var_os("F1_ROOT").expect("external evidence root"))
            .join(format!("cache-{}-{label}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }
    #[test]
    fn p27_cancel_winning_publication_arbitration_does_not_publish() {
        let root = root("cancel");
        let source = root.join("source");
        let cache = root.join("cache");
        std::fs::write(&source, b"A").unwrap();
        let p = Preparation::new(Duration::from_secs(2));
        let cancel = p.cancel.clone();
        HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |phase| {
                if phase == "before_publish" {
                    cancel.cancel();
                }
            }))
        });
        let result = prepare(source, cache.clone(), &p);
        HOOK.with(|h| h.borrow_mut().take());
        assert!(result.is_err(), "cancel before commit must win");
        assert!(!std::fs::read_dir(cache).unwrap().any(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
    }
    #[test]
    fn p28_cache_path_and_published_bytes_use_one_snapshot() {
        let root = root("snapshot");
        let source = root.join("source");
        let cache = root.join("cache");
        std::fs::write(&source, b"A").unwrap();
        let changing = source.clone();
        HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |phase| match phase {
                "snapshot_hashed" => std::fs::write(&changing, b"B").unwrap(),
                "path_selected" => std::fs::write(&changing, b"A").unwrap(),
                _ => {}
            }))
        });
        let result = prepare(source, cache, &Preparation::new(Duration::from_secs(2))).unwrap();
        HOOK.with(|h| h.borrow_mut().take());
        assert_eq!(std::fs::read(&result).unwrap(), b"A");
        assert!(
            result
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(&blake3::hash(b"A").to_hex()[..12]),
            "path must identify published snapshot A: {result:?}"
        );
    }
    #[test]
    fn p28_existing_idb_without_proven_input_is_refused() {
        let root = root("unproven-idb");
        let source = root.join("source");
        let cache = root.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(&source, b"A").unwrap();
        let idb = IdbStore::with_root(cache.clone()).idb_path(&source);
        std::fs::write(&idb, b"unrelated database").unwrap();
        assert!(
            prepare(source, cache, &Preparation::new(Duration::from_secs(2))).is_err(),
            "unproven existing IDB must not be accepted"
        );
        assert_eq!(std::fs::read(idb).unwrap(), b"unrelated database");
    }
}
