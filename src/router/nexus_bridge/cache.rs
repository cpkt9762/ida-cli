//! Prepare a canonical cache input before acquiring any Nexus lease.
#[cfg(test)]
use crate::idb_store::IdbStore;
use crate::{
    blocking,
    error::ToolError,
    preprocess::{Preparation, StagedArtifact},
};
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
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(%error, "cache input staging cleanup failed");
                }
            }
        }
    }
    let remove = Remove(staging.clone());
    let mut source = std::fs::File::open(&path)?;
    let mut buffer = [0; 65536];
    loop {
        preparation.check()?;
        let size = source.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        output.write_all(&buffer[..size])?;
    }
    output.sync_all()?;
    drop(output);
    // Hash only the copied snapshot. The original is never read again.
    let hash = digest(&staging, preparation)?;
    #[cfg(test)]
    hook("snapshot_hashed");
    let short = &hash.to_hex()[..12];
    let mut existing = None;
    for entry in std::fs::read_dir(&cache)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.contains(&format!(".{short}.")) && name.ends_with(".i64") {
            existing = Some(entry.path());
            break;
        }
    }
    let basename = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("input has no basename"))?
        .to_string_lossy();
    let idb = existing.unwrap_or_else(|| cache.join(format!("{basename}.{short}.dylib.i64")));
    let input = idb.with_extension("");
    #[cfg(test)]
    hook("path_selected");
    if input.exists() {
        if digest(&input, preparation)? != hash {
            anyhow::bail!("central cache input collision; refusing replacement");
        }
        return Ok(input);
    }
    if idb.exists() {
        anyhow::bail!(
            "existing central IDB has no input snapshot proving its hash; refusing reuse"
        );
    }
    let stage = StagedArtifact::create(&input)?;
    std::fs::rename(&staging, &stage.output)?;
    drop(remove);
    #[cfg(test)]
    hook("before_publish");
    if let Err(error) = stage.publish(preparation) {
        preparation.check()?;
        if !input.exists() || digest(&input, preparation)? != hash {
            return Err(error.into());
        }
        // Another opener published the identical snapshot. Never overwrite it.
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
    struct TestRoot(PathBuf);
    impl std::ops::Deref for TestRoot {
        type Target = std::path::Path;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove private cache test directory");
        }
    }
    fn root(label: &str) -> TestRoot {
        static IDS: AtomicU64 = AtomicU64::new(1);
        loop {
            let root = std::env::temp_dir().join(format!(
                "nexus-cache-{}-{label}-{}",
                std::process::id(),
                IDS.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&root) {
                Ok(()) => return TestRoot(root),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create private cache test directory: {e}"),
            }
        }
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
