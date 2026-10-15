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

pub struct PreparedOpen {
    pub path: PathBuf,
    pub options: serde_json::Value,
    verification: Option<PathBuf>,
    verification_handed_off: bool,
}
impl Drop for PreparedOpen {
    fn drop(&mut self) {
        if let Some(path) = &self.verification {
            if self.verification_handed_off && !path.join("closed").is_file() {
                tracing::warn!(path = %path.display(), "Nexus verification close unconfirmed; staging retained");
                return;
            }
            if let Err(error) = std::fs::remove_dir_all(path) {
                tracing::warn!(%error,"Nexus cache verification copy cleanup failed");
            }
        }
    }
}
impl PreparedOpen {
    pub fn handed_off(&mut self) {
        self.verification_handed_off = true;
    }
    /// Called only after opened confirms legacy SHA256 verification and probe
    /// closure. Retain that exact input snapshot before exposing the lease, so
    /// another open need not copy a packed IDB owned by a running instance.
    pub async fn publish_verified_input(&self, preparation: &Preparation) -> Result<(), ToolError> {
        let Some(directory) = self.verification.clone() else {
            return Ok(());
        };
        let destination = self.path.with_extension("");
        let preparing = preparation.clone();
        preparation
            .wait(blocking::run(blocking::WorkClass::Prepare, move || {
                anyhow::ensure!(
                    directory.join("closed").is_file(),
                    "legacy verification close unconfirmed"
                );
                let snapshot = directory.join("input");
                let stage = StagedArtifact::create(&destination)?;
                std::fs::hard_link(&snapshot, &stage.output)?;
                if let Err(error) = stage.publish(&preparing) {
                    preparing.check()?;
                    if !destination.exists()
                        || digest(&destination, &preparing)? != digest(&snapshot, &preparing)?
                    {
                        return Err(error.into());
                    }
                    // An identical independently published snapshot is safe; never
                    // replace a collision or touch the packed database itself.
                }
                Ok::<_, anyhow::Error>(())
            }))
            .await?
            .map_err(|error| {
                ToolError::IdaError(format!("Nexus verified input publication: {error:#}"))
            })
    }
    fn plain(path: PathBuf) -> Self {
        Self {
            path,
            options: serde_json::json!({"wait_analysis":true}),
            verification: None,
            verification_handed_off: false,
        }
    }
}
pub async fn prepare_n4_open(
    path: PathBuf,
    cache: PathBuf,
    preparation: &Preparation,
) -> Result<PreparedOpen, ToolError> {
    let preparing = preparation.clone();
    preparation
        .wait(blocking::run(blocking::WorkClass::Prepare, move || {
            prepare_impl(path, cache, &preparing, true)
        }))
        .await?
        .map_err(|error| ToolError::IdaError(format!("Nexus cache preparation: {error:#}")))
}

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
    Ok(prepare_impl(path, cache, preparation, false)?.path.clone())
}

fn prepare_impl(
    path: PathBuf,
    cache: PathBuf,
    preparation: &Preparation,
    allow_legacy: bool,
) -> anyhow::Result<PreparedOpen> {
    preparation.check()?;
    let path = path.canonicalize()?;
    if path.extension().is_some_and(|x| x == "i64" || x == "idb") {
        let mut prepared = PreparedOpen::plain(path);
        prepared.options = serde_json::json!({"auto_analysis":false});
        return Ok(prepared);
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
        if allow_legacy && idb.exists() {
            let mut prepared = PreparedOpen::plain(idb);
            prepared.options = serde_json::json!({"auto_analysis":false});
            return Ok(prepared);
        }
        return Ok(PreparedOpen::plain(input));
    }
    if idb.exists() {
        if allow_legacy {
            // Rejecting verification must never open/save the user's original.
            // Nexus inspects a packed copy with autoanalysis disabled first.
            let directory = cache.join(format!(
                ".nexus-verify-{}-{}",
                std::process::id(),
                IDS.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory)?;
            let prepared = PreparedOpen {
                path: idb.clone(),
                options: serde_json::json!({"verification_idb":directory.join("probe.i64"),
                    "verify_input_snapshot":directory.join("input"),"auto_analysis":false}),
                verification: Some(directory.clone()),
                verification_handed_off: false,
            };
            std::fs::copy(&idb, directory.join("probe.i64"))?;
            std::fs::rename(&staging, directory.join("input"))?;
            drop(remove);
            preparation.check()?;
            return Ok(prepared);
        }
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
    Ok(PreparedOpen::plain(input))
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
    #[test]
    fn legacy_verification_staging_requires_confirmed_close_after_handoff() {
        let root = root("verification-close");
        let input = root.join("raw");
        let cache = root.join("idb");
        std::fs::write(&input, b"test input").unwrap();
        std::fs::create_dir(&cache).unwrap();
        let short = blake3::hash(b"test input").to_hex()[..12].to_string();
        let idb = cache.join(format!("raw.{short}.dylib.i64"));
        std::fs::write(&idb, b"synthetic packed IDB").unwrap();
        for (handed_off, closed) in [(false, false), (true, false), (true, true)] {
            let mut prepared = prepare_impl(
                input.clone(),
                cache.clone(),
                &Preparation::new(Duration::from_secs(10)),
                true,
            )
            .expect("prepare a legacy verification copy");
            let directory = prepared.verification.clone().unwrap();
            if handed_off {
                prepared.handed_off();
            }
            if closed {
                std::fs::write(directory.join("closed"), b"").unwrap();
            }
            drop(prepared);
            assert_eq!(directory.exists(), handed_off && !closed);
            assert_eq!(std::fs::read(&idb).unwrap(), b"synthetic packed IDB");
            if directory.exists() {
                std::fs::remove_dir_all(directory).expect("remove synthetic retained probe");
            }
        }
    }
    #[tokio::test]
    async fn verified_legacy_input_survives_owner_save_without_reprobing_packed_idb() {
        let root = root("verified-input");
        let input = root.join("raw");
        let cache = root.join("idb");
        std::fs::write(&input, b"input snapshot").unwrap();
        std::fs::create_dir(&cache).unwrap();
        let hash = blake3::hash(b"input snapshot").to_hex()[..12].to_string();
        let idb = cache.join(format!("raw.{hash}.dylib.i64"));
        std::fs::write(&idb, b"packed before first verified open").unwrap();
        let p = Preparation::new(Duration::from_secs(10));
        let mut first = prepare_impl(input.clone(), cache.clone(), &p, true).unwrap();
        first.handed_off();
        std::fs::write(first.verification.as_ref().unwrap().join("closed"), b"").unwrap();
        // Caller has received opened only after the bridge verifies IDB SHA256.
        first.publish_verified_input(&p).await.unwrap();
        drop(first);
        std::fs::write(&idb, b"packed saved by active owner").unwrap();
        let second = prepare_impl(input, cache, &p, true).unwrap();
        assert!(
            second.verification.is_none(),
            "warm open must not copy the live packed IDB again"
        );
        assert_eq!(
            std::fs::read(idb.with_extension("")).unwrap(),
            b"input snapshot"
        );
        assert_eq!(
            std::fs::read(&idb).unwrap(),
            b"packed saved by active owner"
        );
        assert_eq!(second.path, idb);
    }
    #[tokio::test]
    async fn verified_input_publication_refuses_unclosed_cancelled_and_conflicting_proof() {
        let root = root("proof-safety");
        let input = root.join("raw");
        let cache = root.join("idb");
        std::fs::write(&input, b"input snapshot").unwrap();
        std::fs::create_dir(&cache).unwrap();
        let hash = blake3::hash(b"input snapshot").to_hex()[..12].to_string();
        let idb = cache.join(format!("raw.{hash}.dylib.i64"));
        std::fs::write(&idb, b"original IDB").unwrap();
        let p = Preparation::new(Duration::from_secs(10));
        let prepared = prepare_impl(input, cache, &p, true).unwrap();
        let destination = idb.with_extension("");
        assert!(prepared.publish_verified_input(&p).await.is_err());
        assert!(!destination.exists(), "unclosed proof cannot publish");
        std::fs::write(prepared.verification.as_ref().unwrap().join("closed"), b"").unwrap();
        let cancelled = Preparation::new(Duration::from_secs(10));
        cancelled.cancel.cancel();
        assert!(prepared.publish_verified_input(&cancelled).await.is_err());
        assert!(!destination.exists(), "cancelled proof cannot publish");
        std::fs::write(&destination, b"conflict").unwrap();
        assert!(prepared.publish_verified_input(&p).await.is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"conflict");
        std::fs::write(&destination, b"input snapshot").unwrap();
        prepared.publish_verified_input(&p).await.unwrap();
        assert_eq!(std::fs::read(&idb).unwrap(), b"original IDB");
    }
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
