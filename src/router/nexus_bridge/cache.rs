//! Prepare a canonical cache input before acquiring any Nexus lease.
#[cfg(test)]
use crate::idb_store::IdbStore;
use crate::{
    blocking,
    error::ToolError,
    preprocess::{Preparation, StagedArtifact},
};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct PreparedOpen {
    pub path: PathBuf,
    pub options: serde_json::Value,
    verification: Option<PathBuf>,
    verification_handed_off: bool,
    verification_input_hash: Option<blake3::Hash>,
    pub(crate) verification_cleanup: Option<std::sync::Arc<super::verification::Cleanup>>,
    generation: Option<(PathBuf, String, PathBuf)>,
    cache_guard: Option<std::sync::Arc<super::cache_lock::CacheGuard>>,
    pub(crate) content_guard: Option<std::sync::Arc<super::cache_lock::CacheGuard>>,
    pub(crate) cache_hit: bool,
}
impl Drop for PreparedOpen {
    fn drop(&mut self) {
        if let Some(cleanup) = &self.verification_cleanup {
            match cleanup.complete(self.verification_handed_off) {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(status=%cleanup.status(),"verification copy awaiting exact owner proof")
                }
                Err(error) => {
                    tracing::warn!(%error,status=%cleanup.status(),"verification copy cleanup retained")
                }
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
        if self
            .verification_cleanup
            .as_ref()
            .is_some_and(|c| c.status()["cleanup_complete"] == true)
        {
            return Ok(());
        }
        if let Some((root, key, idb)) = self.generation.clone() {
            let guard = self.cache_guard.clone();
            let content_guard = self.content_guard.clone();
            let preparing = preparation.clone();
            preparation
                .wait(blocking::run(blocking::WorkClass::Prepare, move || {
                    let _guard = guard;
                    let _content_guard = content_guard;
                    super::generations::publish_index(&root, &key, &idb, &preparing)
                }))
                .await?
                .map_err(|e| ToolError::IdaError(format!("publish generation index: {e:#}")))?;
        }
        let Some(directory) = self.verification.clone() else {
            return Ok(());
        };
        let destination = self.path.with_extension("");
        let preparing = preparation.clone();
        let guard = self.cache_guard.clone();
        let content_guard = self.content_guard.clone();
        let expected_hash = self.verification_input_hash;
        let cleanup = self.verification_cleanup.clone();
        preparation
            .wait(blocking::run(blocking::WorkClass::Prepare, move || {
                let _guard = guard;
                let _content_guard = content_guard;
                anyhow::ensure!(
                    directory.join("closed").is_file(),
                    "legacy verification close unconfirmed"
                );
                let snapshot = directory.join("input");
                let source = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&snapshot)?;
                let snapshot_identity = source.metadata()?;
                anyhow::ensure!(
                    snapshot_identity.is_file() && snapshot_identity.nlink() == 1,
                    "verification input snapshot identity changed"
                );
                anyhow::ensure!(
                    Some(digest_file(source, &preparing)?) == expected_hash,
                    "verification input snapshot changed after custody"
                );
                let stage = StagedArtifact::create(&destination)?;
                let current = std::fs::symlink_metadata(&snapshot)?;
                anyhow::ensure!(
                    current.is_file()
                        && (current.dev(), current.ino())
                            == (snapshot_identity.dev(), snapshot_identity.ino()),
                    "verification input snapshot replaced before publication"
                );
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
                // publish() links rather than renames. Retire this exact owned
                // stage link before checking for unknown extra hard links;
                // StagedArtifact's asynchronous directory cleanup may run later.
                let staged = std::fs::symlink_metadata(&stage.output)?;
                anyhow::ensure!(
                    staged.is_file()
                        && (staged.dev(), staged.ino())
                            == (snapshot_identity.dev(), snapshot_identity.ino()),
                    "verification stage identity changed"
                );
                std::fs::remove_file(&stage.output)?;
                drop(stage);
                if let Some(cleanup) = cleanup {
                    anyhow::ensure!(
                        cleanup.complete(true)?,
                        "verification closure not confirmed"
                    );
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
            verification_input_hash: None,
            verification_cleanup: None,
            generation: None,
            cache_guard: None,
            content_guard: None,
            cache_hit: false,
        }
    }
}
pub async fn prepare_n4_open(
    path: PathBuf,
    cache: PathBuf,
    preparation: &Preparation,
) -> Result<PreparedOpen, ToolError> {
    prepare_n7_open(path, cache, preparation, false).await
}
pub async fn prepare_n7_open(
    path: PathBuf,
    cache: PathBuf,
    preparation: &Preparation,
    refresh: bool,
) -> Result<PreparedOpen, ToolError> {
    let canonical = path.clone();
    let path = preparation
        .wait(blocking::run(blocking::WorkClass::Prepare, move || {
            canonical.canonicalize()
        }))
        .await?
        .map_err(|e| ToolError::InvalidPath(e.to_string()))?;
    // Classify the caller's canonical database before a processor can erase its
    // extension and identity. Direct databases never enter preprocessing.
    if path.extension().is_some_and(|x| x == "i64" || x == "idb") {
        if refresh {
            return Err(ToolError::IdaError(
                "refresh requires the source input, never an existing IDB".into(),
            ));
        }
        let mut prepared = PreparedOpen::plain(path);
        prepared.cache_hit = true;
        prepared.options = serde_json::json!({"auto_analysis":false});
        return Ok(prepared);
    }
    let guard = super::cache_lock::acquire(&cache, preparation).await?;
    let processed =
        super::generations::preprocess(path.clone(), cache.clone(), preparation).await?;
    let source = processed
        .as_ref()
        .map_or(path, |stage| stage.output.clone());
    let hash_source = source.clone();
    let preparing = preparation.clone();
    let hash = preparation
        .wait(blocking::run(blocking::WorkClass::Prepare, move || {
            digest(&hash_source, &preparing)
        }))
        .await?
        .map_err(|e| ToolError::IdaError(format!("cache content identity: {e}")))?;
    let key = hash.to_hex()[..12].to_string();
    let content_guard = super::cache_lock::acquire_content(&cache, &key, preparation).await?;
    let preparing = preparation.clone();
    let result = preparation
        .wait(blocking::run(blocking::WorkClass::Prepare, move || {
            let mut prepared = prepare_impl_inner(source, cache, &preparing, true, refresh)?;
            // An independently mutable source must not publish under another
            // content key than the one whose coordination right we hold.
            let snapshot = if prepared.path.extension().is_some_and(|e| e == "i64") {
                prepared.path.with_extension("")
            } else {
                prepared.path.clone()
            };
            let snapshot = prepared
                .verification
                .as_ref()
                .map_or(snapshot, |p| p.join("input"));
            anyhow::ensure!(
                digest(&snapshot, &preparing)? == hash,
                "source changed while waiting for cache content coordination"
            );
            prepared.cache_guard = Some(guard);
            prepared.content_guard = Some(content_guard);
            Ok::<_, anyhow::Error>(prepared)
        }))
        .await?
        .map_err(|error| ToolError::IdaError(format!("Nexus cache preparation: {error:#}")));
    if let Some(processed) = processed {
        let receipt = processed.cleanup_receipt();
        drop(processed);
        receipt.wait().await?;
    }
    result
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
    digest_file(std::fs::File::open(path)?, preparation)
}
fn digest_file(
    mut input: std::fs::File,
    preparation: &Preparation,
) -> anyhow::Result<blake3::Hash> {
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
    prepare_impl_inner(path, cache, preparation, allow_legacy, false)
}
fn prepare_impl_inner(
    path: PathBuf,
    cache: PathBuf,
    preparation: &Preparation,
    allow_legacy: bool,
    refresh: bool,
) -> anyhow::Result<PreparedOpen> {
    preparation.check()?;
    let path = path.canonicalize()?;
    if path.extension().is_some_and(|x| x == "i64" || x == "idb") {
        anyhow::ensure!(
            !refresh,
            "refresh requires the source input, never an existing IDB"
        );
        let mut prepared = PreparedOpen::plain(path);
        prepared.cache_hit = true;
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
    if allow_legacy && !refresh {
        if let Some(idb) = super::generations::current(&cache, short)? {
            let input = idb.with_extension("");
            anyhow::ensure!(
                digest(&input, preparation)? == hash,
                "generation input hash mismatch"
            );
            let mut prepared = PreparedOpen::plain(if idb.exists() { idb } else { input });
            prepared.cache_hit = true;
            if prepared.path.extension().is_some_and(|e| e == "i64") {
                prepared.options = serde_json::json!({"auto_analysis":false});
            }
            return Ok(prepared);
        }
    }
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
    if allow_legacy && (refresh || existing.is_none()) {
        let input = super::generations::create(&cache, short, &staging, preparation)?;
        let mut prepared = PreparedOpen::plain(input.clone());
        prepared.generation = Some((cache.clone(), short.into(), input.with_extension("i64")));
        return Ok(prepared);
    }
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
            prepared.cache_hit = true;
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
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let identity = std::fs::symlink_metadata(&directory)?;
            let prepared = PreparedOpen {
                path: idb.clone(),
                options: serde_json::json!({"verification_idb":directory.join("probe.i64"),
                    "verify_input_snapshot":directory.join("input"),"auto_analysis":false}),
                verification: Some(directory.clone()),
                verification_handed_off: false,
                verification_input_hash: Some(hash),
                verification_cleanup: Some(std::sync::Arc::new(super::verification::Cleanup::new(
                    directory.clone(),
                    (identity.dev(), identity.ino()),
                    Some(idb.with_extension("")),
                ))),
                generation: None,
                cache_guard: None,
                content_guard: None,
                cache_hit: true,
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
    #[tokio::test]
    async fn n7_fix1_cold_waiter_rechecks_published_index() {
        let root = root("n7-cold-key");
        let source = root.join("source");
        let cache = root.join("cache");
        std::fs::write(&source, b"same cold input").unwrap();
        let prep = Preparation::new(Duration::from_secs(5));
        let first = prepare_n7_open(source.clone(), cache.clone(), &prep, false)
            .await
            .unwrap();
        let second_prep = prep.clone();
        let mut second =
            tokio::spawn(async move { prepare_n7_open(source, cache, &second_prep, false).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut second)
                .await
                .is_err(),
            "cold waiter must not select another generation before first index publication"
        );
        let idb = first.path.with_extension("i64");
        std::fs::write(&idb, b"packed edits").unwrap();
        first.publish_verified_input(&prep).await.unwrap();
        drop(first);
        assert_eq!(second.await.unwrap().unwrap().path, idb);
    }
    #[tokio::test]
    async fn n7_fix1_direct_idb_bypasses_processor_and_rejects_force() {
        if std::env::var("IDA_NEXUS_INPUT_PREPROCESSOR").as_deref() != Ok("/bin/cp") {
            let status = std::process::Command::new("timeout")
                .args(["10s"]).arg(std::env::current_exe().unwrap())
                .args(["--exact", "router::nexus_bridge::cache::f1_regressions::n7_fix1_direct_idb_bypasses_processor_and_rejects_force", "--nocapture"])
                .env("IDA_NEXUS_INPUT_PREPROCESSOR", "/bin/cp").status().unwrap();
            assert!(status.success());
            return;
        }
        let root = root("n7-direct");
        for extension in ["i64", "idb"] {
            let idb = root.join(format!("direct.{extension}"));
            std::fs::write(&idb, b"packed edits").unwrap();
            let prep = Preparation::new(Duration::from_secs(5));
            assert!(
                prepare_n7_open(idb.clone(), root.join("cache"), &prep, true)
                    .await
                    .is_err(),
                "direct IDB force must be rejected before preprocessing"
            );
            let opened = prepare_n7_open(idb.clone(), root.join("cache"), &prep, false)
                .await
                .unwrap();
            assert_eq!(opened.path, idb.canonicalize().unwrap());
            assert_eq!(opened.options, serde_json::json!({"auto_analysis":false}));
        }
    }
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
