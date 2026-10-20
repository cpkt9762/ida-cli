//! IDB store — content-addressed registry of IDA `.i64` databases.
//!
//! Manages the `~/.ida/` directory hierarchy and an `index.json` that tracks
//! metadata about every analysed binary.

#[cfg(test)]
use crate::process_spawn::StdOutputFenced;
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub(crate) fn ida_home_from(explicit: Option<&OsStr>, home: Option<&OsStr>) -> PathBuf {
    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        return PathBuf::from(explicit);
    }
    home.map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ida")
}

pub fn ida_home() -> PathBuf {
    ida_home_from(
        std::env::var_os("IDA_CLI_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

pub fn idb_root() -> PathBuf {
    ida_home().join("idb")
}

pub fn cache_dir() -> PathBuf {
    ida_home().join("cache")
}

pub fn socket_path() -> PathBuf {
    ida_home().join("server.sock")
}

pub fn pid_path() -> PathBuf {
    ida_home().join("server.pid")
}

/// MCP over a Unix socket, served by the daemon next to `server.sock`.
pub fn mcp_socket_path() -> PathBuf {
    ida_home().join("mcp.sock")
}

pub fn log_dir() -> PathBuf {
    ida_home().join("logs")
}

pub fn log_path() -> PathBuf {
    log_dir().join("server.log")
}

pub fn startup_lock_path() -> PathBuf {
    ida_home().join(".startup.lock")
}

pub fn discovery_path() -> PathBuf {
    if std::env::var_os("IDA_CLI_HOME")
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        ida_home().join("discovery.socket")
    } else {
        PathBuf::from("/tmp/ida-cli.socket")
    }
}

pub fn response_cache_dir() -> PathBuf {
    if std::env::var_os("IDA_CLI_HOME")
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        ida_home().join("responses")
    } else {
        PathBuf::from("/tmp/ida-cli-out")
    }
}

pub fn socket_is_live() -> bool {
    let sock = socket_path();
    sock.exists() && std::os::unix::net::UnixStream::connect(&sock).is_ok()
}

pub fn ensure_dirs() -> std::io::Result<()> {
    std::fs::create_dir_all(idb_root())?;
    std::fs::create_dir_all(log_dir())?;
    std::fs::create_dir_all(cache_dir())?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdbEntry {
    pub hash: String,
    pub original_path: String,
    pub binary_type: String, // "native" or "sbpf"
    pub size: u64,
    pub created_at: String,    // ISO 8601
    pub last_accessed: String, // ISO 8601
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdbStoreStats {
    pub root: String,
    pub file_count: usize,
    pub entry_count: usize,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdbEvictionStats {
    pub evicted_groups: usize,
    pub evicted_files: usize,
    pub evicted_bytes: u64,
    pub remaining_bytes: u64,
}

pub struct IdbStore {
    root: PathBuf,
}

impl Default for IdbStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IdbStore {
    fn nexus_gc(&self, max_bytes: u64, key: Option<&str>) -> IdbEvictionStats {
        let result = (|| {
            static EPOCH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            let epoch =
                EPOCH.get_or_init(|| format!("{}-{:?}", std::process::id(), SystemTime::now()));
            let python = crate::router::nexus_tools::runtime_python()?;
            let installation = crate::router::nexus_bridge::installation::Temporary::create()?;
            let mut command = std::process::Command::new(python);
            command
                .args(["-I", "-B"])
                .arg(installation.path.join("installation/bootstrap.py"))
                .arg("cache_store")
                .arg("--root")
                .arg(&self.root)
                .arg("--limit")
                .arg(max_bytes.to_string())
                .arg("--epoch")
                .arg(epoch);
            if let Some(key) = key {
                command.arg("--key").arg(key);
            }
            let output = crate::process_spawn::output_bounded(
                &mut command,
                std::time::Duration::from_secs(10),
                &installation.path,
            )?;
            anyhow::ensure!(
                output.status.success(),
                "cache maintenance failed: {}; {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if value["rejected"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
            {
                tracing::warn!(rejected = %value["rejected"], "Nexus cache candidates retained");
            }
            Ok::<_, anyhow::Error>(serde_json::from_value::<IdbEvictionStats>(value)?)
        })();
        match result {
            Ok(stats) => stats,
            Err(error) => {
                tracing::warn!(%error, root = %self.root.display(), "Nexus GC proof failed; candidates retained");
                IdbEvictionStats {
                    evicted_groups: 0,
                    evicted_files: 0,
                    evicted_bytes: 0,
                    remaining_bytes: self.stats().total_size_bytes,
                }
            }
        }
    }

    /// Create a store using the default idb root (`~/.ida/idb/`).
    pub fn new() -> Self {
        let root = idb_root();
        let _ = std::fs::create_dir_all(&root);
        Self { root }
    }

    /// Create a store backed by an arbitrary root directory (for testing).
    pub fn with_root(root: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&root);
        Self { root }
    }

    /// Error-preserving streaming hash for asynchronous preparation consumers.
    pub fn try_compute_hash(path: &Path) -> std::io::Result<String> {
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        let mut bytes = [0; 64 * 1024];
        loop {
            let n = file.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            hasher.update(&bytes[..n]);
        }
        Ok(hasher.finalize().to_hex()[..12].into())
    }

    /// List all entries from `index.json`.
    pub fn list(&self) -> Vec<IdbEntry> {
        self.try_list().unwrap_or_else(|error| {
            tracing::warn!(%error, "Nexus cache list unavailable");
            Vec::new()
        })
    }

    pub fn lookup_by_hash(&self, hash: &str) -> Option<PathBuf> {
        {
            match self.try_lookup_generation(hash) {
                Ok(Some(path)) => return Some(path),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "Nexus cache lookup failed");
                    return None;
                }
            }
        }
        let pattern = format!(".{}.", hash);
        let entries = std::fs::read_dir(&self.root).ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.contains(&pattern) && name.ends_with(".i64") {
                return Some(entry.path());
            }
        }
        None
    }

    fn try_lookup_generation(&self, hash: &str) -> std::io::Result<Option<PathBuf>> {
        crate::router::nexus_bridge::generations::current(&self.root, hash)
            .map_err(std::io::Error::other)
    }

    /// Current generations and legacy metadata, deduplicated by the same key
    /// used by open. Errors remain available to callers that require evidence.
    pub fn try_list(&self) -> std::io::Result<Vec<IdbEntry>> {
        let mut entries: BTreeMap<String, IdbEntry> =
            match std::fs::read(self.root.join("index.json")) {
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
                Err(e) => return Err(e),
            };
        {
            let index = crate::router::nexus_bridge::generations::read_index(&self.root)
                .map_err(std::io::Error::other)?;
            for (key, relative) in index {
                let current = self.try_lookup_generation(&key)?;
                if entries.contains_key(&key) {
                    continue;
                }
                let size = match current
                    .as_ref()
                    .map(|p| std::fs::metadata(p.with_extension("")))
                {
                    Some(Ok(meta)) => meta.len(),
                    Some(Err(error)) if error.kind() != std::io::ErrorKind::NotFound => {
                        return Err(error)
                    }
                    _ => 0,
                };
                entries.insert(
                    key.clone(),
                    IdbEntry {
                        hash: key,
                        original_path: current
                            .map_or(relative, |p| p.with_extension("").display().to_string()),
                        binary_type: "native".into(),
                        size,
                        created_at: String::new(),
                        last_accessed: String::new(),
                    },
                );
            }
        }
        Ok(entries.into_values().collect())
    }

    pub fn try_stats(&self) -> std::io::Result<IdbStoreStats> {
        let mut file_count = 0;
        let mut total_size_bytes = 0u64;
        {
            use std::os::unix::fs::MetadataExt;
            let mut seen = std::collections::HashSet::new();
            // Recompute unique inode bytes across root files and managed trees.
            let mut directories = vec![self.root.clone()];
            while let Some(directory) = directories.pop() {
                for entry in std::fs::read_dir(&directory)? {
                    let entry = entry?;
                    let meta = entry.path().symlink_metadata()?;
                    if meta.is_dir()
                        && (directory != self.root
                            || matches!(
                                entry.file_name().to_str(),
                                Some("generations" | "quarantine" | "dsc-members")
                            ))
                    {
                        directories.push(entry.path());
                    } else if meta.is_file() {
                        file_count += 1;
                        if seen.insert((meta.dev(), meta.ino())) {
                            total_size_bytes = total_size_bytes.saturating_add(meta.len());
                        }
                    }
                }
            }
        }

        let entry_count = self.try_list()?.len();
        Ok(IdbStoreStats {
            root: self.root.display().to_string(),
            file_count,
            entry_count,
            total_size_bytes,
        })
    }

    pub fn stats(&self) -> IdbStoreStats {
        {
            match self.try_stats() {
                Ok(stats) => return stats,
                Err(error) => {
                    tracing::warn!(%error, "Nexus cache usage unavailable; reporting partial flat-file usage")
                }
            }
        }
        let mut file_count = 0usize;
        let mut total_size_bytes = 0u64;

        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        file_count += 1;
                        total_size_bytes = total_size_bytes.saturating_add(meta.len());
                    }
                }
            }
        }

        let entry_count = self.list().len();

        IdbStoreStats {
            root: self.root.display().to_string(),
            file_count,
            entry_count,
            total_size_bytes,
        }
    }

    pub fn evict_to_limit(
        &self,
        max_bytes: u64,
        _pinned_group_stems: &HashSet<String>,
    ) -> IdbEvictionStats {
        self.nexus_gc(max_bytes, None)
    }

    /// Remove an entry by hash: deletes from `index.json` and all related
    /// files from disk (`.i64`, `.id0`, `.id1`, `.nam`, `.til`, `.imcp`).
    ///
    /// Returns `true` if the entry was found and removed.
    pub fn remove(&self, hash: &str) -> bool {
        self.nexus_gc(0, Some(hash)).evicted_groups > 0
    }

    /// Remove orphaned index entries (where the `.i64` file no longer exists).
    ///
    /// Returns the removed entries.
    pub fn clean(&self) -> Vec<IdbEntry> {
        self.clean_nexus_indices().unwrap_or_else(|error| {
            tracing::warn!(%error, "Nexus orphan index cleanup refused");
            Vec::new()
        })
    }

    fn clean_nexus_indices(&self) -> anyhow::Result<Vec<IdbEntry>> {
        use crate::router::nexus_bridge::{cache_lock, generations};
        let _guard = cache_lock::try_exclusive(&self.root)?;
        let entries = self.try_list()?;
        let mut nexus = generations::read_index(&self.root)?;
        let mut legacy: BTreeMap<String, IdbEntry> =
            match std::fs::read(self.root.join("index.json")) {
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
                Err(e) => return Err(e.into()),
            };
        let mut removed = Vec::new();
        let mut nexus_dirty = false;
        let mut legacy_dirty = false;
        for entry in entries {
            if let Some(relative) = nexus.get(&entry.hash) {
                // Quarantined groups retain their own generation metadata.
                let name = Path::new(relative)
                    .parent()
                    .and_then(Path::file_name)
                    .ok_or_else(|| anyhow::anyhow!("generation name missing"))?;
                if self.try_lookup_generation(&entry.hash)?.is_none()
                    && !self.root.join("quarantine").join(name).exists()
                {
                    nexus.remove(&entry.hash);
                    nexus_dirty = true;
                }
            }
            if legacy.contains_key(&entry.hash) {
                // Do not consult lookup_by_hash: its generation-first lookup
                // says nothing about the independent flat legacy target.
                let pattern = format!(".{}.", entry.hash);
                let mut healthy = false;
                for item in std::fs::read_dir(&self.root)? {
                    let item = item?;
                    let name = item.file_name();
                    let name = name.to_string_lossy();
                    if name.contains(&pattern) && name.ends_with(".i64") {
                        healthy = true;
                        break;
                    }
                }
                if !healthy {
                    legacy.remove(&entry.hash);
                    legacy_dirty = true;
                }
            }
            if !nexus.contains_key(&entry.hash) && !legacy.contains_key(&entry.hash) {
                removed.push(entry);
            }
        }
        if nexus_dirty || legacy_dirty {
            for result in [
                nexus_dirty.then(|| self.replace_metadata("nexus-index.json", &nexus)),
                legacy_dirty.then(|| self.replace_metadata("index.json", &legacy)),
            ]
            .into_iter()
            .flatten()
            {
                if let Err(error) = result {
                    tracing::warn!(%error, "Nexus orphan metadata write failed; reconciling actual removals");
                }
            }
            let remaining = self.try_list()?;
            removed.retain(|entry| !remaining.iter().any(|item| item.hash == entry.hash));
        }
        Ok(removed)
    }
    fn replace_metadata(&self, name: &str, value: &impl serde::Serialize) -> anyhow::Result<()> {
        let destination = self.root.join(name);
        let stage = crate::preprocess::StagedArtifact::create(&destination)?;
        std::fs::write(&stage.output, serde_json::to_vec(value)?)?;
        std::fs::File::open(&stage.output)?.sync_all()?;
        stage.commit(
            &crate::preprocess::Preparation::new(std::time::Duration::from_secs(5)),
            || std::fs::rename(&stage.output, &destination),
        )?;
        std::fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn n7_fix1_clean_preserves_healthy_and_returns_orphans() {
        n7_fix1_store_case("clean");
    }
    #[test]
    fn n7_fix1_observations_use_generation_identity() {
        n7_fix1_store_case("observe");
    }
    fn n7_fix1_store_case(case: &str) {
        if std::env::var("N7_STORE_CASE").as_deref() != Ok(case) {
            let name = if case == "clean" {
                "n7_fix1_clean_preserves_healthy_and_returns_orphans"
            } else {
                "n7_fix1_observations_use_generation_identity"
            };
            let status = std::process::Command::new("timeout")
                .arg("10s")
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("idb_store::tests::{name}"),
                    "--nocapture",
                ])
                .env("N7_STORE_CASE", case)
                .env(
                    "IDA_NEXUS_PYTHON",
                    std::env::var_os("IDA_NEXUS_PYTHON")
                        .unwrap_or_else(|| "/usr/bin/python3".into()),
                )
                .status_fenced()
                .unwrap();
            assert!(status.success());
            return;
        }
        let root = temp_dir(&format!("n7-fix1-{case}"));
        std::fs::create_dir_all(root.join("generations/good")).unwrap();
        let source = root.join("source");
        std::fs::write(&source, b"source").unwrap();
        let key = IdbStore::try_compute_hash(&source).unwrap();
        let idb = root.join("generations/good/input.i64");
        std::fs::write(&idb, b"user edits").unwrap();
        std::fs::write(idb.with_extension(""), b"source").unwrap();
        std::fs::write(
            root.join("generations/good/generation.json"),
            serde_json::to_vec(&serde_json::json!({"version":1,"key":key})).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("nexus-index.json"),
            serde_json::to_vec(&serde_json::json!({key.clone():"generations/good/input.i64"}))
                .unwrap(),
        )
        .unwrap();
        let orphan = IdbEntry {
            hash: "orphan".into(),
            original_path: "missing".into(),
            binary_type: "native".into(),
            size: 0,
            created_at: "1Z".into(),
            last_accessed: "1Z".into(),
        };
        std::fs::write(
            root.join("index.json"),
            serde_json::to_vec(&serde_json::json!({"orphan":orphan})).unwrap(),
        )
        .unwrap();
        let store = IdbStore::with_root(root.clone());
        if case == "clean" {
            let removed = store.clean();
            assert!(
                idb.exists(),
                "clean only removes orphaned indices, never healthy databases"
            );
            assert_eq!(removed.len(), 1);
            assert_eq!(removed[0].hash, "orphan");
            assert!(store.clean().is_empty());
        } else {
            assert_eq!(
                store.try_lookup_generation(&key).unwrap(),
                Some(idb.clone())
            );
            assert_eq!(store.try_lookup_generation(&key).unwrap(), Some(idb));
            assert!(store.list().iter().any(|entry| entry.hash == key));
            assert_eq!(store.try_stats().unwrap().entry_count, store.list().len());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Return a unique temp directory for each test.
    fn temp_dir(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("idb_test_{}_{}", std::process::id(), suffix))
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let dir = temp_dir("hash_det");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.bin");
        std::fs::write(&file, b"deterministic content").unwrap();
        let h1 = IdbStore::try_compute_hash(&file).expect("fixture hash");
        let h2 = IdbStore::try_compute_hash(&file).expect("fixture hash");
        assert_eq!(h1, h2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_compute_hash_different_files() {
        let dir = temp_dir("hash_diff");
        std::fs::create_dir_all(&dir).unwrap();
        let f1 = dir.join("file1.bin");
        let f2 = dir.join("file2.bin");
        std::fs::write(&f1, b"content A").unwrap();
        std::fs::write(&f2, b"content B").unwrap();
        assert_ne!(
            IdbStore::try_compute_hash(&f1).expect("first fixture hash"),
            IdbStore::try_compute_hash(&f2).expect("second fixture hash")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_ida_home() {
        let expected = std::env::var_os("IDA_CLI_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var("HOME").expect("HOME not set")).join(".ida")
            });
        assert_eq!(ida_home(), expected);
    }

    #[test]
    fn test_socket_path() {
        let expected = ida_home().join("server.sock");
        assert_eq!(socket_path(), expected);
    }

    #[test]
    fn test_explicit_ida_home_does_not_modify_process_home() {
        let explicit = OsStr::new("/tmp/ida-cli-isolated");
        let home = OsStr::new("/Users/example");
        assert_eq!(
            ida_home_from(Some(explicit), Some(home)),
            PathBuf::from(explicit)
        );
        assert_eq!(
            ida_home_from(None, Some(home)),
            PathBuf::from(home).join(".ida")
        );
    }
}
