//! IDB store — content-addressed registry of IDA `.i64` databases.
//!
//! Manages the `~/.ida/` directory hierarchy and an `index.json` that tracks
//! metadata about every analysed binary.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

fn ida_home_from(explicit: Option<&OsStr>, home: Option<&OsStr>) -> PathBuf {
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

pub fn clean_stale_imcp_locks() {
    if let Ok(entries) = std::fs::read_dir(idb_root()) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("imcp") {
                tracing::info!(path = %path.display(), "Removing stale .imcp lock on server startup");
                let _ = std::fs::remove_file(&path);
            }
        }
    }
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

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdbEvictionStats {
    pub evicted_groups: usize,
    pub evicted_files: usize,
    pub evicted_bytes: u64,
    pub remaining_bytes: u64,
}

fn now_iso8601() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", d.as_secs())
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

    pub fn prepared_paths(
        &self,
        binary_path: &Path,
    ) -> std::io::Result<(Option<PathBuf>, PathBuf)> {
        let hash = Self::try_compute_hash(binary_path)?;
        let basename = binary_path
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "binary has no basename")
            })?
            .to_string_lossy();
        let destination = self.root.join(format!("{basename}.{hash}.dylib.i64"));
        let pattern = format!(".{hash}.");
        let mut cached = None;
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.contains(&pattern) && name.ends_with(".i64") && entry.file_type()?.is_file() {
                cached = Some(entry.path());
                break;
            }
        }
        Ok((cached, destination))
    }

    /// Compute the blake3 hash of a file and return the first 12 hex characters.
    pub fn compute_hash(path: &Path) -> String {
        let data = std::fs::read(path).unwrap_or_default();
        let hash = blake3::hash(&data);
        let hex = format!("{}", hash.to_hex());
        hex[..12].to_string()
    }

    /// Return the `.i64` file name for a binary: `{basename}.{hash12}.dylib.i64`
    pub fn idb_name(binary_path: &Path) -> String {
        let basename = binary_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let hash = Self::compute_hash(binary_path);
        format!("{}.{}.dylib.i64", basename, hash)
    }

    /// Full path to the `.i64` file inside this store's root.
    pub fn idb_path(&self, binary_path: &Path) -> PathBuf {
        self.root.join(Self::idb_name(binary_path))
    }

    /// Search for an existing `.i64` whose filename contains the content hash.
    ///
    /// This is resilient to binary renames: if the same content was previously
    /// analysed under a different basename, the hash still matches.
    pub fn lookup(&self, binary_path: &Path) -> Option<PathBuf> {
        let hash = Self::compute_hash(binary_path);
        self.lookup_by_hash(&hash)
    }

    /// Search for an existing `.i64` whose filename contains `hash`.
    pub fn lookup_by_hash(&self, hash: &str) -> Option<PathBuf> {
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

    pub fn try_record(&self, binary_path: &Path) -> std::io::Result<()> {
        static INDEX_WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _write = INDEX_WRITE
            .lock()
            .map_err(|_| std::io::Error::other("IDB index writer poisoned"))?;
        let hash = Self::try_compute_hash(binary_path)?;
        let index_path = self.root.join("index.json");
        let mut index: HashMap<String, IdbEntry> = match std::fs::read(&index_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        let now = now_iso8601();
        let created = index
            .get(&hash)
            .map(|e| e.created_at.clone())
            .unwrap_or_else(|| now.clone());
        index.insert(
            hash.clone(),
            IdbEntry {
                hash,
                original_path: binary_path.display().to_string(),
                binary_type: if binary_path.extension().is_some_and(|e| e == "so") {
                    "sbpf".into()
                } else {
                    "native".into()
                },
                size: std::fs::metadata(binary_path)?.len(),
                created_at: created,
                last_accessed: now,
            },
        );
        let temporary = self
            .root
            .join(format!(".index-n2-{}.tmp", std::process::id()));
        std::fs::write(&temporary, serde_json::to_vec(&index)?)?;
        std::fs::rename(temporary, index_path)
    }

    /// Record (or update) an entry in `index.json`.
    ///
    /// `idb_path` is the path of the `.i64` file that was created; it is
    /// accepted for API symmetry but the canonical path is always derived
    /// from `binary_path` inside this store.
    pub fn record(&self, binary_path: &Path, _idb_path: &PathBuf) {
        let index_path = self.root.join("index.json");
        let mut index: HashMap<String, IdbEntry> = std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let hash = Self::compute_hash(binary_path);
        let size = std::fs::metadata(binary_path).map(|m| m.len()).unwrap_or(0);
        let binary_type = if binary_path.extension().and_then(|e| e.to_str()) == Some("so") {
            "sbpf"
        } else {
            "native"
        }
        .to_string();

        let now = now_iso8601();
        let created_at = index
            .get(&hash)
            .map(|e| e.created_at.clone())
            .unwrap_or_else(|| now.clone());

        let entry = IdbEntry {
            hash: hash.clone(),
            original_path: binary_path.to_string_lossy().into_owned(),
            binary_type,
            size,
            created_at,
            last_accessed: now,
        };
        index.insert(hash, entry);

        let tmp = self.root.join("index.json.tmp");
        if let Ok(json) = serde_json::to_string(&index) {
            let _ = std::fs::write(&tmp, json);
            let _ = std::fs::rename(&tmp, &index_path);
        }
    }

    /// List all entries from `index.json`.
    pub fn list(&self) -> Vec<IdbEntry> {
        let index_path = self.root.join("index.json");
        std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|s| serde_json::from_str::<HashMap<String, IdbEntry>>(&s).ok())
            .map(|m| m.into_values().collect())
            .unwrap_or_default()
    }

    pub fn try_stats(&self) -> std::io::Result<IdbStoreStats> {
        let mut file_count = 0;
        let mut total_size_bytes = 0u64;
        for entry in std::fs::read_dir(&self.root)? {
            let meta = entry?.metadata()?;
            if meta.is_file() {
                file_count += 1;
                total_size_bytes = total_size_bytes.saturating_add(meta.len());
            }
        }
        let entry_count = match std::fs::read(self.root.join("index.json")) {
            Ok(bytes) => serde_json::from_slice::<HashMap<String, IdbEntry>>(&bytes)?.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e),
        };
        Ok(IdbStoreStats {
            root: self.root.display().to_string(),
            file_count,
            entry_count,
            total_size_bytes,
        })
    }

    pub fn stats(&self) -> IdbStoreStats {
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
        pinned_group_stems: &HashSet<String>,
    ) -> IdbEvictionStats {
        struct Group {
            files: Vec<PathBuf>,
            bytes: u64,
            newest_mtime: SystemTime,
        }

        impl Default for Group {
            fn default() -> Self {
                Self {
                    files: Vec::new(),
                    bytes: 0,
                    newest_mtime: SystemTime::UNIX_EPOCH,
                }
            }
        }

        let mut groups: BTreeMap<String, Group> = BTreeMap::new();
        let mut total_size = 0u64;

        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if !meta.is_file() {
                    continue;
                }
                total_size = total_size.saturating_add(meta.len());
                let stem = path.with_extension("").display().to_string();
                let group = groups.entry(stem).or_default();
                group.files.push(path);
                group.bytes = group.bytes.saturating_add(meta.len());
                let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                if mtime > group.newest_mtime {
                    group.newest_mtime = mtime;
                }
            }
        }

        if total_size <= max_bytes {
            return IdbEvictionStats {
                evicted_groups: 0,
                evicted_files: 0,
                evicted_bytes: 0,
                remaining_bytes: total_size,
            };
        }

        let mut ordered: Vec<(String, Group)> = groups.into_iter().collect();
        ordered.sort_by_key(|(_, group)| group.newest_mtime);

        let mut evicted_groups = 0usize;
        let mut evicted_files = 0usize;
        let mut evicted_bytes = 0u64;

        for (stem, group) in ordered {
            if total_size <= max_bytes {
                break;
            }
            if pinned_group_stems.contains(&stem) {
                continue;
            }

            for file in &group.files {
                let _ = std::fs::remove_file(file);
            }
            total_size = total_size.saturating_sub(group.bytes);
            evicted_groups += 1;
            evicted_files += group.files.len();
            evicted_bytes = evicted_bytes.saturating_add(group.bytes);
        }

        let _ = self.clean();

        IdbEvictionStats {
            evicted_groups,
            evicted_files,
            evicted_bytes,
            remaining_bytes: total_size,
        }
    }

    /// Remove an entry by hash: deletes from `index.json` and all related
    /// files from disk (`.i64`, `.id0`, `.id1`, `.nam`, `.til`, `.imcp`).
    ///
    /// Returns `true` if the entry was found and removed.
    pub fn remove(&self, hash: &str) -> bool {
        let index_path = self.root.join("index.json");
        let mut index: HashMap<String, IdbEntry> = std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        if let Some(_entry) = index.remove(hash) {
            self.remove_files_by_hash(hash);

            let tmp = self.root.join("index.json.tmp");
            if let Ok(json) = serde_json::to_string(&index) {
                let _ = std::fs::write(&tmp, json);
                let _ = std::fs::rename(&tmp, &index_path);
            }
            true
        } else {
            false
        }
    }

    /// Delete all files in the store root whose name contains `.{hash}.`.
    fn remove_files_by_hash(&self, hash: &str) {
        let pattern = format!(".{}.", hash);
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.contains(&pattern) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    /// Remove orphaned index entries (where the `.i64` file no longer exists).
    ///
    /// Returns the removed entries.
    pub fn clean(&self) -> Vec<IdbEntry> {
        let index_path = self.root.join("index.json");
        let mut index: HashMap<String, IdbEntry> = std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let mut orphaned = Vec::new();
        let mut to_remove: Vec<String> = Vec::new();

        for (hash, entry) in &index {
            if self.lookup_by_hash(hash).is_none() {
                orphaned.push(entry.clone());
                to_remove.push(hash.clone());
            }
        }

        for hash in &to_remove {
            index.remove(hash);
        }

        if !to_remove.is_empty() {
            let tmp = self.root.join("index.json.tmp");
            if let Ok(json) = serde_json::to_string(&index) {
                let _ = std::fs::write(&tmp, json);
                let _ = std::fs::rename(&tmp, &index_path);
            }
        }

        orphaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let h1 = IdbStore::compute_hash(&file);
        let h2 = IdbStore::compute_hash(&file);
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
        assert_ne!(IdbStore::compute_hash(&f1), IdbStore::compute_hash(&f2));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_idb_name_format() {
        let dir = temp_dir("idb_name");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("pump.so");
        std::fs::write(&file, b"pump program data").unwrap();
        let name = IdbStore::idb_name(&file);
        assert!(name.starts_with("pump.so."), "unexpected name: {name}");
        assert!(name.ends_with(".dylib.i64"), "unexpected name: {name}");
        let hash_part = name
            .strip_prefix("pump.so.")
            .unwrap()
            .strip_suffix(".dylib.i64")
            .unwrap();
        assert_eq!(hash_part.len(), 12, "hash part wrong length: {hash_part}");
        assert!(
            hash_part.chars().all(|c| c.is_ascii_hexdigit()),
            "hash part not hex: {hash_part}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_idb_path_under_root() {
        let dir = temp_dir("idb_path");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("test.bin");
        std::fs::write(&binary, b"binary data").unwrap();
        let store_root = dir.join("store");
        let store = IdbStore::with_root(store_root.clone());
        let idb = store.idb_path(&binary);
        assert!(
            idb.starts_with(&store_root),
            "idb path not under root: {idb:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lookup_miss() {
        let dir = temp_dir("lookup_miss");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("ghost.bin");
        std::fs::write(&binary, b"ghost data").unwrap();
        let store_root = dir.join("store");
        let store = IdbStore::with_root(store_root);
        // No .i64 file exists → lookup must return None
        assert!(store.lookup(&binary).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_record_and_lookup() {
        let dir = temp_dir("record_lookup");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("target.bin");
        std::fs::write(&binary, b"target binary").unwrap();
        let store_root = dir.join("store");
        let store = IdbStore::with_root(store_root);
        let idb_path = store.idb_path(&binary);
        // Create the .i64 file so lookup can find it
        std::fs::write(&idb_path, b"fake idb content").unwrap();
        store.record(&binary, &idb_path);
        assert!(store.lookup(&binary).is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_index_json_persistence() {
        let dir = temp_dir("persistence");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("persist.bin");
        std::fs::write(&binary, b"persistent binary").unwrap();
        let store_root = dir.join("store");

        {
            let store = IdbStore::with_root(store_root.clone());
            let idb_path = store.idb_path(&binary);
            std::fs::write(&idb_path, b"fake idb").unwrap();
            store.record(&binary, &idb_path);
        }

        // A brand-new store over the same root must still find the .i64 file.
        let store2 = IdbStore::with_root(store_root);
        assert!(store2.lookup(&binary).is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_remove() {
        let dir = temp_dir("remove");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("removable.bin");
        std::fs::write(&binary, b"removable binary").unwrap();
        let store_root = dir.join("store");
        let store = IdbStore::with_root(store_root);
        let idb_path = store.idb_path(&binary);
        std::fs::write(&idb_path, b"fake idb").unwrap();
        store.record(&binary, &idb_path);
        let hash = IdbStore::compute_hash(&binary);
        assert!(store.remove(&hash));
        assert!(
            store.lookup(&binary).is_none(),
            "lookup should return None after remove"
        );
        assert!(
            !idb_path.exists(),
            ".i64 file should be deleted after remove"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lookup_survives_rename() {
        let dir = temp_dir("rename");
        std::fs::create_dir_all(&dir).unwrap();
        let binary_a = dir.join("original.bin");
        std::fs::write(&binary_a, b"same content").unwrap();
        let store_root = dir.join("store");
        let store = IdbStore::with_root(store_root.clone());
        let idb_path = store.idb_path(&binary_a);
        std::fs::write(&idb_path, b"fake idb").unwrap();
        store.record(&binary_a, &idb_path);

        let binary_b = dir.join("renamed.bin");
        std::fs::write(&binary_b, b"same content").unwrap();
        let store2 = IdbStore::with_root(store_root);
        assert!(
            store2.lookup(&binary_b).is_some(),
            "lookup should find IDB by content hash even after rename"
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
