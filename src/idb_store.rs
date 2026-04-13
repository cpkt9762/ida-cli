//! IDB store — content-addressed registry of IDA `.i64` databases.
//!
//! Manages the `~/.ida/` directory hierarchy and an `index.json` that tracks
//! metadata about every analysed binary.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
}

pub fn ida_home() -> PathBuf {
    home_dir().join(".ida")
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

pub fn log_dir() -> PathBuf {
    ida_home().join("logs")
}

pub fn log_path() -> PathBuf {
    log_dir().join("server.log")
}

pub fn startup_lock_path() -> PathBuf {
    ida_home().join(".startup.lock")
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

fn now_iso8601() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", d.as_secs())
}

pub struct IdbStore {
    root: PathBuf,
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
        let home = std::env::var("HOME").expect("HOME not set");
        let expected = PathBuf::from(home).join(".ida");
        assert_eq!(ida_home(), expected);
    }

    #[test]
    fn test_socket_path() {
        let home = std::env::var("HOME").expect("HOME not set");
        let expected = PathBuf::from(home).join(".ida").join("server.sock");
        assert_eq!(socket_path(), expected);
    }
}
