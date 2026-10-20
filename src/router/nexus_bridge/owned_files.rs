//! Creation identities for bridge IPC and obligation-free probe cleanup.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    directory: bool,
    links: u64,
}
fn identity(path: &Path) -> std::io::Result<Identity> {
    let info = std::fs::symlink_metadata(path)?;
    Ok(from_metadata(&info))
}
fn from_metadata(info: &std::fs::Metadata) -> Identity {
    Identity {
        device: info.dev(),
        inode: info.ino(),
        uid: info.uid(),
        mode: info.mode(),
        directory: info.is_dir(),
        links: if info.is_dir() { 0 } else { info.nlink() },
    }
}
struct Entry {
    identity: Identity,
    digest: Option<Vec<u8>>,
}

pub(super) struct OwnedFiles {
    root: PathBuf,
    entries: BTreeMap<PathBuf, Entry>,
}
impl OwnedFiles {
    pub fn created(root: &Path) -> anyhow::Result<Self> {
        let mut owned = Self {
            root: root.into(),
            entries: BTreeMap::new(),
        };
        owned.record(Path::new(""), false)?;
        Ok(owned)
    }

    /// Called by the creating code before publishing/starting another writer.
    pub fn record(&mut self, relative: &Path, immutable: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            relative
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
            "invalid owned entry"
        );
        let path = self.root.join(relative);
        let original = identity(&path)?;
        let digest = if immutable {
            Some(Self::digest(&path)?)
        } else {
            None
        };
        anyhow::ensure!(
            identity(&path)? == original,
            "created entry changed during capture"
        );
        self.entries.insert(
            relative.into(),
            Entry {
                identity: original,
                digest,
            },
        );
        Ok(())
    }

    pub fn record_installation(&mut self) -> anyhow::Result<()> {
        self.record(Path::new("installation"), false)?;
        // The Rust creator has just written this closed source set, before
        // any child starts. Unlisted files never acquire cleanup authority.
        for name in super::installation::members() {
            self.record(&Path::new("installation").join(name), true)?;
        }
        Ok(())
    }

    pub fn record_validated(
        &mut self,
        relative: &Path,
        validated: &std::fs::Metadata,
    ) -> anyhow::Result<()> {
        self.record(relative, true)?;
        let current = std::fs::symlink_metadata(self.root.join(relative))?;
        anyhow::ensure!(
            from_metadata(validated) == from_metadata(&current)
                && validated.len() == current.len()
                && (
                    validated.mtime(),
                    validated.mtime_nsec(),
                    validated.ctime(),
                    validated.ctime_nsec()
                ) == (
                    current.mtime(),
                    current.mtime_nsec(),
                    current.ctime(),
                    current.ctime_nsec()
                ),
            "validated probe record changed; retained"
        );
        Ok(())
    }

    pub fn record_socket(&mut self, name: &str) -> anyhow::Result<()> {
        match std::fs::symlink_metadata(self.root.join(name)) {
            Ok(info) => {
                anyhow::ensure!(
                    info.file_type().is_socket(),
                    "created endpoint is not a socket"
                );
                self.record(Path::new(name), false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn digest(path: &Path) -> anyhow::Result<Vec<u8>> {
        use std::io::Read;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "owned payload is not a regular file"
        );
        let mut hash = Sha256::new();
        let mut data = [0; 65536];
        loop {
            let count = file.read(&mut data)?;
            if count == 0 {
                break;
            }
            hash.update(&data[..count]);
        }
        Ok(hash.finalize().to_vec())
    }

    fn verify_ancestors(&self, relative: &Path) -> anyhow::Result<()> {
        let mut parent = relative.parent();
        while let Some(path) = parent {
            let expected = self
                .entries
                .get(path)
                .ok_or_else(|| anyhow::anyhow!("unrecorded parent"))?;
            anyhow::ensure!(
                identity(&self.root.join(path))? == expected.identity,
                "owned parent replaced; retained"
            );
            parent = path.parent();
        }
        Ok(())
    }

    fn remove(&self, relative: &Path) -> anyhow::Result<()> {
        self.verify_ancestors(relative)?;
        let Some(expected) = self.entries.get(relative) else {
            return Ok(());
        };
        let path = self.root.join(relative);
        let actual = match identity(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            actual == expected.identity,
            "owned entry replaced; retained: {}",
            path.display()
        );
        if let Some(digest) = &expected.digest {
            anyhow::ensure!(
                &Self::digest(&path)? == digest && identity(&path)? == actual,
                "owned entry bytes changed; retained: {}",
                path.display()
            );
        }
        if actual.directory {
            // Never recursively delete: unknown children leave this directory
            // nonempty, and therefore retain both themselves and their parent.
            std::fs::remove_dir(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn remove_socket(&self, name: &str) -> anyhow::Result<()> {
        self.remove(Path::new(name))
    }

    pub fn cleanup(self) -> anyhow::Result<()> {
        let mut paths: Vec<_> = self.entries.keys().cloned().collect();
        paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        let mut errors = Vec::new();
        for path in paths {
            if let Err(error) = self.remove(&path) {
                errors.push(error.to_string());
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "probe cleanup retained unknown/replaced entries: {}",
            errors.join("; ")
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("probe-files-{}-{label}", std::process::id()));
        std::fs::create_dir(&root).expect("private probe root");
        root
    }
    #[test]
    fn unknown_and_replaced_entries_are_retained() {
        let root = fixture("foreign");
        let mut owned = OwnedFiles::created(&root).expect("creation record");
        std::fs::write(root.join("own"), b"own").expect("owned file");
        owned
            .record(Path::new("own"), true)
            .expect("record payload");
        std::fs::rename(root.join("own"), root.join("original")).expect("preserve original inode");
        std::fs::write(root.join("own"), b"foreign").expect("replacement");
        std::fs::write(root.join("unknown"), b"foreign").expect("unknown entry");
        assert!(owned.cleanup().is_err());
        assert_eq!(
            std::fs::read(root.join("own")).expect("replacement retained"),
            b"foreign"
        );
        assert_eq!(
            std::fs::read(root.join("unknown")).expect("unknown retained"),
            b"foreign"
        );
        std::fs::remove_dir_all(root).expect("only fixture cleanup");
    }
    #[test]
    fn replaced_parent_never_authorizes_descendant_deletion() {
        let root = fixture("parent");
        let mut owned = OwnedFiles::created(&root).expect("creation record");
        std::fs::create_dir(root.join("child")).expect("own directory");
        owned
            .record(Path::new("child"), false)
            .expect("record directory");
        std::fs::write(root.join("child/data"), b"own").expect("own payload");
        owned
            .record(Path::new("child/data"), true)
            .expect("record payload");
        std::fs::rename(root.join("child"), root.join("original")).expect("replace parent");
        std::fs::create_dir(root.join("child")).expect("foreign directory");
        std::fs::write(root.join("child/data"), b"foreign").expect("foreign bytes");
        assert!(owned.cleanup().is_err());
        assert_eq!(
            std::fs::read(root.join("child/data")).expect("foreign retained"),
            b"foreign"
        );
        std::fs::remove_dir_all(root).expect("only fixture cleanup");
    }

    #[test]
    fn socket_replacement_survives_while_owned_socket_is_removed() {
        let root = fixture("sockets");
        let mut owned = OwnedFiles::created(&root).expect("creation record");
        let business = std::os::unix::net::UnixListener::bind(root.join("b")).expect("owned b");
        let helper = std::os::unix::net::UnixListener::bind(root.join("h")).expect("owned h");
        owned.record_socket("b").expect("b creation");
        owned.record_socket("h").expect("h creation");
        std::fs::rename(root.join("b"), root.join("original-b")).expect("retain original inode");
        std::fs::write(root.join("b"), b"replacement").expect("foreign replacement");
        drop((business, helper));
        assert!(owned.cleanup().is_err());
        assert_eq!(
            std::fs::read(root.join("b")).expect("replacement retained"),
            b"replacement"
        );
        assert!(!root.join("h").exists(), "recorded helper socket removed");
        std::fs::remove_dir_all(root).expect("only fixture cleanup");
    }
}
