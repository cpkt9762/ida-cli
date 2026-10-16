//! Root shared locks cover preparation, publication and tracked leases.
use crate::{error::ToolError, preprocess::Preparation};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

pub struct CacheGuard(File);
impl Drop for CacheGuard {
    fn drop(&mut self) {
        // SAFETY: the live File owns this descriptor until after unlocking.
        if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) } != 0 {
            tracing::error!(error = %std::io::Error::last_os_error(), "cache lock unlock failed");
        }
    }
}
pub async fn acquire(root: &Path, preparation: &Preparation) -> Result<Arc<CacheGuard>, ToolError> {
    acquire_named(root, ".cache.lock".into(), libc::LOCK_SH, preparation).await
}
/// Hold from the first index lookup through final open/index publication.
pub async fn acquire_content(
    root: &Path,
    key: &str,
    preparation: &Preparation,
) -> Result<Arc<CacheGuard>, ToolError> {
    let name = blake3::hash(key.as_bytes()).to_hex();
    acquire_named(
        root,
        format!(".content-{name}.lock"),
        libc::LOCK_EX,
        preparation,
    )
    .await
}

/// Synchronous metadata maintenance must never wait on an active publisher.
pub fn try_exclusive(root: &Path) -> std::io::Result<CacheGuard> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join(".cache.lock"))?;
    // SAFETY: this owned live descriptor is used only for a nonblocking flock.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(CacheGuard(file))
}
/// Serialize final verification/open of the same IDB across cooperating routers.
pub async fn acquire_open(
    root: &Path,
    path: &Path,
    preparation: &Preparation,
) -> Result<Arc<CacheGuard>, ToolError> {
    let idb = if path.extension().is_some_and(|e| e == "i64" || e == "idb") {
        path.to_path_buf()
    } else {
        std::path::PathBuf::from(format!("{}.i64", path.display()))
    };
    let idb = preparation
        .wait(crate::blocking::run(
            crate::blocking::WorkClass::Prepare,
            move || canonical_idb(&idb),
        ))
        .await?
        .map_err(|error| ToolError::IdaError(format!("cache open identity: {error}")))?;
    let key = blake3::hash(idb.as_os_str().as_encoded_bytes()).to_hex();
    acquire_named(
        root,
        format!(".open-{key}.lock"),
        libc::LOCK_EX,
        preparation,
    )
    .await
}
fn canonical_idb(path: &Path) -> std::io::Result<std::path::PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "IDB has no parent")
            })?;
            let name = path.file_name().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "IDB has no filename")
            })?;
            Ok(parent.canonicalize()?.join(name))
        }
        Err(error) => Err(error),
    }
}
async fn acquire_named(
    root: &Path,
    name: String,
    mode: i32,
    preparation: &Preparation,
) -> Result<Arc<CacheGuard>, ToolError> {
    let root = root.to_path_buf();
    let guard = preparation
        .wait(crate::blocking::run(
            crate::blocking::WorkClass::Prepare,
            move || {
                std::fs::create_dir_all(&root)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(root.join(name))
            },
        ))
        .await?
        .map_err(|error| ToolError::IdaError(format!("cache lock open: {error}")))?;
    let guard = Arc::new(CacheGuard(guard));
    loop {
        preparation.check()?;
        // SAFETY: only a nonblocking flock on our live owned descriptor.
        if unsafe { libc::flock(guard.0.as_raw_fd(), mode | libc::LOCK_NB) } == 0 {
            return Ok(guard);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(ToolError::IdaError(format!("cache lock acquire: {error}")));
        }
        // Neither a blocking syscall nor a blocking-pool waiter holds a permit.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn same_idb_aliases_share_cross_process_open_lock_until_release() {
        let root = std::env::temp_dir().join(format!(
            "n7-open-lock-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir(&root).expect("private test root");
        let cache = root.as_path().join("cache");
        std::fs::create_dir(&cache).expect("private cache");
        let alias = root.as_path().join("alias");
        std::os::unix::fs::symlink(&cache, &alias).expect("cache alias");
        let path = cache.join("input.i64");
        assert_eq!(
            canonical_idb(&path).expect("new IDB identity"),
            canonical_idb(&alias.join("input.i64")).expect("aliased IDB identity")
        );
        let prep = Preparation::new(std::time::Duration::from_secs(5));
        let guard = acquire_open(&alias, &path.with_extension(""), &prep)
            .await
            .expect("hold actual router open guard");
        let lock = std::fs::read_dir(&cache)
            .expect("lock directory")
            .next()
            .expect("open lock")
            .expect("lock entry")
            .path();
        let contender = || {
            std::process::Command::new("timeout")
                .args(["5s", "/usr/bin/python3", "-c", "import fcntl,sys; f=open(sys.argv[1], 'r+');\ntry: fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(4)"])
                .arg(&lock)
                .status()
                .expect("independent lock contender")
                .code()
        };
        assert_eq!(contender(), Some(4), "other router must be excluded");
        drop(guard);
        assert_eq!(contender(), Some(0), "confirmed release permits next open");
        std::fs::remove_dir_all(root).expect("remove private lock root");
    }
}
