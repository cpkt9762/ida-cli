//! Atomically reserve a fresh session directory before any session writes.
use anyhow::Context;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const ATTEMPTS: usize = 1024;
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(super) fn allocate(root: &Path) -> anyhow::Result<PathBuf> {
    reserve(root, std::process::id(), &SEQUENCE, ATTEMPTS)
}

fn reserve(
    root: &Path,
    pid: u32,
    sequence: &AtomicU64,
    attempts: usize,
) -> anyhow::Result<PathBuf> {
    let root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let mut path = root.clone();
    for _ in 0..attempts {
        path = root.join(format!(
            "n4-{pid}-{}",
            sequence.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                let message = format!("create session directory {}: {error}", path.display());
                return Err(error).context(message);
            }
        }
    }
    anyhow::bail!(
        "session directory allocation exhausted after {attempts} attempts; last path: {}",
        path.display()
    )
}

#[cfg(test)]
#[path = "../../../tests/support/session_directory.rs"]
mod tests;
