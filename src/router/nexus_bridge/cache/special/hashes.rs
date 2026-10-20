//! Metadata-bound SHA256 memo. All access holds root SH and member-store EX.
use super::storage::Binding;
use super::*;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    path::Path,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sha256: String,
    identity: Binding,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u8,
    entries: BTreeMap<String, Record>,
}
/// Metadata reuse needs a qualified local filesystem with nanosecond change times.
pub(super) fn metadata_reusable(file: &File) -> anyhow::Result<bool> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd;
        let mut result = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: fstatfs initializes statfs on success; the File owns its FD.
        if unsafe { libc::fstatfs(file.as_raw_fd(), result.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: the successful syscall initialized the complete output.
        let info = unsafe { result.assume_init() };
        #[cfg(target_os = "macos")]
        {
            let kind: Vec<u8> = info
                .f_fstypename
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| *c as u8)
                .collect();
            Ok(info.f_flags & (libc::MNT_LOCAL as u32) != 0 && kind == b"apfs")
        }
        #[cfg(target_os = "linux")]
        {
            Ok(matches!(
                info.f_type as u64,
                0xef53 | 0x58465342 | 0x9123683e | 0x01021994
            ))
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = file;
        Ok(false)
    }
}
fn same_named_file(path: &Path, file: &File, before: &Binding) -> anyhow::Result<()> {
    let named = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        named.is_file()
            && Binding::of(&named)? == *before
            && Binding::of(&file.metadata()?)? == *before,
        "DSC source changed during digest observation: {}",
        path.display()
    );
    Ok(())
}
fn load(path: &Path) -> anyhow::Result<(Ledger, Option<Binding>)> {
    let file = match storage::open_private(path, 0o600) {
        Ok(file) => file,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|v| v.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok((
                Ledger {
                    version: 1,
                    entries: BTreeMap::new(),
                },
                None,
            ))
        }
        Err(e) => return Err(e),
    };
    let binding = Binding::of(&file.metadata()?)?;
    anyhow::ensure!(
        binding.nlink == 1 && binding.size <= 16 * 1024 * 1024,
        "unsafe or oversized DSC source-hash ledger"
    );
    let ledger: Ledger = serde_json::from_reader(&file)?;
    anyhow::ensure!(
        ledger.version == 1 && ledger.entries.len() <= 8192,
        "invalid DSC hash ledger"
    );
    for entry in ledger.entries.values() {
        anyhow::ensure!(valid_digest(&entry.sha256), "invalid memoized DSC digest");
    }
    same_named_file(path, &file, &binding)?;
    Ok((ledger, Some(binding)))
}
pub(super) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
}
fn publish(
    path: &Path,
    ledger: &Ledger,
    expected: Option<Binding>,
    prep: &Preparation,
) -> anyhow::Result<()> {
    let stage = StagedArtifact::create(path)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stage.output)?;
    output.write_all(&serde_json::to_vec(ledger)?)?;
    output.sync_all()?;
    match expected {
        None => {
            stage.publish(prep)?;
            std::fs::remove_file(&stage.output)?;
        }
        Some(identity) => {
            let current = storage::open_private(path, 0o600)?;
            same_named_file(path, &current, &identity)?;
            stage.commit(prep, || std::fs::rename(&stage.output, path))?;
        }
    }
    File::open(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("memo parent missing"))?,
    )?
    .sync_all()?;
    Ok(())
}
pub(super) fn identity(
    files: &[PathBuf],
    config: &DscInput,
    root: &Path,
    prep: &Preparation,
) -> anyhow::Result<Vec<u8>> {
    let path = root.join("dsc-source-hashes.json");
    let (mut ledger, observed) = load(&path)?;
    let mut changed = false;
    let mut hashes = BTreeMap::new();
    for source in files {
        prep.check()?;
        let key = source
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("DSC source path is not UTF-8"))?;
        let name = source
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| anyhow::anyhow!("DSC source name is not UTF-8"))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(source)?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "DSC source is not a regular file"
        );
        let binding = Binding::of(&file.metadata()?)?;
        same_named_file(source, &file, &binding)?;
        let reusable = metadata_reusable(&file)?;
        if !reusable {
            tracing::debug!(path=%source.display(),"DSC filesystem is not qualified for metadata digest reuse; verifying complete content");
        }
        let digest = match ledger.entries.get(key) {
            Some(record) if reusable && record.identity == binding => record.sha256.clone(),
            _ => {
                let digest = super::content_hash(source, prep)?;
                same_named_file(source, &file, &binding)?;
                ledger.entries.insert(
                    key.into(),
                    Record {
                        sha256: digest.clone(),
                        identity: binding.clone(),
                    },
                );
                changed = true;
                digest
            }
        };
        same_named_file(source, &file, &binding)?;
        hashes.insert(name, digest);
    }
    if changed {
        anyhow::ensure!(
            ledger.entries.len() <= 8192,
            "DSC hash ledger capacity exceeded"
        );
        publish(&path, &ledger, observed, prep)?;
    }
    Ok(serde_json::to_vec(
        &serde_json::json!({"kind":"dsc-sha256-v1","files":hashes,"loader":config}),
    )?)
}
