//! Closed production source installation. Runtime Python executes verified bytes.
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Private verified installation for short maintenance invocations. It uses
/// the same source closure and bootstrap as the long-lived production bridge.
pub(crate) struct Temporary {
    pub path: std::path::PathBuf,
    identity: (u64, u64),
}
impl Temporary {
    pub fn create() -> anyhow::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let path = std::env::temp_dir().join(format!(
            "ida-nexus-maint-{}-{}",
            std::process::id(),
            crate::router::nexus_transport::monotonic_ns()?
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        let info = std::fs::symlink_metadata(&path)?;
        let temporary = Self {
            path,
            identity: (info.dev(), info.ino()),
        };
        create(&temporary.path.join("installation"))?;
        Ok(temporary)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let result = (|| -> anyhow::Result<()> {
            let info = std::fs::symlink_metadata(&self.path)?;
            anyhow::ensure!(
                info.is_dir() && (info.dev(), info.ino()) == self.identity,
                "maintenance installation identity changed; retained"
            );
            std::fs::remove_dir_all(&self.path)?;
            Ok(())
        })();
        if let Err(error) = result {
            tracing::warn!(%error, path=%self.path.display(), "maintenance installation cleanup failed");
        }
    }
}

const SOURCES: &[(&str, &[u8])] = &[
    (
        "recovery_probe.py",
        include_bytes!("../../../nexus_bridge/custody/recovery_probe.py"),
    ),
    (
        "maintenance-launch",
        include_bytes!("../../../nexus_bridge/custody/maintenance-launch"),
    ),
    (
        "recovery_maintenance.py",
        include_bytes!("../../../nexus_bridge/custody/recovery_maintenance.py"),
    ),
    (
        "recovery_job.py",
        include_bytes!("../../../nexus_bridge/custody/recovery_job.py"),
    ),
    (
        "recovery_transfer.py",
        include_bytes!("../../../nexus_bridge/custody/recovery_transfer.py"),
    ),
    (
        "recovery_files.py",
        include_bytes!("../../../nexus_bridge/custody/recovery_files.py"),
    ),
    (
        "recovery_transaction.py",
        include_bytes!("../../../nexus_bridge/custody/recovery_transaction.py"),
    ),
    (
        "durable_records.py",
        include_bytes!("../../../nexus_bridge/custody/durable_records.py"),
    ),
    (
        "owner_modules.py",
        include_bytes!("../../../nexus_bridge/owner_modules.py"),
    ),
    (
        "owner_release.py",
        include_bytes!("../../../nexus_bridge/owner_release.py"),
    ),
    (
        "acquisition.py",
        include_bytes!("../../../nexus_bridge/custody/acquisition.py"),
    ),
    (
        "analysis_tools.py",
        include_bytes!("../../../nexus_bridge/analysis_tools.py"),
    ),
    (
        "bootstrap.py",
        include_bytes!("../../../nexus_bridge/custody/bootstrap.py"),
    ),
    (
        "bridge.py",
        include_bytes!("../../../nexus_bridge/bridge.py"),
    ),
    (
        "bridge_observer.py",
        include_bytes!("../../../nexus_bridge/custody/bridge_observer.py"),
    ),
    (
        "cache_store.py",
        include_bytes!("../../../nexus_bridge/cache_store.py"),
    ),
    (
        "config.py",
        include_bytes!("../../../nexus_bridge/config.py"),
    ),
    (
        "edit_tools.py",
        include_bytes!("../../../nexus_bridge/edit_tools.py"),
    ),
    (
        "lifecycle.py",
        include_bytes!("../../../nexus_bridge/lifecycle.py"),
    ),
    (
        "lifetime.py",
        include_bytes!("../../../nexus_bridge/lifetime.py"),
    ),
    (
        "metadata.py",
        include_bytes!("../../../nexus_bridge/metadata.py"),
    ),
    (
        "open_recovery.py",
        include_bytes!("../../../nexus_bridge/open_recovery.py"),
    ),
    (
        "origin.py",
        include_bytes!("../../../nexus_bridge/custody/origin.py"),
    ),
    (
        "owner_identity.py",
        include_bytes!("../../../nexus_bridge/custody/owner_identity.py"),
    ),
    (
        "custody_process_identity.py",
        include_bytes!("../../../nexus_bridge/custody/custody_process_identity.py"),
    ),
    (
        "proof_helper.py",
        include_bytes!("../../../nexus_bridge/custody/proof_helper.py"),
    ),
    (
        "protocol.py",
        include_bytes!("../../../nexus_bridge/protocol.py"),
    ),
    (
        "query_tools.py",
        include_bytes!("../../../nexus_bridge/query_tools.py"),
    ),
    (
        "save_guard.py",
        include_bytes!("../../../nexus_bridge/save_guard.py"),
    ),
    (
        "search_tools.py",
        include_bytes!("../../../nexus_bridge/search_tools.py"),
    ),
    (
        "slices.py",
        include_bytes!("../../../nexus_bridge/slices.py"),
    ),
    (
        "struct_tools.py",
        include_bytes!("../../../nexus_bridge/struct_tools.py"),
    ),
    (
        "target_journal.py",
        include_bytes!("../../../nexus_bridge/custody/target_journal.py"),
    ),
    (
        "target_coordination.py",
        include_bytes!("../../../nexus_bridge/custody/target_coordination.py"),
    ),
    ("tools.py", include_bytes!("../../../nexus_bridge/tools.py")),
    (
        "type_tools.py",
        include_bytes!("../../../nexus_bridge/type_tools.py"),
    ),
];

pub(super) fn create(directory: &Path) -> anyhow::Result<()> {
    std::fs::create_dir(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    let mut files = serde_json::Map::new();
    for (name, bytes) in SOURCES {
        write_new(&directory.join(name), bytes)?;
        let mode = if *name == "maintenance-launch" {
            0o700
        } else {
            0o600
        };
        if mode != 0o600 {
            std::fs::set_permissions(directory.join(name), std::fs::Permissions::from_mode(mode))?;
            File::open(directory.join(name))?.sync_all()?;
        }
        files.insert(
            (*name).into(),
            serde_json::json!({"sha256":format!("{:x}", Sha256::digest(bytes)), "mode":mode}),
        );
    }
    write_new(
        &directory.join("manifest.json"),
        &serde_json::to_vec(&serde_json::json!({"schema":1,"files":files}))?,
    )?;
    File::open(directory)?.sync_all()?;
    File::open(
        directory
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installation parent missing"))?,
    )?
    .sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(all(test, feature = "nexus-test-support"))]
mod tests {
    #[test]
    fn installed_maintenance_modes_offline_preview_and_apply() {
        let root =
            std::path::PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
        let installation = root.join("maintenance-installation");
        super::create(&installation).expect("current closed installation");
        let output = std::process::Command::new("timeout")
            .args(["30s"])
            .arg(std::env::var_os("R3A_PYTHON").expect("private prepared SDK Python"))
            .arg("-B")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/r4_maintenance.py"
            ))
            .arg(installation)
            .output()
            .expect("actual private operator driver");
        std::fs::write(root.join("maintenance.stdout"), &output.stdout).expect("stdout evidence");
        std::fs::write(root.join("maintenance.stderr"), &output.stderr).expect("stderr evidence");
        assert!(
            output.status.success(),
            "maintenance failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
