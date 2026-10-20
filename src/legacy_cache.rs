//! Explicit offline legacy-cache maintenance; never starts a router or owner.
use crate::process_spawn::StdOutputFenced;
use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

pub fn run(arguments: Vec<OsString>) -> anyhow::Result<()> {
    // Internal streaming content-key service for verified migration snapshots.
    if arguments.len() == 2 && arguments[0] == "--content-key" {
        let key = crate::idb_store::IdbStore::try_compute_hash(Path::new(&arguments[1]))?;
        writeln!(std::io::stdout().lock(), "{key}")?;
        return Ok(());
    }
    let python = std::env::var_os("IDA_NEXUS_PYTHON")
        .ok_or_else(|| anyhow::anyhow!("cache-legacy requires IDA_NEXUS_PYTHON"))?;
    let installation = crate::router::nexus_bridge::installation::Temporary::create()?;
    let status = std::process::Command::new("timeout")
        .arg("120s")
        .arg(python)
        .args(["-I", "-B"])
        .arg(installation.path.join("installation/bootstrap.py"))
        .arg("legacy_cache")
        .args(arguments)
        .env("IDA_CLI_LEGACY_TOOL", std::env::current_exe()?)
        .status_fenced()?;
    anyhow::ensure!(
        status.success(),
        "legacy cache maintenance failed: {status}"
    );
    Ok(())
}
