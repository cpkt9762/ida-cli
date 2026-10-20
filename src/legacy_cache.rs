//! Explicit offline legacy-cache maintenance; never starts a router or owner.
use crate::process_spawn::SpawnFenced;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;

const TIMEOUT_ENV: &str = "IDA_CLI_LEGACY_TIMEOUT_SECS";
const DEFAULT_TIMEOUT_SECS: u64 = 1800;
const ROLLBACK_GRACE_SECS: u64 = 35;

fn timeout_seconds(value: Option<&OsStr>) -> anyhow::Result<u64> {
    let Some(value) = value else {
        return Ok(DEFAULT_TIMEOUT_SECS);
    };
    let seconds = value
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{TIMEOUT_ENV} must be an integer"))?
        .parse::<u64>()?;
    anyhow::ensure!(
        (1..=3600).contains(&seconds),
        "{TIMEOUT_ENV} must be between 1 and 3600 seconds"
    );
    Ok(seconds)
}

pub fn run(arguments: Vec<OsString>) -> anyhow::Result<()> {
    if arguments.len() == 2 && arguments[0] == "--content-key" {
        let key = crate::idb_store::IdbStore::try_compute_hash(Path::new(&arguments[1]))?;
        writeln!(std::io::stdout().lock(), "{key}")?;
        return Ok(());
    }
    let seconds = timeout_seconds(std::env::var_os(TIMEOUT_ENV).as_deref())?;
    let python = crate::router::nexus_tools::runtime_python()?;
    let installation = crate::router::nexus_bridge::installation::Temporary::create()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (status, expired) = runtime.block_on(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut command = tokio::process::Command::new(python);
        command
            .args(["-I", "-B"])
            .arg(installation.path.join("installation/bootstrap.py"))
            .arg("legacy_cache")
            .args(arguments)
            .env(TIMEOUT_ENV, seconds.to_string())
            .env("IDA_CLI_LEGACY_TOOL", std::env::current_exe()?);
        // A distinct, owned group lets direct signals to the CLI reach its
        // maintenance child. Helpers have their own supervised process groups.
        command.process_group(0);
        let mut child = command.spawn_fenced()?;
        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("maintenance child has no pid"))?;
        let group = i32::try_from(pid)?;
        let deadline = tokio::time::sleep(std::time::Duration::from_secs(seconds));
        tokio::pin!(deadline);
        let mut expired = false;
        let mut grace = None;
        loop {
            let received = tokio::select! {
                result = child.wait() => {
                    let status = result?;
                    #[cfg(feature = "nexus-test-support")]
                    crate::router::nexus_bridge::test_record_child_exit(pid, &status, "maintenance.Child.wait");
                    break Ok::<_, anyhow::Error>((status, expired));
                },
                _ = &mut deadline, if !expired => {
                    expired = true;
                    grace = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(ROLLBACK_GRACE_SECS));
                    libc::SIGTERM
                },
                _ = async { if let Some(at) = grace { tokio::time::sleep_until(at).await } else { std::future::pending::<()>().await } } => {
                    grace = None;
                    libc::SIGKILL
                },
                _ = terminate.recv() => libc::SIGTERM,
                _ = interrupt.recv() => libc::SIGINT,
            };
            // SAFETY: this group was created for our live owned child above.
            if unsafe { libc::kill(-group, received) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    crate::router::nexus_bridge::kill_child(&mut child).await?;
                    return Err(error.into());
                }
            }
        }
    })?;
    anyhow::ensure!(!expired && status.success(),
        "legacy cache maintenance stopped: {status} (budget {seconds}s, expired={expired}, rollback grace {ROLLBACK_GRACE_SECS}s). \
         Inspect --backup: if manifest.json exists, preview --mode restore --backup <same directory> \
         and apply with fresh offline evidence. Without a completed manifest, original files and indices \
         were not changed; retain the partial backup and use a new backup directory for another attempt.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_timeout_is_configurable_and_bounded() {
        assert_eq!(timeout_seconds(None).expect("default timeout"), 1800);
        assert_eq!(
            timeout_seconds(Some(OsStr::new("150"))).expect("explicit timeout"),
            150
        );
        for value in ["0", "3601", "-1", "150s", ""] {
            assert!(timeout_seconds(Some(OsStr::new(value))).is_err(), "{value}");
        }
    }
}
