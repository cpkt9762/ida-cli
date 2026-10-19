//! Test-only scheduling points. They never change a production predicate.
use serde_json::Value;
use std::{path::PathBuf, time::Duration};
pub(super) fn fail_once(name: &str, value: Value) -> anyhow::Result<()> {
    let Some(root) = std::env::var_os("R3F2_BARRIER_ROOT").map(PathBuf::from) else {
        return Ok(());
    };
    let arm = root.join(format!("{name}.fail"));
    if arm.is_file() {
        std::fs::rename(&arm, root.join(format!("{name}.consumed")))?;
        std::fs::write(
            root.join(format!("{name}.fired")),
            serde_json::to_vec(&value)?,
        )?;
        anyhow::bail!("controlled {name} failure after exact helper retirement");
    }
    Ok(())
}
fn armed(name: &str, value: Value) -> anyhow::Result<Option<PathBuf>> {
    let Some(root) = std::env::var_os("R3F2_BARRIER_ROOT").map(PathBuf::from) else {
        return Ok(None);
    };
    if !root.join(format!("{name}.arm")).exists() {
        return Ok(None);
    }
    let temporary = root.join(format!("{name}.arrived.new"));
    std::fs::write(&temporary, serde_json::to_vec(&value)?)?;
    std::fs::rename(temporary, root.join(format!("{name}.arrived")))?;
    Ok(Some(root.join(format!("{name}.release"))))
}
pub(super) async fn asynchronous(name: &str, value: Value) -> anyhow::Result<()> {
    if let Some(release) = armed(name, value)? {
        tokio::time::timeout(Duration::from_secs(8), async {
            while !release.exists() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
    }
    Ok(())
}
pub(super) fn blocking(name: &str, value: Value) -> anyhow::Result<()> {
    if let Some(release) = armed(name, value)? {
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while !release.exists() {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "test scheduling barrier expired: {name}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}
