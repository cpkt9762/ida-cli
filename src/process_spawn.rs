//! Process-wide exclusion between descriptor reception and synchronous spawn.
//!
//! SCM_RIGHTS is not atomically CLOEXEC on every supported OS. Every process
//! creation participates here, including std output/status and test fixtures.
//! Guards never escape a synchronous call and are never held across await.
use std::io;
use std::sync::{RwLock, RwLockWriteGuard};

static DESCRIPTORS: RwLock<()> = RwLock::new(());

pub(crate) fn receive_fence() -> io::Result<RwLockWriteGuard<'static, ()>> {
    DESCRIPTORS
        .write()
        .map_err(|_| io::Error::other("process descriptor fence poisoned"))
}

pub(crate) fn with_spawn_fence<T>(spawn: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let _guard = DESCRIPTORS
        .read()
        .map_err(|_| io::Error::other("process descriptor fence poisoned"))?;
    spawn()
}

pub trait SpawnFenced {
    type Child;
    fn spawn_fenced(&mut self) -> io::Result<Self::Child>;
}

impl SpawnFenced for std::process::Command {
    type Child = std::process::Child;
    fn spawn_fenced(&mut self) -> io::Result<Self::Child> {
        #[cfg(feature = "nexus-test-support")]
        {
            crate::router::nexus_bridge::test_spawn_std_child(self).map_err(io::Error::other)
        }
        #[cfg(not(feature = "nexus-test-support"))]
        {
            with_spawn_fence(|| self.spawn())
        }
    }
}

impl SpawnFenced for tokio::process::Command {
    type Child = tokio::process::Child;
    fn spawn_fenced(&mut self) -> io::Result<Self::Child> {
        #[cfg(feature = "nexus-test-support")]
        {
            crate::router::nexus_bridge::test_spawn_child(self).map_err(io::Error::other)
        }
        #[cfg(not(feature = "nexus-test-support"))]
        {
            with_spawn_fence(|| self.spawn())
        }
    }
}

pub trait StdOutputFenced {
    fn output_fenced(&mut self) -> io::Result<std::process::Output>;
    fn status_fenced(&mut self) -> io::Result<std::process::ExitStatus>;
}

impl StdOutputFenced for std::process::Command {
    fn output_fenced(&mut self) -> io::Result<std::process::Output> {
        self.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = self.spawn_fenced()?;
        #[cfg(feature = "nexus-test-support")]
        let pid = child.id();
        let output = child.wait_with_output()?;
        #[cfg(feature = "nexus-test-support")]
        crate::router::nexus_bridge::test_record_child_exit(
            pid,
            &output.status,
            "Child.wait_with_output.std",
        );
        Ok(output)
    }

    fn status_fenced(&mut self) -> io::Result<std::process::ExitStatus> {
        let mut child = self.spawn_fenced()?;
        #[cfg(feature = "nexus-test-support")]
        let pid = child.id();
        let status = child.wait()?;
        #[cfg(feature = "nexus-test-support")]
        crate::router::nexus_bridge::test_record_child_exit(pid, &status, "Child.wait.std_status");
        Ok(status)
    }
}
