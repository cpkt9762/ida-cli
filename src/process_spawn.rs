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

/// Capture maintenance output in a caller-owned private directory. Regular
/// files avoid pipe backpressure and inherited-pipe hangs during bounded reap.
pub(crate) fn output_bounded(
    command: &mut std::process::Command,
    budget: std::time::Duration,
    directory: &std::path::Path,
) -> io::Result<std::process::Output> {
    use std::os::unix::{fs::OpenOptionsExt, process::CommandExt};
    let capture = |name| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(name))
    };
    let stdout = capture("stdout")?;
    let stderr = capture("stderr")?;
    command
        .stdin(std::process::Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .process_group(0);
    let mut child = command.spawn_fenced()?;
    let pid = child.id();
    let deadline = std::time::Instant::now() + budget;
    let mut failure = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Ok(None) => {
                failure = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "maintenance budget expired",
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => failure = Some(error),
        }
        let group = i32::try_from(pid).map_err(io::Error::other)?;
        // SAFETY: this unreaped child is the leader of our private group.
        if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                child.kill()?;
                failure = Some(error);
            }
        }
        break child.wait()?;
    };
    #[cfg(feature = "nexus-test-support")]
    crate::router::nexus_bridge::test_record_child_exit(pid, &status, "bounded.Child.wait");
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(std::process::Output {
        status,
        stdout: std::fs::read(directory.join("stdout"))?,
        stderr: std::fs::read(directory.join("stderr"))?,
    })
}

pub trait AsyncOutputFenced {
    fn output_fenced(
        &mut self,
    ) -> impl std::future::Future<Output = io::Result<std::process::Output>> + Send;
}

impl AsyncOutputFenced for tokio::process::Command {
    async fn output_fenced(&mut self) -> io::Result<std::process::Output> {
        self.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = self.spawn_fenced()?;
        #[cfg(feature = "nexus-test-support")]
        {
            crate::router::nexus_bridge::test_output_child(child).await
        }
        #[cfg(not(feature = "nexus-test-support"))]
        {
            child.wait_with_output().await
        }
    }
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

#[cfg(test)]
mod bounded_tests {
    use super::*;

    #[test]
    fn maintenance_capture_is_bounded_without_timeout_in_path() {
        let root = std::env::temp_dir().join(format!("bounded-{}", std::process::id()));
        std::fs::create_dir(&root).expect("private capture directory");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "printf out; printf err >&2"])
            .env("PATH", "");
        let output = output_bounded(&mut command, std::time::Duration::from_secs(1), &root)
            .expect("capture without timeout binary");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
        std::fs::remove_file(root.join("stdout")).expect("reset stdout");
        std::fs::remove_file(root.join("stderr")).expect("reset stderr");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "echo $$ > \"$1\"; exec /bin/sleep 60", "fixture"])
            .arg(root.join("pid"))
            .env("PATH", "");
        let error = output_bounded(&mut command, std::time::Duration::from_millis(100), &root)
            .expect_err("owned maintenance must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let pid: i32 = std::fs::read_to_string(root.join("pid"))
            .expect("child pid")
            .trim()
            .parse()
            .expect("numeric pid");
        // SAFETY: signal zero observes the exact recorded child without signalling it.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        // SAFETY: waitpid only asks whether this exact child remains unreaped.
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        std::fs::remove_dir_all(root).expect("remove owned capture directory");
    }
}
