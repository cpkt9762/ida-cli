//! Task-owned offline processes. Never manages Nexus owners or shared IDA workers.
//! The unreaped group leader pins PID/PGID until the last destructive signal.
use crate::error::ToolError;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

static PROCESS_GATE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));
static QUEUE_GATE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(8)));
const CAPTURE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Preparation {
    pub deadline: Instant,
    pub cancel: PreparationCancellation,
}
#[derive(Debug, Clone)]
pub struct PreparationCancellation {
    token: CancellationToken,
    publication: Arc<AtomicU8>,
}
impl PreparationCancellation {
    /// Returns false once publication has won; callers must not report cancellation.
    pub fn cancel(&self) -> bool {
        if self
            .publication
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        self.token.cancel();
        true
    }
    pub fn is_cancelled(&self) -> bool {
        self.publication.load(Ordering::SeqCst) == 1
    }
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }
}
impl Preparation {
    pub fn new(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
            cancel: PreparationCancellation {
                token: CancellationToken::new(),
                publication: Arc::new(AtomicU8::new(0)),
            },
        }
    }
    /// Bound pure input work without losing the blocking closure's owned permit.
    /// Do not wrap supervised native/child work: cancellation must await cleanup.
    pub async fn wait<T>(
        &self,
        work: impl std::future::Future<Output = Result<T, ToolError>>,
    ) -> Result<T, ToolError> {
        self.check()?;
        tokio::select! {biased;
            _=self.cancel.cancelled()=>Err(ToolError::Preparation {message:"cancelled during bounded input work; no command sent; background permit retained".into(),execution_stopped:false}),
            _=tokio::time::sleep_until(self.deadline.into())=>Err(ToolError::Preparation {message:"total deadline expired during bounded input work; no command sent; background permit retained".into(),execution_stopped:false}),
            result=work=>result,
        }
    }
    pub fn check(&self) -> Result<(), ToolError> {
        if self.cancel.is_cancelled() {
            return Err(ToolError::Preparation {
                message: "cancelled before work".into(),
                execution_stopped: true,
            });
        }
        if self.deadline <= Instant::now() {
            return Err(ToolError::Timeout(0));
        }
        Ok(())
    }
}
pub(crate) struct CancelOnDrop(Option<PreparationCancellation>);
impl Preparation {
    pub(crate) fn cancel_on_drop(&self) -> CancelOnDrop {
        CancelOnDrop(Some(self.cancel.clone()))
    }
}
impl CancelOnDrop {
    pub(crate) fn disarm(&mut self) {
        self.0 = None;
    }
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(token) = &self.0 {
            let _ = token.cancel();
        }
    }
}
#[derive(Debug)]
pub struct ProcessOutput {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub pid: u32,
}

pub async fn run(
    mut command: Command,
    preparation: Preparation,
) -> Result<ProcessOutput, ToolError> {
    preparation.check()?;
    let admission = Arc::clone(&QUEUE_GATE)
        .try_acquire_owned()
        .map_err(|_| ToolError::Busy)?;
    // Admission is bounded before spawning a task. Queue time shares the caller deadline.
    let permit = tokio::select! {
        biased;
        _ = preparation.cancel.cancelled() => return Err(ToolError::Preparation { message: "cancelled before spawn".into(), execution_stopped: true }),
        _ = tokio::time::sleep_until(preparation.deadline.into()) => return Err(ToolError::Timeout(0)),
        permit = Arc::clone(&PROCESS_GATE).acquire_owned() => permit.map_err(|_| ToolError::Busy)?,
    };
    preparation.check()?;
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(false);
    #[cfg(unix)]
    command.process_group(0);
    let child = command
        .spawn()
        .map_err(|e| ToolError::IdaError(format!("offline process spawn: {e}")))?;
    let pid = child
        .id()
        .ok_or_else(|| ToolError::IdaError("offline child PID missing".into()))?;
    let owner = OwnedChild {
        child: Some(child),
        pid: i32::try_from(pid).map_err(|e| ToolError::IdaError(e.to_string()))?,
        reaped: false,
        cleanup_confirmed: false,
        permits: Some((permit, admission)),
    };
    let (send, receive) = oneshot::channel();
    let mut guard = CancelOnDrop(Some(preparation.cancel.clone()));
    tokio::spawn(async move {
        let result = supervise(owner, preparation).await;
        let _ = send.send(result);
    });
    let result = receive.await.map_err(|_| {
        ToolError::IdaError("offline supervisor exited without cleanup evidence".into())
    })?;
    guard.0 = None; // Do not cancel the shared request after successful preparation.
    result
}

struct OwnedChild {
    child: Option<Child>,
    pid: i32,
    reaped: bool,
    cleanup_confirmed: bool,
    permits: Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.cleanup_confirmed {
            return;
        }
        if !self.reaped
            && exited_without_reaping(self.pid)
                .is_err_and(|error| error.raw_os_error() == Some(libc::ECHILD))
        {
            tracing::error!(
                pid = self.pid,
                "offline child ownership lost; refusing a destructive stale-PID signal"
            );
            self.reaped = true;
        }
        if !self.reaped {
            // SAFETY: exclusively owned unreaped leader still pins the process group.
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
            }
        }
        let pid = self.pid;
        let reaped = self.reaped;
        let child = self.child.take();
        let permits = self.permits.take();
        // Never block a runtime thread on an uninterruptible child. At most four
        // emergency reapers can exist: they retain both process/admission permits.
        std::thread::spawn(move || {
            let _child = child;
            let _permits = permits;
            if !reaped {
                loop {
                    // SAFETY: this thread exclusively inherits wait ownership.
                    let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                    if result == pid {
                        break;
                    }
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EINTR) {
                        tracing::error!(pid,error=%error,"emergency offline reap failed");
                        break;
                    }
                }
            }
            // No destructive signals after reaping: only observe this owned group.
            // Unconfirmed descendants retain the finite capacity, including at runtime exit.
            while !matches!(group_gone(pid), Ok(true)) {
                std::thread::sleep(Duration::from_millis(10));
            }
        });
    }
}
fn group_gone(pid: i32) -> std::io::Result<bool> {
    // SAFETY: non-destructive existence probe only; never signal a reaped PID/PGID.
    if unsafe { libc::kill(-pid, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        return Ok(true);
    }
    #[cfg(target_os = "macos")]
    return group_members(pid).map(|members| members.is_empty());
    #[cfg(not(target_os = "macos"))]
    Ok(false)
}
fn exited_without_reaping(pid: i32) -> std::io::Result<bool> {
    // SAFETY: zero is valid siginfo_t storage; waitid writes it and WNOWAIT
    // preserves this supervisor's exclusive child/PID ownership.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        if libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info.si_pid() == pid)
    }
}
#[cfg(target_os = "macos")]
fn group_members(pid: i32) -> std::io::Result<Vec<libc::proc_bsdinfo>> {
    // Apple libproc.h: PROC_PGRP_ONLY=2, PROC_PIDTBSDINFO=3. The group is
    // pinned by our unreaped leader; no process-name or global PID scan is used.
    let mut pids = [0i32; 256];
    // SAFETY: bounded writable PID array, exact byte size, read-only kernel query.
    let count = unsafe {
        libc::proc_listpids(
            2,
            pid as u32,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(&pids) as i32,
        )
    };
    if count < 0 || count as usize >= std::mem::size_of_val(&pids) {
        return Err(std::io::Error::other(
            "owned process group enumeration failed or truncated",
        ));
    }
    let mut members = Vec::new();
    for member in pids
        .into_iter()
        .take(count as usize / std::mem::size_of::<i32>())
        .filter(|p| *p > 0)
    {
        // SAFETY: zero initializes C output storage; libproc writes exactly its size.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        let read = unsafe {
            libc::proc_pidinfo(
                member,
                3,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if read != size {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error);
        }
        if info.pbi_pid != member as u32 || info.pbi_pgid != pid as u32 {
            return Err(std::io::Error::other("owned group identity changed"));
        }
        members.push(info);
    }
    Ok(members)
}
fn signal_group(pid: i32, signal: i32) -> std::io::Result<()> {
    // SAFETY: caller still exclusively owns the unreaped group leader.
    if unsafe { libc::kill(-pid, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    if error.raw_os_error() == Some(libc::EPERM)
        && group_members(pid)?
            .iter()
            .all(|member| member.pbi_status == 5)
    {
        // Darwin refuses signals to an all-zombie group. Explicit kernel status
        // proves no member can run; EPERM alone is never interpreted as stopped.
        return Ok(());
    }
    Err(error)
}
async fn drain<R: AsyncRead + Unpin>(mut pipe: R) -> std::io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let n = pipe.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        let keep = (CAPTURE_BYTES - captured.len()).min(n);
        captured.extend_from_slice(&buffer[..keep]);
    }
    Ok(captured)
}
struct DrainTasks {
    stdout: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
    stderr: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
}
impl Drop for DrainTasks {
    fn drop(&mut self) {
        // A supervisor error/drop must close its pipes rather than detach readers.
        self.stdout.abort();
        self.stderr.abort();
    }
}
async fn supervise(
    mut owner: OwnedChild,
    preparation: Preparation,
) -> Result<ProcessOutput, ToolError> {
    let pid = owner.pid as u32;
    let child = owner
        .child
        .as_mut()
        .ok_or_else(|| ToolError::IdaError("offline child missing".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ToolError::IdaError("offline stdout missing".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ToolError::IdaError("offline stderr missing".into()))?;
    let mut drains = DrainTasks {
        stdout: tokio::spawn(drain(stdout)),
        stderr: tokio::spawn(drain(stderr)),
    };
    let mut ticker = tokio::time::interval(Duration::from_millis(10));
    let reason = loop {
        if exited_without_reaping(owner.pid)
            .map_err(|e| ToolError::IdaError(format!("offline waitid: {e}")))?
        {
            break None;
        }
        tokio::select! { biased;
            _ = preparation.cancel.cancelled() => break Some("cancelled"),
            _ = tokio::time::sleep_until(preparation.deadline.into()) => break Some("total deadline expired"),
            _ = ticker.tick() => {},
        }
    };
    if reason.is_some() {
        signal_group(owner.pid, libc::SIGTERM)
            .map_err(|e| ToolError::IdaError(format!("offline cleanup SIGTERM: {e}")))?;
        let grace = Instant::now() + Duration::from_millis(300);
        while !exited_without_reaping(owner.pid).map_err(|e| ToolError::IdaError(e.to_string()))?
            && Instant::now() < grace
        {
            ticker.tick().await;
        }
    }
    // Even successful leaders must not leave same-group descendants using the staging output.
    signal_group(owner.pid, libc::SIGKILL)
        .map_err(|e| ToolError::IdaError(format!("offline cleanup SIGKILL: {e}")))?;
    let child = owner
        .child
        .as_mut()
        .ok_or_else(|| ToolError::IdaError("offline child missing".into()))?;
    let status = match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            if error.raw_os_error() == Some(libc::ECHILD) {
                owner.reaped = true;
            }
            return Err(ToolError::Preparation {
                message: format!("offline reap: {error}"),
                execution_stopped: false,
            });
        }
        Err(_) => {
            return Err(ToolError::Preparation {
                message: "offline reap unconfirmed; owned emergency reaper retains capacity".into(),
                execution_stopped: false,
            })
        }
    };
    owner.reaped = true;
    let read_stdout = tokio::time::timeout(Duration::from_secs(3), &mut drains.stdout).await;
    let read_stderr = tokio::time::timeout(Duration::from_secs(3), &mut drains.stderr).await;
    let stdout = read_stdout
        .map_err(|_| {
            ToolError::IdaError(
                "offline cleanup unconfirmed: stdout remains open (escaped descendant)".into(),
            )
        })?
        .map_err(|e| ToolError::IdaError(e.to_string()))?
        .map_err(|e| ToolError::IdaError(e.to_string()))?;
    let stderr = read_stderr
        .map_err(|_| {
            ToolError::IdaError(
                "offline cleanup unconfirmed: stderr remains open (escaped descendant)".into(),
            )
        })?
        .map_err(|e| ToolError::IdaError(e.to_string()))?
        .map_err(|e| ToolError::IdaError(e.to_string()))?;
    let cleanup_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if group_gone(owner.pid).map_err(|e| ToolError::Preparation {
            message: e.to_string(),
            execution_stopped: false,
        })? {
            break;
        }
        if Instant::now() >= cleanup_deadline {
            return Err(ToolError::Preparation {
                message: format!("process group {pid} cleanup unconfirmed"),
                execution_stopped: false,
            });
        }
        ticker.tick().await;
    }
    owner.cleanup_confirmed = true;
    if let Some(reason) = reason {
        return Err(ToolError::Preparation {
            message: format!("process {pid} {reason}; owned leader reaped and pipes closed"),
            execution_stopped: true,
        });
    }
    preparation.check()?;
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
        pid,
    })
}

/// Unique sibling directory; final output is published without replacing a valid file.
#[derive(Debug)]
pub struct StagedArtifact {
    pub directory: PathBuf,
    pub output: PathBuf,
    destination: PathBuf,
}
impl StagedArtifact {
    pub fn create(destination: &Path) -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let parent = destination.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "output has no parent")
        })?;
        std::fs::create_dir_all(parent)?;
        let directory = parent.join(format!(
            ".n2-prepare-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory)?;
        let output = directory.join(destination.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "output has no file name")
        })?);
        Ok(Self {
            directory,
            output,
            destination: destination.into(),
        })
    }
    pub fn publish(&self, preparation: &Preparation) -> Result<(), ToolError> {
        preparation.check()?;
        preparation
            .cancel
            .publication
            .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| ToolError::Preparation {
                message: "cancelled before publication".into(),
                execution_stopped: true,
            })?;
        // This is the commit point. Later cancellation explicitly returns false.
        // The blocking job retains its permit and stage until the syscall returns.
        let result = std::fs::hard_link(&self.output, &self.destination).map_err(|e| {
            ToolError::IdaError(format!(
                "publish {} without overwrite: {e}",
                self.destination.display()
            ))
        });
        preparation
            .cancel
            .publication
            .store(if result.is_ok() { 3 } else { 0 }, Ordering::SeqCst);
        result
    }
}
impl Drop for StagedArtifact {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.directory) {
            tracing::warn!(path = %self.directory.display(), error = %e, "staging cleanup failed");
        }
    }
}
