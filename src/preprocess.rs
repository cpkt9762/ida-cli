//! Task-owned offline processes. Never manages Nexus owners or shared IDA workers.
//! The unreaped group leader pins PID/PGID until the last destructive signal.
use crate::error::ToolError;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
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
    input_jobs: Arc<AtomicUsize>,
}
impl PreparationCancellation {
    /// Cancellation belongs to the whole preparation. A committed artifact is
    /// retained, but must not disable cancellation of later open/query phases.
    pub fn cancel(&self) -> bool {
        let first = self.publication.fetch_or(1, Ordering::SeqCst) & 1 == 0;
        self.token.cancel();
        first
    }
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
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
                input_jobs: Arc::new(AtomicUsize::new(0)),
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
        self.scope(async { tokio::select! {biased;
            _=self.cancel.cancelled()=>Err(ToolError::Preparation {message:"cancelled during bounded input work; no command sent; background permit retained".into(),execution_stopped:false}),
            _=tokio::time::sleep_until(self.deadline.into())=>Err(ToolError::Preparation {message:"total deadline expired during bounded input work; no command sent; background permit retained".into(),execution_stopped:false}),
            result=work=>result,
        }}).await
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
    #[cfg(test)]
    record_owned_fixture(pid, true, "offline-supervisor");
    let owner = OwnedChild {
        child: Some(child),
        pid: i32::try_from(pid).map_err(|e| ToolError::IdaError(e.to_string()))?,
        reaped: false,
        cleanup_confirmed: false,
        #[cfg(unix)]
        pipes: Vec::new(),
        #[cfg(unix)]
        pipes_observed: false,
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
    #[cfg(unix)]
    pipes: Vec<OwnedFd>,
    #[cfg(unix)]
    pipes_observed: bool,
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
        #[cfg(unix)]
        let mut pipes = std::mem::take(&mut self.pipes);
        #[cfg(unix)]
        let pipes_observed = self.pipes_observed;
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
            #[cfg(unix)]
            let mut pipe_error_logged = false;
            #[cfg(unix)]
            let pipes_closed = || {
                if !pipes_observed {
                    return false;
                }
                match pipes_eof(&mut pipes) {
                    Ok(closed) => closed,
                    Err(error) => {
                        if !pipe_error_logged {
                            tracing::error!(%error,"offline pipe cleanup remains unconfirmed");
                            pipe_error_logged = true;
                        }
                        false
                    }
                }
            };
            #[cfg(not(unix))]
            let pipes_closed = || false;
            let mut pipes_closed = pipes_closed;
            while !matches!(group_gone(pid), Ok(true)) || !pipes_closed() {
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
mod process_query;
#[cfg(target_os = "macos")]
use process_query::group_members;
use process_query::signal_group;

#[cfg(unix)]
fn duplicate_pipe(fd: std::os::fd::RawFd) -> std::io::Result<OwnedFd> {
    // SAFETY: duplicate a live owned pipe; CLOEXEC prevents descriptor leaks.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful fcntl returned a new exclusively owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}
#[cfg(unix)]
fn pipes_eof(pipes: &mut Vec<OwnedFd>) -> std::io::Result<bool> {
    let mut buffer = [0u8; 8192];
    let mut index = 0;
    while index < pipes.len() {
        // SAFETY: live nonblocking owned pipe and bounded writable byte buffer.
        let n = unsafe {
            libc::read(
                pipes[index].as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if n == 0 {
            pipes.swap_remove(index);
            continue;
        }
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
                return Err(error);
            }
        }
        index += 1;
    }
    Ok(pipes.is_empty())
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
    #[cfg(unix)]
    {
        owner.pipes = vec![
            duplicate_pipe(stdout.as_raw_fd())
                .map_err(|error| ToolError::IdaError(format!("stdout ownership: {error}")))?,
            duplicate_pipe(stderr.as_raw_fd())
                .map_err(|error| ToolError::IdaError(format!("stderr ownership: {error}")))?,
        ];
        owner.pipes_observed = true;
    }
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

mod cleanup;
pub use cleanup::{CleanupReceipt, StagedArtifact};

tokio::task_local! { pub(crate) static CURRENT_PREPARATION: Preparation; }
pub(crate) fn current() -> Option<Preparation> {
    CURRENT_PREPARATION.try_with(Clone::clone).ok()
}
impl Preparation {
    pub(crate) async fn scope<T>(&self, work: impl std::future::Future<Output = T>) -> T {
        CURRENT_PREPARATION.scope(self.clone(), work).await
    }
    /// Native work is not interrupted by dropping its receiver. A sent request
    /// without its real response remains unknown, regardless of cancellation.
    pub(crate) async fn native<T>(
        &self,
        work: impl std::future::Future<Output = Result<T, ToolError>>,
    ) -> Result<T, ToolError> {
        self.check()?;
        self.scope(async {
            tokio::select! { biased;
                result=work => result,
                _=self.cancel.cancelled() => Err(ToolError::Preparation { message: "native request may have been sent; cancellation requires stop evidence; never replay".into(), execution_stopped:false }),
                _=tokio::time::sleep_until(self.deadline.into()) => Err(ToolError::Preparation { message: "native request total deadline expired; stop unconfirmed; never replay".into(), execution_stopped:false }),
            }
        }).await
    }
}

pub(crate) struct InputJob(Arc<AtomicUsize>);
impl Drop for InputJob {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Preparation {
    pub fn active_input_jobs(&self) -> usize {
        self.cancel.input_jobs.load(Ordering::SeqCst)
    }
    pub(crate) fn track_input(&self) -> InputJob {
        self.cancel.input_jobs.fetch_add(1, Ordering::SeqCst);
        InputJob(self.cancel.input_jobs.clone())
    }
}

#[cfg(test)]
pub(crate) fn record_owned_fixture(pid: u32, group_owned: bool, kind: &str) {
    use std::io::Write;
    let path = std::env::temp_dir().join("n2-process-identities.jsonl");
    let record = serde_json::json!({"pid":pid,"pgid":if group_owned {Some(pid)}else{None},"kind":kind,"owned_spawn":true});
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("isolated owned fixture audit")
        .write_all(format!("{record}\n").as_bytes())
        .expect("complete audit append");
}

#[cfg(test)]
mod pipe_ownership_regressions {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    #[tokio::test(flavor = "current_thread")]
    async fn escaped_open_pipe_is_unknown_and_retains_owned_capacity_until_real_eof() {
        let directory =
            std::env::temp_dir().join(format!("n2-escaped-pipe-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("ready.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/n2_process_fixture.py"
            ))
            .arg("escaped_pipe")
            .arg(&socket)
            .arg(directory.join("unused-final"));
        let task = tokio::spawn(run(command, Preparation::new(Duration::from_secs(15))));
        let (stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        let identity: serde_json::Value = serde_json::from_str(&line).unwrap();
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(
                directory
                    .parent()
                    .unwrap()
                    .join("n2-process-identities.jsonl"),
            )
            .unwrap()
            .write_all(line.as_bytes())
            .unwrap();
        stream.get_mut().write_all(b"G").await.unwrap();
        let result = task.await.unwrap();
        let retained = PROCESS_GATE.available_permits() < 4;
        // Release the escaped fixture through its owned handshake, never a PID signal.
        let mut release = tokio::net::UnixStream::connect(directory.join("escaped.sock"))
            .await
            .unwrap();
        release.write_all(b"R").await.unwrap();
        let mut closed = String::new();
        BufReader::new(release)
            .read_line(&mut closed)
            .await
            .unwrap();
        assert_eq!(closed, "closed\n");
        let child = identity["child"].as_i64().unwrap() as i32;
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                // SAFETY: non-destructive probe of the exact fixture handshake PID.
                if unsafe { libc::kill(child, 0) } != 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                    && PROCESS_GATE.available_permits() == 4
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            retained,
            "a reaped group leader cannot release capacity while task-owned pipe writers remain"
        );
        assert!(
            matches!(result,Err(ToolError::IdaError(ref message)) if message.contains("cleanup unconfirmed") && message.contains("remains open")),
            "{result:?}"
        );
    }
}
