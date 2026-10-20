use super::{Preparation, ToolError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use tokio::sync::oneshot;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Unique sibling directory; final output is published without replacing a valid file.
#[derive(Debug)]
pub struct StagedArtifact {
    pub directory: PathBuf,
    pub output: PathBuf,
    destination: PathBuf,
    cleanup: CleanupReceipt,
    cleanup_permit: Option<OwnedSemaphorePermit>,
    #[cfg(test)]
    cleanup_hook: Option<CleanupBarrier>,
}
impl StagedArtifact {
    pub fn create(destination: &Path) -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        cleanup_service()?;
        let cleanup_permit = CLEANUP_GATE.clone().try_acquire_owned().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "staging cleanup capacity exhausted",
            )
        })?;
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
            cleanup: CleanupReceipt::default(),
            cleanup_permit: Some(cleanup_permit),
            #[cfg(test)]
            cleanup_hook: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn cleanup_barrier(
        &mut self,
        started: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.cleanup_hook = Some(CleanupBarrier {
            started,
            release: std::sync::Mutex::new(release),
        });
    }
    pub fn cleanup_receipt(&self) -> CleanupReceipt {
        self.cleanup.clone()
    }
    pub fn publish(&self, preparation: &Preparation) -> Result<(), ToolError> {
        self.commit(preparation, || {
            std::fs::hard_link(&self.output, &self.destination)
        })
    }
    /// Publish one entire generation group at its unique, previously absent path.
    pub fn publish_directory(&self, preparation: &Preparation) -> Result<(), ToolError> {
        self.commit(preparation, || {
            if self.destination.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "generation already exists",
                ));
            }
            rename_group(&self.output, &self.destination)
        })
    }
    /// Publish a complete task-owned subdirectory without replacing any destination.
    pub(crate) fn publish_owned_directory(
        &self,
        source: &Path,
        destination: &Path,
        preparation: &Preparation,
    ) -> Result<(), ToolError> {
        if source.parent() != Some(self.directory.as_path()) {
            return Err(ToolError::InvalidPath(
                "directory is not owned by this preparation stage".into(),
            ));
        }
        self.commit(preparation, || rename_group(source, destination))
    }
    pub(crate) fn commit(
        &self,
        preparation: &Preparation,
        publish: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<(), ToolError> {
        preparation.check()?;
        preparation
            .cancel
            .publication
            .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| ToolError::Preparation {
                message: "cancelled before publication".into(),
                execution_stopped: true,
            })?;
        // This is the artifact commit point. Later cancellation keeps this file
        // and still prevents subsequent work.
        // The blocking job retains its permit and stage until the syscall returns.
        let result = publish().map_err(|e| {
            ToolError::IdaError(format!(
                "publish {} without overwrite: {e}",
                self.destination.display()
            ))
        });
        preparation
            .cancel
            .publication
            .fetch_and(!2, Ordering::SeqCst);
        result
    }
}
fn rename_group(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = std::ffi::CString::new(source.as_os_str().as_encoded_bytes())?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_encoded_bytes())?;
    #[cfg(target_os = "macos")]
    // SAFETY: both C strings are valid and live through this non-replacing rename.
    let result =
        unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(target_os = "linux")]
    // SAFETY: absolute paths, valid live C strings; kernel enforces no replacement.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic non-replacing group rename unavailable",
    ));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
static CLEANUP_GATE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(8)));
#[derive(Debug, Clone, Default)]
pub struct CleanupReceipt {
    result: Arc<std::sync::Mutex<Option<Result<(), String>>>>,
    notify: Arc<tokio::sync::Notify>,
}
impl CleanupReceipt {
    fn complete(&self, result: Result<(), String>) {
        if let Err(error) = &result {
            tracing::error!(%error,"staging cleanup failed; directory retained for inspection");
        }
        *self.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
        self.notify.notify_waiters();
    }
    pub async fn wait(&self) -> Result<(), ToolError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(result) = self
                .result
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                return result.map_err(|message| ToolError::Preparation {
                    message,
                    execution_stopped: false,
                });
            }
            notified.await;
        }
    }
}
struct CleanupJob {
    directory: PathBuf,
    receipt: CleanupReceipt,
    _permit: OwnedSemaphorePermit,
    #[cfg(test)]
    hook: Option<CleanupBarrier>,
}
impl Drop for CleanupJob {
    fn drop(&mut self) {
        let incomplete = self
            .receipt
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none();
        if incomplete {
            self.receipt.complete(Err(format!(
                "staging cleanup worker lost ownership before completion: {}",
                self.directory.display()
            )));
        }
    }
}
fn cleanup_service() -> std::io::Result<&'static std::sync::mpsc::SyncSender<CleanupJob>> {
    static SERVICE: std::sync::OnceLock<Result<std::sync::mpsc::SyncSender<CleanupJob>, String>> =
        std::sync::OnceLock::new();
    SERVICE
        .get_or_init(|| {
            let (send, receive) = std::sync::mpsc::sync_channel::<CleanupJob>(8);
            std::thread::Builder::new()
                .name("ida-staging-cleanup".into())
                .spawn(move || {
                    while let Ok(job) = receive.recv() {
                        #[cfg(test)]
                        let mut job = job;
                        #[cfg(test)]
                        if let Some(hook) = job.hook.take() {
                            hook.block();
                        }
                        let result = std::fs::remove_dir_all(&job.directory).map_err(|error| {
                            format!("staging cleanup {}: {error}", job.directory.display())
                        });
                        job.receipt.complete(result);
                    }
                })
                .map_err(|error| format!("cleanup worker spawn: {error}"))?;
            Ok(send)
        })
        .as_ref()
        .map_err(|error| std::io::Error::other(error.clone()))
}
impl Drop for StagedArtifact {
    fn drop(&mut self) {
        let Some(permit) = self.cleanup_permit.take() else {
            return;
        };
        let job = CleanupJob {
            directory: self.directory.clone(),
            receipt: self.cleanup.clone(),
            _permit: permit,
            #[cfg(test)]
            hook: self.cleanup_hook.take(),
        };
        // Every producer owns one of eight permits; queue(8) plus the active
        // worker cannot be overfilled. Failure is recorded, never synchronous IO.
        match cleanup_service() {
            Ok(sender) => {
                if let Err(error) = sender.try_send(job) {
                    self.cleanup.complete(Err(format!(
                        "staging cleanup submission failed for {}: {error}",
                        self.directory.display()
                    )));
                }
            }
            Err(error) => self.cleanup.complete(Err(error.to_string())),
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct CleanupBarrier {
    started: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
#[cfg(test)]
impl CleanupBarrier {
    fn block(self) {
        self.started.send(()).unwrap();
        self.release.into_inner().unwrap().recv().unwrap();
    }
}
#[cfg(test)]
mod cleanup_regressions {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn blocked_stage_cleanup_does_not_block_local_control() {
        let directory =
            std::env::temp_dir().join(format!("n2-cleanup-control-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let mut stage = StagedArtifact::create(&directory.join("final")).unwrap();
        let (started, start) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        stage.cleanup_hook = Some(CleanupBarrier {
            started,
            release: std::sync::Mutex::new(released),
        });
        let (trigger, triggered) = oneshot::channel();
        let (ack, acknowledged) = std::sync::mpsc::channel();
        let control = tokio::spawn(async move {
            triggered.await.unwrap();
            ack.send(()).unwrap();
        });
        let controller = std::thread::spawn(move || {
            start.recv_timeout(Duration::from_secs(2)).unwrap();
            trigger.send(()).unwrap();
            let progressed = acknowledged
                .recv_timeout(Duration::from_millis(200))
                .is_ok();
            release.send(()).unwrap();
            if !progressed {
                acknowledged
                    .recv_timeout(Duration::from_secs(2))
                    .expect("control after cleanup release");
            }
            progressed
        });
        let cleanup = stage.cleanup_receipt();
        drop(stage);
        control.await.unwrap();
        cleanup.wait().await.unwrap();
        std::fs::remove_dir(&directory).unwrap();
        assert!(
            controller.join().unwrap(),
            "current-thread control must progress while cleanup is blocked"
        );
    }
}

#[cfg(test)]
mod drop_regressions {
    use super::*;
    #[test]
    fn stage_future_abort_and_runtime_exit_keep_cleanup_owned_until_receipt() {
        for mode in ["abort", "runtime"] {
            let directory =
                std::env::temp_dir().join(format!("n2-stage-drop-{}-{mode}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let mut stage = StagedArtifact::create(&directory.join("final")).unwrap();
            let path = stage.directory.clone();
            let receipt = stage.cleanup_receipt();
            std::fs::write(&stage.output, b"owned stage").unwrap();
            let (started, start) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            stage.cleanup_barrier(started, released);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let (task, ()) = runtime.block_on(async {
                let (started, start) = oneshot::channel();
                let task = tokio::spawn(async move {
                    let _stage = stage;
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
                start.await.unwrap();
                (task, ())
            });
            if mode == "abort" {
                runtime.block_on(async {
                    task.abort();
                    assert!(task.await.unwrap_err().is_cancelled());
                });
            }
            drop(runtime);
            start.recv_timeout(Duration::from_secs(2)).unwrap();
            let retained = path.exists();
            release.send(()).unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(receipt.wait())
                .unwrap();
            assert!(retained, "cleanup remains owned across runtime exit");
            assert!(!path.exists());
            assert!(!directory.join("final").exists());
            std::fs::remove_dir(directory).unwrap();
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn failed_publication_has_a_waitable_cleanup_receipt_and_preserves_final() {
        let directory =
            std::env::temp_dir().join(format!("n2-stage-conflict-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let final_path = directory.join("final");
        std::fs::write(&final_path, b"user").unwrap();
        let stage = StagedArtifact::create(&final_path).unwrap();
        std::fs::write(&stage.output, b"new").unwrap();
        let receipt = stage.cleanup_receipt();
        let path = stage.directory.clone();
        let preparation = Preparation::new(Duration::from_secs(1));
        assert!(stage.publish(&preparation).is_err());
        drop(stage);
        receipt.wait().await.unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(&final_path).unwrap(), b"user");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
