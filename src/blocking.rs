//! Bounded blocking work. A dropped waiter never releases a running job's permit.
//! Waiting for capacity is bounded by the request's preparation (deadline and
//! cancellation), or by `DEFAULT_WAIT` when there is none; expiry is `Busy`.
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

static PREPARE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));
static ENCODE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
static METADATA: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));
static CONTROL: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));

/// Wait ceiling for callers outside any preparation (no request deadline).
const DEFAULT_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub enum WorkClass {
    Prepare,
    Encode,
    Metadata,
    Control,
}

impl WorkClass {
    fn name(self) -> &'static str {
        match self {
            WorkClass::Prepare => "prepare",
            WorkClass::Encode => "encode",
            WorkClass::Metadata => "metadata",
            WorkClass::Control => "control",
        }
    }
}

pub async fn run<T: Send + 'static>(
    class: WorkClass,
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, crate::error::ToolError> {
    let gate = match class {
        WorkClass::Prepare => &PREPARE,
        WorkClass::Encode => &ENCODE,
        WorkClass::Metadata => &METADATA,
        WorkClass::Control => &CONTROL,
    };
    run_with(gate, class, DEFAULT_WAIT, job).await
}

/// Wait for capacity within the current preparation's deadline and cancellation.
/// Callers outside a preparation wait at most `default_wait`. Control is the
/// control-plane lane: it must answer promptly, so it never queues. Permits are
/// only ever held by synchronous leaf jobs (never across an await), so waiting
/// cannot form a cycle.
async fn acquire(
    gate: &Arc<Semaphore>,
    class: WorkClass,
    default_wait: Duration,
) -> Result<OwnedSemaphorePermit, crate::error::ToolError> {
    use crate::error::ToolError;
    let started = Instant::now();
    if matches!(class, WorkClass::Control) {
        return Arc::clone(gate).try_acquire_owned().map_err(|_| {
            warn!(
                class = class.name(),
                waited_ms = 0u64,
                "control capacity full"
            );
            ToolError::Busy
        });
    }
    let preparation = crate::preprocess::current();
    let deadline = preparation
        .as_ref()
        .map_or(started + default_wait, |preparation| preparation.deadline);
    let cancelled = async {
        match &preparation {
            Some(preparation) => preparation.cancel.cancelled().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! { biased;
        _ = cancelled => Err(ToolError::Preparation {
            message: "cancelled while waiting for blocking capacity; no work started".into(),
            execution_stopped: true,
        }),
        permit = Arc::clone(gate).acquire_owned() => permit.map_err(|_| ToolError::Busy),
        _ = tokio::time::sleep_until(deadline.into()) => {
            warn!(
                class = class.name(),
                waited_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "blocking capacity wait expired"
            );
            Err(ToolError::Busy)
        }
    }
}

async fn run_with<T: Send + 'static>(
    gate: &Arc<Semaphore>,
    class: WorkClass,
    default_wait: Duration,
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, crate::error::ToolError> {
    let permit = acquire(gate, class, default_wait).await?;
    let tracking = crate::preprocess::current().map(|preparation| preparation.track_input());
    if matches!(class, WorkClass::Control) {
        let (send, receive) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("ida-local-control".into())
            .spawn(move || {
                let _permit = permit;
                let _tracking = tracking;
                let _ = send.send(job());
            })
            .map_err(|e| crate::error::ToolError::IdaError(format!("control worker spawn: {e}")))?;
        return receive
            .await
            .map_err(|e| crate::error::ToolError::IdaError(format!("control worker exited: {e}")));
    }
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _tracking = tracking;
        job()
    })
    .await
    .map_err(|e| crate::error::ToolError::IdaError(format!("blocking work failed: {e}")))
}

/// Response work has independent, bounded capacity and waits for backpressure.
/// Callers are connection-owned bounded writers, never one task per response.
pub async fn response<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, crate::error::ToolError> {
    static GATE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
    independent(GATE.clone(), "ida-response-encode", job).await
}
/// Control replies have independent backpressure, including simultaneous
/// observation deadlines. A full encoder must not silently close a socket.
pub async fn control_response<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, crate::error::ToolError> {
    static GATE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
    independent(GATE.clone(), "ida-control-encode", job).await
}
pub async fn request_decode<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, crate::error::ToolError> {
    static GATE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
    independent(GATE.clone(), "ida-request-decode", job).await
}
async fn independent<T: Send + 'static>(
    gate: Arc<Semaphore>,
    name: &'static str,
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, crate::error::ToolError> {
    let permit = gate
        .acquire_owned()
        .await
        .map_err(|_| crate::error::ToolError::Busy)?;
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let _permit = permit;
            let _ = send.send(job());
        })
        .map_err(|error| crate::error::ToolError::IdaError(format!("{name} spawn: {error}")))?;
    receive
        .await
        .map_err(|error| crate::error::ToolError::IdaError(format!("{name}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ToolError;
    use crate::preprocess::Preparation;

    const LONG: Duration = Duration::from_secs(30);

    fn gate(size: usize) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(size))
    }
    fn hold_all(gate: &Arc<Semaphore>, size: u32) -> OwnedSemaphorePermit {
        gate.clone()
            .try_acquire_many_owned(size)
            .expect("gate must start free")
    }

    #[tokio::test]
    async fn fifth_prepare_waits_for_a_released_permit() {
        let gate = gate(4);
        let held = hold_all(&gate, 4);
        let waiter = {
            let gate = gate.clone();
            tokio::spawn(async move { run_with(&gate, WorkClass::Prepare, LONG, || 7).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "waiter must queue, not fail fast");
        drop(held);
        let value = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter must finish after release")
            .expect("waiter task must not panic")
            .expect("released capacity must run the job");
        assert_eq!(value, 7);
        assert_eq!(gate.available_permits(), 4);
    }

    #[tokio::test]
    async fn preparation_deadline_expiry_returns_busy() {
        let gate = gate(1);
        let _held = hold_all(&gate, 1);
        let preparation = Preparation::new(Duration::from_millis(150));
        let started = Instant::now();
        let result = preparation
            .scope(run_with(&gate, WorkClass::Prepare, LONG, || ()))
            .await;
        let waited = started.elapsed();
        assert!(matches!(result, Err(ToolError::Busy)), "got {result:?}");
        assert!(waited >= Duration::from_millis(140), "waited {waited:?}");
        assert!(waited < Duration::from_secs(5), "waited {waited:?}");
    }

    #[tokio::test]
    async fn no_preparation_uses_the_default_ceiling() {
        let gate = gate(1);
        let _held = hold_all(&gate, 1);
        let started = Instant::now();
        let result = run_with(
            &gate,
            WorkClass::Metadata,
            Duration::from_millis(150),
            || (),
        )
        .await;
        assert!(matches!(result, Err(ToolError::Busy)), "got {result:?}");
        assert!(started.elapsed() >= Duration::from_millis(140));
    }

    #[tokio::test]
    async fn cancellation_while_waiting_returns_promptly() {
        let gate = gate(1);
        let _held = hold_all(&gate, 1);
        let preparation = Preparation::new(Duration::from_secs(60));
        let canceller = preparation.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            canceller.cancel();
        });
        let started = Instant::now();
        let result = preparation
            .scope(run_with(&gate, WorkClass::Prepare, LONG, || ()))
            .await;
        assert!(
            matches!(
                result,
                Err(ToolError::Preparation {
                    execution_stopped: true,
                    ..
                })
            ),
            "got {result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(gate.available_permits(), 0, "held permit is untouched");
    }

    #[tokio::test]
    async fn dropping_the_waiter_keeps_the_running_jobs_permit() {
        let gate = gate(1);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let running = {
            let gate = gate.clone();
            tokio::spawn(async move {
                run_with(&gate, WorkClass::Prepare, LONG, move || {
                    started_tx.send(()).expect("test observes job start");
                    release_rx.recv().expect("test releases the job");
                })
                .await
            })
        };
        tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .expect("join")
            .expect("job must start");
        running.abort();
        let _ = running.await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            gate.available_permits(),
            0,
            "dropped waiter must not free the permit"
        );
        release_tx.send(()).expect("job still waiting");
        tokio::time::timeout(Duration::from_secs(5), gate.acquire())
            .await
            .expect("permit returns once the job ends")
            .expect("semaphore open")
            .forget();
    }

    #[tokio::test]
    async fn control_class_still_fails_fast() {
        let gate = gate(1);
        let _held = hold_all(&gate, 1);
        let started = Instant::now();
        let result = run_with(&gate, WorkClass::Control, LONG, || ()).await;
        assert!(matches!(result, Err(ToolError::Busy)), "got {result:?}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
