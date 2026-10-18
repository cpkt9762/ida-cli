//! Bounded blocking work. A dropped waiter never releases a running job's permit.
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

static PREPARE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));
static ENCODE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
static METADATA: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));
static CONTROL: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));

#[derive(Clone, Copy)]
pub enum WorkClass {
    Prepare,
    Encode,
    Metadata,
    Control,
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
    let permit = Arc::clone(gate)
        .try_acquire_owned()
        .map_err(|_| crate::error::ToolError::Busy)?;
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
