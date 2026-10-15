//! Persistent public Python client adapter. Neither lane shares a physical stream.
pub mod cache;
use super::nexus_transport::{Delivery, NexusEndpoint, NexusWireFrame};
use crate::nexus::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{unix::OwnedWriteHalf, UnixListener, UnixStream};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{broadcast, Mutex as AsyncMutex};

type Writer = Arc<AsyncMutex<OwnedWriteHalf>>;
#[derive(Clone)]
pub struct BridgeConfig {
    pub python: PathBuf,
    pub script: PathBuf,
    /// New private directory; must not already exist. Short enough for Unix sockets.
    pub directory: PathBuf,
    pub environment: BTreeMap<String, String>,
}
struct Pending {
    attempt: DeliveryAttempt,
    granted: bool,
    uncertain: bool,
    stopped: bool,
    open_disconnected: Option<SessionLease>,
}
struct State {
    endpoint: NexusEndpoint,
    callbacks: Mutex<()>,
    pending: Mutex<HashMap<u64, Pending>>,
    leases: Mutex<HashMap<LeaseId, SessionLease>>,
    events: broadcast::Sender<Value>,
    open_replies: Mutex<HashMap<OperationId, tokio::sync::oneshot::Sender<Value>>>,
    open_reply_capacity: usize,
    failed: std::sync::atomic::AtomicBool,
    stop: tokio_util::sync::CancellationToken,
}
impl State {
    fn open_reply(
        &self,
        id: &OperationId,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<Value>> {
        let mut replies = self.open_replies.lock().unwrap_or_else(|e| e.into_inner());
        anyhow::ensure!(
            !self.failed.load(std::sync::atomic::Ordering::Acquire),
            "bridge disconnected"
        );
        anyhow::ensure!(
            replies.len() < self.open_reply_capacity && !replies.contains_key(id),
            "Busy: open reply capacity or duplicate identity"
        );
        let (sender, receiver) = tokio::sync::oneshot::channel();
        replies.insert(id.clone(), sender);
        Ok(receiver)
    }
    fn emit(&self, event: Value) {
        tracing::debug!(event = event["event"].as_str(), attempt = ?event.get("attempt"), lease = ?event.get("lease"), "Nexus bridge lifecycle");
        if event["attempt"]["target"]["kind"] == "open" && event.get("error").is_some() {
            tracing::warn!(
                category = event["error"]["code"].as_str(),
                reason = event["error"]["message"].as_str(),
                operation = event["attempt"]["target"]["identity"]["operation_id"].as_str(),
                "Nexus open failed"
            );
        }
        // Open transfers lease responsibility: diagnostic broadcast may lag,
        // but a registered supervisor must receive its exact terminal outcome.
        if matches!(
            event["event"].as_str(),
            Some("opened" | "failed" | "uncertain" | "not_sent" | "remote_error")
        ) && event["attempt"]["target"]["kind"] == "open"
        {
            if let Some(id) = event["attempt"]["target"]["identity"]["operation_id"].as_str() {
                if let Ok(id) = OperationId::new(id) {
                    if let Some(sender) = self
                        .open_replies
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&id)
                    {
                        let _ = sender.send(event.clone());
                    }
                }
            }
        }
        if event["event"] == "bridge_disconnected" {
            for (_, sender) in self
                .open_replies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .drain()
            {
                let _ = sender.send(event.clone());
            }
        }
        let _ = self.events.send(event); // Diagnostics only; N1 remains authoritative.
    }
    fn fail(&self, reason: &str) {
        if self.failed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        self.stop.cancel();
        let pending = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
        let leases: Vec<_> = self
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        self.endpoint.transition(|sessions, _| {
            for item in pending.values() {
                let error = NexusError::new(NexusErrorCode::Disconnected, reason);
                let result = sessions.delivery_failed(
                    &item.attempt,
                    if item.granted {
                        DispatchFailure::Uncertain(error)
                    } else {
                        DispatchFailure::NotSent(error)
                    },
                );
                if let Err(error) = result {
                    tracing::error!(%error, "bridge failure callback rejected");
                }
            }
            for lease in leases {
                sessions.disconnected(&lease.instance_id, lease.generation);
            }
        });
        self.emit(json!({"event":"bridge_disconnected", "reason":reason}));
    }
}
/// Owned by one RouterState. Dropping it kills only its own bridge, never an owner.
pub struct NexusBridge {
    state: Arc<State>,
    child: AsyncMutex<Child>,
    lifetime: AsyncMutex<Option<ChildStdin>>,
    control: Writer,
    directory: PathBuf,
    pub pid: u32,
}
impl NexusBridge {
    pub async fn start(router: &super::RouterState, config: BridgeConfig) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(&config.directory)?;
        std::fs::set_permissions(&config.directory, std::fs::Permissions::from_mode(0o700))?;
        let business_path = config.directory.join("b");
        let control_path = config.directory.join("c");
        let business = UnixListener::bind(&business_path)?;
        let control = UnixListener::bind(&control_path)?;
        let capacity = router.config.max_pending_per_tenant;
        let log = std::fs::File::create(config.directory.join("stderr.log"))?;
        let mut child = Command::new(&config.python)
            .arg(&config.script)
            .arg(&business_path)
            .arg(&control_path)
            .arg(capacity.to_string())
            .env_clear()
            .envs(&config.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()?;
        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("bridge exited before PID registration"))?;
        let lifetime = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("bridge stdout missing"))?;
        let mut lines = BufReader::new(stdout).lines();
        let startup = async {
            let line = lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("bridge exited without readiness"))?;
            let ready: Value = serde_json::from_str(&line)?;
            if ready["ready"] != true {
                anyhow::bail!("Nexus readiness: {}", ready["error"]);
            }
            let caps: NexusCapabilities = serde_json::from_value(ready["capabilities"].clone())?;
            caps.runtime.validate()?;
            let (b, _) = business.accept().await?;
            let (c, _) = control.accept().await?;
            Ok::<_, anyhow::Error>((caps, b, c))
        };
        let connected = tokio::time::timeout(Duration::from_secs(15), startup).await;
        let (caps, b, c) = match connected {
            Ok(Ok(value)) => value,
            other => {
                child.kill().await?;
                child.wait().await?;
                std::fs::remove_file(&business_path)?;
                std::fs::remove_file(&control_path)?;
                return Err(match other {
                    Ok(Err(error)) => error,
                    _ => anyhow::anyhow!("bridge readiness deadline expired"),
                });
            }
        };
        router.install_nexus_capabilities(caps)?;
        let endpoint = router.nexus_endpoint();
        let lanes = endpoint
            .take_lanes()
            .ok_or_else(|| anyhow::anyhow!("Nexus lanes already consumed"))?;
        let (events, _) = broadcast::channel(capacity.max(8));
        let state = Arc::new(State {
            endpoint,
            callbacks: Mutex::new(()),
            pending: Mutex::new(HashMap::new()),
            leases: Mutex::new(HashMap::new()),
            events,
            open_replies: Mutex::new(HashMap::new()),
            open_reply_capacity: capacity,
            failed: std::sync::atomic::AtomicBool::new(false),
            stop: tokio_util::sync::CancellationToken::new(),
        });
        let bw = start_channel(b, state.clone(), false);
        let cw = start_channel(c, state.clone(), true);
        tokio::spawn(pump(lanes.business, bw, state.clone()));
        tokio::spawn(pump(lanes.control, cw.clone(), state.clone()));
        let ticking = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            while !ticking.failed.load(std::sync::atomic::Ordering::Acquire) {
                interval.tick().await;
                let operations: Vec<_> = ticking
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .filter_map(|p| match &p.attempt.target {
                        DeliveryTarget::Execute { identity } => Some(identity.clone()),
                        _ => None,
                    })
                    .collect();
                let leases: Vec<_> = ticking
                    .leases
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .cloned()
                    .collect();
                ticking.endpoint.transition(|s, t| {
                    for lease in leases {
                        if s.status(&lease.client_id, &lease).is_ok_and(|status| status.phase == SessionPhase::ReleaseRequired) {
                            if let Err(error) = s.release(&lease.client_id, &lease, t) {
                                tracing::debug!(%error, lease_id=lease.lease_id.as_str(), "Nexus retained open lease cleanup pending");
                            }
                        }
                    }
                    for op in operations {
                        if s.operation_progress(&op.lease.client_id, &op)
                            .is_ok_and(|snapshot| snapshot.status.is_terminal() && snapshot.execution_stopped) {
                            continue;
                        }
                        if let Err(error) = s.expire(&op.lease.client_id, &op, t) {
                            tracing::debug!(%error, operation_id=op.operation_id.as_str(), "bridge deadline poll");
                        }
                    }
                });
            }
        });
        Ok(Self {
            state,
            child: AsyncMutex::new(child),
            lifetime: AsyncMutex::new(lifetime),
            control: cw,
            directory: config.directory,
            pid,
        })
    }
    pub fn subscribe(&self) -> broadcast::Receiver<Value> {
        self.state.events.subscribe()
    }
    pub fn open_reply(
        &self,
        id: &OperationId,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<Value>> {
        self.state.open_reply(id)
    }
    pub fn forget_open_reply(&self, id: &OperationId) {
        self.state
            .open_replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }
    #[cfg(test)]
    pub(crate) fn test_reply_count(&self) -> usize {
        self.state.open_replies.lock().unwrap().len()
    }
    pub fn endpoint(&self) -> NexusEndpoint {
        self.state.endpoint.clone()
    }
    pub async fn status(&self, id: &str) -> anyhow::Result<()> {
        send(&self.control, &json!({"local_status":id})).await
    }
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.lifetime.lock().await.take();
        let mut child = self.child.lock().await;
        match tokio::time::timeout(Duration::from_secs(12), child.wait()).await {
            Ok(status) => {
                status?;
            }
            Err(_) => {
                child.kill().await?;
                child.wait().await?;
                anyhow::bail!(
                    "bridge cleanup deadline expired; own bridge killed, owner stop unconfirmed"
                );
            }
        }
        self.state.fail("bridge stopped");
        Ok(())
    }
    /// Test supervisor may terminate this exact child; no process-name scans.
    pub async fn terminate(&self) -> anyhow::Result<()> {
        let mut child = self.child.lock().await;
        child.kill().await?;
        child.wait().await?;
        self.state.fail("bridge terminated");
        Ok(())
    }
}
impl Drop for NexusBridge {
    fn drop(&mut self) {
        self.state.fail("bridge owner dropped");
        for name in ["b", "c"] {
            if let Err(error) = std::fs::remove_file(self.directory.join(name)) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(%error, "bridge socket cleanup");
                }
            }
        }
    }
}
async fn send(writer: &Writer, value: &Value) -> anyhow::Result<()> {
    let mut data = serde_json::to_vec(value)?;
    data.push(b'\n');
    writer.lock().await.write_all(&data).await?;
    Ok(())
}
async fn pump(mut lane: tokio::sync::mpsc::Receiver<Delivery>, writer: Writer, state: Arc<State>) {
    loop {
        let delivery = tokio::select! {
            _ = state.stop.cancelled() => break,
            delivery = lane.recv() => match delivery { Some(value) => value, None => break },
        };
        if state.failed.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        #[cfg(test)]
        if std::env::var("N4_F2_OPEN_FAULT").as_deref() == Ok("zero-byte") {
            static FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
            if let DeliveryTarget::Open { identity } = &delivery.attempt.target {
                if FIRST.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    state
                        .endpoint
                        .transition(|s, _| s.cancel_open(&identity.client_id, identity))
                        .unwrap();
                }
            }
        }
        let sequence = delivery.attempt.sequence.get();
        state
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                sequence,
                Pending {
                    attempt: delivery.attempt.clone(),
                    granted: false,
                    uncertain: false,
                    stopped: false,
                    open_disconnected: None,
                },
            );
        let mut stream = writer.lock().await;
        let mut counted = CountingWriter {
            inner: &mut stream,
            bytes: 0,
        };
        let result = tokio::select! {
            _ = state.stop.cancelled() => break,
            result = delivery.write(&mut counted) => result,
        };
        if let Err(error) = result {
            state
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&sequence);
            tracing::warn!(%error, "bridge lane write failed");
            if counted.bytes != 0 || error.code == NexusErrorCode::Disconnected {
                state.fail("bridge lane stream failed");
                break;
            }
            // Proven zero-byte local failure affects this request only.
        }
    }
}
struct CountingWriter<'a> {
    inner: &'a mut OwnedWriteHalf,
    bytes: usize,
}
impl tokio::io::AsyncWrite for CountingWriter<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut *self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(size)) = result {
            self.bytes += size;
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

// One in-flight decoder, queued by the existing control stream reader. No
// try-acquire, no CLI control encoder permit, no increase in lane admission.
async fn decode_control(line: String) -> anyhow::Result<Result<Value, serde_json::Error>> {
    static GATE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));
    let permit = GATE.clone().acquire_owned().await?;
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("nexus-control-decode".into())
        .spawn(move || {
            let _permit = permit;
            let _ = send.send(serde_json::from_str(&line));
        })?;
    Ok(receive.await?)
}

fn start_channel(stream: UnixStream, state: Arc<State>, control: bool) -> Writer {
    let (read, write) = stream.into_split();
    let writer = Arc::new(AsyncMutex::new(write));
    let responding = writer.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(read).lines();
        loop {
            let next = tokio::select! { _ = state.stop.cancelled() => break, next = lines.next_line() => next };
            match next {
                Ok(Some(line)) => {
                    let decoded = if control {
                        decode_control(line)
                            .await
                            .map_err(|e| crate::error::ToolError::IdaError(e.to_string()))
                    } else {
                        crate::blocking::request_decode(move || {
                            serde_json::from_str::<Value>(&line)
                        })
                        .await
                    };
                    let event = match decoded {
                        Ok(Ok(value)) => value,
                        other => {
                            tracing::error!(?other, "invalid bridge event");
                            break;
                        }
                    };
                    if let Err(error) = event_received(event, &responding, &state, control).await {
                        tracing::error!(%error, "bridge event failed");
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(%error, "bridge response read failed");
                    break;
                }
            }
        }
        state.fail("bridge response stream disconnected");
        if let Err(error) = responding.lock().await.shutdown().await {
            tracing::debug!(%error, "bridge half-close");
        }
    });
    writer
}
async fn event_received(
    mut event: Value,
    writer: &Writer,
    state: &Arc<State>,
    control: bool,
) -> anyhow::Result<()> {
    if event["event"] == "dispatch_ready" {
        let encoded = event["frame"].take();
        let frame: NexusWireFrame = if control {
            serde_json::from_value(encoded)?
        } else {
            crate::blocking::request_decode(move || serde_json::from_value(encoded)).await??
        };
        let sequence = frame.attempt.sequence.get();
        let mut output = writer.lock().await;
        let attempt = frame.attempt.clone();
        let expires = frame.expires_monotonic_ns;
        // Retain the N2 frame until the Python executor is ready. The final
        // grant carries remaining duration only, never the absolute clock.
        let endpoint = state.endpoint.clone();
        let checking = attempt.clone();
        let consume = move || {
            frame.consume().and_then(|(command, _)| {
                endpoint.transition(|s, _| s.send_eligible(&command, &checking))?;
                Ok(command)
            })
        };
        let command = if control {
            consume()
        } else {
            crate::blocking::request_decode(consume).await?
        };
        let mut garbage = None;
        let remaining = expires.saturating_sub(super::nexus_transport::monotonic_ns()?) / 1_000_000;
        let command = if remaining == 0 {
            if let Ok(command) = command {
                garbage = Some(command);
            }
            Err(NexusError::new(
                NexusErrorCode::QueueExpired,
                "expired before dispatch grant",
            ))
        } else {
            command
        };
        let reply = match command {
            Ok(command) => {
                if let Some(pending) = state
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_mut(&sequence)
                {
                    pending.granted = true;
                }
                // Drop the possibly large DTO on a bounded worker. Python retains
                // the original payload; this final grant is constant size.
                garbage = Some(command);
                json!({"grant":true,"sequence":sequence,"remaining_ms":remaining})
            }
            Err(error) => {
                state.endpoint.transition(|s, _| {
                    s.delivery_failed(&attempt, DispatchFailure::NotSent(error))
                })?;
                state
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&sequence);
                json!({"grant":false,"sequence":sequence})
            }
        };
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        output.write_all(&bytes).await?;
        drop(output);
        if let Some(command) = garbage {
            crate::blocking::response(move || drop(command)).await?;
        }
        return Ok(());
    }
    let owned = state.clone();
    if control {
        apply_event(event, &owned)
    } else {
        crate::blocking::response(move || apply_event(event, &owned)).await?
    }
}
fn apply_event(event: Value, state: &State) -> anyhow::Result<()> {
    if event["event"] == "disconnected" {
        let lease: SessionLease = serde_json::from_value(event["lease"].clone())?;
        let _ordered = state.callbacks.lock().unwrap_or_else(|e| e.into_inner());
        let registered = state
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&lease.lease_id)
            .cloned();
        if registered.is_some() {
            state
                .endpoint
                .transition(|s, _| s.lease_disconnected(&lease))?;
        } else {
            let attempt: DeliveryAttempt = decode(event["attempt"].clone())?;
            let DeliveryTarget::Open { identity } = &attempt.target else {
                return Err(invalid("disconnect open correlation missing").into());
            };
            if identity.client_id != lease.client_id {
                return Err(invalid("disconnect client mismatch").into());
            }
            let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(open) = pending.get_mut(&attempt.sequence.get()) {
                if open.attempt != attempt
                    || open
                        .open_disconnected
                        .as_ref()
                        .is_some_and(|old| old != &lease)
                {
                    return Err(invalid("disconnect open attempt mismatch").into());
                }
                open.open_disconnected = Some(lease);
            }
            // No pending open and no registered lease means cleanup/failure
            // already won. A late callback cannot invalidate sibling sessions.
        }
        state.emit(event);
        return Ok(());
    }
    if event["event"] == "local_status" {
        state.emit(event);
        return Ok(());
    }
    let name = event["event"].as_str().unwrap_or("");
    // Clone/decode potentially large results and errors before taking N1's lock.
    // Business callbacks already run on the bounded response worker.
    let mut value = event.get("result").cloned().unwrap_or(Value::Null);
    let mut received_error: Option<NexusError> =
        event.get("error").cloned().map(decode).transpose()?;
    let mut take_error = || {
        received_error
            .take()
            .ok_or_else(|| invalid("bridge error missing"))
    };
    let _ordered = state.callbacks.lock().unwrap_or_else(|e| e.into_inner());
    let attempt: DeliveryAttempt = serde_json::from_value(event["attempt"].clone())?;
    let sequence = attempt.sequence.get();
    {
        let pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.get(&sequence).is_none_or(|p| p.attempt != attempt) {
            if event["event"] == "stopped" && !pending.contains_key(&sequence) {
                state.endpoint.transition(|s, _| {
                    let DeliveryTarget::Execute { identity } = &attempt.target else {
                        return Err(invalid("stop target mismatch"));
                    };
                    s.delivery_status(&identity.lease.client_id, &attempt)?;
                    s.execution_stopped(identity)?;
                    Ok::<_, NexusError>(())
                })?;
                state.emit(event);
                return Ok(());
            }
            anyhow::bail!("unknown or mismatched bridge attempt");
        }
    }
    let result = state.endpoint.transition(|s, _| -> Result<(), NexusError> {
        match name {
            "ack" => {
                s.delivery_acknowledged(&attempt)?;
            }
            "opened" => {
                let lease: SessionLease = decode(event["lease"].clone())?;
                let caps: NexusCapabilities = decode(event["capabilities"].clone())?;
                let DeliveryTarget::Open { identity } = &attempt.target else {
                    return Err(invalid("open target mismatch"));
                };
                state
                    .leases
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(lease.lease_id.clone(), lease.clone());
                match s.opened(identity, lease.clone(), caps)? {
                    OpenDisposition::Ready(_) => {}
                    OpenDisposition::ReleaseRequired { .. } => {
                        // The bridge poll owns retries after proven NotSent. A
                        // full control lane must not discard lease responsibility.
                    }
                }
                let pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(disconnected) = pending
                    .get(&sequence)
                    .and_then(|p| p.open_disconnected.as_ref())
                {
                    if disconnected != &lease {
                        return Err(invalid("opened lease differs from buffered disconnect"));
                    }
                    s.lease_disconnected(&lease)?;
                }
            }
            "completed" => {
                let DeliveryTarget::Execute { identity } = &attempt.target else {
                    return Err(invalid("execute target mismatch"));
                };
                s.complete(identity, Completion::Success(value.take()))?;
            }
            "stopped" => {
                let DeliveryTarget::Execute { identity } = &attempt.target else {
                    return Err(invalid("stop target mismatch"));
                };
                let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(item) = pending.get_mut(&sequence) {
                    item.stopped = true;
                    if item.uncertain {
                        s.execution_stopped(identity)?;
                    }
                }
            }
            "cancel_ack" => {
                if event["accepted"] == true {
                    s.delivery_acknowledged(&attempt)?;
                } else {
                    s.delivery_failed(
                        &attempt,
                        DispatchFailure::Uncertain(NexusError::new(
                            NexusErrorCode::CancelPending,
                            "public cancellation returned false; no stop confirmation",
                        )),
                    )?;
                }
                if event["outcome"]["execution_stopped"] == true {
                    let DeliveryTarget::Cancel { identity, .. } = &attempt.target else {
                        return Err(invalid("cancel proof target mismatch"));
                    };
                    let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
                    let execution = pending.values_mut().find(|p| {
                        matches!(&p.attempt.target,
                        DeliveryTarget::Execute { identity: original } if original == identity)
                    });
                    if let Some(execution) = execution {
                        execution.stopped = true;
                        if execution.uncertain {
                            s.execution_stopped(identity)?;
                        }
                    } else {
                        s.execution_stopped(identity)?;
                    }
                }
            }
            "released" => {
                s.released(&attempt)?;
                if let DeliveryTarget::Release { lease } = &attempt.target {
                    state
                        .leases
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&lease.lease_id);
                }
            }
            "shutdown_completed" => {
                s.shutdown_completed(&attempt)?;
            }
            "remote_error" if matches!(&attempt.target, DeliveryTarget::Execute { .. }) => {
                let DeliveryTarget::Execute { identity } = &attempt.target else {
                    return Err(invalid("execute target mismatch"));
                };
                let completion = match event["remote_code"].as_str() {
                    Some("operation_cancelled") => Completion::Cancelled,
                    Some("operation_timeout") => Completion::ExecutionTimedOut,
                    _ => Completion::Failed(take_error()?),
                };
                s.complete(identity, completion)?;
            }
            "stop_unconfirmed" => {}
            "uncertain" => {
                s.delivery_failed(&attempt, DispatchFailure::Uncertain(take_error()?))?;
                if let DeliveryTarget::Execute { identity } = &attempt.target {
                    let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(item) = pending.get_mut(&sequence) {
                        item.uncertain = true;
                        if item.stopped {
                            s.execution_stopped(identity)?;
                        }
                    }
                }
            }
            "remote_error" if matches!(&attempt.target, DeliveryTarget::Shutdown { .. }) => {
                s.shutdown_rejected(&attempt)?;
            }
            "failed" | "not_sent" | "remote_error" => {
                s.delivery_failed(&attempt, DispatchFailure::NotSent(take_error()?))?;
                if let DeliveryTarget::Open { identity } = &attempt.target {
                    s.open_failed(identity)?;
                }
            }
            _ => return Err(invalid("unknown bridge event")),
        }
        Ok(())
    });
    result?;
    let waiting_for_outcome_or_proof = state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&sequence)
        .is_some_and(|p| {
            (name == "uncertain" && !p.stopped) || (name == "stopped" && !p.uncertain)
        });
    if !matches!(name, "ack" | "stop_unconfirmed") && !waiting_for_outcome_or_proof {
        state
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&sequence);
    }
    state.emit(event);
    Ok(())
}
fn invalid(message: &str) -> NexusError {
    NexusError::new(NexusErrorCode::InvalidTransition, message)
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, NexusError> {
    serde_json::from_value(value).map_err(|error| invalid(&error.to_string()))
}

#[cfg(test)]
#[path = "../../tests/support/n4_bridge.rs"]
mod n4_fix_regressions;
