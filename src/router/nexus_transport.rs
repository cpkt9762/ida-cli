//! N2 bounded handoff for N3. Business and control are separate receivers and
//! must be attached to separate physical connections / public API schedulers.
use crate::nexus::*;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

type Sessions = Arc<Mutex<NexusSessions<SystemClock>>>;
type Failures = Arc<Mutex<Vec<DeferredFailure>>>;
struct DeferredFailure {
    attempt: DeliveryAttempt,
    failure: DispatchFailure,
    _permit: OwnedSemaphorePermit,
}
fn apply_failure(
    sessions: &mut NexusSessions<SystemClock>,
    attempt: &DeliveryAttempt,
    failure: DispatchFailure,
) {
    if let Err(error) = sessions.delivery_failed(attempt, failure) {
        tracing::error!(%error,"Nexus delivery callback rejected");
    }
}
fn flush_failures(sessions: &mut NexusSessions<SystemClock>, failures: &Failures) {
    let queued = std::mem::take(&mut *failures.lock().unwrap_or_else(|e| e.into_inner()));
    for failure in queued {
        apply_failure(sessions, &failure.attempt, failure.failure);
    }
}
#[derive(Clone)]
pub struct NexusTransport {
    business: mpsc::Sender<Delivery>,
    control: mpsc::Sender<Delivery>,
    business_gate: Arc<Semaphore>,
    control_gate: Arc<Semaphore>,
    sessions: Sessions,
    failures: Failures,
}
pub struct NexusLanes {
    pub business: mpsc::Receiver<Delivery>,
    pub control: mpsc::Receiver<Delivery>,
}
/// A bounded in-flight delivery; dropping it reports to the N1 coordinator.
pub struct Delivery {
    command: SessionCommand,
    pub attempt: DeliveryAttempt,
    deadline: Option<Instant>,
    sessions: Sessions,
    _permit: Option<OwnedSemaphorePermit>,
    failures: Failures,
    possible: bool,
    reported: bool,
}
impl Drop for Delivery {
    fn drop(&mut self) {
        if !self.reported {
            let error = NexusError::new(
                NexusErrorCode::Disconnected,
                "transport consumer dropped delivery",
            );
            self.report(if self.possible {
                DispatchFailure::Uncertain(error)
            } else {
                DispatchFailure::NotSent(error)
            });
        }
    }
}
impl Delivery {
    fn report(&mut self, failure: DispatchFailure) {
        self.reported = true;
        match self.sessions.try_lock() {
            Ok(mut sessions) => apply_failure(&mut sessions, &self.attempt, failure),
            Err(std::sync::TryLockError::Poisoned(error)) => {
                apply_failure(&mut error.into_inner(), &self.attempt, failure)
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                // A receiver can disappear during send(), while N1 holds sessions.
                // Retain its lane permit: callbacks cannot become an unbounded queue.
                if let Some(permit) = self._permit.take() {
                    self.failures
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(DeferredFailure {
                            attempt: self.attempt.clone(),
                            failure,
                            _permit: permit,
                        });
                }
            }
        }
    }
    fn eligible(&self) -> Result<(), NexusError> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send_eligible(&self.command, &self.attempt)
    }
    /// Call only when the independent public API adapter is about to perform I/O.
    /// Queue residence is deducted before giving N3 a command.
    pub fn begin(&mut self) -> Result<SessionCommand, NexusError> {
        if self.possible || self.reported {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "delivery may begin only once",
            ));
        }
        if let Err(error) = self.eligible() {
            self.report(DispatchFailure::NotSent(error.clone()));
            return Err(error);
        }
        if let Some(deadline) = self.deadline {
            let ms = u64::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .map_err(|_| {
                NexusError::new(NexusErrorCode::InvalidTimeout, "transport budget overflow")
            })?;
            if ms == 0 {
                let error = NexusError::new(
                    NexusErrorCode::QueueExpired,
                    "expired in bounded transport queue",
                );
                self.report(DispatchFailure::NotSent(error.clone()));
                return Err(error);
            }
            let remaining = RemainingBudget::try_from(ms)?;
            match &mut self.command {
                SessionCommand::Open { remaining_ms, .. }
                | SessionCommand::Shutdown { remaining_ms, .. } => *remaining_ms = remaining,
                SessionCommand::Execute(execute) => execute.remaining_ms = remaining,
                _ => {}
            }
        }
        self.possible = true;
        Ok(self.command.clone())
    }
    pub fn failed(mut self, failure: DispatchFailure) {
        self.report(failure);
    }
    /// ACK is transport-only. N3 separately completes real lifecycle evidence.
    pub fn acknowledged(mut self) -> Result<(), NexusError> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .delivery_acknowledged(&self.attempt)?;
        self.reported = true;
        Ok(())
    }
    /// JSON-line N2 internal frame; never accepted by the legacy RPC path.
    pub async fn write<W: AsyncWrite + Unpin>(mut self, writer: &mut W) -> Result<(), NexusError> {
        let command = self.begin()?;
        // Encoding alone proves no send. Reset the possible-send flag until the first write.
        self.possible = false;
        let attempt = self.attempt.clone();
        let expires_monotonic_ns = wire_expiry(self.deadline)?;
        let encoding = async {
            if matches!(
                command,
                SessionCommand::Cancel { .. }
                    | SessionCommand::Release { .. }
                    | SessionCommand::Shutdown { .. }
            ) {
                // Control DTOs contain bounded identities/booleans only; they never
                // compete with heavy business encoding for blocking-worker permits.
                Ok(serde_json::to_vec(&NexusWireFrame {
                    nexus_frame: 2,
                    expires_monotonic_ns,
                    attempt,
                    payload: command,
                }))
            } else {
                crate::blocking::run(crate::blocking::WorkClass::Encode, move || {
                    serde_json::to_vec(&NexusWireFrame {
                        nexus_frame: 2,
                        expires_monotonic_ns,
                        attempt,
                        payload: command,
                    })
                })
                .await
            }
        };
        let encoded = if let Some(deadline) = self.deadline {
            match tokio::time::timeout_at(deadline.into(), encoding).await {
                Ok(result) => result,
                Err(_) => {
                    let error = NexusError::new(
                        NexusErrorCode::QueueExpired,
                        "total transport deadline expired before encoding completed",
                    );
                    self.report(DispatchFailure::NotSent(error.clone()));
                    return Err(error);
                }
            }
        } else {
            encoding.await
        };
        let mut bytes = match encoded {
            Ok(Ok(b)) if b.len() < super::transport::MAX_FRAME_BYTES => b,
            other => {
                let message = match other {
                    Ok(Ok(bytes)) => format!("Nexus frame exceeds 16 MiB ({} bytes)", bytes.len()),
                    Ok(Err(error)) => format!("Nexus frame encoding: {error}"),
                    Err(error) => format!("Nexus frame encoding worker: {error}"),
                };
                let error = NexusError::new(NexusErrorCode::OperationFailed, message);
                self.report(DispatchFailure::NotSent(error.clone()));
                return Err(error);
            }
        };
        bytes.push(b'\n');
        let mut offset = 0;
        while offset < bytes.len() {
            // Recheck after encoding and on every write poll. No session lock is
            // held during I/O. A concurrent transition after this gate is possible
            // delivery, never proof of non-delivery or permission to replay.
            let deadline = self.deadline;
            let write = std::future::poll_fn(|cx| {
                if let Err(error) = self.eligible() {
                    return std::task::Poll::Ready(Err(error));
                }
                // timeout_at polls its inner future first, including after the
                // timer expired. Enforce the local deadline before every writer
                // poll for business AND control frames, even if it is Ready.
                if deadline.is_some_and(|limit| limit <= Instant::now()) {
                    return std::task::Poll::Ready(Err(NexusError::new(
                        NexusErrorCode::QueueExpired,
                        "total transport deadline before write",
                    )));
                }
                self.possible = true;
                match std::pin::Pin::new(&mut *writer).poll_write(cx, &bytes[offset..]) {
                    std::task::Poll::Pending => {
                        self.possible = offset != 0;
                        std::task::Poll::Pending
                    }
                    std::task::Poll::Ready(result) => std::task::Poll::Ready(result.map_err(|e| {
                        NexusError::new(
                            NexusErrorCode::Disconnected,
                            format!("Nexus pipe write: {e}"),
                        )
                    })),
                }
            });
            let result = if let Some(deadline) = deadline {
                match tokio::time::timeout_at(deadline.into(), write).await {
                    Ok(result) => result,
                    Err(_) => Err(NexusError::new(
                        NexusErrorCode::QueueExpired,
                        "total transport deadline",
                    )),
                }
            } else {
                write.await
            };
            match result {
                Ok(n) if n > 0 => {
                    offset += n;
                    self.possible = true;
                }
                result => {
                    let error = match result {
                        Err(error) => error,
                        Ok(_) => NexusError::new(
                            NexusErrorCode::Disconnected,
                            "Nexus pipe zero write / broken pipe",
                        ),
                    };
                    self.report(if offset == 0 {
                        DispatchFailure::NotSent(error.clone())
                    } else {
                        DispatchFailure::Uncertain(error.clone())
                    });
                    return Err(error);
                }
            }
        }
        // Write success does not ACK or confirm native execution. N3 owns the response.
        self.reported = true;
        Ok(())
    }
}
/// Same-host wire deadline. CLOCK_MONOTONIC has a process-independent epoch;
/// unlike remaining_ms it continues expiring in encoding, pipes and receiver queues.
/// N3 must call consume immediately before dispatch, on the same host/boot.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NexusWireFrame {
    pub nexus_frame: u8,
    pub expires_monotonic_ns: u64,
    pub attempt: DeliveryAttempt,
    pub payload: SessionCommand,
}
pub(crate) fn monotonic_ns() -> Result<u64, NexusError> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid initialized output; read-only system clock query.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(NexusError::new(
            NexusErrorCode::OperationFailed,
            format!("monotonic clock: {}", std::io::Error::last_os_error()),
        ));
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|sec| sec.checked_mul(1_000_000_000))
        .and_then(|ns| ns.checked_add(time.tv_nsec as u64))
        .ok_or_else(|| NexusError::new(NexusErrorCode::InvalidTimeout, "monotonic clock overflow"))
}
pub(crate) fn wire_expiry(deadline: Option<Instant>) -> Result<u64, NexusError> {
    let now = monotonic_ns()?;
    let remaining = deadline
        .ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidTimeout, "missing transport deadline")
        })?
        .saturating_duration_since(Instant::now());
    now.checked_add(
        u64::try_from(remaining.as_nanos()).map_err(|_| {
            NexusError::new(NexusErrorCode::InvalidTimeout, "wire deadline overflow")
        })?,
    )
    .ok_or_else(|| NexusError::new(NexusErrorCode::InvalidTimeout, "wire deadline overflow"))
}
impl NexusWireFrame {
    pub fn consume(mut self) -> Result<(SessionCommand, DeliveryAttempt), NexusError> {
        if self.nexus_frame != 2 {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "unsupported Nexus frame",
            ));
        }
        let remaining = self.expires_monotonic_ns.saturating_sub(monotonic_ns()?) / 1_000_000;
        if remaining == 0 {
            return Err(NexusError::new(
                NexusErrorCode::QueueExpired,
                "wire deadline expired before receiver dispatch",
            ));
        }
        let budget = RemainingBudget::try_from(remaining)?;
        match &mut self.payload {
            SessionCommand::Open { remaining_ms, .. }
            | SessionCommand::Shutdown { remaining_ms, .. } => *remaining_ms = budget,
            SessionCommand::Execute(c) => c.remaining_ms = budget,
            _ => {}
        }
        Ok((self.payload, self.attempt))
    }
}
impl NexusTransport {
    #[cfg(test)]
    pub(crate) fn test_hold_control(&self) -> OwnedSemaphorePermit {
        self.control_gate
            .clone()
            .try_acquire_many_owned(self.control_gate.available_permits() as u32)
            .unwrap()
    }
    pub fn new(
        sessions: Sessions,
        business_capacity: usize,
        control_capacity: usize,
    ) -> (Self, NexusLanes) {
        let (business, business_rx) = mpsc::channel(business_capacity.max(1));
        let (control, control_rx) = mpsc::channel(control_capacity.max(1));
        (
            Self {
                business,
                control,
                business_gate: Arc::new(Semaphore::new(business_capacity)),
                control_gate: Arc::new(Semaphore::new(control_capacity)),
                sessions,
                failures: Arc::new(Mutex::new(Vec::new())),
            },
            NexusLanes {
                business: business_rx,
                control: control_rx,
            },
        )
    }
    fn enqueue(
        &self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
        control: bool,
    ) -> Result<(), DispatchFailure> {
        let is_control = matches!(
            command,
            SessionCommand::Cancel { .. }
                | SessionCommand::Release { .. }
                | SessionCommand::Shutdown { .. }
        );
        if is_control != control {
            return Err(DispatchFailure::NotSent(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "command assigned to wrong transport lane",
            )));
        }
        let (sender, gate) = if control {
            (&self.control, &self.control_gate)
        } else {
            (&self.business, &self.business_gate)
        };
        let permit = gate.clone().try_acquire_owned().map_err(|_| {
            DispatchFailure::NotSent(NexusError::new(
                NexusErrorCode::Busy,
                "Nexus lane capacity exhausted",
            ))
        })?;
        let queue = sender.try_reserve().map_err(|e| {
            DispatchFailure::NotSent(NexusError::new(
                if sender.is_closed() {
                    NexusErrorCode::Disconnected
                } else {
                    NexusErrorCode::Busy
                },
                format!("Nexus lane admission: {e}"),
            ))
        })?;
        let budget = match &command {
            SessionCommand::Open { remaining_ms, .. }
            | SessionCommand::Shutdown { remaining_ms, .. } => Some(*remaining_ms),
            SessionCommand::Execute(c) => Some(c.remaining_ms),
            _ => None,
        };
        let deadline = Some(
            Instant::now()
                + std::time::Duration::from_millis(budget.map_or(
                    if matches!(command, SessionCommand::Release { .. }) {
                        15000
                    } else {
                        2000
                    },
                    |b| b.milliseconds(),
                )),
        );
        queue.send(Delivery {
            command,
            attempt,
            deadline,
            sessions: self.sessions.clone(),
            _permit: Some(permit),
            failures: self.failures.clone(),
            possible: false,
            reported: false,
        });
        Ok(())
    }
}
impl NexusBackend for NexusTransport {
    fn send(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure> {
        self.enqueue(command, attempt, false)
    }
    fn send_control(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure> {
        self.enqueue(command, attempt, true)
    }
}

/// Production router owns the coordinator and backend. N3 takes the receivers
/// once; the existing external RPC remains on the comparison path until N3/N4.
#[derive(Clone)]
pub struct NexusEndpoint {
    sessions: Sessions,
    transport: NexusTransport,
    lanes: Arc<Mutex<Option<NexusLanes>>>,
}
impl NexusEndpoint {
    pub fn new(capacity: usize) -> Self {
        Self::with_capabilities(
            capacity,
            Err(NexusError::new(
                NexusErrorCode::BridgeUnavailable,
                "N3 capability handshake is not installed",
            )),
        )
    }
    pub fn with_capabilities(
        capacity: usize,
        capabilities: Result<NexusCapabilities, NexusError>,
    ) -> Self {
        Self::with_limits(capacity, capacity, capabilities)
    }
    pub fn with_limits(
        business_capacity: usize,
        retention_capacity: usize,
        capabilities: Result<NexusCapabilities, NexusError>,
    ) -> Self {
        let sessions = Arc::new(Mutex::new(NexusSessions::with_limits(
            SystemClock,
            capabilities,
            business_capacity,
            retention_capacity,
        )));
        let (transport, lanes) = NexusTransport::new(sessions.clone(), business_capacity, 8);
        Self {
            sessions,
            transport,
            lanes: Arc::new(Mutex::new(Some(lanes))),
        }
    }
    pub fn take_lanes(&self) -> Option<NexusLanes> {
        self.lanes.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
    /// A short local transition only. Closures must never wait for remote work.
    pub fn transition<T>(
        &self,
        action: impl FnOnce(&mut NexusSessions<SystemClock>, &mut NexusTransport) -> T,
    ) -> T {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mut transport = self.transport.clone();
        flush_failures(&mut sessions, &transport.failures);
        let result = action(&mut sessions, &mut transport);
        flush_failures(&mut sessions, &transport.failures);
        result
    }
}
