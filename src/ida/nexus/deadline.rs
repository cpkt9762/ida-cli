use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{NexusError, NexusErrorCode, RequestId, TaskId};

pub trait Clock {
    fn now(&self) -> Instant;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Local-only monotonic deadline. Never serialize an Instant across processes.
#[derive(Debug, Clone, Copy)]
pub struct Deadline(Instant);

/// Milliseconds remaining at dispatch. Receivers start a local monotonic budget
/// at IPC reception and subtract their own queue time before Nexus execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct RemainingBudget(u64);

impl TryFrom<u64> for RemainingBudget {
    type Error = NexusError;
    fn try_from(ms: u64) -> Result<Self, Self::Error> {
        if ms == 0 || ms > 3_600_000 {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTimeout,
                "remaining_ms must be 1..=3600000",
            ));
        }
        Ok(Self(ms))
    }
}

impl From<RemainingBudget> for u64 {
    fn from(value: RemainingBudget) -> Self {
        value.0
    }
}

impl RemainingBudget {
    pub fn milliseconds(self) -> u64 {
        self.0
    }

    pub fn start(self, now: Instant) -> Result<Deadline, NexusError> {
        Deadline::after(now, Duration::from_millis(self.0))
    }
}

impl Deadline {
    fn after(now: Instant, duration: Duration) -> Result<Self, NexusError> {
        now.checked_add(duration).map(Self).ok_or_else(|| {
            NexusError::new(
                NexusErrorCode::InvalidTimeout,
                "deadline exceeds monotonic clock range",
            )
        })
    }

    pub fn expired(self, now: Instant) -> bool {
        self.0.saturating_duration_since(now).as_millis() == 0
    }

    pub fn remaining(self, now: Instant) -> Result<RemainingBudget, NexusError> {
        // Round down: a sub-millisecond remainder is exhausted, never extended.
        let ms = self.0.saturating_duration_since(now).as_millis();
        let ms = u64::try_from(ms)
            .map_err(|_| NexusError::new(NexusErrorCode::InvalidTimeout, "budget overflow"))?;
        if ms == 0 {
            return Err(NexusError::new(
                NexusErrorCode::DeadlineExpired,
                "total request budget exhausted",
            ));
        }
        RemainingBudget::try_from(ms)
    }
}

/// Construct at request acceptance, before file preparation, hashing or queues.
/// IDs and payload cannot be replaced later to give a request a fresh deadline.
#[derive(Debug, Clone)]
pub struct AcceptedRequest {
    pub(crate) request_id: RequestId,
    pub(crate) task_id: Option<TaskId>,
    pub(crate) method: String,
    pub(crate) params: Value,
    pub(crate) deadline: Deadline,
}

impl AcceptedRequest {
    pub fn new(
        clock: &impl Clock,
        request_id: RequestId,
        task_id: Option<TaskId>,
        method: &str,
        params: Value,
    ) -> Result<Self, NexusError> {
        let now = clock.now();
        // Match the existing router: seconds, default 120, cap open at 3600
        // and other methods at 600. Non-u64 JSON uses the historical default.
        // Zero remains an immediate expiration, not an unbounded timeout.
        let maximum = if method == "open" { 3600 } else { 600 };
        let seconds = params
            .get("timeout_secs")
            .and_then(Value::as_u64)
            .unwrap_or(120)
            .min(maximum);
        Ok(Self {
            request_id,
            task_id,
            method: method.into(),
            params,
            deadline: Deadline::after(now, Duration::from_secs(seconds))?,
        })
    }

    pub fn remaining(&self, clock: &impl Clock) -> Result<RemainingBudget, NexusError> {
        self.deadline.remaining(clock.now())
    }
}
