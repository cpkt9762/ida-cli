use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{NexusError, NexusErrorCode, RemainingBudget};

macro_rules! identity {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, NexusError> {
                Self::try_from(value.into())
            }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl TryFrom<String> for $name {
            type Error = NexusError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                if value.is_empty() || value.len() > 128 || !value.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c)) {
                    return Err(NexusError::new(NexusErrorCode::InvalidIdentity, concat!(stringify!($name), " must be 1..=128 ASCII identifier characters")));
                }
                Ok(Self(value))
            }
        }
        impl From<$name> for String { fn from(value: $name) -> Self { value.0 } }
    )+};
}

identity!(
    ClientId,
    TaskId,
    RequestId,
    OperationId,
    LeaseId,
    InstanceId
);

/// Non-secret IDs. lease_id is a bridge handle key, not a Nexus private token.
/// Authentication/close_token resolution stays in the router;
/// clients must not be allowed to assert another authenticated ClientId.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionLease {
    pub client_id: ClientId,
    pub lease_id: LeaseId,
    pub instance_id: InstanceId,
    pub generation: u64,
    pub owner: OwnerKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind {
    Managed,
    Gui,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationIdentity {
    pub task_id: Option<TaskId>,
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub lease: SessionLease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenIdentity {
    pub client_id: ClientId,
    pub task_id: Option<TaskId>,
    pub request_id: RequestId,
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version(pub u32, pub u32, pub u32);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexusRuntime {
    pub ida: Version,
    pub python: Version,
    pub nexus: Option<Version>,
    pub domain: Option<Version>,
}

impl NexusRuntime {
    pub fn validate(&self) -> Result<(), NexusError> {
        if self.ida < Version(9, 4, 0) || self.python < Version(3, 11, 0) {
            return Err(NexusError::new(
                NexusErrorCode::RuntimeUnavailable,
                "Nexus requires IDA >=9.4 and Python >=3.11",
            ));
        }
        let (Some(nexus), Some(domain)) = (self.nexus, self.domain) else {
            return Err(NexusError::new(
                NexusErrorCode::DependencyUnavailable,
                "ida-nexus and ida-domain are required",
            ));
        };
        if nexus < Version(0, 13, 4) || domain < Version(0, 5, 1) {
            return Err(NexusError::new(NexusErrorCode::DependencyUnavailable, "requires ida-nexus >=0.13.4 and ida-domain >=0.5.1; validated baseline is 0.13.4/0.5.1"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodEffect {
    ReadOnly,
    MayWrite,
}

/// Advertise only methods actually implemented by the bridge and available in
/// this licensed runtime. Unknown methods never inherit a legacy capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexusCapabilities {
    pub runtime: NexusRuntime,
    pub methods: BTreeMap<String, MethodEffect>,
}

impl NexusCapabilities {
    pub fn require(&self, method: &str) -> Result<MethodEffect, NexusError> {
        self.runtime.validate()?;
        if matches!(
            method,
            "open"
                | "open_idb"
                | "close"
                | "close_idb"
                | "shutdown"
                | "shutdown_database"
                | "release_lease"
                | "cancel_operation"
                | "status"
        ) {
            return Err(NexusError::new(
                NexusErrorCode::UnsupportedCapability,
                "lifecycle/control methods require the session API",
            ));
        }
        self.methods.get(method).copied().ok_or_else(|| {
            NexusError::new(
                NexusErrorCode::UnsupportedCapability,
                format!("Nexus method {method} is not available"),
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    Client,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    Running,
    CancelRequested,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    UnknownOutcome,
}

impl OperationStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running | Self::CancelRequested)
    }

    pub fn legacy_status(self) -> &'static str {
        match self {
            Self::Queued | Self::Running | Self::CancelRequested => "running",
            Self::Succeeded => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed | Self::TimedOut | Self::UnknownOutcome => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OperationSnapshot {
    pub identity: OperationIdentity,
    pub status: OperationStatus,
    /// Unknown outcome is final for the caller but does NOT prove native code
    /// stopped. Keep the slot and lease until stopped or a new owner generation.
    pub execution_stopped: bool,
    pub cancel_reason: Option<CancelReason>,
    /// Transport state is independent of the immutable caller outcome.
    pub cancel_delivery: Option<DeliverySnapshot>,
    pub error: Option<NexusError>,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Preparing,
    Active,
    ReleaseRequired,
    ReleaseRequested,
    ShutdownRequested,
    Released,
    Disconnected,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub lease: SessionLease,
    pub phase: SessionPhase,
    pub capabilities: NexusCapabilities,
    pub pending_shutdown: Option<OperationIdentity>,
    pub control_delivery: Option<DeliverySnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteCommand {
    pub identity: OperationIdentity,
    pub method: String,
    pub params: Value,
    pub effect: MethodEffect,
    pub remaining_ms: RemainingBudget,
}

/// Protocol DTOs only: they are not added to the old worker JSON-RPC envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum SessionCommand {
    Open {
        identity: OpenIdentity,
        path: String,
        options: Value,
        remaining_ms: RemainingBudget,
    },
    Execute(ExecuteCommand),
    Cancel {
        identity: OperationIdentity,
        reason: CancelReason,
    },
    Release {
        lease: SessionLease,
    },
    /// Bridge must use Nexus's authoritative exclusive-managed-worker check.
    /// A single router-local lease does not establish global exclusivity.
    Shutdown {
        identity: OperationIdentity,
        save: bool,
        require_exclusive: bool,
        remaining_ms: RemainingBudget,
    },
}

#[derive(Debug, Clone)]
pub enum DispatchFailure {
    /// Proven not sent: no remote operation can have started.
    NotSent(NexusError),
    /// Dispatch may have reached the remote instance; never replay it.
    Uncertain(NexusError),
}

/// Synchronous, bounded enqueue only. It must not perform remote I/O or wait
/// for a result. Ok proves local enqueue only: N2/N3 must retain the attempt
/// and report later transport failures through delivery_failed. Only native
/// lifecycle callbacks prove completion. No automatic replay is permitted.
pub trait NexusBackend {
    fn send(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure>;
    /// Independent bounded control capacity; never queued behind business work.
    fn send_control(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure>;
}

/// Explicit failure until N3 installs a real bridge. No fallback exists here.
pub struct UnconnectedNexus;

impl NexusBackend for UnconnectedNexus {
    fn send(&mut self, _: SessionCommand, _: DeliveryAttempt) -> Result<(), DispatchFailure> {
        Err(DispatchFailure::NotSent(NexusError::new(
            NexusErrorCode::BridgeUnavailable,
            "Nexus bridge is not connected",
        )))
    }
    fn send_control(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure> {
        self.send(command, attempt)
    }
}

#[derive(Debug, Clone)]
pub enum Completion {
    Success(Value),
    Failed(NexusError),
    Cancelled,
    ExecutionTimedOut,
}

#[derive(Debug, Clone)]
pub struct OpenSpec {
    pub operation_id: OperationId,
    pub path: String,
    pub options: Value,
}

#[derive(Debug, Clone)]
pub struct ShutdownSpec {
    pub request: super::AcceptedRequest,
    pub operation_id: OperationId,
    pub save: bool,
}

#[must_use = "a late open owns a lease that must be released"]
#[derive(Debug, Clone)]
pub enum OpenDisposition {
    Ready(SessionLease),
    ReleaseRequired {
        lease: SessionLease,
        error: NexusError,
    },
}

/// Full authenticated identity plus a nonzero coordinator-local send sequence.
/// N2/N3 echo this unchanged; restart requires a fresh identity namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    pub target: DeliveryTarget,
    pub sequence: std::num::NonZeroU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeliveryTarget {
    Open {
        identity: OpenIdentity,
    },
    Execute {
        identity: OperationIdentity,
    },
    Cancel {
        identity: OperationIdentity,
        reason: CancelReason,
    },
    Release {
        lease: SessionLease,
    },
    Shutdown {
        identity: OperationIdentity,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Queued,
    Acknowledged,
    NotSent,
    Uncertain,
    Confirmed,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeliverySnapshot {
    pub attempt: DeliveryAttempt,
    pub state: DeliveryState,
    pub error: Option<NexusError>,
}
