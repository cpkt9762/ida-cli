use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NexusErrorCode {
    InvalidIdentity,
    InvalidTimeout,
    UnsupportedCapability,
    DependencyUnavailable,
    RuntimeUnavailable,
    BridgeUnavailable,
    Busy,
    InvalidLease,
    StaleGeneration,
    DuplicateIdentity,
    InvalidTransition,
    QueueExpired,
    DeadlineExpired,
    ExecutionTimeout,
    CancelPending,
    Cancelled,
    Disconnected,
    /// Entire outer request refused before acquisition or dispatch.
    BridgeLostNotDispatched,
    UnknownOutcome,
    OperationFailed,
    ExclusiveCloseRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryAdvice {
    NeverReplay,
    NewRequest,
    ReconnectThenNewRequest,
    ObserveOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("Nexus {code:?}: {message}")]
pub struct NexusError {
    pub code: NexusErrorCode,
    pub message: String,
    #[source]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<Box<NexusError>>,
}

impl NexusError {
    pub fn new(code: NexusErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            cause: None,
        }
    }

    pub fn caused_by(code: NexusErrorCode, message: &str, cause: NexusError) -> Self {
        Self {
            code,
            message: message.into(),
            cause: Some(Box::new(cause)),
        }
    }

    /// Advice is for a new explicit request, never automatic replay.
    pub fn retry_advice(&self) -> RetryAdvice {
        match self.code {
            NexusErrorCode::Busy | NexusErrorCode::QueueExpired => RetryAdvice::NewRequest,
            NexusErrorCode::Disconnected => RetryAdvice::ReconnectThenNewRequest,
            NexusErrorCode::CancelPending => RetryAdvice::ObserveOperation,
            _ => RetryAdvice::NeverReplay,
        }
    }

    pub fn details(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.code,
            "message": self.message,
            "retry": self.retry_advice(),
            "automatic_replay": false,
            "cause": self.cause,
        })
    }

    pub fn rpc_code(&self) -> i64 {
        match self.code {
            NexusErrorCode::InvalidIdentity | NexusErrorCode::InvalidTimeout => -32602,
            NexusErrorCode::UnsupportedCapability => -32601,
            _ => -32000,
        }
    }
}
