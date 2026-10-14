//! Nexus-only migration contract. No IPC or IDA execution is implemented here.
//!
//! N2 owns bounded command transport; N3 supplies the public Nexus API adapter.
//! Callers serialize mutations of `NexusSessions`, but never wait for remote
//! execution while holding that lock. `NexusBackend::send` only enqueues commands.
//! The legacy worker selection remains a development comparison until N9.

mod deadline;
mod error;
mod model;
mod operation;
mod session;

pub use deadline::{AcceptedRequest, Clock, Deadline, RemainingBudget, SystemClock};
pub use error::{NexusError, NexusErrorCode, RetryAdvice};
pub use model::*;
pub use session::NexusSessions;
