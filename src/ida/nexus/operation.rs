use super::session::Operation;
use super::*;

impl<C: Clock> NexusSessions<C> {
    pub fn queue(
        &mut self,
        client: &ClientId,
        lease: &SessionLease,
        request: AcceptedRequest,
        operation_id: OperationId,
    ) -> Result<OperationIdentity, NexusError> {
        self.active(client, lease)?;
        self.ready()?;
        let effect = self
            .authorize(client, lease)?
            .capabilities
            .require(&request.method)?;
        self.reserve(&request.request_id, &operation_id)?;
        let identity = OperationIdentity {
            task_id: request.task_id.clone(),
            request_id: request.request_id.clone(),
            operation_id,
            lease: lease.clone(),
        };
        self.operations.insert(
            identity.operation_id.clone(),
            Operation {
                snapshot: OperationSnapshot {
                    identity: identity.clone(),
                    status: OperationStatus::Queued,
                    execution_stopped: true,
                    cancel_reason: None,
                    error: None,
                    result: None,
                },
                request,
                effect,
            },
        );
        Ok(identity)
    }

    fn operation(
        &self,
        client: &ClientId,
        identity: &OperationIdentity,
    ) -> Result<&Operation, NexusError> {
        self.authorize(client, &identity.lease)?;
        self.match_operation(identity)
    }

    fn match_operation(&self, identity: &OperationIdentity) -> Result<&Operation, NexusError> {
        let operation = self
            .operations
            .get(&identity.operation_id)
            .ok_or_else(|| NexusError::new(NexusErrorCode::InvalidIdentity, "unknown operation"))?;
        if &operation.snapshot.identity != identity {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "operation identity mismatch",
            ));
        }
        Ok(operation)
    }

    pub fn operation_status(
        &self,
        client: &ClientId,
        identity: &OperationIdentity,
    ) -> Result<OperationSnapshot, NexusError> {
        Ok(self.operation(client, identity)?.snapshot.clone())
    }

    pub(super) fn occupied(&self, lease: &SessionLease) -> bool {
        self.operations.values().any(|op| {
            op.snapshot.identity.lease.instance_id == lease.instance_id
                && op.snapshot.identity.lease.generation == lease.generation
                && !op.snapshot.execution_stopped
        })
    }

    /// Last local gate before enqueueing any command with possible side effects.
    /// Running means dispatched (including a remote queue), not proof of native
    /// execution. The bridge must subtract its queue time from remaining_ms.
    pub fn dispatch(
        &mut self,
        client: &ClientId,
        identity: &OperationIdentity,
        backend: &mut impl NexusBackend,
    ) -> Result<(), NexusError> {
        self.active(client, &identity.lease)?;
        let op = self.operation(client, identity)?;
        if op.snapshot.status != OperationStatus::Queued {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "only a queued operation can dispatch",
            ));
        }
        let remaining_ms = match op.request.remaining(&self.clock) {
            Ok(budget) => budget,
            Err(_) => {
                let error = NexusError::new(
                    NexusErrorCode::QueueExpired,
                    "total deadline expired before execution",
                );
                self.terminal(
                    identity,
                    OperationStatus::TimedOut,
                    Some(error.clone()),
                    None,
                    true,
                );
                return Err(error);
            }
        };
        if self.occupied(&identity.lease) {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "instance has an operation without stop confirmation",
            ));
        }
        let command = SessionCommand::Execute(ExecuteCommand {
            identity: identity.clone(),
            method: op.request.method.clone(),
            params: op.request.params.clone(),
            effect: op.effect,
            remaining_ms,
        });
        if let Some(op) = self.operations.get_mut(&identity.operation_id) {
            op.snapshot.status = OperationStatus::Running;
            op.snapshot.execution_stopped = false;
        }
        match backend.send(command) {
            Ok(()) => Ok(()),
            Err(DispatchFailure::NotSent(error)) => {
                self.terminal(
                    identity,
                    OperationStatus::Failed,
                    Some(error.clone()),
                    None,
                    true,
                );
                Err(error)
            }
            Err(DispatchFailure::Uncertain(error)) => {
                let error = Self::unknown(error);
                self.terminal(
                    identity,
                    OperationStatus::UnknownOutcome,
                    Some(error.clone()),
                    None,
                    false,
                );
                Err(error)
            }
        }
    }

    pub fn cancel(
        &mut self,
        client: &ClientId,
        identity: &OperationIdentity,
        reason: CancelReason,
        backend: &mut impl NexusBackend,
    ) -> Result<OperationSnapshot, NexusError> {
        self.active(client, &identity.lease)?;
        if reason == CancelReason::Deadline
            && !self
                .operation(client, identity)?
                .request
                .deadline
                .expired(self.clock.now())
        {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "total deadline has not expired",
            ));
        }
        let status = self.operation(client, identity)?.snapshot.status;
        if status.is_terminal() {
            return self.operation_status(client, identity);
        }
        if status == OperationStatus::Queued {
            let (status, code) = if reason == CancelReason::Deadline {
                (OperationStatus::TimedOut, NexusErrorCode::QueueExpired)
            } else {
                (OperationStatus::Cancelled, NexusErrorCode::Cancelled)
            };
            self.terminal(
                identity,
                status,
                Some(NexusError::new(code, "request removed before dispatch")),
                None,
                true,
            );
        } else {
            if let Some(op) = self.operations.get_mut(&identity.operation_id) {
                op.snapshot.status = OperationStatus::CancelRequested;
                // Total deadline dominates a previous client cancellation.
                if op.snapshot.cancel_reason != Some(CancelReason::Deadline) {
                    op.snapshot.cancel_reason = Some(reason);
                }
                op.snapshot.error = Some(NexusError::new(
                    NexusErrorCode::CancelPending,
                    "cancellation requested; remote stop is not confirmed",
                ));
            }
            // Even a successful control enqueue is not a stop acknowledgment.
            if let Err(DispatchFailure::NotSent(error) | DispatchFailure::Uncertain(error)) =
                backend.send_control(SessionCommand::Cancel {
                    identity: identity.clone(),
                    reason,
                })
            {
                if let Some(op) = self.operations.get_mut(&identity.operation_id) {
                    op.snapshot.error = Some(NexusError::caused_by(
                        NexusErrorCode::CancelPending,
                        "cancellation delivery failed; remote stop is not confirmed",
                        error.clone(),
                    ));
                }
                return Err(error);
            }
        }
        self.operation_status(client, identity)
    }

    pub fn expire(
        &mut self,
        client: &ClientId,
        identity: &OperationIdentity,
        backend: &mut impl NexusBackend,
    ) -> Result<OperationSnapshot, NexusError> {
        if !self
            .operation(client, identity)?
            .request
            .deadline
            .expired(self.clock.now())
        {
            return self.operation_status(client, identity);
        }
        self.cancel(client, identity, CancelReason::Deadline, backend)
    }

    /// Completion events mean the remote operation has actually returned/stopped.
    /// Nexus cancel_operation's bool is only a request acknowledgment and MUST
    /// NOT be translated into Completion::Cancelled by the bridge.
    pub fn complete(
        &mut self,
        identity: &OperationIdentity,
        completion: Completion,
    ) -> Result<bool, NexusError> {
        let op = self.match_operation(identity)?;
        if self.generations.get(&identity.lease.instance_id) != Some(&identity.lease.generation) {
            return Ok(false);
        }
        if op.snapshot.status.is_terminal() {
            if op.snapshot.status == OperationStatus::UnknownOutcome {
                // A late response is evidence of stopping, not a new outcome.
                if let Some(op) = self.operations.get_mut(&identity.operation_id) {
                    op.snapshot.execution_stopped = true;
                }
            }
            return Ok(false);
        }
        if op.snapshot.status == OperationStatus::Queued {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "unsent operation cannot complete",
            ));
        }
        let expired = op.request.deadline.expired(self.clock.now());
        let (status, error, result) = match completion {
            Completion::Success(result) if !expired => {
                (OperationStatus::Succeeded, None, Some(result))
            }
            Completion::Success(_) => (
                OperationStatus::TimedOut,
                Some(NexusError::new(
                    NexusErrorCode::DeadlineExpired,
                    "completed after total deadline; effects may already exist",
                )),
                None,
            ),
            Completion::Failed(error) if expired => (
                OperationStatus::TimedOut,
                Some(NexusError::caused_by(
                    NexusErrorCode::DeadlineExpired,
                    "operation returned an error after total deadline; effects may remain",
                    error,
                )),
                None,
            ),
            Completion::Failed(error) => (
                OperationStatus::Failed,
                Some(NexusError::caused_by(
                    NexusErrorCode::OperationFailed,
                    "remote operation returned an error; effects may remain",
                    error,
                )),
                None,
            ),
            Completion::ExecutionTimedOut => (
                OperationStatus::TimedOut,
                Some(NexusError::new(
                    NexusErrorCode::ExecutionTimeout,
                    "remote execution stopped after execution timeout; effects may remain",
                )),
                None,
            ),
            Completion::Cancelled => {
                if op.snapshot.status != OperationStatus::CancelRequested {
                    return Err(NexusError::new(
                        NexusErrorCode::InvalidTransition,
                        "unsolicited cancellation confirmation",
                    ));
                }
                if expired || op.snapshot.cancel_reason == Some(CancelReason::Deadline) {
                    (
                        OperationStatus::TimedOut,
                        Some(NexusError::new(
                            NexusErrorCode::DeadlineExpired,
                            "total deadline expired; stop confirmed",
                        )),
                        None,
                    )
                } else {
                    (
                        OperationStatus::Cancelled,
                        Some(NexusError::new(
                            NexusErrorCode::Cancelled,
                            "remote stop confirmed; effects may remain",
                        )),
                        None,
                    )
                }
            }
        };
        self.terminal(identity, status, error, result, true);
        Ok(true)
    }

    fn terminal(
        &mut self,
        identity: &OperationIdentity,
        status: OperationStatus,
        error: Option<NexusError>,
        result: Option<serde_json::Value>,
        stopped: bool,
    ) {
        if let Some(op) = self.operations.get_mut(&identity.operation_id) {
            if !op.snapshot.status.is_terminal() {
                op.snapshot.status = status;
                op.snapshot.error = error;
                op.snapshot.result = result;
                op.snapshot.execution_stopped = stopped;
            }
        }
    }

    pub(super) fn unknown(error: NexusError) -> NexusError {
        NexusError::caused_by(
            NexusErrorCode::UnknownOutcome,
            "dispatch/connection may have executed; do not replay",
            error,
        )
    }
}
