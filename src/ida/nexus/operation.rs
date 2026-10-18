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
        let turn = self.next_turn()?;
        let identity = OperationIdentity {
            task_id: request.task_id.clone(),
            request_id: request.request_id.clone(),
            operation_id,
            lease: lease.clone(),
        };
        self.operations.insert(
            identity.operation_id.clone(),
            Operation {
                turn,
                snapshot: OperationSnapshot {
                    identity: identity.clone(),
                    status: OperationStatus::Queued,
                    execution_stopped: true,
                    cancel_reason: None,
                    cancel_delivery: None,
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
        let mut snapshot = self.operation(client, identity)?.snapshot.clone();
        snapshot.cancel_delivery = self.cancel_delivery(identity);
        Ok(snapshot)
    }

    /// Metadata-only status. Never clones the business Value under a session lock.
    pub fn operation_progress(
        &self,
        client: &ClientId,
        identity: &OperationIdentity,
    ) -> Result<OperationSnapshot, NexusError> {
        let snapshot = &self.operation(client, identity)?.snapshot;
        Ok(OperationSnapshot {
            identity: snapshot.identity.clone(),
            status: snapshot.status,
            execution_stopped: snapshot.execution_stopped,
            cancel_reason: snapshot.cancel_reason,
            cancel_delivery: self.cancel_delivery(identity),
            error: snapshot.error.clone(),
            result: None,
        })
    }

    /// Destructive read for the single result consumer; identity/status tombstones
    /// remain. The JSON allocation is moved out, never cloned while locked.
    pub fn take_operation_result(
        &mut self,
        client: &ClientId,
        identity: &OperationIdentity,
    ) -> Result<Option<serde_json::Value>, NexusError> {
        self.operation(client, identity)?;
        Ok(self
            .operations
            .get_mut(&identity.operation_id)
            .and_then(|op| op.snapshot.result.take()))
    }

    pub(super) fn occupied(&self, lease: &SessionLease) -> bool {
        self.operations.values().any(|op| {
            op.snapshot.identity.lease.instance_id == lease.instance_id
                && op.snapshot.identity.lease.generation == lease.generation
                && !op.snapshot.execution_stopped
                && !self
                    .resource_retirements
                    .contains_key(&op.snapshot.identity.lease.lease_id)
        })
    }

    fn next_turn(&mut self) -> Result<u64, NexusError> {
        self.queue_sequence = self
            .queue_sequence
            .checked_add(1)
            .ok_or_else(|| NexusError::new(NexusErrorCode::Busy, "queue sequence exhausted"))?;
        Ok(self.queue_sequence)
    }

    /// A returned slice proves native execution stopped. Retain the
    /// logical identity/deadline and rejoin the tail of this instance's FIFO.
    pub fn yield_operation(
        &mut self,
        identity: &OperationIdentity,
        checkpoint: serde_json::Value,
    ) -> Result<(), NexusError> {
        let op = self.match_operation(identity)?;
        if op.snapshot.status.is_terminal() {
            // A late slice proves stop, never permission to resume or a new
            // caller outcome after disconnection/uncertainty.
            self.complete(identity, Completion::Success(serde_json::Value::Null))?;
            return Ok(());
        }
        if !matches!(
            op.request.method.as_str(),
            "batch_decompile" | "search_pseudocode" | "run_auto_analysis" | "batch_rename"
        ) || !matches!(
            op.snapshot.status,
            OperationStatus::Running | OperationStatus::CancelRequested
        ) || self.generations.get(&identity.lease.instance_id)
            != Some(&identity.lease.generation)
        {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "invalid continuation boundary",
            ));
        }
        if op.snapshot.status == OperationStatus::CancelRequested {
            self.complete(identity, Completion::Cancelled)?;
            return Ok(());
        }
        if op.request.deadline.expired(self.clock.now()) {
            self.complete(identity, Completion::ExecutionTimedOut)?;
            return Ok(());
        }
        let turn = self.next_turn()?;
        if let Some(op) = self.operations.get_mut(&identity.operation_id) {
            op.request.params["_n5_checkpoint"] = checkpoint;
            op.snapshot.status = OperationStatus::Queued;
            op.snapshot.execution_stopped = true;
            op.turn = turn;
        }
        self.confirm_delivery(DeliveryTarget::Execute {
            identity: identity.clone(),
        });
        Ok(())
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
                let message = if op.request.params.get("_n5_checkpoint").is_some() {
                    "total deadline expired after completed slices; effects may remain"
                } else {
                    "total deadline expired before execution"
                };
                let error = NexusError::new(NexusErrorCode::QueueExpired, message);
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
        if self.operations.values().any(|other| {
            other.snapshot.status == OperationStatus::Queued
                && other.snapshot.identity.lease.instance_id == identity.lease.instance_id
                && other.snapshot.identity.lease.generation == identity.lease.generation
                && other.turn < op.turn
        }) {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "earlier instance request is queued",
            ));
        }
        let command = SessionCommand::Execute(ExecuteCommand {
            identity: identity.clone(),
            method: op.request.method.clone(),
            params: op.request.params.clone(),
            effect: op.effect,
            remaining_ms,
        });
        let attempt = self.begin_delivery(&command, None)?;
        if let Some(op) = self.operations.get_mut(&identity.operation_id) {
            op.snapshot.status = OperationStatus::Running;
            op.snapshot.execution_stopped = false;
        }
        self.send_delivery(command, attempt, backend)
    }

    pub(super) fn execute_delivery_failed(
        &mut self,
        identity: &OperationIdentity,
        uncertain: bool,
        error: NexusError,
    ) {
        if uncertain {
            self.terminal(
                identity,
                OperationStatus::UnknownOutcome,
                Some(Self::unknown(error)),
                None,
                false,
            );
        } else {
            self.terminal(identity, OperationStatus::Failed, Some(error), None, true);
            if let Some(op) = self.operations.get_mut(&identity.operation_id) {
                // A later proof of non-delivery may stop retention after a
                // connection event, without rewriting the caller's outcome.
                op.snapshot.execution_stopped = true;
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
        self.current_owner(client, &identity.lease)?;
        let op = self.operation(client, identity)?;
        let expired = op.request.deadline.expired(self.clock.now());
        if reason == CancelReason::Deadline && !expired {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "total deadline has not expired",
            ));
        }
        let reason = if expired || op.snapshot.cancel_reason == Some(CancelReason::Deadline) {
            CancelReason::Deadline
        } else {
            reason
        };
        let status = op.snapshot.status;
        // A caller terminal result is independent of native stop evidence.
        if op.snapshot.execution_stopped && status != OperationStatus::Queued {
            return self.operation_status(client, identity);
        }
        if status == OperationStatus::Queued {
            let message = if op.request.params.get("_n5_checkpoint").is_some() {
                "continuation removed after completed slices; effects may remain"
            } else {
                "request removed before dispatch"
            };
            let (status, code) = if reason == CancelReason::Deadline {
                (OperationStatus::TimedOut, NexusErrorCode::QueueExpired)
            } else {
                (OperationStatus::Cancelled, NexusErrorCode::Cancelled)
            };
            self.terminal(
                identity,
                status,
                Some(NexusError::new(code, message)),
                None,
                true,
            );
            return self.operation_status(client, identity);
        }
        // Repeating the same pending/acknowledged request does not flood control
        // capacity. Explicit calls retry failed attempts, including uncertainty;
        // deadline escalation gets a new attempt and supersedes client intent.
        if let Some(delivery) = self.cancel_delivery(identity) {
            if matches!(delivery.attempt.target, DeliveryTarget::Cancel { reason: old, .. } if old == reason)
                && matches!(
                    delivery.state,
                    DeliveryState::Queued | DeliveryState::Acknowledged
                )
            {
                return self.operation_status(client, identity);
            }
        }
        let command = SessionCommand::Cancel {
            identity: identity.clone(),
            reason,
        };
        let attempt = self.begin_delivery(&command, None)?;
        if let Some(op) = self.operations.get_mut(&identity.operation_id) {
            op.snapshot.cancel_reason = Some(reason);
            if !op.snapshot.status.is_terminal() {
                op.snapshot.status = OperationStatus::CancelRequested;
                op.snapshot.error = Some(NexusError::new(
                    NexusErrorCode::CancelPending,
                    "cancellation requested; remote stop is not confirmed",
                ));
            }
        }
        // Transport failure is recorded separately and never overwrites an
        // UnknownOutcome, its source cause, result or NeverReplay advice.
        self.send_delivery(command, attempt, backend)?;
        self.operation_status(client, identity)
    }

    pub fn expire(
        &mut self,
        client: &ClientId,
        identity: &OperationIdentity,
        backend: &mut impl NexusBackend,
    ) -> Result<OperationSnapshot, NexusError> {
        self.current_owner(client, &identity.lease)?;
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

    /// Independent stop evidence after an unknown result. This never supplies a
    /// business outcome or permits queued/running work to finish successfully.
    pub fn execution_stopped(&mut self, identity: &OperationIdentity) -> Result<bool, NexusError> {
        let op = self.match_operation(identity)?;
        if self.generations.get(&identity.lease.instance_id) != Some(&identity.lease.generation) {
            return Ok(false);
        }
        if !op.snapshot.status.is_terminal() {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "stop proof requires a determined caller outcome",
            ));
        }
        let changed = !op.snapshot.execution_stopped;
        if let Some(op) = self.operations.get_mut(&identity.operation_id) {
            op.snapshot.execution_stopped = true;
        }
        self.confirm_delivery(DeliveryTarget::Execute {
            identity: identity.clone(),
        });
        self.confirm_delivery(DeliveryTarget::Cancel {
            identity: identity.clone(),
            reason: CancelReason::Client,
        });
        Ok(changed)
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
            self.confirm_delivery(DeliveryTarget::Execute {
                identity: identity.clone(),
            });
            self.confirm_delivery(DeliveryTarget::Cancel {
                identity: identity.clone(),
                reason: CancelReason::Client,
            });
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
        self.confirm_delivery(DeliveryTarget::Execute {
            identity: identity.clone(),
        });
        self.confirm_delivery(DeliveryTarget::Cancel {
            identity: identity.clone(),
            reason: CancelReason::Client,
        });
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
