use std::num::NonZeroU64;

use super::*;

/// One latest attempt per logical command; retries replace records rather than
/// accumulating history. Open/execute/shutdown IDs and session IDs are bounded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum DeliveryKey {
    Open(OperationId),
    Execute(OperationId),
    Cancel(OperationId),
    Release(LeaseId),
    Shutdown(OperationId),
}

pub(super) struct DeliveryRecord {
    pub snapshot: DeliverySnapshot,
    pub previous_phase: Option<SessionPhase>,
}

impl DeliveryTarget {
    pub(super) fn key(&self) -> DeliveryKey {
        match self {
            Self::Open { identity } => DeliveryKey::Open(identity.operation_id.clone()),
            Self::Execute { identity } => DeliveryKey::Execute(identity.operation_id.clone()),
            Self::Cancel { identity, .. } => DeliveryKey::Cancel(identity.operation_id.clone()),
            Self::Release { lease } => DeliveryKey::Release(lease.lease_id.clone()),
            Self::Shutdown { identity } => DeliveryKey::Shutdown(identity.operation_id.clone()),
        }
    }

    fn lease(&self) -> Option<&SessionLease> {
        match self {
            Self::Open { .. } => None,
            Self::Execute { identity }
            | Self::Cancel { identity, .. }
            | Self::Shutdown { identity } => Some(&identity.lease),
            Self::Release { lease } => Some(lease),
        }
    }

    fn client(&self) -> &ClientId {
        match self {
            Self::Open { identity } => &identity.client_id,
            Self::Execute { identity }
            | Self::Cancel { identity, .. }
            | Self::Shutdown { identity } => &identity.lease.client_id,
            Self::Release { lease } => &lease.client_id,
        }
    }
}

impl SessionCommand {
    fn target(&self) -> DeliveryTarget {
        match self {
            Self::Open { identity, .. } => DeliveryTarget::Open {
                identity: identity.clone(),
            },
            Self::Execute(command) => DeliveryTarget::Execute {
                identity: command.identity.clone(),
            },
            Self::Cancel { identity, reason } => DeliveryTarget::Cancel {
                identity: identity.clone(),
                reason: *reason,
            },
            Self::Release { lease } => DeliveryTarget::Release {
                lease: lease.clone(),
            },
            Self::Shutdown { identity, .. } => DeliveryTarget::Shutdown {
                identity: identity.clone(),
            },
        }
    }
}

impl<C: Clock> NexusSessions<C> {
    pub(super) fn begin_delivery(
        &mut self,
        command: &SessionCommand,
        previous_phase: Option<SessionPhase>,
    ) -> Result<DeliveryAttempt, NexusError> {
        let sequence = self
            .send_sequence
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::Busy, "send attempt sequence exhausted")
            })?;
        self.send_sequence = sequence.get();
        let attempt = DeliveryAttempt {
            target: command.target(),
            sequence,
        };
        self.deliveries.insert(
            attempt.target.key(),
            DeliveryRecord {
                snapshot: DeliverySnapshot {
                    attempt: attempt.clone(),
                    state: DeliveryState::Queued,
                    error: None,
                },
                previous_phase,
            },
        );
        Ok(attempt)
    }

    pub(super) fn send_delivery(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
        backend: &mut impl NexusBackend,
    ) -> Result<(), NexusError> {
        let result = if matches!(
            command,
            SessionCommand::Open { .. } | SessionCommand::Execute(_)
        ) {
            backend.send(command, attempt.clone())
        } else {
            backend.send_control(command, attempt.clone())
        };
        if let Err(failure) = result {
            self.delivery_failed(&attempt, failure)?;
            let error = self
                .current_delivery(&attempt)?
                .snapshot
                .error
                .clone()
                .ok_or_else(|| {
                    NexusError::new(
                        NexusErrorCode::InvalidTransition,
                        "failed enqueue did not record its transport error",
                    )
                })?;
            return Err(error);
        }
        Ok(())
    }

    fn current_delivery(&self, attempt: &DeliveryAttempt) -> Result<&DeliveryRecord, NexusError> {
        let record = self.deliveries.get(&attempt.target.key()).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "unknown send attempt")
        })?;
        // A reused key with forged request/task/lease fields is never accepted.
        if record.snapshot.attempt.target != attempt.target {
            // Cancellation reason may legitimately change between attempts.
            if record.snapshot.attempt.sequence == attempt.sequence {
                return Err(NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "send attempt identity mismatch",
                ));
            }
        }
        Ok(record)
    }

    /// True only for an exact target replaced by a strictly newer N1 attempt.
    /// Physical adapters may receive its late callback before registering the
    /// successor locally. Unknown/forged identities are never classified stale.
    pub fn delivery_superseded(&self, attempt: &DeliveryAttempt) -> bool {
        self.deliveries
            .get(&attempt.target.key())
            .is_some_and(|record| {
                record.snapshot.attempt.target == attempt.target
                    && record.snapshot.attempt.sequence > attempt.sequence
            })
    }

    pub fn delivery_status(
        &self,
        client: &ClientId,
        attempt: &DeliveryAttempt,
    ) -> Result<DeliverySnapshot, NexusError> {
        if client != attempt.target.client() {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "send attempt owner mismatch",
            ));
        }
        let record = self.current_delivery(attempt)?;
        if record.snapshot.attempt != *attempt {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "stale send attempt",
            ));
        }
        Ok(record.snapshot.clone())
    }

    /// Read-only last send gate. ACK/uncertainty authorize callbacks, never a
    /// second send. Stop controls deliberately permit a live UnknownOutcome.
    pub fn send_eligible(
        &self,
        command: &SessionCommand,
        attempt: &DeliveryAttempt,
    ) -> Result<(), NexusError> {
        if command.target() != attempt.target {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "command/attempt mismatch",
            ));
        }
        let record = self.current_delivery(attempt)?;
        if record.snapshot.attempt != *attempt || record.snapshot.state != DeliveryState::Queued {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "send attempt is stale or already resolved",
            ));
        }
        if let Some(lease) = attempt.target.lease() {
            self.current_owner(attempt.target.client(), lease)?;
        }
        let eligible = match command {
            SessionCommand::Open { identity, .. } => return self.open_send_eligible(identity),
            SessionCommand::Execute(c) => {
                self.active(&c.identity.lease.client_id, &c.identity.lease)?;
                let snapshot = self.operation_status(&c.identity.lease.client_id, &c.identity)?;
                snapshot.status == OperationStatus::Running
                    && !snapshot.execution_stopped
                    && snapshot.cancel_reason.is_none()
                    && !self
                        .operations
                        .get(&c.identity.operation_id)
                        .is_some_and(|operation| {
                            operation.request.deadline.expired(self.clock.now())
                        })
            }
            SessionCommand::Cancel { identity, reason } => {
                let snapshot = self.operation_status(&identity.lease.client_id, identity)?;
                !snapshot.execution_stopped && snapshot.cancel_reason == Some(*reason)
            }
            SessionCommand::Release { lease } => matches!(
                self.authorize(&lease.client_id, lease)?.phase,
                SessionPhase::ReleaseRequested | SessionPhase::Disconnected
            ),
            SessionCommand::Shutdown { identity, .. } => {
                let session = self.authorize(&identity.lease.client_id, &identity.lease)?;
                session.pending_shutdown.as_ref() == Some(identity)
                    && matches!(
                        session.phase,
                        SessionPhase::ShutdownRequested | SessionPhase::Disconnected
                    )
            }
        };
        if !eligible {
            return Err(NexusError::new(
                NexusErrorCode::Cancelled,
                "command lifecycle no longer permits send",
            ));
        }
        Ok(())
    }

    pub(super) fn live_delivery(&self, attempt: &DeliveryAttempt) -> Result<bool, NexusError> {
        let record = self.current_delivery(attempt)?;
        if record.snapshot.attempt != *attempt {
            return Ok(false);
        }
        if let Some(lease) = attempt.target.lease() {
            if self.generations.get(&lease.instance_id) != Some(&lease.generation) {
                return Ok(false);
            }
        }
        Ok(!matches!(
            record.snapshot.state,
            DeliveryState::NotSent | DeliveryState::Confirmed
        ))
    }

    /// Optional transport/request ACK. This never proves native execution or
    /// lease release stopped, and must not be translated to complete(Cancelled).
    pub fn delivery_acknowledged(&mut self, attempt: &DeliveryAttempt) -> Result<bool, NexusError> {
        if !self.live_delivery(attempt)?
            || self.current_delivery(attempt)?.snapshot.state != DeliveryState::Queued
        {
            return Ok(false);
        }
        if let Some(record) = self.deliveries.get_mut(&attempt.target.key()) {
            record.snapshot.state = DeliveryState::Acknowledged;
        }
        Ok(true)
    }

    /// A request-local transport outcome after successful bounded enqueue.
    /// It is NOT an execution completion, nor an instance disconnect event.
    /// Only the current attempt's first failure is applied; stale/duplicate
    /// callbacks return false and cannot change successors or confirmed results.
    pub fn delivery_failed(
        &mut self,
        attempt: &DeliveryAttempt,
        failure: DispatchFailure,
    ) -> Result<bool, NexusError> {
        if !self.live_delivery(attempt)? {
            return Ok(false);
        }
        let state = self.current_delivery(attempt)?.snapshot.state;
        if matches!(state, DeliveryState::Uncertain) {
            return Ok(false);
        }
        if state == DeliveryState::Acknowledged && matches!(failure, DispatchFailure::NotSent(_)) {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "acknowledged delivery cannot be proven not sent",
            ));
        }
        let (uncertain, error) = match failure {
            DispatchFailure::NotSent(error) => (false, error),
            DispatchFailure::Uncertain(error) => (true, error),
        };
        // NotSent describes this attempt, not earlier completed slices. Keep
        // the operation result AND the synchronous dispatch return consistent.
        let error = match &attempt.target {
            DeliveryTarget::Execute { identity } if !uncertain => {
                self.continuation_delivery_error(identity, error)
            }
            _ => error,
        };
        let previous = self.current_delivery(attempt)?.previous_phase;
        match &attempt.target {
            DeliveryTarget::Execute { identity } => {
                self.execute_delivery_failed(identity, uncertain, error.clone())
            }
            DeliveryTarget::Open { identity } => {
                if let Some(opening) = self.openings.get_mut(&identity.operation_id) {
                    opening.uncertain = uncertain;
                    opening.failure = Some(if uncertain {
                        Self::unknown(error.clone())
                    } else {
                        error.clone()
                    });
                }
                if !uncertain {
                    // Exact NotSent means the adapter did not start this send.
                    // Registered watches/leases must retain their own custody.
                    let acquisition = self
                        .openings
                        .get(&identity.operation_id)
                        .and_then(|o| {
                            o.acquisitions.iter().rev().find(|a| {
                                a.identity.purpose != AcquisitionPurpose::Auxiliary && !a.closed
                            })
                        })
                        .map(|a| a.identity.clone());
                    if let Some(acquisition) = acquisition {
                        if self.acquisition_lease(&acquisition)?.is_none()
                            && !self
                                .startup_origins
                                .values()
                                .any(|(bound, _)| bound == &acquisition)
                        {
                            self.acquisition_unstarted(&acquisition)?;
                        }
                    }
                }
            }
            DeliveryTarget::Cancel { .. } => {} // The original outcome/cause is immutable.
            DeliveryTarget::Release { lease }
            | DeliveryTarget::Shutdown {
                identity: OperationIdentity { lease, .. },
            } => {
                if !uncertain {
                    if let Some(session) = self.sessions.get_mut(&lease.lease_id) {
                        // A subsequent real disconnect cannot be undone by a
                        // request-local NotSent callback.
                        if !matches!(
                            session.phase,
                            SessionPhase::Disconnected | SessionPhase::Released
                        ) {
                            session.phase = previous.unwrap_or(SessionPhase::ReleaseRequired);
                        }
                        if matches!(attempt.target, DeliveryTarget::Shutdown { .. }) {
                            session.pending_shutdown = None;
                        }
                    }
                }
            }
        }
        if let Some(record) = self.deliveries.get_mut(&attempt.target.key()) {
            record.snapshot.state = if uncertain {
                DeliveryState::Uncertain
            } else {
                DeliveryState::NotSent
            };
            record.snapshot.error = Some(
                if uncertain && !matches!(attempt.target, DeliveryTarget::Cancel { .. }) {
                    Self::unknown(error)
                } else {
                    error
                },
            );
        }
        Ok(true)
    }

    pub(super) fn confirm_delivery(&mut self, target: DeliveryTarget) {
        if let Some(record) = self.deliveries.get_mut(&target.key()) {
            record.snapshot.state = DeliveryState::Confirmed;
        }
    }

    pub(super) fn cancel_delivery(&self, identity: &OperationIdentity) -> Option<DeliverySnapshot> {
        self.deliveries
            .get(&DeliveryKey::Cancel(identity.operation_id.clone()))
            .map(|record| record.snapshot.clone())
    }

    pub(super) fn control_delivery(&self, lease: &SessionLease) -> Option<DeliverySnapshot> {
        self.deliveries
            .values()
            .filter(|record| {
                matches!(
                    record.snapshot.attempt.target,
                    DeliveryTarget::Release { .. } | DeliveryTarget::Shutdown { .. }
                ) && record.snapshot.attempt.target.lease() == Some(lease)
            })
            .max_by_key(|record| record.snapshot.attempt.sequence)
            .map(|record| record.snapshot.clone())
    }
}
