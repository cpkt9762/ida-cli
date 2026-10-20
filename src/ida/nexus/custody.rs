//! Early acquisition custody and per-RPC execution authority. N1 owns phases;
//! the adapter retains physical handles until an exact cleanup grant.
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionId {
    pub parent: OpenIdentity,
    pub purpose: AcquisitionPurpose,
    pub ordinal: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionPurpose {
    Final,
    Verification,
    InitialRootRetry,
    Auxiliary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyDisposition {
    Prepare,
    CleanupOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyDecision {
    pub disposition: CustodyDisposition,
    pub grant_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalPurpose {
    Runtime,
    Guard,
    Root,
    Analysis,
    Cleanup,
}

pub(super) struct Custody {
    pub(super) acquisition: AcquisitionId,
    lease: SessionLease,
    decision: CustodyDecision,
    subscribed: bool,
    issued_operations: usize,
}

impl<C: Clock> NexusSessions<C> {
    pub fn cleanup_exhausted(&self, lease: &SessionLease) -> bool {
        self.custodies
            .get(&lease.lease_id)
            .is_some_and(|c| c.lease == *lease && c.issued_operations >= 16)
            && !self.occupied(lease)
    }
    /// The adapter has durably verified every prior owner proof and typed
    /// absence of a lease. Consume the separate allowance before calling SDK.
    pub fn consume_post_exit_resolve(&mut self, parent: &OpenIdentity) -> Result<(), NexusError> {
        self.open_send_eligible(parent)?;
        let opening = self.openings.get_mut(&parent.operation_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "post-exit parent missing")
        })?;
        if opening.post_exit_resolve_used {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "post-exit resolver allowance already consumed; never replay",
            ));
        }
        opening.post_exit_resolve_used = true;
        Ok(())
    }
    /// Called only after the adapter validates and durably adopts a matching
    /// public owner lifetime proof. ACK/delivery and original results stay intact.
    pub fn public_owner_lifetime(&mut self, lease: &SessionLease) -> Result<(), NexusError> {
        self.authorize(&lease.client_id, lease)?;
        if self.resource_retirements.contains_key(&lease.lease_id) {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "old boot resource retired; historical lifetime result cannot change",
            ));
        }
        for opening in self.openings.values_mut() {
            for acquisition in &mut opening.acquisitions {
                if acquisition.lease.as_ref() == Some(lease) {
                    acquisition.owner_proof = true;
                }
            }
        }
        let operations: Vec<_> = self
            .operations
            .values()
            .filter(|op| op.snapshot.identity.lease == *lease && !op.snapshot.execution_stopped)
            .map(|op| op.snapshot.identity.clone())
            .collect();
        for operation in operations {
            if let Some(op) = self.operations.get_mut(&operation.operation_id) {
                if !op.snapshot.status.is_terminal() {
                    op.snapshot.status = OperationStatus::UnknownOutcome;
                    op.snapshot.error = Some(NexusError::new(
                        NexusErrorCode::UnknownOutcome,
                        "owner lifetime ended before RPC result; effects unknown; never replay",
                    ));
                }
            }
            self.execution_stopped(&operation)?;
        }
        if let Some(session) = self.sessions.get_mut(&lease.lease_id) {
            session.phase = SessionPhase::Released;
        }
        Ok(())
    }

    /// Called after both durable consumer and producer closure. Internal RPC
    /// details no longer hold a live obligation; user results are left intact.
    pub fn settle_internal_custody(&mut self, lease: &SessionLease) -> Result<(), NexusError> {
        if !self.custody_settle_ready(lease)? {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "custody has live obligations",
            ));
        }
        let ids: Vec<_> = self
            .internal_operations
            .keys()
            .filter(|id| {
                self.operations.get(*id).is_some_and(|op| {
                    op.snapshot.identity.lease == *lease
                        && op.snapshot.status == OperationStatus::Succeeded
                        && op.snapshot.execution_stopped
                })
            })
            .cloned()
            .collect();
        for id in ids {
            self.internal_operations.remove(&id);
            // Retain the original public identity tombstones. Resource
            // settlement never authorizes reusing an operation/request ID.
            self.operations.remove(&id);
            self.deliveries
                .retain(|_, d| match &d.snapshot.attempt.target {
                    DeliveryTarget::Execute { identity }
                    | DeliveryTarget::Cancel { identity, .. } => identity.operation_id != id,
                    _ => true,
                });
        }
        self.custodies.remove(&lease.lease_id);
        Ok(())
    }

    /// Readiness never supplies stop proof or changes the original ACK/result.
    pub fn custody_settle_ready(&self, lease: &SessionLease) -> Result<bool, NexusError> {
        let status = self.authorize(&lease.client_id, lease)?;
        Ok(status.phase == SessionPhase::Released && !self.occupied(lease))
    }
    /// Idempotent only for the exact reserved acquisition and physical lease.
    /// Callers must verify the helper's durable subscription before setting
    /// subscribed. No remote I/O occurs while this authority is borrowed.
    pub fn acquired(
        &mut self,
        acquisition: &AcquisitionId,
        lease: SessionLease,
        subscribed: bool,
    ) -> Result<CustodyDecision, NexusError> {
        if lease.client_id != acquisition.parent.client_id {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "acquisition lease client differs from retained parent",
            ));
        }
        if let Some(old) = self.custodies.get(&lease.lease_id) {
            if old.acquisition != *acquisition || old.lease != lease {
                return Err(NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "custody identity conflicts with retained resource",
                ));
            }
            return self.custody_decision(&lease);
        }
        let parent = self
            .openings
            .get(&acquisition.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "acquisition parent missing",
                )
            })?;
        let reserved = parent
            .acquisitions
            .iter()
            .find(|a| a.identity == *acquisition && !a.closed && a.lease.is_none())
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "acquisition is not the reserved ordinal/purpose",
                )
            })?;
        let publish_parent = reserved.publish_parent;
        let caps = self.ready()?.clone();
        let disposition = if publish_parent {
            match self.register_acquisition(&acquisition.parent, lease.clone(), caps, false)? {
                OpenDisposition::Ready(_) if subscribed => CustodyDisposition::Prepare,
                _ => CustodyDisposition::CleanupOnly,
            }
        } else {
            let prepare = acquisition.purpose != AcquisitionPurpose::Auxiliary
                && subscribed
                && !parent.cancel_requested
                && !parent.uncertain
                && parent.failure.is_none()
                && !parent.request.deadline.expired(self.clock.now());
            self.register(lease.clone(), caps)?;
            if prepare {
                CustodyDisposition::Prepare
            } else {
                CustodyDisposition::CleanupOnly
            }
        };
        if let Some(reservation) = self
            .openings
            .get_mut(&acquisition.parent.operation_id)
            .and_then(|p| {
                p.acquisitions
                    .iter_mut()
                    .find(|a| a.identity == *acquisition)
            })
        {
            reservation.lease = Some(lease.clone());
        }
        if let Some(session) = self.sessions.get_mut(&lease.lease_id) {
            session.phase = if disposition == CustodyDisposition::Prepare {
                SessionPhase::Preparing
            } else {
                SessionPhase::ReleaseRequired
            };
        }
        self.custodies.insert(
            lease.lease_id.clone(),
            Custody {
                acquisition: acquisition.clone(),
                lease,
                decision: CustodyDecision {
                    disposition,
                    grant_epoch: 1,
                },
                subscribed,
                issued_operations: 0,
            },
        );
        self.custody_decision_by_acquisition(acquisition)
    }

    /// Compatibility for the existing serial initial-Root retry. The next
    /// physical acquisition is reserved only after the prior lease is Released
    /// and its exact operations are stopped. File/owner proof stays with Tools.
    pub fn reserve_root_retry(
        &mut self,
        parent: &OpenIdentity,
        predecessor: &AcquisitionId,
    ) -> Result<AcquisitionId, NexusError> {
        let opening = self.openings.get(&parent.operation_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "retry parent missing")
        })?;
        self.open_progress(&parent.client_id, parent)?;
        if opening.cancel_requested
            || opening.uncertain
            || opening.failure.is_some()
            || opening.request.deadline.expired(self.clock.now())
        {
            return Err(NexusError::new(
                NexusErrorCode::Cancelled,
                "retry parent no longer permits acquisition",
            ));
        }
        let reservation = opening
            .acquisitions
            .iter()
            .find(|a| {
                a.identity == *predecessor
                    && predecessor.parent == *parent
                    && predecessor.purpose != AcquisitionPurpose::Auxiliary
            })
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "retry predecessor mismatch",
                )
            })?;
        let previous = reservation.lease.as_ref().ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidTransition, "no prior acquisition")
        })?;
        let publish_parent = reservation.publish_parent;
        let owner_proof = reservation.owner_proof;
        let retired = self.resource_retirements.contains_key(&previous.lease_id);
        let settled = opening
            .acquisitions
            .iter()
            .any(|a| a.lease.as_ref() == Some(previous) && a.closed);
        if previous.owner != OwnerKind::Managed
            || !settled
            || (!retired
                && (!owner_proof
                    || self.status(&parent.client_id, previous)?.phase != SessionPhase::Released
                    || self.occupied(previous)
                    || !self.control_delivery(previous).is_some_and(|d| {
                        d.state == DeliveryState::Confirmed
                            && matches!(d.attempt.target, DeliveryTarget::Release { .. })
                    })))
            || opening.root_attempts >= 3
        {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "prior acquisition not settled or retry limit reached",
            ));
        }
        let ordinal = opening.acquisition_ordinal + 1;
        self.reserve_physical_slot(Some(parent))?;
        let opening = self.openings.get_mut(&parent.operation_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "retry parent disappeared")
        })?;
        opening.acquisition_ordinal = ordinal;
        opening.root_attempts += 1;
        if publish_parent {
            opening.acquired = None;
        }
        let identity = AcquisitionId {
            parent: parent.clone(),
            purpose: AcquisitionPurpose::InitialRootRetry,
            ordinal,
        };
        opening
            .acquisitions
            .push(super::acquisition::AcquisitionReservation {
                identity: identity.clone(),
                lease: None,
                closed: false,
                primary: None,
                publish_parent,
                owner_proof: false,
                sdk_finished: false,
            });
        Ok(identity)
    }

    pub fn acquisition_cleanup(
        &mut self,
        acquisition: &AcquisitionId,
        lease: &SessionLease,
    ) -> Result<(), NexusError> {
        if !self.custodies.contains_key(&lease.lease_id)
            && self.acquisition_lease(acquisition)?.as_ref() == Some(lease)
            && (self.status(&lease.client_id, lease)?.phase == SessionPhase::Released
                || self.resource_retirement(lease)?.is_some())
        {
            return Ok(());
        }
        let custody = self.custodies.get_mut(&lease.lease_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "cleanup custody missing")
        })?;
        if custody.acquisition != *acquisition || custody.lease != *lease {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "cleanup custody mismatch",
            ));
        }
        if custody.decision.disposition == CustodyDisposition::Prepare {
            custody.decision.grant_epoch =
                custody.decision.grant_epoch.checked_add(1).ok_or_else(|| {
                    NexusError::new(NexusErrorCode::Busy, "custody epoch exhausted")
                })?;
            custody.decision.disposition = CustodyDisposition::CleanupOnly;
        }
        let session = self.sessions.get_mut(&lease.lease_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidLease, "cleanup lease missing")
        })?;
        if session.phase == SessionPhase::Preparing {
            session.phase = SessionPhase::ReleaseRequired;
        }
        Ok(())
    }

    fn custody_decision_by_acquisition(
        &mut self,
        id: &AcquisitionId,
    ) -> Result<CustodyDecision, NexusError> {
        let lease = self
            .custodies
            .values()
            .find(|c| c.acquisition == *id)
            .map(|c| c.lease.clone())
            .ok_or_else(|| NexusError::new(NexusErrorCode::InvalidIdentity, "unknown custody"))?;
        self.custody_decision(&lease)
    }

    pub fn custody_decision(
        &mut self,
        lease: &SessionLease,
    ) -> Result<CustodyDecision, NexusError> {
        if !self.custodies.contains_key(&lease.lease_id)
            && (self.status(&lease.client_id, lease)?.phase == SessionPhase::Released
                || self.resource_retirement(lease)?.is_some())
        {
            // Settled facts have no remaining execution epoch. They may still
            // deliver the original parent error, but cannot grant another RPC.
            return Ok(CustodyDecision {
                disposition: CustodyDisposition::CleanupOnly,
                grant_epoch: 0,
            });
        }
        let custody = self
            .custodies
            .get(&lease.lease_id)
            .ok_or_else(|| NexusError::new(NexusErrorCode::InvalidIdentity, "unknown custody"))?;
        if custody.lease != *lease {
            return Err(NexusError::new(
                NexusErrorCode::InvalidLease,
                "custody lease mismatch",
            ));
        }
        let opening = self
            .openings
            .get(&custody.acquisition.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::InvalidIdentity, "custody parent missing")
            })?;
        let revoked = opening.cancel_requested
            || opening.uncertain
            || opening.failure.is_some()
            || opening.request.deadline.expired(self.clock.now())
            || !custody.subscribed
            || self.authorize(&lease.client_id, lease)?.phase != SessionPhase::Preparing;
        let custody = self.custodies.get_mut(&lease.lease_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "custody disappeared")
        })?;
        if revoked && custody.decision.disposition == CustodyDisposition::Prepare {
            custody.decision.disposition = CustodyDisposition::CleanupOnly;
            custody.decision.grant_epoch =
                custody.decision.grant_epoch.checked_add(1).ok_or_else(|| {
                    NexusError::new(NexusErrorCode::Busy, "custody epoch exhausted")
                })?;
            if let Some(session) = self.sessions.get_mut(&lease.lease_id) {
                if session.phase == SessionPhase::Preparing {
                    session.phase = SessionPhase::ReleaseRequired;
                }
            }
        }
        Ok(custody.decision.clone())
    }

    /// Grant one exact public RPC once. A repeated ID is rejected so an ACK
    /// retry cannot authorize another physical execution.
    pub fn internal_grant(
        &mut self,
        acquisition: &AcquisitionId,
        identity: OperationIdentity,
        purpose: InternalPurpose,
        grant_epoch: u64,
    ) -> Result<(DeliveryAttempt, RemainingBudget), NexusError> {
        let lease = &identity.lease;
        if self.resource_retirement(lease)?.is_some()
            || self.status(&lease.client_id, lease)?.phase == SessionPhase::Released
        {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "released acquisition cannot execute another RPC",
            ));
        }
        let decision = self.custody_decision(lease)?;
        let custody = self.custodies.get(&lease.lease_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "internal custody missing")
        })?;
        if custody.acquisition != *acquisition || decision.grant_epoch != grant_epoch {
            return Err(NexusError::new(
                NexusErrorCode::Cancelled,
                "internal grant epoch revoked",
            ));
        }
        if purpose != InternalPurpose::Cleanup
            && decision.disposition != CustodyDisposition::Prepare
        {
            return Err(NexusError::new(
                NexusErrorCode::Cancelled,
                "custody is cleanup-only",
            ));
        }
        if self
            .internal_operations
            .contains_key(&identity.operation_id)
        {
            return Err(NexusError::new(
                NexusErrorCode::DuplicateIdentity,
                "internal RPC grant already issued; do not replay",
            ));
        }
        if self.occupied(lease) {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "owner has an operation without stop confirmation",
            ));
        }
        if custody.issued_operations
            >= if purpose == InternalPurpose::Cleanup {
                16
            } else {
                14
            }
        {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "acquisition internal RPC budget exhausted; responsibility retained",
            ));
        }
        let parent = self
            .openings
            .get(&acquisition.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::InvalidIdentity, "internal parent missing")
            })?;
        let mut request = parent.request.clone();
        if purpose == InternalPurpose::Cleanup {
            // Cleanup is an already accepted resource obligation. Its bounded
            // attempt has an independent deadline after the caller's terminal.
            request = AcceptedRequest::new(
                &self.clock,
                identity.request_id.clone(),
                identity.task_id.clone(),
                "_internal_cleanup",
                serde_json::json!({"timeout_secs":15}),
            )?;
        }
        request.request_id = identity.request_id.clone();
        request.method = format!("_internal_{purpose:?}");
        let remaining = request.remaining(&self.clock)?;
        self.reserve_internal(&identity.request_id, &identity.operation_id)?;
        if let Some(custody) = self.custodies.get_mut(&lease.lease_id) {
            custody.issued_operations += 1;
        }
        let command = SessionCommand::Execute(ExecuteCommand {
            identity: identity.clone(),
            method: request.method.clone(),
            params: serde_json::Value::Null,
            effect: MethodEffect::MayWrite,
            remaining_ms: remaining,
        });
        let attempt = self.begin_delivery(&command, None)?;
        self.operations.insert(
            identity.operation_id.clone(),
            super::session::Operation {
                turn: 0,
                request,
                effect: MethodEffect::MayWrite,
                snapshot: OperationSnapshot {
                    identity: identity.clone(),
                    status: OperationStatus::Running,
                    execution_stopped: false,
                    cancel_reason: None,
                    cancel_delivery: None,
                    error: None,
                    result: None,
                },
            },
        );
        self.internal_operations.insert(
            identity.operation_id.clone(),
            (acquisition.clone(), purpose, grant_epoch),
        );
        Ok((attempt, remaining))
    }

    pub fn preparing_failed(
        &mut self,
        acquisition: &AcquisitionId,
        error: NexusError,
    ) -> Result<(), NexusError> {
        let opening = self
            .openings
            .get(&acquisition.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "failed acquisition parent missing",
                )
            })?;
        let current = opening
            .acquisitions
            .iter()
            .rev()
            .find(|a| a.identity.purpose != AcquisitionPurpose::Auxiliary);
        let terminal = self
            .deliveries
            .get(&super::delivery::DeliveryKey::Open(
                acquisition.parent.operation_id.clone(),
            ))
            .is_some_and(|d| d.snapshot.state == DeliveryState::Confirmed);
        if current.is_none_or(|a| a.identity != *acquisition)
            || (terminal && opening.failure.is_none())
        {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "late acquisition failure cannot replace the parent terminal or a newer ordinal",
            ));
        }
        let lease = self
            .custodies
            .values()
            .find(|c| c.acquisition == *acquisition)
            .map(|c| c.lease.clone())
            .or(self.acquisition_lease(acquisition)?)
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "failed preparation has no custody",
                )
            })?;
        let parent = self
            .openings
            .get_mut(&acquisition.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "failed preparation parent missing",
                )
            })?;
        if parent.failure.is_none() {
            parent.failure = Some(error);
        }
        if self.custodies.contains_key(&lease.lease_id) {
            self.custody_decision(&lease)?;
        } else if self.status(&lease.client_id, &lease)?.phase != SessionPhase::Released
            && self.resource_retirement(&lease)?.is_none()
        {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "failed preparation retains live custody",
            ));
        }
        self.confirm_delivery(DeliveryTarget::Open {
            identity: acquisition.parent.clone(),
        });
        Ok(())
    }

    pub fn poll_preparation(
        &mut self,
        lease: &SessionLease,
        backend: &mut impl NexusBackend,
    ) -> Result<(), NexusError> {
        if !self.custodies.contains_key(&lease.lease_id) {
            return Ok(());
        }
        let phase = self.status(&lease.client_id, lease)?.phase;
        if !matches!(
            phase,
            SessionPhase::Preparing | SessionPhase::ReleaseRequired
        ) {
            return Ok(());
        }
        if self.custody_decision(lease)?.disposition == CustodyDisposition::CleanupOnly {
            let running: Vec<_> = self
                .operations
                .values()
                .filter(|op| {
                    op.snapshot.identity.lease == *lease
                        && !op.snapshot.execution_stopped
                        && !self
                            .internal_operations
                            .get(&op.snapshot.identity.operation_id)
                            .is_some_and(|(_, purpose, _)| *purpose == InternalPurpose::Cleanup)
                })
                .map(|op| op.snapshot.identity.clone())
                .collect();
            for identity in running {
                self.cancel(&lease.client_id, &identity, CancelReason::Client, backend)?;
            }
        }
        Ok(())
    }

    pub fn prepared(
        &mut self,
        acquisition: &AcquisitionId,
        lease: &SessionLease,
        capabilities: NexusCapabilities,
        wait_analysis: bool,
    ) -> Result<(), NexusError> {
        if self.custody_decision(lease)?.disposition != CustodyDisposition::Prepare {
            return Err(NexusError::new(
                NexusErrorCode::Cancelled,
                "late ready cannot revive a failed or cancelled parent",
            ));
        }
        let custody = self.custodies.get(&lease.lease_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "prepared custody missing")
        })?;
        let parent = self
            .openings
            .get(&acquisition.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::InvalidIdentity, "prepared parent missing")
            })?;
        if custody.acquisition != *acquisition
            || parent.wait_analysis != wait_analysis
            || !parent
                .acquisitions
                .iter()
                .any(|a| a.identity == *acquisition && a.publish_parent)
            || !matches!(
                acquisition.purpose,
                AcquisitionPurpose::Final | AcquisitionPurpose::InitialRootRetry
            )
        {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "prepared acquisition or analysis requirement mismatch",
            ));
        }
        capabilities.runtime.validate()?;
        let required = [
            InternalPurpose::Runtime,
            InternalPurpose::Guard,
            InternalPurpose::Root,
        ];
        for purpose in required
            .into_iter()
            .chain(wait_analysis.then_some(InternalPurpose::Analysis))
        {
            let succeeded = self.internal_operations.iter().any(|(id, (parent, p, _))| {
                parent == acquisition
                    && *p == purpose
                    && self.operations.get(id).is_some_and(|op| {
                        op.snapshot.status == OperationStatus::Succeeded
                            && op.snapshot.execution_stopped
                    })
            });
            if !succeeded {
                return Err(NexusError::new(
                    NexusErrorCode::InvalidTransition,
                    "required preparation RPC has not succeeded",
                ));
            }
        }
        if self.occupied(lease) {
            return Err(NexusError::new(
                NexusErrorCode::CancelPending,
                "preparation has an operation without stop confirmation",
            ));
        }
        let session = self.sessions.get_mut(&lease.lease_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidLease, "prepared lease missing")
        })?;
        session.capabilities = capabilities;
        session.phase = SessionPhase::Active;
        self.confirm_delivery(DeliveryTarget::Open {
            identity: acquisition.parent.clone(),
        });
        Ok(())
    }
}
