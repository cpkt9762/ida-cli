use std::collections::{HashMap, HashSet};

use super::*;

pub(super) struct Operation {
    pub(super) snapshot: OperationSnapshot,
    pub(super) request: AcceptedRequest,
    pub(super) effect: MethodEffect,
}

pub(super) struct Opening {
    identity: OpenIdentity,
    request: AcceptedRequest,
    pub(super) uncertain: bool,
    cancel_requested: bool,
    pub(super) failure: Option<NexusError>,
    acquired: Option<SessionLease>,
}

/// Pure local coordinator. All mutations are serialized by `&mut self`.
/// Responses must carry the complete identity; a request id alone is inadequate.
/// Terminal IDs are retained for this coordinator's lifetime; reaching capacity
/// returns Busy rather than forgetting tombstones or replaying an old request.
pub struct NexusSessions<C> {
    pub(super) clock: C,
    capabilities: Result<NexusCapabilities, NexusError>,
    capacity: usize,
    pub(super) sessions: HashMap<LeaseId, SessionSnapshot>,
    pub(super) deliveries: HashMap<super::delivery::DeliveryKey, super::delivery::DeliveryRecord>,
    pub(super) send_sequence: u64,
    pub(super) generations: HashMap<InstanceId, u64>,
    pub(super) operations: HashMap<OperationId, Operation>,
    pub(super) openings: HashMap<OperationId, Opening>,
    requests: HashSet<RequestId>,
    used_operations: HashSet<OperationId>,
}

impl<C: Clock> NexusSessions<C> {
    /// Capabilities come from an actual readiness handshake in N3. Before then
    /// pass BridgeUnavailable, not the legacy backend's advertised methods.
    pub fn new(
        clock: C,
        capabilities: Result<NexusCapabilities, NexusError>,
        capacity: usize,
    ) -> Self {
        Self {
            clock,
            capabilities,
            capacity,
            sessions: HashMap::new(),
            deliveries: HashMap::new(),
            send_sequence: 0,
            generations: HashMap::new(),
            operations: HashMap::new(),
            openings: HashMap::new(),
            requests: HashSet::new(),
            used_operations: HashSet::new(),
        }
    }

    pub(super) fn ready(&self) -> Result<&NexusCapabilities, NexusError> {
        let caps = self.capabilities.as_ref().map_err(Clone::clone)?;
        caps.runtime.validate()?;
        Ok(caps)
    }

    pub(super) fn reserve(
        &mut self,
        request: &RequestId,
        operation: &OperationId,
    ) -> Result<(), NexusError> {
        if self.requests.contains(request) || self.used_operations.contains(operation) {
            return Err(NexusError::new(
                NexusErrorCode::DuplicateIdentity,
                "request/operation identity cannot be reused",
            ));
        }
        if self.used_operations.len() >= self.capacity {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "Nexus contract retention capacity reached",
            ));
        }
        self.requests.insert(request.clone());
        self.used_operations.insert(operation.clone());
        Ok(())
    }

    pub fn open(
        &mut self,
        client: &ClientId,
        request: AcceptedRequest,
        spec: OpenSpec,
        backend: &mut impl NexusBackend,
    ) -> Result<OpenIdentity, NexusError> {
        self.ready()?;
        if request.method != "open" || spec.path.is_empty() {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "open requires an accepted open request and nonempty path",
            ));
        }
        let remaining_ms = request.remaining(&self.clock)?;
        self.reserve(&request.request_id, &spec.operation_id)?;
        let identity = OpenIdentity {
            client_id: client.clone(),
            task_id: request.task_id.clone(),
            request_id: request.request_id.clone(),
            operation_id: spec.operation_id,
        };
        let command = SessionCommand::Open {
            identity: identity.clone(),
            path: spec.path,
            options: spec.options,
            remaining_ms,
        };
        let attempt = self.begin_delivery(&command, None)?;
        self.openings.insert(
            identity.operation_id.clone(),
            Opening {
                identity: identity.clone(),
                request,
                uncertain: false,
                cancel_requested: false,
                failure: None,
                acquired: None,
            },
        );
        self.send_delivery(command, attempt, backend)?;
        Ok(identity)
    }

    /// A late successful open must still track and release its acquired lease.
    /// The caller must drive ReleaseRequired through release/released, not drop
    /// the handle or pretend the remote lease never existed.
    pub fn opened(
        &mut self,
        identity: &OpenIdentity,
        lease: SessionLease,
        capabilities: NexusCapabilities,
    ) -> Result<OpenDisposition, NexusError> {
        let opening = self.openings.get(&identity.operation_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "unknown open operation")
        })?;
        if &opening.identity != identity || lease.client_id != identity.client_id {
            return Err(NexusError::new(
                NexusErrorCode::InvalidLease,
                "open response identity/owner mismatch",
            ));
        }
        if opening.acquired.is_some() {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "open already reconciled; adapter retains any new unregistered handle for cleanup",
            ));
        }
        let closing = self.sessions.values().any(|session| {
            session.lease.instance_id == lease.instance_id
                && session.lease.generation == lease.generation
                && session.pending_shutdown.is_some()
        });
        let error = if let Some(error) = &opening.failure {
            Some(error.clone())
        } else if opening.uncertain {
            Some(NexusError::new(
                NexusErrorCode::UnknownOutcome,
                "late uncertain open is reconciled for lease cleanup, not replayed as success",
            ))
        } else if opening.request.deadline.expired(self.clock.now()) {
            Some(NexusError::new(
                NexusErrorCode::DeadlineExpired,
                "open completed after total deadline; release acquired lease",
            ))
        } else if opening.cancel_requested {
            Some(NexusError::new(
                NexusErrorCode::Cancelled,
                "open returned after cancellation; release the acquired lease",
            ))
        } else if closing {
            Some(NexusError::new(
                NexusErrorCode::Busy,
                "owner has a pending shutdown; release the new lease",
            ))
        } else {
            capabilities.runtime.validate().err()
        };
        self.register(lease.clone(), capabilities)?;
        if let Some(opening) = self.openings.get_mut(&identity.operation_id) {
            opening.acquired = Some(lease.clone());
        }
        self.confirm_delivery(DeliveryTarget::Open {
            identity: identity.clone(),
        });
        if error.is_some() {
            if let Some(session) = self.sessions.get_mut(&lease.lease_id) {
                session.phase = SessionPhase::ReleaseRequired;
            }
        }
        Ok(if let Some(error) = error {
            OpenDisposition::ReleaseRequired { lease, error }
        } else {
            OpenDisposition::Ready(lease)
        })
    }

    /// Confirmed open failure retains a bounded identity tombstone. Even a
    /// contradictory late acquisition must be reconciled for lease cleanup.
    /// Existing unknown outcomes and their source errors are not rewritten.
    pub fn open_failed(&mut self, identity: &OpenIdentity) -> Result<(), NexusError> {
        let opening = self.openings.get(&identity.operation_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidIdentity, "unknown open operation")
        })?;
        if &opening.identity != identity {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "open failure identity mismatch",
            ));
        }
        if opening.acquired.is_some() {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "open already acquired a tracked lease",
            ));
        }
        if let Some(opening) = self.openings.get_mut(&identity.operation_id) {
            if opening.failure.is_none() {
                opening.failure = Some(NexusError::new(
                    NexusErrorCode::OperationFailed,
                    "open failed; any contradictory late acquisition requires cleanup",
                ));
            }
        }
        self.confirm_delivery(DeliveryTarget::Open {
            identity: identity.clone(),
        });
        Ok(())
    }

    /// A pending acquisition must still be current and uncancelled before send.
    pub(super) fn open_send_eligible(&self, identity: &OpenIdentity) -> Result<(), NexusError> {
        let opening = self
            .openings
            .get(&identity.operation_id)
            .ok_or_else(|| NexusError::new(NexusErrorCode::InvalidIdentity, "unknown opening"))?;
        if &opening.identity != identity {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "opening identity mismatch",
            ));
        }
        if opening.cancel_requested
            || opening.uncertain
            || opening.failure.is_some()
            || opening.acquired.is_some()
            || opening.request.deadline.expired(self.clock.now())
        {
            return Err(NexusError::new(
                NexusErrorCode::Cancelled,
                "opening no longer permits acquisition",
            ));
        }
        Ok(())
    }

    /// There is no public handle yet to cancel an IDA operation. Retain the
    /// opening and its bounded startup wait; a late handle goes to cleanup.
    /// This records intent only and never claims startup/native work stopped.
    pub fn cancel_open(
        &mut self,
        client: &ClientId,
        identity: &OpenIdentity,
    ) -> Result<OperationStatus, NexusError> {
        let opening = self
            .openings
            .get_mut(&identity.operation_id)
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::InvalidIdentity, "unknown open operation")
            })?;
        if &opening.identity != identity || &identity.client_id != client {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "open cancellation identity/owner mismatch",
            ));
        }
        if opening.acquired.is_some() {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "open already reconciled; use the acquired session lifecycle",
            ));
        }
        opening.cancel_requested = true;
        Ok(if let Some(error) = &opening.failure {
            if error.code == NexusErrorCode::UnknownOutcome {
                OperationStatus::UnknownOutcome
            } else {
                OperationStatus::Failed
            }
        } else if opening.uncertain {
            OperationStatus::UnknownOutcome
        } else {
            OperationStatus::CancelRequested
        })
    }

    /// Register only a confirmed public Nexus handle, never a discovered owner
    /// alone. Each logical close_token and warm reference gets its own lease.
    fn register(
        &mut self,
        lease: SessionLease,
        capabilities: NexusCapabilities,
    ) -> Result<(), NexusError> {
        if lease.generation == 0 || self.sessions.contains_key(&lease.lease_id) {
            return Err(NexusError::new(
                NexusErrorCode::InvalidLease,
                "zero generation or reused lease id",
            ));
        }
        if self.sessions.len() >= self.capacity {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "session capacity reached",
            ));
        }
        if self.sessions.values().any(|s| {
            s.lease.instance_id == lease.instance_id
                && s.lease.generation == lease.generation
                && s.lease.owner != lease.owner
        }) {
            return Err(NexusError::new(
                NexusErrorCode::InvalidLease,
                "owner kind changed without a new generation",
            ));
        }
        if let Some(generation) = self.generations.get(&lease.instance_id).copied() {
            if lease.generation < generation {
                return Err(NexusError::new(
                    NexusErrorCode::StaleGeneration,
                    "old owner generation",
                ));
            }
            if lease.generation > generation {
                self.disconnect_generation(&lease.instance_id, generation);
                for operation in self.operations.values_mut() {
                    if operation.snapshot.identity.lease.instance_id == lease.instance_id
                        && operation.snapshot.identity.lease.generation == generation
                    {
                        operation.snapshot.execution_stopped = true;
                    }
                }
            }
        }
        self.generations
            .insert(lease.instance_id.clone(), lease.generation);
        self.sessions.insert(
            lease.lease_id.clone(),
            SessionSnapshot {
                lease,
                phase: SessionPhase::Active,
                capabilities,
                pending_shutdown: None,
                control_delivery: None,
            },
        );
        Ok(())
    }

    pub(super) fn authorize(
        &self,
        client: &ClientId,
        lease: &SessionLease,
    ) -> Result<&SessionSnapshot, NexusError> {
        let session = self
            .sessions
            .get(&lease.lease_id)
            .ok_or_else(|| NexusError::new(NexusErrorCode::InvalidLease, "unknown lease"))?;
        if client != &lease.client_id || &session.lease != lease {
            return Err(NexusError::new(
                NexusErrorCode::InvalidLease,
                "lease does not belong to this authenticated session",
            ));
        }
        Ok(session)
    }

    pub(super) fn active(&self, client: &ClientId, lease: &SessionLease) -> Result<(), NexusError> {
        self.current_owner(client, lease)?;
        let session = self.authorize(client, lease)?;
        if session.phase != SessionPhase::Active {
            return Err(NexusError::new(
                NexusErrorCode::Disconnected,
                "lease is releasing, released or disconnected",
            ));
        }
        Ok(())
    }

    pub(super) fn current_owner(
        &self,
        client: &ClientId,
        lease: &SessionLease,
    ) -> Result<(), NexusError> {
        self.authorize(client, lease)?;
        if self.generations.get(&lease.instance_id) != Some(&lease.generation) {
            return Err(NexusError::new(
                NexusErrorCode::StaleGeneration,
                "owner was replaced",
            ));
        }
        Ok(())
    }

    pub fn status(
        &self,
        client: &ClientId,
        lease: &SessionLease,
    ) -> Result<SessionSnapshot, NexusError> {
        let mut snapshot = self.authorize(client, lease)?.clone();
        snapshot.control_delivery = self.control_delivery(lease);
        Ok(snapshot)
    }

    /// Loss of one public client lease/SSE stream says nothing about siblings.
    pub fn lease_disconnected(&mut self, lease: &SessionLease) -> Result<bool, NexusError> {
        self.authorize(&lease.client_id, lease)?;
        if self.generations.get(&lease.instance_id) != Some(&lease.generation) {
            return Ok(false);
        }
        let session = self
            .sessions
            .get_mut(&lease.lease_id)
            .ok_or_else(|| NexusError::new(NexusErrorCode::InvalidIdentity, "unknown lease"))?;
        if matches!(
            session.phase,
            SessionPhase::Released | SessionPhase::Disconnected
        ) {
            return Ok(false);
        }
        session.phase = SessionPhase::Disconnected;
        for op in self.operations.values_mut() {
            if &op.snapshot.identity.lease == lease && !op.snapshot.status.is_terminal() {
                let sent = !op.snapshot.execution_stopped;
                op.snapshot.status = if sent {
                    OperationStatus::UnknownOutcome
                } else {
                    OperationStatus::Failed
                };
                op.snapshot.error = Some(NexusError::new(
                    if sent { NexusErrorCode::UnknownOutcome } else { NexusErrorCode::Disconnected },
                    "client lease disconnected; effects and stop of dispatched work are unknown; do not replay",
                ));
            }
        }
        Ok(true)
    }

    /// Called only for an actual disconnect event from this exact owner.
    /// A global instance count or a failed health poll is insufficient evidence.
    pub fn disconnected(&mut self, instance: &InstanceId, generation: u64) -> bool {
        if self.generations.get(instance) != Some(&generation) {
            return false;
        }
        self.disconnect_generation(instance, generation);
        true
    }

    fn disconnect_generation(&mut self, instance: &InstanceId, generation: u64) {
        for session in self.sessions.values_mut() {
            if &session.lease.instance_id == instance
                && session.lease.generation == generation
                && session.phase != SessionPhase::Released
            {
                session.phase = SessionPhase::Disconnected;
            }
        }
        for op in self.operations.values_mut() {
            if &op.snapshot.identity.lease.instance_id == instance
                && op.snapshot.identity.lease.generation == generation
                && !op.snapshot.status.is_terminal()
            {
                let sent = !op.snapshot.execution_stopped;
                op.snapshot.status = if sent {
                    OperationStatus::UnknownOutcome
                } else {
                    OperationStatus::Failed
                };
                op.snapshot.error = Some(NexusError::new(
                    if sent {
                        NexusErrorCode::UnknownOutcome
                    } else {
                        NexusErrorCode::Disconnected
                    },
                    if sent {
                        "connection lost after dispatch; effects and stop are unknown; do not replay"
                    } else {
                        "connection lost before dispatch"
                    },
                ));
            }
        }
    }

    fn lease_busy(&self, lease: &SessionLease) -> bool {
        self.operations.values().any(|op| {
            &op.snapshot.identity.lease == lease
                && (!op.snapshot.status.is_terminal() || !op.snapshot.execution_stopped)
        })
    }

    /// Release only this lease; other client and warm leases remain independent.
    pub fn release(
        &mut self,
        client: &ClientId,
        lease: &SessionLease,
        backend: &mut impl NexusBackend,
    ) -> Result<(), NexusError> {
        let phase = self.authorize(client, lease)?.phase;
        if self.generations.get(&lease.instance_id) != Some(&lease.generation) {
            return Err(NexusError::new(
                NexusErrorCode::StaleGeneration,
                "cannot release a replacement owner",
            ));
        }
        if phase == SessionPhase::Released || phase == SessionPhase::ReleaseRequested {
            return Ok(());
        }
        if self.control_delivery(lease).is_some_and(|delivery| {
            matches!(delivery.attempt.target, DeliveryTarget::Release { .. })
                && matches!(
                    delivery.state,
                    DeliveryState::Queued | DeliveryState::Acknowledged | DeliveryState::Uncertain
                )
        }) {
            // A genuine disconnect changes the session phase but does not
            // erase an unresolved release attempt or permit silent replay.
            return Ok(());
        }
        if self.authorize(client, lease)?.pending_shutdown.is_some() {
            return Err(NexusError::new(
                NexusErrorCode::CancelPending,
                "shutdown is still pending confirmation",
            ));
        }
        if self.lease_busy(lease) {
            return Err(NexusError::new(
                NexusErrorCode::CancelPending,
                "lease retained until queued work and stop confirmation resolve",
            ));
        }
        let command = SessionCommand::Release {
            lease: lease.clone(),
        };
        let attempt = self.begin_delivery(&command, Some(phase))?;
        if let Some(session) = self.sessions.get_mut(&lease.lease_id) {
            session.phase = SessionPhase::ReleaseRequested;
        }
        self.send_delivery(command, attempt, backend)
    }

    /// Public handle release completed for this exact send attempt. A late
    /// confirmation after real disconnect may release only this tracked lease.
    pub fn released(&mut self, attempt: &DeliveryAttempt) -> Result<bool, NexusError> {
        let DeliveryTarget::Release { lease } = &attempt.target else {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "not a release attempt",
            ));
        };
        self.current_owner(&lease.client_id, lease)?;
        if !self.live_delivery(attempt)? {
            return Ok(false);
        }
        if let Some(session) = self.sessions.get_mut(&lease.lease_id) {
            if !matches!(
                session.phase,
                SessionPhase::ReleaseRequested | SessionPhase::Disconnected
            ) {
                return Err(NexusError::new(
                    NexusErrorCode::InvalidTransition,
                    "release was not requested",
                ));
            }
            session.phase = SessionPhase::Released;
        }
        self.confirm_delivery(attempt.target.clone());
        Ok(true)
    }

    pub fn shutdown(
        &mut self,
        client: &ClientId,
        lease: &SessionLease,
        spec: ShutdownSpec,
        backend: &mut impl NexusBackend,
    ) -> Result<OperationIdentity, NexusError> {
        self.active(client, lease)?;
        if spec.request.method != "shutdown" {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "shutdown requires an accepted shutdown request",
            ));
        }
        let shared = self.sessions.values().any(|s| {
            s.lease.instance_id == lease.instance_id
                && s.lease.generation == lease.generation
                && s.lease.lease_id != lease.lease_id
                && !matches!(s.phase, SessionPhase::Released | SessionPhase::Disconnected)
        });
        if lease.owner != OwnerKind::Managed
            || shared
            || self.lease_busy(lease)
            || self.occupied(lease)
        {
            return Err(NexusError::new(
                NexusErrorCode::ExclusiveCloseRequired,
                "shutdown requires an idle exclusively leased managed worker; GUI is never closed",
            ));
        }
        let remaining_ms = spec.request.remaining(&self.clock)?;
        self.reserve(&spec.request.request_id, &spec.operation_id)?;
        let identity = OperationIdentity {
            task_id: spec.request.task_id,
            request_id: spec.request.request_id,
            operation_id: spec.operation_id,
            lease: lease.clone(),
        };
        let command = SessionCommand::Shutdown {
            identity: identity.clone(),
            save: spec.save,
            require_exclusive: true,
            remaining_ms,
        };
        let attempt = self.begin_delivery(&command, Some(SessionPhase::Active))?;
        if let Some(session) = self.sessions.get_mut(&lease.lease_id) {
            session.pending_shutdown = Some(identity.clone());
            session.phase = SessionPhase::ShutdownRequested;
        }
        self.send_delivery(command, attempt, backend)?;
        Ok(identity)
    }

    /// Public shutdown rejection must match the current exact send attempt.
    /// Unlike uncertainty, a definitive rejection permits explicit new work.
    pub fn shutdown_rejected(&mut self, attempt: &DeliveryAttempt) -> Result<bool, NexusError> {
        self.finish_shutdown(attempt, false)
    }

    /// Only the public shutdown call's successful return proves owner shutdown.
    pub fn shutdown_completed(&mut self, attempt: &DeliveryAttempt) -> Result<bool, NexusError> {
        self.finish_shutdown(attempt, true)
    }

    fn finish_shutdown(
        &mut self,
        attempt: &DeliveryAttempt,
        completed: bool,
    ) -> Result<bool, NexusError> {
        let DeliveryTarget::Shutdown { identity } = &attempt.target else {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "not a shutdown attempt",
            ));
        };
        let lease = &identity.lease;
        self.current_owner(&lease.client_id, lease)?;
        if !self.live_delivery(attempt)? {
            return Ok(false);
        }
        let session = self.sessions.get_mut(&lease.lease_id).ok_or_else(|| {
            NexusError::new(NexusErrorCode::InvalidLease, "unknown shutdown lease")
        })?;
        if session.pending_shutdown.as_ref() != Some(identity)
            || !matches!(
                session.phase,
                SessionPhase::ShutdownRequested | SessionPhase::Disconnected
            )
        {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "shutdown was not requested",
            ));
        }
        if completed {
            session.phase = SessionPhase::Released;
        } else if session.phase != SessionPhase::Disconnected {
            session.phase = SessionPhase::Active;
        }
        session.pending_shutdown = None;
        self.confirm_delivery(attempt.target.clone());
        Ok(true)
    }
}
