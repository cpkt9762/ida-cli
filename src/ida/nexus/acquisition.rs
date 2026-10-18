//! Parent admission and exact physical acquisition reservations.
use super::*;

/// Admission belongs to the retained parent. It reserves capacity before SDK
/// acquisition, and is replaced by the exact lease when custody is accepted.
pub(super) struct AcquisitionReservation {
    pub identity: AcquisitionId,
    pub lease: Option<SessionLease>,
    pub closed: bool,
    pub primary: Option<SessionLease>,
    pub publish_parent: bool,
    pub owner_proof: bool,
    pub sdk_finished: bool,
}

impl<C: Clock> NexusSessions<C> {
    /// A transport NotSent or adapter's verified pre-SDK absence owns no
    /// physical slot. Keep the exact parent and acquisition tombstones.
    pub fn acquisition_unstarted(&mut self, id: &AcquisitionId) -> Result<(), NexusError> {
        self.open_progress(&id.parent.client_id, &id.parent)?;
        if self.acquisition_lease(id)?.is_some()
            || self.startup_origins.values().any(|(bound, _)| bound == id)
        {
            return Err(NexusError::new(
                NexusErrorCode::InvalidTransition,
                "unstarted absence conflicts with physical/observation custody",
            ));
        }
        self.finish_acquisition(id)?;
        self.acquisition_absent(id)
    }
    /// Existing reservations carry the verification obligation across root
    /// retries. A final or auxiliary acquisition can never gain it by name.
    pub fn acquisition_verifies_copy(&self, id: &AcquisitionId) -> Result<bool, NexusError> {
        self.open_progress(&id.parent.client_id, &id.parent)?;
        let opening = &self.openings[&id.parent.operation_id];
        let reservation = opening
            .acquisitions
            .iter()
            .find(|a| a.identity == *id)
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "verification provenance acquisition missing",
                )
            })?;
        Ok(!reservation.publish_parent
            && matches!(
                id.purpose,
                AcquisitionPurpose::Verification | AcquisitionPurpose::InitialRootRetry
            )
            && opening.acquisitions.iter().any(|a| {
                a.identity.purpose == AcquisitionPurpose::Verification && !a.publish_parent
            }))
    }
    pub fn acquisition_watch_bound(&self, id: &AcquisitionId, watch: &str) -> bool {
        self.startup_origins
            .get(watch)
            .is_some_and(|(bound, _)| bound == id)
    }
    pub fn finish_acquisition(&mut self, id: &AcquisitionId) -> Result<(), NexusError> {
        self.open_progress(&id.parent.client_id, &id.parent)?;
        let acquisition = self
            .openings
            .get_mut(&id.parent.operation_id)
            .and_then(|o| o.acquisitions.iter_mut().find(|a| a.identity == *id))
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "SDK completion acquisition missing",
                )
            })?;
        acquisition.sdk_finished = true;
        Ok(())
    }
    pub fn acquisition_sdk_finished(&self, id: &AcquisitionId) -> Result<bool, NexusError> {
        self.open_progress(&id.parent.client_id, &id.parent)?;
        self.openings[&id.parent.operation_id]
            .acquisitions
            .iter()
            .find(|a| a.identity == *id)
            .map(|a| a.sdk_finished)
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "SDK completion acquisition missing",
                )
            })
    }
    /// Cancellation ends the caller's preparation wait before a cleanup result
    /// can be known. The retained parent still owns all acquisition obligations.
    pub fn open_wait_ended(&self, parent: &OpenIdentity) -> Result<bool, NexusError> {
        self.open_progress(&parent.client_id, parent)?;
        let opening = &self.openings[&parent.operation_id];
        Ok(opening.cancel_requested
            || opening.uncertain
            || opening.failure.is_some()
            || opening.request.deadline.expired(self.clock.now()))
    }
    /// The adapter already consumed a durable public proof for this exact
    /// acquisition/owner before the SDK callback reached custody. This records
    /// a disposed handle, never a detach ACK or an executable session.
    pub fn adopt_disposed_acquisition(
        &mut self,
        id: &AcquisitionId,
        lease: SessionLease,
    ) -> Result<CustodyDecision, NexusError> {
        self.open_progress(&id.parent.client_id, &id.parent)?;
        if lease.generation == 0
            || lease.client_id != id.parent.client_id
            || self.sessions.contains_key(&lease.lease_id)
        {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "disposed acquisition lease binding conflict",
            ));
        }
        let mut capabilities = self.ready()?.clone();
        capabilities.runtime.ida = Version(0, 0, 0); // Exited before runtime query: explicitly unknown.
        capabilities.methods.clear();
        let opening = self
            .openings
            .get_mut(&id.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::InvalidIdentity, "disposed parent missing")
            })?;
        let latest = opening
            .acquisitions
            .iter()
            .rev()
            .find(|a| a.identity.purpose != AcquisitionPurpose::Auxiliary)
            .map(|a| a.identity.clone());
        let reservation = opening
            .acquisitions
            .iter_mut()
            .find(|a| a.identity == *id && a.lease.is_none())
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "disposed acquisition was not reserved",
                )
            })?;
        reservation.lease = Some(lease.clone());
        reservation.closed = true;
        reservation.owner_proof = true;
        if reservation.publish_parent && latest.as_ref() == Some(id) && opening.acquired.is_none() {
            opening.acquired = Some(lease.clone());
        }
        self.sessions.insert(
            lease.lease_id.clone(),
            SessionSnapshot {
                lease,
                phase: SessionPhase::Released,
                capabilities,
                pending_shutdown: None,
                control_delivery: None,
            },
        );
        Ok(CustodyDecision {
            disposition: CustodyDisposition::CleanupOnly,
            grant_epoch: 0,
        })
    }
    pub(super) fn reserve_physical_slot(
        &self,
        parent: Option<&OpenIdentity>,
    ) -> Result<(), NexusError> {
        let pending = self
            .openings
            .values()
            .flat_map(|o| &o.acquisitions)
            .filter(|a| {
                !a.closed && a.lease.is_none() && !self.acquisition_resources_retired(&a.identity)
            })
            .count();
        let live = self
            .sessions
            .values()
            .filter(|s| {
                s.phase != SessionPhase::Released
                    && !self.resource_retirements.contains_key(&s.lease.lease_id)
            })
            .count();
        if pending + live >= self.capacity {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "tenant physical acquisition capacity reached before SDK send",
            ));
        }
        if let Some(parent) = parent {
            let opening = self.openings.get(&parent.operation_id).ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "acquisition parent missing",
                )
            })?;
            let slots = opening
                .acquisitions
                .iter()
                .filter(|a| {
                    !a.closed
                        && !self.acquisition_resources_retired(&a.identity)
                        && a.lease.as_ref().is_none_or(|l| {
                            self.sessions
                                .get(&l.lease_id)
                                .is_none_or(|s| s.phase != SessionPhase::Released)
                                && !self.resource_retirements.contains_key(&l.lease_id)
                        })
                })
                .count();
            if slots >= 2 {
                return Err(NexusError::new(
                    NexusErrorCode::Busy,
                    "parent already holds two physical acquisition slots",
                ));
            }
        }
        Ok(())
    }

    /// Additional work uses the original retained parent, even after its caller
    /// has ended. Only auxiliary may be admitted after that terminal, and its
    /// acquired lease is irrevocably cleanup-only.
    pub fn reserve_acquisition(
        &mut self,
        parent: &OpenIdentity,
        purpose: AcquisitionPurpose,
    ) -> Result<AcquisitionId, NexusError> {
        self.open_progress(&parent.client_id, parent)?;
        if purpose == AcquisitionPurpose::Auxiliary {
            let opening = &self.openings[&parent.operation_id];
            let ended = opening.acquired.as_ref().is_some_and(|lease| {
                self.resource_retirements.contains_key(&lease.lease_id)
                    || opening
                        .acquisitions
                        .iter()
                        .any(|a| a.lease.as_ref() == Some(lease) && a.owner_proof)
            });
            if ended || (opening.acquired.is_none() && self.startup_resources_retired(parent)) {
                return Err(NexusError::new(
                    NexusErrorCode::InvalidTransition,
                    "parent execution resources ended; only existing file cleanup may continue",
                ));
            }
        }
        if purpose != AcquisitionPurpose::Auxiliary {
            let opening = &self.openings[&parent.operation_id];
            if opening.cancel_requested
                || opening.uncertain
                || opening.failure.is_some()
                || opening.request.deadline.expired(self.clock.now())
            {
                return Err(NexusError::new(
                    NexusErrorCode::Cancelled,
                    "parent no longer permits business acquisition",
                ));
            }
            if purpose != AcquisitionPurpose::Final
                || opening.acquired.is_some()
                || opening.acquisitions.iter().any(|a| !a.closed)
            {
                return Err(NexusError::new(
                    NexusErrorCode::Busy,
                    "serial acquisition predecessor not settled",
                ));
            }
        }
        self.reserve_physical_slot(Some(parent))?;
        let opening = self.openings.get_mut(&parent.operation_id).ok_or_else(|| {
            NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "acquisition parent missing",
            )
        })?;
        // Fixed diagnostic retention is separate from the two live slots.
        if opening.acquisitions.len() >= 7 {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "parent acquisition identity retention full",
            ));
        }
        let ordinal = opening.acquisition_ordinal.checked_add(1).ok_or_else(|| {
            NexusError::new(NexusErrorCode::Busy, "acquisition ordinal exhausted")
        })?;
        let identity = AcquisitionId {
            parent: parent.clone(),
            purpose,
            ordinal,
        };
        opening.acquisition_ordinal = ordinal;
        let primary = (purpose == AcquisitionPurpose::Auxiliary)
            .then(|| opening.acquired.clone())
            .flatten();
        opening.acquisitions.push(AcquisitionReservation {
            identity: identity.clone(),
            lease: None,
            closed: false,
            primary,
            publish_parent: purpose == AcquisitionPurpose::Final,
            owner_proof: false,
            sdk_finished: false,
        });
        Ok(identity)
    }

    pub fn acquisition_settled(
        &mut self,
        id: &AcquisitionId,
        lease: &SessionLease,
    ) -> Result<(), NexusError> {
        if self.resource_retirement(lease)?.is_none()
            && (self.status(&lease.client_id, lease)?.phase != SessionPhase::Released
                || self.occupied(lease))
        {
            return Err(NexusError::new(
                NexusErrorCode::Busy,
                "acquisition resource still live",
            ));
        }
        let opening = self
            .openings
            .get_mut(&id.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::InvalidIdentity, "settled parent missing")
            })?;
        let reservation = opening
            .acquisitions
            .iter_mut()
            .find(|a| a.identity == *id && a.lease.as_ref() == Some(lease))
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "settled acquisition mismatch",
                )
            })?;
        reservation.closed = true;
        Ok(())
    }

    pub fn release_members(&self, lease: &SessionLease) -> Result<Vec<SessionLease>, NexusError> {
        self.authorize(&lease.client_id, lease)?;
        let mut members = vec![lease.clone()];
        for opening in self.openings.values() {
            for reservation in &opening.acquisitions {
                if reservation.primary.as_ref() == Some(lease) {
                    if let Some(member) = &reservation.lease {
                        members.push(member.clone());
                    }
                }
            }
        }
        Ok(members)
    }

    pub fn acquisition_lease(
        &self,
        id: &AcquisitionId,
    ) -> Result<Option<SessionLease>, NexusError> {
        self.open_progress(&id.parent.client_id, &id.parent)?;
        self.openings[&id.parent.operation_id]
            .acquisitions
            .iter()
            .find(|a| a.identity == *id)
            .map(|a| a.lease.clone())
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::InvalidIdentity, "unreserved acquisition")
            })
    }

    pub fn acquisition_absent(&mut self, id: &AcquisitionId) -> Result<(), NexusError> {
        self.open_progress(&id.parent.client_id, &id.parent)?;
        let opening = self
            .openings
            .get_mut(&id.parent.operation_id)
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "absent acquisition parent missing",
                )
            })?;
        let reservation = opening
            .acquisitions
            .iter_mut()
            .find(|a| a.identity == *id && a.lease.is_none())
            .ok_or_else(|| {
                NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "absent acquisition binding mismatch",
                )
            })?;
        reservation.closed = true;
        Ok(())
    }
    pub fn acquisition_closed(&self, id: &AcquisitionId) -> Result<bool, NexusError> {
        self.open_progress(&id.parent.client_id, &id.parent)?;
        self.openings[&id.parent.operation_id]
            .acquisitions
            .iter()
            .find(|a| a.identity == *id)
            .map(|a| a.closed)
            .ok_or_else(|| {
                NexusError::new(NexusErrorCode::InvalidIdentity, "acquisition not reserved")
            })
    }

    fn acquisition_resources_retired(&self, id: &AcquisitionId) -> bool {
        let watches: Vec<_> = self
            .startup_origins
            .iter()
            .filter(|(_, (a, _))| a == id)
            .map(|(w, _)| w)
            .collect();
        !watches.is_empty()
            && watches
                .iter()
                .all(|watch| self.startup_retirements.contains_key(*watch))
    }

    pub fn acquisition_status(&self) -> serde_json::Value {
        let parents: Vec<_> = self.openings.values().map(|opening| {
            let acquisitions: Vec<_> = opening.acquisitions.iter().map(|a| {
                let phase = a.lease.as_ref().and_then(|l| self.sessions.get(&l.lease_id)).map(|s| s.phase);
                let retired = a.lease.as_ref().is_some_and(|l| self.resource_retirements.contains_key(&l.lease_id))
                    || self.acquisition_resources_retired(&a.identity);
                let slot = !a.closed && !retired && phase != Some(SessionPhase::Released);
                let operations: Vec<_> = self.operations.values().filter(|op| a.lease.as_ref() == Some(&op.snapshot.identity.lease))
                    .map(|op| op.snapshot.identity.operation_id.clone()).collect();
                serde_json::json!({"acquisition":a.identity,"lease":a.lease,"primary":a.primary,
                    "phase":phase,"physical_slot":slot,"settled":a.closed,"resource_retired":retired,
                    "publish_parent":a.publish_parent,"public_operation_ids":operations,"public_owner_proof":a.owner_proof,
                    "sdk_acquisition_finished":a.sdk_finished})
            }).collect();
            serde_json::json!({"parent":opening.identity,"cancelled":opening.cancel_requested,
                "failure":opening.failure,"post_exit_resolve_used":opening.post_exit_resolve_used,
                "root_attempts":opening.root_attempts,"acquisitions":acquisitions})
        }).collect();
        serde_json::json!({"tenant_physical_limit":self.capacity,"per_parent_physical_limit":2,"parents":parents})
    }
}
