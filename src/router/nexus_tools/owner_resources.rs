//! Physical owner resources are independent of N1's lease completion.
use super::*;

pub(super) struct OwnerResources {
    pub path: PathBuf,
    pub references: HashMap<
        LeaseId,
        (
            SessionLease,
            Arc<super::super::nexus_bridge::cache_lock::CacheGuard>,
        ),
    >,
}

impl Tools {
    fn auxiliary_guard_needed(
        &self,
        bridge: &super::super::nexus_bridge::NexusBridge,
        primary: &SessionLease,
    ) -> bool {
        let members = match bridge
            .endpoint()
            .transition(|s, _| s.release_members(primary))
        {
            Ok(members) => members,
            Err(error) => {
                tracing::warn!(%error,"auxiliary custody query failed; root protection retained");
                return true;
            }
        };
        members.iter().skip(1).any(|member| {
            let facts = bridge.owner_release_status(member);
            if facts["owner_released"] == true || !facts["resource_retirement"].is_null() {
                return false;
            }
            let detached = bridge
                .endpoint()
                .transition(|s, _| s.status(&member.client_id, member))
                .is_ok_and(|s| s.phase == SessionPhase::Released);
            !detached || facts["outcome"]["ack_kind"] != "nonlast"
        })
    }
    pub(super) fn consume_released(&self, bridge: &super::super::nexus_bridge::NexusBridge) {
        let endpoint = bridge.endpoint();
        self.cleanup_records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, db| {
                let auxiliary = self.auxiliary_guard_needed(bridge, &db.lease);
                if !auxiliary {
                    db._cache_guard = None;
                }
                let facts = bridge.owner_release_status(&db.lease);
                auxiliary
                    || (facts["owner_released"] != true && facts["resource_retirement"].is_null())
            });
        let mut owners = self
            .owner_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        owners.retain(|_, owner| {
            owner.references.retain(|_, (lease, _)| {
                let status = bridge.owner_release_status(lease);
                status["owner_released"] != true && status["resource_retirement"].is_null()
            });
            !owner.references.is_empty()
        });
        let mut released = Vec::new();
        self.records().retain(|handle, db| {
            let retired = endpoint
                .transition(|s, _| s.resource_retirement(&db.lease))
                .is_ok_and(|s| s.is_some());
            let confirmed = retired
                || endpoint
                    .transition(|s, _| s.status(&db.lease.client_id, &db.lease))
                    .is_ok_and(|s| s.phase == SessionPhase::Released);
            if !confirmed {
                return true;
            }
            let auxiliary = self.auxiliary_guard_needed(bridge, &db.lease);
            let facts = bridge.owner_release_status(&db.lease);
            if auxiliary
                || (facts["owner_released"] != true && facts["resource_retirement"].is_null())
            {
                self.cleanup_records
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        db.token.clone(),
                        CleanupReference {
                            handle: handle.clone(),
                            path: db.path.clone(),
                            lease: db.lease.clone(),
                            _cache_guard: auxiliary.then(|| db._cache_guard.clone()),
                        },
                    );
            }
            self.owner_diagnostics
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(db.lease.clone(), db.path.clone());
            // A nonlast ACK removes only this lease's root SH. An absent or
            // partial owner fact never authorizes dropping last/unknown guards.
            if !retired
                && facts["owner_released"] != true
                && facts["outcome"]["ack_kind"] != "nonlast"
            {
                let owner = facts["owner"].clone();
                // Missing identity cannot combine unrelated retained guards.
                let key = if owner.is_object() {
                    owner.to_string()
                } else {
                    format!("unbound:{}", db.lease.lease_id.as_str())
                };
                owners
                    .entry(key)
                    .or_insert_with(|| OwnerResources {
                        path: db.path.clone(),
                        references: HashMap::new(),
                    })
                    .references
                    .insert(
                        db.lease.lease_id.clone(),
                        (db.lease.clone(), db._cache_guard.clone()),
                    );
            }
            released.push(db.lease.clone());
            false
        });
        drop(owners);
        self.operations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|op| !released.contains(&op.lease));
    }

    pub(super) fn owner_pending(&self, lease: &SessionLease) -> bool {
        self.owner_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|r| r.references.contains_key(&lease.lease_id))
            || self
                .cleanup_records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .any(|db| db.lease == *lease && db._cache_guard.is_some())
    }

    pub fn owner_status(&self, router: &RouterState) -> Vec<Value> {
        let Some(bridge) = router.nexus_bridge.get() else {
            return Vec::new();
        };
        self.consume_released(bridge);
        self.owner_diagnostics
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|lease, _| bridge.retains_owner_observation(lease));
        let diagnostics = self
            .owner_diagnostics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut statuses: Vec<_> = diagnostics
            .iter()
            .map(|(lease, path)| {
                let mut facts = bridge.owner_release_status(lease);
                facts["lease"] = json!(lease);
                facts["path"] = json!(path);
                facts["owner_observation_ref"] = facts["watch"].clone();
                facts["cleanup_failures"] = facts["outcome"]["cleanup_failures"].clone();
                facts["save_guard_error"] = json!(bridge.take_release_error(lease));
                facts["owned_members"] = bridge
                    .endpoint()
                    .transition(|s, _| s.release_members(lease))
                    .map_or_else(
                        |error| json!({"error":error.details()}),
                        |members| {
                            json!(members
                                .into_iter()
                                .skip(1)
                                .map(|member| {
                                    let mut details = bridge.owner_release_status(&member);
                                    details["phase"] = bridge
                                        .endpoint()
                                        .transition(|s, _| s.status(&member.client_id, &member))
                                        .map_or_else(
                                            |error| json!({"error":error.details()}),
                                            |status| json!(status.phase),
                                        );
                                    details["lease"] = json!(member);
                                    details
                                })
                                .collect::<Vec<_>>())
                        },
                    );
                facts["lease_detached"] = json!(bridge
                    .endpoint()
                    .transition(|s, _| s.status(&lease.client_id, lease))
                    .is_ok_and(|s| s.phase == SessionPhase::Released));
                facts["root_shared_guard"] = json!(
                    self.owner_pending(lease)
                        || self.records().values().any(|db| db.lease == *lease)
                );
                facts["cache_root"] = json!(crate::idb_store::idb_root());
                facts["resource_disposition"] = json!(if facts["resource_retirement"].is_null() {
                    "Live"
                } else {
                    "RetiredByBootChange"
                });
                facts["next_action"] = json!(if facts["cleanup_state"] == "CleanupBlocked" {
                    "inspect_cleanup_blocked"
                } else if facts["owner_pending"] == true {
                    "wait_owner_exit"
                } else {
                    "none"
                });
                facts
            })
            .collect();
        statuses.extend(
            self.uncertain_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter_map(|opening| {
                    opening.verification.as_ref().map(|verification| {
                        json!({"kind":"opening_cleanup","parent":opening.identity,
                    "verification":verification.status(),"root_shared_guard":true})
                    })
                }),
        );
        statuses
    }

    pub async fn wait_owner_exit(
        &self,
        router: &RouterState,
        reference: &str,
        preparation: Preparation,
    ) -> Result<Value, ToolError> {
        loop {
            preparation.check()?;
            let status = self
                .owner_status(router)
                .into_iter()
                .find(|s| s["owner_observation_ref"] == reference)
                .ok_or_else(|| diagnostic("unknown or retired owner observation reference; closed observation history is bounded to 128; immutable proof files remain in the bridge/target custody journals"))?;
            if status["owner_released"] == true || !status["resource_retirement"].is_null() {
                return Ok(status);
            }
            // This is a read-only observation with no outstanding input job.
            // Report its own deadline, never an unproven native execution.
            tokio::time::sleep_until(
                preparation
                    .deadline
                    .min(Instant::now() + Duration::from_millis(10))
                    .into(),
            )
            .await;
        }
    }

    pub(super) async fn wait_draining(
        &self,
        router: &RouterState,
        path: &Path,
        preparation: &Preparation,
    ) -> Result<(), ToolError> {
        let Some(bridge) = router.nexus_bridge.get() else {
            return Ok(());
        };
        loop {
            self.consume_released(bridge);
            let draining = self
                .owner_resources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .any(|r| r.path == path)
                || self
                    .owner_diagnostics
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|(lease, old_path)| {
                        old_path == path && bridge.resource_retirement_pending(lease)
                    });
            if !draining {
                return Ok(());
            }
            if preparation.check().is_err() {
                return Err(NexusError::new(NexusErrorCode::CancelPending,
                    "owner still draining at this open's original deadline; retained observation remains available").into());
            }
            preparation
                .wait(async {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok(())
                })
                .await?;
        }
    }
}
