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
    pub(super) fn consume_released(&self, bridge: &super::super::nexus_bridge::NexusBridge) {
        let endpoint = bridge.endpoint();
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
        self.records().retain(|_, db| {
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
            let facts = bridge.owner_release_status(&db.lease);
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
    }

    pub fn owner_status(&self, router: &RouterState) -> Vec<Value> {
        let Some(bridge) = router.nexus_bridge.get() else {
            return Vec::new();
        };
        self.consume_released(bridge);
        let diagnostics = self
            .owner_diagnostics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        diagnostics
            .iter()
            .map(|(lease, path)| {
                let mut facts = bridge.owner_release_status(lease);
                facts["lease"] = json!(lease);
                facts["path"] = json!(path);
                facts["owner_observation_ref"] = facts["watch"].clone();
                facts["cleanup_failures"] = facts["outcome"]["cleanup_failures"].clone();
                facts["save_guard_error"] = json!(bridge.take_release_error(lease));
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
                facts["next_action"] = json!(if facts["owner_pending"] == true {
                    "wait_owner_exit"
                } else {
                    "none"
                });
                facts
            })
            .collect()
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
                .ok_or_else(|| diagnostic("unknown owner observation reference"))?;
            if status["owner_released"] == true || !status["resource_retirement"].is_null() {
                return Ok(status);
            }
            preparation
                .wait(async {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok(())
                })
                .await?;
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
