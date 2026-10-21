//! Early resource handoff and exact preparation grants, independent of pending commands.
use super::*;
use std::path::Path;

#[derive(Clone)]
pub(super) struct Resource {
    pub acquisition: AcquisitionId,
    pub lease: SessionLease,
    pub owner: Value,
    pub watch: String,
    pub receipt: Value,
    pub target: Value,
    pub coord_key: Value,
    pub proof: Option<Value>,
    pub consumer: Option<Value>,
    pub nonlast_transfer: Option<Value>,
    pub bridge_proof_ack: bool,
    pub backup: Option<Value>,
    pub origin_binding: Value,
    pub cache_guard: Arc<Mutex<Option<Arc<cache_lock::CacheGuard>>>>,
}

/// Both facts meet under startups -> N1, the same order used to register a
/// watch. No snapshot crosses these locks and no synchronous guard spans await.
fn settle_unleased_acquisition(
    state: &State,
    id: &AcquisitionId,
    sdk_finished: bool,
) -> anyhow::Result<bool> {
    join_acquisition_completion(&state.endpoint, &state.startups, id, sdk_finished)
}
fn join_acquisition_completion(
    endpoint: &NexusEndpoint,
    startups: &Mutex<HashMap<String, Value>>,
    id: &AcquisitionId,
    sdk_finished: bool,
) -> anyhow::Result<bool> {
    let startups = startups.lock().unwrap_or_else(|e| e.into_inner());
    let pending = startups
        .values()
        .any(|item| item["acquisition"] == json!(id));
    Ok(endpoint.transition(|s, _| {
        if sdk_finished {
            s.finish_acquisition(id)?;
        }
        if !pending && s.acquisition_sdk_finished(id)? && s.acquisition_lease(id)?.is_none() {
            s.acquisition_absent(id)?;
        }
        s.acquisition_closed(id)
    })?)
}

/// Resource proof and command delivery have independent lifetimes. The public
/// proof tombstone survives retirement ACK removal; only its exact N1 lease and
/// acquisition can authorize a late command observation, never another attach.
fn release_observation_binding(
    state: &State,
    event: &Value,
    lease: &SessionLease,
) -> anyhow::Result<Value> {
    let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
    let resource = state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&lease.lease_id)
        .cloned();
    let binding = if let Some(resource) = resource {
        anyhow::ensure!(
            resource.lease == *lease,
            "release observation lease mismatch"
        );
        json!({"owner":resource.owner,"watch":resource.watch,"acquisition":resource.acquisition,
            "target":resource.target,"coord_key":resource.coord_key,
            "subscription_epoch":resource.receipt["record"]["subscription_epoch"]})
    } else {
        let proof = state
            .owner_proofs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&lease.lease_id)
            .filter(|(exact, _)| exact == lease)
            .map(|(_, proof)| proof.clone())
            .ok_or_else(|| {
                anyhow::anyhow!("release observation has no exact public proof custody")
            })?;
        state.endpoint.transition(|s, _| {
            if s.acquisition_lease(&acquisition)?.as_ref() != Some(lease)
                || !s.acquisition_closed(&acquisition)?
                || s.resource_retirement(lease)?.is_some()
            {
                return Err(invalid("release observation resource closure mismatch"));
            }
            Ok::<_, NexusError>(())
        })?;
        let mut binding = proof["record"].clone();
        binding["target"] = binding["owner"]["canonical_idb_path"].clone();
        binding
    };
    anyhow::ensure!(
        binding["owner"] == event["owner"]
            && binding["watch"] == event["watch"]
            && binding["acquisition"] == json!(acquisition),
        "release observation physical identity mismatch"
    );
    Ok(binding)
}

async fn retain_observation(
    event: &Value,
    state: &Arc<State>,
    helper: &helper::Helper,
    action: &str,
) -> anyhow::Result<()> {
    let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
    state
        .endpoint
        .transition(|s, _| s.open_progress(&acquisition.parent.client_id, &acquisition.parent))?;
    let watch = event["watch"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("startup watch missing"))?;
    let status = helper.call(json!({"kind":"lookup", "watch":watch})).await?;
    anyhow::ensure!(
        status["state_root"] == helper.state_root,
        "startup state root mismatch"
    );
    let item = status
        .get("item")
        .filter(|item| !item.is_null())
        .ok_or_else(|| anyhow::anyhow!("startup not signed by helper"))?;
    anyhow::ensure!(
        item["launch"] == event["launch"]
            && (action != "observe" || item["owner"] == event["owner"])
            && item["acquisition"] == event["acquisition"]
            && item["target"] == event["target"]
            && item["coord_key"] == event["coord_key"],
        "startup binding mismatch"
    );
    let expected = if action == "spawned" {
        &item["spawned"]
    } else {
        &item["receipt"]
    };
    anyhow::ensure!(
        *expected == event["receipt"],
        "startup durable receipt mismatch"
    );
    let verified = helper.journal(json!({"action":if action == "observe" {"verify_observe"} else {"verify_launch"}, "target":event["target"],
                "coord_key":event["coord_key"], "watch":watch,"receipt":event["receipt"],
                "launch":event["launch"],"owner":event["owner"],"acquisition":event["acquisition"]})).await?;
    let mut startups = state.startups.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = startups.get(watch) {
        anyhow::ensure!(
            old["launch"] == event["launch"]
                && old["owner"] == event["owner"]
                && old["acquisition"] == event["acquisition"],
            "conflicting startup responsibility"
        );
    } else {
        anyhow::ensure!(
            action != "spawned" && startups.len() < state.open_reply_capacity,
            "startup/observation capacity full or unreserved spawn"
        );
    }
    let mut retained = event.clone();
    retained["origin_binding"] = verified["origin_binding"].clone();
    let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
    state.endpoint.transition(|s, _| {
        s.bind_startup_origin(&acquisition, watch, verified["origin_binding"].clone())
    })?;
    startups.insert(watch.into(), retained);
    Ok(())
}

pub(super) async fn receive(event: &Value, state: &Arc<State>) -> anyhow::Result<Value> {
    let nonce = event["nonce"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("custody nonce missing"))?;
    anyhow::ensure!(
        nonce.len() <= 128 && !nonce.is_empty(),
        "invalid custody nonce"
    );
    let action = event["action"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("custody action missing"))?;
    let helper = state
        .helper
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("mandatory proof helper unavailable"))?;
    let mut response = json!({"custody_reply":nonce,"ok":true});
    match action {
        "file_job_prepare" => {
            response["job"] = helper.prepare_file_job(event.clone()).await?;
        }
        "acquisition_finished" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let watches: Vec<String> = decode(event["watches"].clone())?;
            for watch in &watches {
                if !state.endpoint.transition(|s, _| {
                    Ok::<_, NexusError>(s.acquisition_watch_bound(&acquisition, watch))
                })? {
                    // A signed helper watch can precede a failed/lost stage
                    // handoff. Recover only that exact durable responsibility;
                    // this grants no SDK call, retry or owner-release authority.
                    let found = helper.call(json!({"kind":"lookup", "watch":watch})).await?;
                    let item = &found["item"];
                    anyhow::ensure!(item["watch"] == *watch && item["acquisition"] == json!(acquisition),
                        "SDK completion lacks exact signed helper custody; restore target storage and reconnect the same helper incarnation");
                    let binding = json!({"watch":watch,"acquisition":acquisition,"owner":item["owner"],
                        "launch":item["launch"],"target":item["target"],"coord_key":item["coord_key"],"receipt":item["receipt"]});
                    retain_observation(
                        &binding,
                        state,
                        helper,
                        if item["owner"].is_object() {
                            "observe"
                        } else {
                            "launch"
                        },
                    )
                    .await?;
                }
            }
            #[cfg(feature = "nexus-test-support")]
            {
                let pending = state
                    .startups
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .any(|v| v["acquisition"] == json!(acquisition));
                super::test_barriers::asynchronous(
                    "sdk_pending",
                    json!({"acquisition":acquisition,"pending":pending}),
                )
                .await?;
            }
            settle_unleased_acquisition(state, &acquisition, true)?;
        }
        "acquisition_status" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            response["settled"] = json!(state
                .endpoint
                .transition(|s, _| s.acquisition_closed(&acquisition))?);
        }
        "auxiliary_failed" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let lease: SessionLease = decode(event["lease"].clone())?;
            let error: NexusError = decode(event["error"].clone())?;
            anyhow::ensure!(
                state
                    .endpoint
                    .transition(|s, _| s.acquisition_lease(&acquisition))?
                    .as_ref()
                    == Some(&lease),
                "auxiliary failure parent mismatch"
            );
            let mut facts = state
                .release_facts
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let entry = facts
                .entry(lease.lease_id.clone())
                .or_insert_with(|| (lease.clone(), json!({})));
            anyhow::ensure!(entry.0 == lease, "auxiliary failure lease mismatch");
            if entry.1["auxiliary_error"].is_null() {
                entry.1["auxiliary_error"] = json!(error);
            }
        }
        "unstarted_acquisition" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            anyhow::ensure!(
                event["sdk_entered"] == false && event["file_obligation"] == false,
                "unstarted acquisition requires explicit no-SDK and no-file-obligation evidence"
            );
            anyhow::ensure!(
                state
                    .startups
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .all(|item| item["acquisition"] != event["acquisition"])
                    && state
                        .custody_resources
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .values()
                        .all(|r| r.acquisition != acquisition),
                "unstarted acquisition already has physical/observation responsibility"
            );
            state
                .endpoint
                .transition(|s, _| s.acquisition_unstarted(&acquisition))?;
            helper
                .call(json!({"kind":"retire_parent","parent":acquisition.parent}))
                .await?;
        }
        "reserve_acquisition" => {
            let parent: OpenIdentity = decode(event["parent"].clone())?;
            let purpose: AcquisitionPurpose = decode(event["purpose"].clone())?;
            response["acquisition"] = serde_json::to_value(
                state
                    .endpoint
                    .transition(|s, _| s.reserve_acquisition(&parent, purpose))?,
            )?;
        }
        "post_exit_resolve" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let watches = event["watches"]
                .as_array()
                .filter(|w| !w.is_empty() && w.len() <= 2)
                .ok_or_else(|| anyhow::anyhow!("post-exit watches missing"))?;
            let attempts = event["attempts"]
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 2)
                .ok_or_else(|| anyhow::anyhow!("post-exit attach attempts missing"))?;
            let mut owners = Vec::new();
            for watch in watches {
                let status = helper.call(json!({"kind":"lookup", "watch":watch})).await?;
                anyhow::ensure!(
                    status["state_root"] == helper.state_root,
                    "post-exit root mismatch"
                );
                let cached = state
                    .startup_proofs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(
                        watch
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("post-exit watch type"))?,
                    )
                    .cloned();
                let item = if status["item"].is_null() {
                    cached.unwrap_or(Value::Null)
                } else {
                    status["item"].clone()
                };
                if item["proof"].is_null() {
                    response["ready"] = json!(false);
                    return Ok(response);
                }
                anyhow::ensure!(
                    status["state_root"] == helper.state_root
                        && item["acquisition"] == event["acquisition"]
                        && item["proof"]["record"]["evidence_type"] == "public_owner_lifetime",
                    "post-exit exact durable public proof missing"
                );
                anyhow::ensure!(
                    item["attach_attempts"]
                        .as_object()
                        .is_some_and(|a| !a.is_empty()
                            && a.values()
                                .all(|v| v["state"] == "not_sent" || v["state"] == "lease_absent")),
                    "post-exit unknown or acquired attach cannot be replayed"
                );
                if !status["item"].is_null() {
                    helper
                        .journal(json!({"action":"proof", "target":item["target"],
                        "coord_key":item["coord_key"],"watch":watch,"proof":item["proof"]}))
                        .await?;
                }
                owners.push(item["owner"].clone());
            }
            anyhow::ensure!(
                attempts.iter().all(|a| owners.contains(&a["owner"])
                    && (a["failure_kind"] == "not_sent" || a["failure_kind"] == "lease_absent")),
                "post-exit attempt owner mismatch"
            );
            state
                .endpoint
                .transition(|s, _| s.consume_post_exit_resolve(&acquisition.parent))?;
            response["ready"] = json!(true);
        }
        "release_observation" => {
            let lease: SessionLease = decode(event["lease"].clone())?;
            let attempt: DeliveryAttempt = decode(event["attempt"].clone())?;
            anyhow::ensure!(
                attempt.target
                    == DeliveryTarget::Release {
                        lease: lease.clone()
                    },
                "release observation target mismatch"
            );
            state
                .endpoint
                .transition(|s, _| s.delivery_status(&lease.client_id, &attempt))?;
            let binding = release_observation_binding(state, event, &lease)?;
            helper
                .journal(json!({"action":action, "target":binding["target"],
                "coord_key":binding["coord_key"],"lease":lease,"watch":event["watch"],"acquisition":event["acquisition"],
                "epoch":binding["subscription_epoch"],"owner":event["owner"],
                "attempt":attempt,"observation_id":nonce,"outcome":event["outcome"]}))
                .await?;
            state.remember_save_guard_error(&lease, &event["outcome"]["save_guard_error"])?;
            let mut facts = state
                .release_facts
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let entry = facts.entry(lease.lease_id.clone()).or_insert_with(|| {
                (
                    lease,
                    json!({"owner":event["owner"],"watch":event["watch"]}),
                )
            });
            entry.1["preflight"] = event["outcome"].clone();
            if entry.1["original_preflight"].is_null() {
                entry.1["original_preflight"] = event["outcome"].clone();
            }
        }
        "no_attach" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let watch = event["watch"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("no-attach watch missing"))?;
            let old = state
                .startups
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(watch)
                .cloned();
            if let Some(old) = old {
                anyhow::ensure!(
                    old["acquisition"] == event["acquisition"] && old["owner"] == event["owner"],
                    "no-attach identity mismatch"
                );
                let status = helper.call(json!({"kind":"lookup","watch":watch})).await?;
                anyhow::ensure!(
                    status["item"]["consumer"] == event["consumer"]
                        && status["item"]["no_attach"] == true,
                    "no-attach helper closure missing"
                );
                helper.journal(json!({"action":"no_attach","watch":watch,"target":event["target"],
                    "coord_key":event["coord_key"],"consumer":event["consumer"],"bridge_consumer":event["bridge_consumer"],
                    "custody_accepted":true})).await?;
                // The verified target receipt must survive helper retirement,
                // including a later writer failure or lost custody reply.
                {
                    let mut startups = state.startups.lock().unwrap_or_else(|e| e.into_inner());
                    let retained = startups
                        .get_mut(watch)
                        .ok_or_else(|| anyhow::anyhow!("no-attach responsibility disappeared"))?;
                    retained["pending_no_attach"] = event.clone();
                }
                finish_no_attach(state, helper, event).await?;
            } else {
                anyhow::ensure!(
                    state
                        .retired_open_resources
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains(&acquisition.parent.operation_id),
                    "unknown no-attach identity"
                );
            }
            helper
                .call(json!({"kind":"retire_parent","parent":acquisition.parent}))
                .await?;
            settle_unleased_acquisition(state, &acquisition, false)?;
        }
        "observe" | "launch" | "spawned" => {
            retain_observation(event, state, helper, action).await?;
        }
        "acquired" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let lease: SessionLease = decode(event["lease"].clone())?;
            let watch = event["watch"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("watch missing"))?;
            anyhow::ensure!(
                lease.client_id == acquisition.parent.client_id
                    && event["owner"]["record_id"].as_str() == Some(lease.instance_id.as_str())
                    && (lease.owner == OwnerKind::Gui) == (event["owner"]["backend"] == "gui"),
                "acquired complete lease binding mismatch"
            );
            let registered = state
                .endpoint
                .transition(|s, _| s.acquisition_lease(&acquisition))?;
            if registered.as_ref() == Some(&lease) {
                let status = state
                    .endpoint
                    .transition(|s, _| s.status(&lease.client_id, &lease))?;
                let retired = state
                    .endpoint
                    .transition(|s, _| s.resource_retirement(&lease))?;
                if status.phase == SessionPhase::Released || retired.is_some() {
                    let proof = state
                        .owner_proofs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&lease.lease_id)
                        .map(|(_, p)| p.clone());
                    let binding = retired
                        .clone()
                        .or_else(|| proof.as_ref().map(|p| p["record"].clone()))
                        .unwrap_or(Value::Null);
                    anyhow::ensure!(
                        binding["owner"] == event["owner"]
                            && binding["watch"] == event["watch"]
                            && binding["acquisition"] == event["acquisition"],
                        "settled custody owner binding mismatch"
                    );
                    response["decision"] = json!(state
                        .endpoint
                        .transition(|s, _| s.custody_decision(&lease))?);
                    response["settled"] = json!(!state
                        .custody_resources
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains_key(&lease.lease_id));
                    return Ok(response);
                }
            }
            if registered.is_none() {
                let cached = state
                    .startup_proofs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(watch)
                    .cloned();
                if let Some(cached) = cached {
                    anyhow::ensure!(
                        cached["owner"] == event["owner"]
                            && cached["acquisition"] == event["acquisition"]
                            && cached["receipt"] == event["receipt"]
                            && cached["target"] == event["target"]
                            && cached["coord_key"] == event["coord_key"]
                            && cached["proof"]["record"]["evidence_type"]
                                == "public_owner_lifetime",
                        "late acquired callback does not match the already consumed public proof"
                    );
                    response["decision"] = json!(state.endpoint.transition(
                        |s, _| s.adopt_disposed_acquisition(&acquisition, lease.clone())
                    )?);
                    state
                        .owner_proofs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(lease.lease_id.clone(), (lease, cached["proof"].clone()));
                    response["settled"] = json!(true);
                    return Ok(response);
                }
            }
            let status = helper.call(json!({"kind":"lookup", "watch":watch})).await?;
            anyhow::ensure!(
                status["state_root"] == helper.state_root
                    && event["owner"]["state_root"] == helper.state_root,
                "custody state root mismatch"
            );
            let observation = status
                .get("item")
                .filter(|item| !item.is_null())
                .ok_or_else(|| anyhow::anyhow!("helper did not subscribe this owner"))?;
            anyhow::ensure!(
                observation["owner"] == event["owner"]
                    && observation["acquisition"] == event["acquisition"]
                    && observation["receipt"] == event["receipt"],
                "helper subscription binding mismatch"
            );
            anyhow::ensure!(
                event["owner"]["record_id"].as_str() == Some(lease.instance_id.as_str()),
                "custody owner differs from lease"
            );
            let reserved = state
                .endpoint
                .transition(|s, _| s.acquisition_lease(&acquisition))?;
            anyhow::ensure!(
                lease.client_id == acquisition.parent.client_id
                    && reserved.as_ref().is_none_or(|old| old == &lease),
                "acquisition reservation binding mismatch"
            );
            let mut verify = event.clone();
            verify["action"] = json!("verify_adopt");
            let verified = helper.journal(verify).await?;
            let cache_guard = {
                use std::os::unix::fs::MetadataExt;
                let root = if event["coord_key"]["kind"] == "generation" {
                    let target = Path::new(
                        event["target"]
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("target missing"))?,
                    );
                    let root = target
                        .parent()
                        .and_then(Path::parent)
                        .and_then(Path::parent)
                        .ok_or_else(|| anyhow::anyhow!("managed target root missing"))?;
                    let metadata = std::fs::symlink_metadata(root)?;
                    anyhow::ensure!(
                        metadata.is_dir()
                            && verified["native_coord_key"]["kind"] == "generation"
                            && verified["native_coord_key"]["root"]
                                == json!([metadata.dev(), metadata.ino(), metadata.uid()]),
                        "actual cache root identity mismatch"
                    );
                    root.to_path_buf()
                } else {
                    state.cache_root.clone()
                };
                Some(
                    cache_lock::acquire(
                        &root,
                        &crate::preprocess::Preparation::new(Duration::from_secs(2)),
                    )
                    .await?,
                )
            };
            {
                let _ordered = state.callbacks.lock().unwrap_or_else(|e| e.into_inner());
                let mut resources = state
                    .custody_resources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                anyhow::ensure!(
                    resources.contains_key(&lease.lease_id)
                        || resources.len() < state.open_reply_capacity,
                    "custody resource capacity exceeded; bridge retains resource"
                );
                let decision = state
                    .endpoint
                    .transition(|s, _| s.acquired(&acquisition, lease.clone(), true))?;
                state.endpoint.transition(|s, _| {
                    s.bind_resource_origin(&lease, verified["origin_binding"].clone())
                })?;
                let resource = Resource {
                    acquisition,
                    lease: lease.clone(),
                    owner: event["owner"].clone(),
                    watch: watch.into(),
                    receipt: event["receipt"].clone(),
                    target: event["target"].clone(),
                    coord_key: event["coord_key"].clone(),
                    proof: None,
                    consumer: None,
                    nonlast_transfer: None,
                    bridge_proof_ack: false,
                    backup: None,
                    origin_binding: verified["origin_binding"].clone(),
                    cache_guard: Arc::new(Mutex::new(cache_guard)),
                };
                if let Some(old) = resources.get(&lease.lease_id) {
                    anyhow::ensure!(
                        old.acquisition == resource.acquisition
                            && old.lease == lease
                            && old.owner == resource.owner
                            && old.watch == resource.watch
                            && old.receipt == resource.receipt,
                        "conflicting retained custody"
                    );
                } else {
                    resources.insert(lease.lease_id.clone(), resource);
                }
                state
                    .leases
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(lease.lease_id.clone(), lease);
                response["decision"] = serde_json::to_value(decision)?;
            }
        }
        "rpc" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let identity: OperationIdentity = decode(event["identity"].clone())?;
            let purpose: InternalPurpose = decode(event["purpose"].clone())?;
            let epoch = event["grant_epoch"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("grant epoch missing"))?;
            let resource = state
                .custody_resources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&identity.lease.lease_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("RPC custody missing"))?;
            anyhow::ensure!(
                resource.acquisition == acquisition && resource.lease == identity.lease,
                "RPC acquisition mismatch"
            );
            let status = helper
                .call(json!({"kind":"lookup", "watch":resource.watch}))
                .await?;
            anyhow::ensure!(
                status["state_root"] == helper.state_root
                    && status["item"]["owner"] == resource.owner
                    && status["item"].get("observation_error").is_none(),
                "owner helper observation unavailable"
            );
            let _ordered = state.callbacks.lock().unwrap_or_else(|e| e.into_inner());
            let (attempt, remaining) = state
                .endpoint
                .transition(|s, _| s.internal_grant(&acquisition, identity, purpose, epoch))?;
            state
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    attempt.sequence.get(),
                    Pending {
                        attempt: attempt.clone(),
                        granted: true,
                        uncertain: false,
                        stopped: false,
                        open_disconnected: None,
                    },
                );
            response["attempt"] = serde_json::to_value(attempt)?;
            response["remaining_ms"] = serde_json::to_value(remaining)?;
        }
        "cleanup" | "failed" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let lease: SessionLease = decode(event["lease"].clone())?;
            let resource = state
                .custody_resources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&lease.lease_id)
                .cloned();
            anyhow::ensure!(
                resource
                    .as_ref()
                    .is_some_and(|r| r.acquisition == acquisition && r.lease == lease)
                    || (resource.is_none()
                        && state
                            .endpoint
                            .transition(|s, _| s.acquisition_lease(&acquisition))?
                            .as_ref()
                            == Some(&lease)),
                "cleanup acquisition mismatch"
            );
            state.endpoint.transition(|s, _| {
                if action == "failed" {
                    s.preparing_failed(&acquisition, decode(event["error"].clone())?)?;
                }
                s.acquisition_cleanup(&acquisition, &lease)
            })?;
            response["decision"] = serde_json::to_value(
                state
                    .endpoint
                    .transition(|s, _| s.custody_decision(&lease))?,
            )?;
            if action == "failed" {
                let attempt: DeliveryAttempt = decode(event["attempt"].clone())?;
                anyhow::ensure!(
                    attempt.target
                        == DeliveryTarget::Open {
                            identity: acquisition.parent.clone()
                        },
                    "failed preparation outer correlation"
                );
                state.emit(json!({"event":"failed", "attempt":attempt, "lease":lease,"error":event["error"]}));
            }
        }
        "ready" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let lease: SessionLease = decode(event["lease"].clone())?;
            let caps: NexusCapabilities = decode(event["capabilities"].clone())?;
            let resource = state
                .custody_resources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&lease.lease_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("ready custody missing"))?;
            anyhow::ensure!(
                resource.acquisition == acquisition
                    && resource.lease == lease
                    && event["idb_path"] == resource.owner["canonical_idb_path"]
                    && event["pid"] == resource.owner["pid"],
                "ready physical resource mismatch"
            );
            let attempt: DeliveryAttempt = decode(event["attempt"].clone())?;
            anyhow::ensure!(
                attempt.target
                    == DeliveryTarget::Open {
                        identity: acquisition.parent.clone()
                    },
                "ready outer correlation"
            );
            state.endpoint.transition(|s, _| {
                s.prepared(&acquisition, &lease, caps, event["wait_analysis"] == true)
            })?;
            state
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&attempt.sequence.get());
            let mut ready = event.clone();
            ready["event"] = json!("opened");
            state.emit(ready);
        }
        "root_retry" => {
            let parent: OpenIdentity = decode(event["parent"].clone())?;
            let predecessor: AcquisitionId = decode(event["predecessor"].clone())?;
            response["acquisition"] = serde_json::to_value(
                state
                    .endpoint
                    .transition(|s, _| s.reserve_root_retry(&parent, &predecessor))?,
            )?;
        }
        "cleanup_status" => {
            let lease: SessionLease = decode(event["lease"].clone())?;
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let status = {
                let resources = state
                    .custody_resources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(resource) = resources.get(&lease.lease_id) {
                    anyhow::ensure!(
                        resource.lease == lease && resource.acquisition == acquisition,
                        "cleanup status binding mismatch"
                    );
                } else {
                    let acquired = state
                        .endpoint
                        .transition(|s, _| s.acquisition_lease(&acquisition))?;
                    anyhow::ensure!(
                        acquired.as_ref() == Some(&lease),
                        "settled cleanup parent mismatch"
                    );
                }
                state
                    .endpoint
                    .transition(|s, _| s.status(&lease.client_id, &lease))?
            };
            let retired = state
                .endpoint
                .transition(|s, _| s.resource_retirement(&lease))?;
            let public = state
                .owner_proofs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&lease.lease_id)
                .is_some_and(|(l, _)| *l == lease);
            let facts = state
                .release_facts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&lease.lease_id)
                .filter(|(l, _)| *l == lease)
                .map(|(_, facts)| facts.clone())
                .unwrap_or(Value::Null);
            let ack = facts["outcome"]["lease_released"] == true;
            let terminal = status.control_delivery.as_ref().is_none_or(|d| {
                matches!(
                    d.state,
                    DeliveryState::Confirmed | DeliveryState::NotSent | DeliveryState::Uncertain
                )
            });
            // Public lifetime ends the physical resource, but its independent
            // helper retirement may still be in flight. Do not free the serial
            // acquisition slot until every predecessor observer for this exact
            // parent has finished: a late retire_parent could otherwise erase
            // the successor's newly reserved helper budget before subscribe.
            // This is local custody closure, not a retirement ACK or a new
            // lifetime/command result, and it never authorizes another detach.
            let observers_closed = state
                .custody_resources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .all(|r| r.acquisition.parent != acquisition.parent)
                && state
                    .startups
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .all(|item| item["acquisition"]["parent"] != json!(acquisition.parent));
            let ready = (event["owner_required"] == false || observers_closed)
                && (retired.is_some()
                    || (status.phase == SessionPhase::Released
                        && (event["owner_required"] == false || public)
                        && terminal
                        && (event["require_ack"] != true || ack)));
            response["ready"] = json!(ready);
            response["parent_terminal"] = json!(state
                .endpoint
                .transition(|s, _| s.open_wait_ended(&acquisition.parent))?);
            response["resource_retirement"] = json!(retired);
            response["outcome"] = facts["outcome"].clone();
            response["command_error"] = facts["command_error"].clone();
            if ready {
                if let Some(recovery_id) = event["recovery_id"].as_str() {
                    anyhow::ensure!(
                        recovery_id.len() == 32
                            && recovery_id
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                        "invalid exact file RecoveryId"
                    );
                    if retired.is_none() {
                        anyhow::ensure!(
                            public && ack,
                            "file recovery requires original ACK and public proof"
                        );
                        let attempt: DeliveryAttempt = decode(facts["attempt"].clone())?;
                        anyhow::ensure!(
                            attempt.target
                                == DeliveryTarget::Release {
                                    lease: lease.clone()
                                },
                            "file recovery release attempt mismatch"
                        );
                        state.endpoint.transition(|s, _| {
                            let delivery = s.delivery_status(&lease.client_id, &attempt)?;
                            if delivery.state != DeliveryState::Confirmed {
                                return Err(invalid("file recovery ACK delivery is not confirmed"));
                            }
                            Ok::<_, NexusError>(())
                        })?;
                        let proof = state
                            .owner_proofs
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&lease.lease_id)
                            .filter(|(exact, _)| exact == &lease)
                            .map(|(_, value)| value.clone())
                            .ok_or_else(|| {
                                anyhow::anyhow!("file recovery exact public proof missing")
                            })?;
                        anyhow::ensure!(
                            proof["record"]["acquisition"] == json!(acquisition),
                            "file recovery public proof acquisition mismatch"
                        );
                        helper.journal(json!({"action":"recovery_permission",
                            "target":proof["record"]["owner"]["canonical_idb_path"],
                            "coord_key":proof["record"]["coord_key"],
                            "watch":proof["record"]["watch"],"epoch":proof["record"]["subscription_epoch"],
                            "owner":proof["record"]["owner"],"lease":lease,"acquisition":acquisition,
                            "recovery_id":recovery_id,"attempt":attempt,"outcome":facts["outcome"]})).await?;
                    }
                }
                state
                    .endpoint
                    .transition(|s, _| s.acquisition_settled(&acquisition, &lease))?;
            }
        }
        _ => anyhow::bail!("unknown custody request"),
    }
    Ok(response)
}

/// Record the parsed ACK without an additional bridge round trip. Persistence
/// failure is a separate local cleanup error, never a reversal of this ACK.
pub(super) async fn detach_fact(event: &Value, state: &Arc<State>) -> anyhow::Result<()> {
    let attempt: DeliveryAttempt = decode(event["attempt"].clone())?;
    let DeliveryTarget::Release { lease } = &attempt.target else {
        anyhow::bail!("detach target mismatch");
    };
    let retired = state.endpoint.transition(|s, _| {
        s.delivery_status(&lease.client_id, &attempt)?;
        s.resource_retirement(lease)
    })?;
    anyhow::ensure!(retired.is_none(), "late ACK for retired boot resource");
    anyhow::ensure!(
        !state
            .release_facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&lease.lease_id)
            .is_some_and(|(exact, value)| exact == lease
                && value["attempt"] == json!(attempt)
                && value["terminal"].is_string()),
        "duplicate release terminal before persistence"
    );
    let resource = state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&lease.lease_id)
        .cloned();
    let Some(resource) = resource else {
        // Public proof can durably settle and compact before the original ACK.
        // N1 still validates that ACK's exact delivery; do not recreate a watch.
        return Ok(());
    };
    if event["outcome"]["lease_released"] == true && event["outcome"]["ack_kind"] == "nonlast" {
        // The parsed ACK is independent of subsequent local persistence I/O.
        resource
            .cache_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
    let ordinary = state
        .release_facts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&lease.lease_id)
        .is_some_and(|(exact, v)| *exact == *lease && !v["preflight"].is_null());
    if !ordinary {
        return Ok(());
    } // Existing auxiliary/R3b compatibility.
    let helper = state
        .helper
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("mandatory helper missing"))?;
    let recorded = helper.journal(json!({"action":"detach_outcome","target":resource.target,"coord_key":resource.coord_key,
        "watch":resource.watch,"epoch":resource.receipt["record"]["subscription_epoch"],
        "lease":lease,"owner":resource.owner,"attempt":attempt,"outcome":event["outcome"]})).await?;
    if recorded["successor"].is_string() {
        if let Some(current) = state
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&lease.lease_id)
        {
            current.nonlast_transfer =
                Some(json!({"successor":recorded["successor"],"consumer":null,"bridge":null}));
        }
    }
    Ok(())
}

pub(super) async fn nonlast_ack(event: &Value, state: &Arc<State>) -> anyhow::Result<()> {
    let consumer = &event["consumer"];
    let watch = consumer["record"]["watch"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("nonlast watch missing"))?;
    let resource = state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .find(|r| r.watch == watch)
        .cloned();
    let Some(resource) = resource else {
        anyhow::ensure!(
            state
                .custody_retirements
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(watch),
            "nonlast ACK has no retained custody"
        );
        return Ok(());
    };
    let transfer = resource
        .nonlast_transfer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("unrequested nonlast closure"))?;
    anyhow::ensure!(
        transfer["consumer"] == *consumer
            && state.bridge_observer.as_deref()
                == event["bridge_consumer"]["record"]["helper"].as_str(),
        "nonlast producer ACK identity mismatch"
    );
    let helper = state
        .helper
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("mandatory helper missing"))?;
    helper.journal(json!({"action":"nonlast_closed","target":resource.target,"coord_key":resource.coord_key,
        "watch":watch,"consumer":consumer,"bridge_consumer":event["bridge_consumer"]})).await?;
    if let Some(current) = state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_mut(&resource.lease.lease_id)
    {
        if let Some(transfer) = current.nonlast_transfer.as_mut() {
            transfer["bridge"] = event["bridge_consumer"].clone();
        }
    }
    Ok(())
}

async fn consolidate_nonlast(state: &Arc<State>, writer: &Writer, helper: &helper::Helper) {
    let resources: Vec<_> = state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .filter(|r| r.nonlast_transfer.is_some())
        .cloned()
        .collect();
    for resource in resources {
        let watch = resource.watch.clone();
        let result = consolidate_resource(state, writer, helper, resource).await;
        observation_result(state, &watch, result);
    }
}

async fn consolidate_resource(
    state: &Arc<State>,
    writer: &Writer,
    helper: &helper::Helper,
    resource: Resource,
) -> anyhow::Result<()> {
    let ready = state
        .endpoint
        .transition(|s, _| s.custody_settle_ready(&resource.lease))?;
    if !ready {
        return Ok(());
    }
    let mut transfer = resource
        .nonlast_transfer
        .clone()
        .ok_or_else(|| anyhow::anyhow!("nonlast plan missing"))?;
    if transfer["consumer"].is_null() {
        let status = helper
            .call(json!({"kind":"lookup","watch":resource.watch}))
            .await?;
        if status["item"]["proof"].is_object() && status["item"]["consumer"].is_null() {
            if let Some(current) = state
                .custody_resources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&resource.lease.lease_id)
            {
                current.nonlast_transfer = None;
            }
            return Ok(());
        }
        let closed = helper.call(json!({"kind":"nonlast_transfer","watch":resource.watch,"successor":transfer["successor"]})).await?;
        helper.journal(json!({"action":"nonlast_transfer","target":resource.target,"coord_key":resource.coord_key,
            "watch":resource.watch,"consumer":closed["consumer"]})).await?;
        transfer["consumer"] = closed["consumer"].clone();
        if let Some(current) = state
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&resource.lease.lease_id)
        {
            current.nonlast_transfer = Some(transfer.clone());
        }
    }
    if transfer["bridge"].is_null() {
        let exited = state
            .bridge_exit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(exit) = exited {
            helper.journal(json!({"action":"nonlast_exited","target":resource.target,"coord_key":resource.coord_key,
                "watch":resource.watch,"consumer":transfer["consumer"],"exit":exit,"incarnation":state.bridge_observer})).await?;
            transfer["bridge"] = json!({"exit":exit});
            if let Some(current) = state
                .custody_resources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&resource.lease.lease_id)
            {
                current.nonlast_transfer = Some(transfer.clone());
            }
        } else if !state.failed.load(std::sync::atomic::Ordering::Acquire) {
            send(writer, &json!({"nonlast_transfer":transfer["consumer"]})).await?;
            return Ok(());
        } else {
            return Ok(());
        }
    }
    helper
        .call(
            json!({"kind":"retire","watch":resource.watch,"sha256":transfer["consumer"]["sha256"]}),
        )
        .await?;
    finish_resource(state, helper, resource).await
}

/// Independent of command pending and bridge health. A public proof is first
/// committed by the target writer, then consumed by N1, then acknowledged.
pub(super) async fn proofs(state: &Arc<State>, writer: &Writer) -> anyhow::Result<()> {
    state.compact_closed_history();
    let Some(helper) = &state.helper else {
        return Ok(());
    };
    let heartbeat = helper
        .call(json!({"kind":"heartbeat", "summary_only":true}))
        .await?;
    consolidate_nonlast(state, writer, helper).await;
    let resources: Vec<_> = state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect();
    let launches: Vec<_> = state
        .startups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect();
    for launch in launches {
        let watch = launch["watch"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("observation watch missing"))?
            .to_owned();
        let has_successor = resources.iter().any(|r| {
            r.watch == watch
                || (!launch["launch"].is_null() && json!(r.acquisition) == launch["acquisition"])
        });
        let old_boot = &launch["origin_binding"]["creator"]["boot_id"];
        let result = if !has_successor
            && launch.get("pending_no_attach").is_none()
            && !old_boot.is_null()
            && *old_boot != heartbeat["identity"]["boot_id"]
        {
            retire_startup(state, writer, helper, launch).await
        } else if !has_successor && unspawned_candidate(&launch) {
            match settle_unspawned_launch(state, helper, &launch).await {
                Ok(true) => Ok(()),
                // Not provably unspawned (settling, owner present, identity known):
                // the ordinary public-lifetime path keeps the launch.
                Ok(false) => observe_launch(state, writer, helper, &resources, launch).await,
                Err(error) => Err(error),
            }
        } else {
            observe_launch(state, writer, helper, &resources, launch).await
        };
        observation_result(state, &watch, result);
    }
    // Independent watches retain separate facts and target EX serialization.
    // Bound in-flight writers so a full owner does not delay every retirement
    // behind all earlier subprocess startup and IPC waits.
    let mut observations = tokio::task::JoinSet::new();
    for resource in resources {
        if observations.len() == 4 {
            if let Some(result) = observations.join_next().await {
                result?;
            }
        }
        let state = Arc::clone(state);
        let writer = Arc::clone(writer);
        let helper = Arc::clone(helper);
        let current_boot = heartbeat["identity"]["boot_id"].clone();
        observations.spawn(async move {
            let watch = resource.watch.clone();
            let old_boot = &resource.origin_binding["creator"]["boot_id"];
            let result = if !old_boot.is_null() && *old_boot != current_boot {
                retire_resource(&state, &writer, &helper, resource).await
            } else {
                observe_resource(&state, &writer, &helper, resource).await
            };
            observation_result(&state, &watch, result);
        });
    }
    while let Some(result) = observations.join_next().await {
        result?;
    }
    let retirements: Vec<_> = state
        .custody_retirements
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect();
    if !state.failed.load(std::sync::atomic::Ordering::Acquire) {
        for receipt in &retirements {
            send(writer, &json!({"custody_retired":receipt})).await?;
        }
    }
    // After exact bridge exit the existing target writer can finish a
    // verification copy whose SDK actor can no longer publish its receipt.
    // Source loss alone never substitutes for owner or launch proof.
    if state
        .bridge_exit
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
    {
        for receipt in retirements {
            #[cfg(feature = "nexus-test-support")]
            super::test_barriers::asynchronous("verification_dispatch", receipt.clone()).await?;
            let acquisition: AcquisitionId = decode(receipt["acquisition"].clone())?;
            let verification = state
                .endpoint
                .transition(|s, _| s.acquisition_verifies_copy(&acquisition))?;
            if !verification
                || receipt["verification_removed"] == true
                || receipt["target"].is_null()
            {
                continue;
            }
            let ready = state.endpoint.transition(|s, _| {
                Ok::<_, NexusError>(
                    s.open_wait_ended(&acquisition.parent)?
                        && s.acquisition_closed(&acquisition)?,
                )
            })?;
            if !ready {
                continue;
            }
            let watch = receipt["watch"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("verification retirement watch missing"))?;
            let result = helper
                .journal(json!({"action":"verification_probe_cleanup",
                "target":receipt["target"],"coord_key":receipt["coord_key"],
                "parent":acquisition.parent,"state_root":helper.state_root}))
                .await;
            let result = result.map(|_| {
                if let Some(exact) = state
                    .custody_retirements
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_mut(watch)
                {
                    exact["verification_removed"] = json!(true);
                }
            });
            observation_result(state, watch, result);
        }
    }
    Ok(())
}

async fn retire_resource(
    state: &Arc<State>,
    writer: &Writer,
    helper: &helper::Helper,
    resource: Resource,
) -> anyhow::Result<()> {
    let result = helper
        .journal(json!({"action":"retire_old_boot","target":resource.target,
        "coord_key":resource.coord_key}))
        .await?;
    let evidence = result["retirements"]
        .as_array()
        .and_then(|a| {
            a.iter().find(|v| {
                v["watch"] == resource.watch
                    && v["owner"] == resource.owner
                    && v["lease"] == json!(resource.lease)
                    && v["acquisition"] == json!(resource.acquisition)
                    && v["binding"] == resource.origin_binding
                    && v["coord_key"] == resource.coord_key
            })
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("exact durable boot resource retirement missing"))?;
    state
        .endpoint
        .transition(|s, _| s.retire_boot_resource(&resource.lease, evidence.clone()))?;
    resource
        .cache_guard
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    helper
        .call(json!({"kind":"resource_retired","watch":resource.watch,"evidence":evidence}))
        .await?;
    {
        let mut facts = state
            .release_facts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = facts
            .entry(resource.lease.lease_id.clone())
            .or_insert_with(|| {
                (
                    resource.lease.clone(),
                    json!({"owner":resource.owner,"watch":resource.watch}),
                )
            });
        anyhow::ensure!(
            entry.0 == resource.lease,
            "resource retirement lease changed"
        );
        entry.1["resource_retirement"] = evidence.clone();
    }
    state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&resource.lease.lease_id);
    state
        .startups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&resource.watch);
    helper
        .call(json!({"kind":"retire_parent","parent":resource.acquisition.parent}))
        .await?;
    state
        .leases
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&resource.lease.lease_id);
    state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, p| match &p.attempt.target {
            DeliveryTarget::Release { lease } => lease != &resource.lease,
            DeliveryTarget::Execute { identity }
            | DeliveryTarget::Cancel { identity, .. }
            | DeliveryTarget::Shutdown { identity } => identity.lease != resource.lease,
            DeliveryTarget::Open { .. } => true,
        });
    state
        .custody_retirements
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            resource.watch.clone(),
            json!({"lease":resource.lease,"watch":resource.watch,"acquisition":resource.acquisition,
            "resource_retirement":evidence}),
        );
    send(
        writer,
        &json!({"custody_retired":{"lease":resource.lease,"watch":resource.watch,
        "acquisition":resource.acquisition,"resource_retirement":evidence}}),
    )
    .await?;
    state.emit(json!({"event":"resource_retired","lease":resource.lease,"evidence":evidence}));
    Ok(())
}

async fn retire_startup(
    state: &Arc<State>,
    _writer: &Writer,
    helper: &helper::Helper,
    launch: Value,
) -> anyhow::Result<()> {
    let watch = launch["watch"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("startup watch missing"))?;
    let acquisition: AcquisitionId = decode(launch["acquisition"].clone())?;
    let result = helper
        .journal(json!({"action":"retire_old_boot","target":launch["target"],
        "coord_key":launch["coord_key"]}))
        .await?;
    let evidence = result["retirements"]
        .as_array()
        .and_then(|a| {
            a.iter().find(|v| {
                v["watch"] == watch
                    && v["acquisition"] == launch["acquisition"]
                    && v["lease"].is_null()
                    && v["owner"] == launch["owner"]
                    && v["launch"] == launch["launch"]
                    && v["binding"] == launch["origin_binding"]
                    && v["coord_key"] == launch["coord_key"]
            })
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("exact durable startup retirement missing"))?;
    state
        .endpoint
        .transition(|s, _| s.retire_boot_startup(&acquisition, watch, evidence.clone()))?;
    helper
        .call(json!({"kind":"resource_retired","watch":watch,"evidence":evidence}))
        .await?;
    state
        .startups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(watch);
    state
        .retired_open_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(acquisition.parent.operation_id.clone());
    helper
        .call(json!({"kind":"retire_parent","parent":acquisition.parent}))
        .await?;
    state.custody_retirements.lock().unwrap_or_else(|e|e.into_inner()).insert(watch.into(),
        json!({"lease":null,"watch":watch,"acquisition":acquisition,"resource_retirement":evidence}));
    state.emit(json!({"event":"startup_resource_retired","acquisition":acquisition,"watch":watch,"evidence":evidence}));
    Ok(())
}

#[cfg(feature = "nexus-test-support")]
pub(super) async fn test_boot_resource_projection(
    state: &Arc<State>,
    writer: &Writer,
) -> anyhow::Result<()> {
    let helper = state
        .helper
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("helper missing"))?;
    let resources: Vec<_> = state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect();
    let startups: Vec<_> = state
        .startups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect();
    for resource in &resources {
        retire_resource(state, writer, helper, resource.clone()).await?;
    }
    for startup in startups {
        if !resources.iter().any(|r| {
            r.watch == startup["watch"].as_str().unwrap_or("")
                || (!startup["launch"].is_null() && json!(r.acquisition) == startup["acquisition"])
        }) {
            retire_startup(state, writer, helper, startup).await?;
        } else if let Some(watch) = startup["watch"].as_str() {
            state
                .startups
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(watch);
        }
    }
    Ok(())
}

fn observation_result(state: &State, watch: &str, result: anyhow::Result<()>) {
    let mut faults = state
        .observation_faults
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match result {
        Ok(()) => {
            faults.remove(watch);
        }
        Err(error) => {
            let reason = error.to_string();
            if faults.get(watch) != Some(&reason) {
                tracing::warn!(watch, %reason, "target observation blocked; sibling custody continues");
                state.emit(json!({"event":"observation_blocked", "watch":watch,"reason":reason}));
            }
            faults.insert(watch.into(), reason);
        }
    }
}

async fn finish_no_attach(
    state: &State,
    helper: &helper::Helper,
    event: &Value,
) -> anyhow::Result<()> {
    let watch = event["watch"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("pending no-attach watch missing"))?;
    let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
    helper
        .call(json!({"kind":"retire","watch":watch,"sha256":event["consumer"]["sha256"]}))
        .await?;
    #[cfg(feature = "nexus-test-support")]
    super::test_barriers::fail_once("no_attach_settle", event.clone())?;
    helper
        .journal(json!({"action":"settle","target":event["target"],"coord_key":event["coord_key"]}))
        .await?;
    helper
        .call(json!({"kind":"retire_parent","parent":acquisition.parent}))
        .await?;
    state
        .startups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(watch);
    state
        .retired_open_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(acquisition.parent.operation_id.clone());
    let closed = settle_unleased_acquisition(state, &acquisition, false)?;
    state.custody_retirements.lock().unwrap_or_else(|e|e.into_inner()).insert(watch.into(),
        json!({"acquisition":acquisition,"lease":null,"watch":watch,"acquisition_closed":closed}));
    Ok(())
}

async fn observe_launch(
    state: &Arc<State>,
    writer: &Writer,
    helper: &helper::Helper,
    resources: &[Resource],
    launch: Value,
) -> anyhow::Result<()> {
    if let Some(pending) = launch.get("pending_no_attach") {
        let inflight = pending["nonce"].as_str().is_some_and(|nonce| {
            state
                .custody_replies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(nonce)
                .is_some_and(|(_, reply)| reply.is_null())
        });
        if !inflight {
            finish_no_attach(state, helper, pending).await?;
        }
        return Ok(());
    }
    let successor = resources.iter().find(|r| {
        r.watch == launch["watch"].as_str().unwrap_or("")
            || (!launch["launch"].is_null()
                && serde_json::to_value(&r.acquisition).is_ok_and(|id| id == launch["acquisition"]))
    });
    let Some(successor) = successor else {
        startup_proof(state, writer, helper, launch).await?;
        return Ok(());
    };
    if launch["launch"].is_null() {
        state
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(successor.watch.as_str());
        return Ok(());
    }
    let transfer = helper
        .call(
            json!({"kind":"startup_transfer","watch":launch["watch"],"successor":successor.watch}),
        )
        .await?;
    helper.journal(json!({"action":"startup_transfer","target":successor.target,"coord_key":successor.coord_key,
            "watch":launch["watch"],"consumer":transfer["consumer"],"successor":successor.watch})).await?;
    helper.call(json!({"kind":"retire","watch":launch["watch"],"sha256":transfer["consumer"]["sha256"]})).await?;
    state
        .startups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(
            launch["watch"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("startup watch missing"))?,
        );
    Ok(())
}

async fn observe_resource(
    state: &Arc<State>,
    writer: &Writer,
    helper: &helper::Helper,
    mut resource: Resource,
) -> anyhow::Result<()> {
    if resource.nonlast_transfer.is_some() {
        return Ok(());
    }
    let status = helper
        .call(json!({"kind":"lookup", "watch":resource.watch}))
        .await?;
    anyhow::ensure!(
        status["state_root"] == helper.state_root,
        "proof state root changed"
    );
    let observation = status.get("item").filter(|item| !item.is_null());
    if resource.proof.is_none() {
        let Some(item) = observation else {
            return Ok(());
        };
        let proof = item.get("proof").or(resource.backup.as_ref());
        let Some(proof) = proof else {
            if !state.failed.load(std::sync::atomic::Ordering::Acquire) {
                send(writer, &json!({"owner_backup_query":{"watch":resource.watch,"owner":resource.owner,
                        "target":resource.target,"coord_key":resource.coord_key,"acquisition":resource.acquisition,
                        "subscription_epoch":resource.receipt["record"]["subscription_epoch"]}})).await?;
            }
            return Ok(());
        };
        // Lookup and adoption are separate RPCs. The helper can publish its
        // own public proof between them; its adoption response selects the
        // immutable proof that actually owns this watch's closure.
        let adopted;
        let proof = if item.get("proof").is_none() {
            adopted = helper
                .call(json!({"kind":"adopt_public_proof","watch":resource.watch,"proof":proof}))
                .await?;
            adopted
                .get("proof")
                .ok_or_else(|| anyhow::anyhow!("adopted public proof missing"))?
        } else {
            proof
        };
        anyhow::ensure!(
            item["owner"] == resource.owner
                && item["acquisition"] == serde_json::to_value(&resource.acquisition)?,
            "proof physical owner binding mismatch"
        );
        let selected = helper
            .journal(
                json!({"action":"proof", "target":resource.target,"coord_key":resource.coord_key,
                "watch":resource.watch,"proof":proof}),
            )
            .await?;
        let selected = helper
            .call(json!({"kind":"adopt_public_proof","watch":resource.watch,
            "proof":selected["proof"]}))
            .await?;
        let proof = &selected["proof"];
        anyhow::ensure!(proof.is_object(), "canonical public proof missing");
        resource.proof = Some(proof.clone());
        state
            .owner_proofs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                resource.lease.lease_id.clone(),
                (resource.lease.clone(), proof.clone()),
            );
        state
            .endpoint
            .transition(|s, _| s.public_owner_lifetime(&resource.lease))?;
        resource
            .cache_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        state
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(resource.lease.lease_id.clone(), resource.clone());
        state.emit(
            json!({"event":"owner_released", "lease":resource.lease, "owner":resource.owner,
                "watch":resource.watch, "proof":proof}),
        );
        // A disconnected bridge keeps no IPC source; helper proof remains
        // durable. Healthy bridge releases only its matching original ref.
    }
    if !resource.bridge_proof_ack {
        let exited = state
            .bridge_exit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(exit) = exited {
            helper
                .journal(
                    json!({"action":"bridge_process_closed","target":resource.target,
                    "coord_key":resource.coord_key,"watch":resource.watch,"exit":exit,
                    "incarnation":state.bridge_observer}),
                )
                .await?;
            resource.bridge_proof_ack = true;
        }
    }
    if !resource.bridge_proof_ack {
        // A lost acknowledgement cannot authorize compaction while the
        // original bridge may still retain a producer/reference. Actual
        // public proof has already discharged N1's resource obligations.
        let already_closed = state
            .custody_resources
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&resource.lease.lease_id)
            .is_some_and(|current| current.bridge_proof_ack);
        if !already_closed
            && !state.failed.load(std::sync::atomic::Ordering::Acquire)
            && state
                .proof_handoffs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(resource.watch.clone())
        {
            // One reliable control handoff per watch. A slow target writer
            // must not turn 100ms proof polling into an unbounded ACK backlog.
            if let Err(error) = send(writer, &json!({"owner_proof_custody":{"owner":resource.owner,"watch":resource.watch,"proof":resource.proof,"target":resource.target}})).await {
                state.proof_handoffs.lock().unwrap_or_else(|error|error.into_inner()).remove(&resource.watch);
                return Err(error);
            }
        }
        return Ok(());
    }
    if resource.consumer.is_none() {
        let proof = resource
            .proof
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("proof disappeared before ACK"))?;
        let reply = helper
            .call(json!({"kind":"proof_custody_ack", "watch":resource.watch,
                "path":proof["path"], "sha256":proof["sha256"]}))
            .await?;
        helper.journal(json!({"action":"producer_closed", "target":resource.target,"coord_key":resource.coord_key,
                "watch":resource.watch,"consumer":reply["consumer"]})).await?;
        resource.consumer = Some(reply["consumer"].clone());
        state
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(resource.lease.lease_id.clone(), resource.clone());
    }
    helper.call(json!({"kind":"retire", "watch":resource.watch,
            "sha256":resource.consumer.as_ref().ok_or_else(|| anyhow::anyhow!("consumer receipt missing"))?["sha256"]})).await?;
    finish_resource(state, helper, resource).await
}

async fn finish_resource(
    state: &Arc<State>,
    helper: &helper::Helper,
    resource: Resource,
) -> anyhow::Result<()> {
    helper
        .journal(
            json!({"action":"settle", "target":resource.target,"coord_key":resource.coord_key}),
        )
        .await?;
    #[cfg(feature = "nexus-test-support")]
    if std::env::var("R4_PARENT_TARGET").ok().as_deref() == resource.target.as_str() {
        super::test_barriers::asynchronous("helper_parent_retire", json!(resource.acquisition))
            .await?;
    }
    helper
        .call(json!({"kind":"retire_parent","parent":resource.acquisition.parent}))
        .await?;
    state.endpoint.transition(|s, _| {
        s.settle_internal_custody(&resource.lease)?;
        s.acquisition_settled(&resource.acquisition, &resource.lease)
    })?;
    if state
        .endpoint
        .transition(|s, _| s.acquisition_verifies_copy(&resource.acquisition))?
    {
        state
            .retired_open_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(resource.acquisition.parent.operation_id.clone());
    }
    state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&resource.lease.lease_id);
    state
        .custody_retirements
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            resource.watch.clone(),
            json!({"acquisition":resource.acquisition,"lease":resource.lease,"watch":resource.watch,
                "target":resource.target,"coord_key":resource.coord_key}),
        );
    Ok(())
}

/// A retained launch with no OS identity, no discovered owner and no pending
/// no-attach closure: the shape in which the bridge may have died before Popen
/// or before the Spawned fact was signed.
fn unspawned_candidate(launch: &Value) -> bool {
    launch["launch"].is_object()
        && launch["owner"].is_null()
        && launch["os_identity"].is_null()
        && launch.get("pending_no_attach").is_none()
        && launch.get("proof").is_none()
}

/// Close a signed LaunchIntent whose owner provably does not exist.
///
/// Preconditions held here: the exact bridge child was reaped (so no worker can
/// be forked for this launch any more) and the exec margin elapsed. The helper
/// then reads the process table and public discovery itself; any worker or
/// published instance carrying the launch suffix keeps the launch on the normal
/// public-lifetime path (`Ok(false)`). Absence is recorded as an immutable
/// `LaunchAbandonedUnspawned` fact, adopted by the target journal, and only then
/// are the helper watch, parent reservation and acquisition settled. This never
/// fabricates an owner proof and never replays the open.
async fn settle_unspawned_launch(
    state: &Arc<State>,
    helper: &helper::Helper,
    launch: &Value,
) -> anyhow::Result<bool> {
    let watch = launch["watch"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("startup watch missing"))?
        .to_owned();
    let Some(exit) = state
        .bridge_exit
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    else {
        return Ok(false);
    };
    let age = {
        let mut clock = state
            .launch_settle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(reaped) = clock.reaped_at else {
            return Ok(false);
        };
        if clock
            .probed
            .get(&watch)
            .is_some_and(|at| at.elapsed() < LAUNCH_SETTLE_PROBE)
        {
            return Ok(false);
        }
        clock
            .probed
            .insert(watch.clone(), std::time::Instant::now());
        reaped.elapsed()
    };
    let reply = helper
        .call(json!({"kind":"launch_settle","watch":watch,
            "bridge":{"pid":exit["pid"],"status":exit["status"],"exited_secs":age.as_secs_f64()}}))
        .await?;
    let verdict = reply["state"].as_str().unwrap_or_default().to_owned();
    if verdict != "abandoned" {
        let mut clock = state
            .launch_settle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let detail = format!("{verdict} {}", reply["pids"]);
        if clock.reported.get(&watch) != Some(&detail) {
            tracing::info!(watch, %verdict, pids = %reply["pids"],
                "bridge reaped before Spawned; launch stays on the public-lifetime path");
            clock.reported.insert(watch, detail);
        }
        anyhow::ensure!(
            matches!(
                verdict.as_str(),
                "settling" | "owner_present" | "not_applicable"
            ),
            "unexpected launch_settle verdict"
        );
        return Ok(false);
    }
    let consumer = reply["consumer"].clone();
    anyhow::ensure!(
        consumer["record"]["kind"] == "LaunchAbandonedUnspawned"
            && consumer["record"]["watch"] == json!(watch)
            && consumer["record"]["launch"] == launch["launch"]
            && consumer["record"]["acquisition"] == launch["acquisition"],
        "launch abandonment fact does not match the retained launch"
    );
    let acquisition: AcquisitionId = decode(launch["acquisition"].clone())?;
    helper
        .journal(
            json!({"action":"launch_abandoned","target":launch["target"],
            "coord_key":launch["coord_key"],"watch":watch,"consumer":consumer}),
        )
        .await?;
    helper
        .call(json!({"kind":"retire","watch":watch,"sha256":consumer["sha256"]}))
        .await?;
    helper
        .journal(
            json!({"action":"settle","target":launch["target"],"coord_key":launch["coord_key"]}),
        )
        .await?;
    helper
        .call(json!({"kind":"retire_parent","parent":acquisition.parent}))
        .await?;
    state
        .startups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&watch);
    state
        .retired_open_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(acquisition.parent.operation_id.clone());
    let closed = settle_unleased_acquisition(state, &acquisition, true)?;
    state
        .custody_retirements
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            watch.clone(),
            json!({"acquisition":acquisition,"lease":null,"watch":watch,
                "acquisition_closed":closed,"launch_abandoned":consumer["sha256"],
                "target":launch["target"],"coord_key":launch["coord_key"]}),
        );
    {
        let mut clock = state
            .launch_settle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clock.probed.remove(&watch);
        clock.reported.remove(&watch);
    }
    tracing::warn!(watch, evidence = %consumer["record"]["evidence"],
        "bridge was lost before the owner was spawned; launch settled as abandoned on process-table and discovery evidence");
    state.emit(json!({"event":"launch_abandoned_unspawned","acquisition":acquisition,"watch":watch,
        "evidence":consumer["record"]["evidence"],"receipt":{"path":consumer["path"],"sha256":consumer["sha256"]}}));
    Ok(true)
}

async fn startup_proof(
    state: &Arc<State>,
    writer: &Writer,
    helper: &helper::Helper,
    mut launch: Value,
) -> anyhow::Result<()> {
    let watch = launch["watch"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("startup watch missing"))?
        .to_owned();
    if launch.get("proof").is_none() {
        let status = helper.call(json!({"kind":"lookup","watch":watch})).await?;
        anyhow::ensure!(
            status["state_root"] == helper.state_root,
            "startup proof root mismatch"
        );
        let item = &status["item"];
        let proof = item.get("proof").or(launch.get("backup_proof")).cloned();
        let Some(proof) = proof else {
            if !launch["owner"].is_null()
                && !state.failed.load(std::sync::atomic::Ordering::Acquire)
            {
                send(writer, &json!({"owner_backup_query":{"watch":watch,"owner":launch["owner"],
                    "target":launch["target"],"coord_key":launch["coord_key"],"acquisition":launch["acquisition"],
                    "subscription_epoch":launch["receipt"]["record"]["subscription_epoch"]}})).await?;
            }
            return Ok(());
        };
        let proof = if item.get("proof").is_none() {
            helper
                .call(json!({"kind":"adopt_public_proof","watch":watch,"proof":proof}))
                .await?["proof"]
                .clone()
        } else {
            proof
        };
        anyhow::ensure!(proof.is_object(), "adopted startup public proof missing");
        anyhow::ensure!(
            item["acquisition"] == launch["acquisition"] && item["launch"] == launch["launch"],
            "startup proof origin mismatch"
        );
        if !launch["launch"].is_null() {
            helper.journal(json!({"action":"startup_owner","target":launch["target"],"coord_key":launch["coord_key"],
                "watch":watch,"receipt":item["owner_receipt"]})).await?;
        }
        let selected = helper
            .journal(
                json!({"action":"proof","target":launch["target"],"coord_key":launch["coord_key"],
            "watch":watch,"proof":proof}),
            )
            .await?;
        let selected = helper
            .call(json!({"kind":"adopt_public_proof","watch":watch,
            "proof":selected["proof"]}))
            .await?;
        let proof = selected["proof"].clone();
        anyhow::ensure!(proof.is_object(), "canonical startup proof missing");
        let mut durable_item = item.clone();
        durable_item["proof"] = proof.clone();
        state
            .startup_proofs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(watch.clone(), durable_item);
        launch["proof"] = proof.clone();
        launch["owner"] = item["owner"].clone();
        state
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(watch.clone(), launch.clone());
        state.emit(json!({"event":"startup_owner_released","acquisition":launch["acquisition"],"owner":item["owner"],"proof":proof}));
    }
    if launch["bridge_proof_ack"] != true {
        let exited = state
            .bridge_exit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(exit) = exited {
            helper
                .journal(
                    json!({"action":"bridge_process_closed","target":launch["target"],
                "coord_key":launch["coord_key"],"watch":watch,"exit":exit,
                "incarnation":state.bridge_observer}),
                )
                .await?;
            launch["bridge_proof_ack"] = json!(true);
        }
    }
    if launch["bridge_proof_ack"] != true {
        if !state.failed.load(std::sync::atomic::Ordering::Acquire) {
            send(writer, &json!({"owner_proof_custody":{"owner":launch["owner"],"watch":watch,"proof":launch["proof"],"target":launch["target"]}})).await?;
        }
        return Ok(());
    }
    if launch.get("consumer").is_none() {
        let reply = helper
            .call(json!({"kind":"proof_custody_ack","watch":watch,
            "path":launch["proof"]["path"],"sha256":launch["proof"]["sha256"]}))
            .await?;
        helper.journal(json!({"action":"producer_closed","target":launch["target"],"coord_key":launch["coord_key"],
            "watch":watch,"consumer":reply["consumer"]})).await?;
        launch["consumer"] = reply["consumer"].clone();
        state
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(watch.clone(), launch.clone());
    }
    #[cfg(feature = "nexus-test-support")]
    super::test_barriers::asynchronous("proof_before_retire", launch.clone()).await?;
    if launch["retirement_ready"] != true {
        // Public lifetime can precede the final typed attach facts. Cache the
        // producer-closed helper view, rather than the earlier proof snapshot,
        // before retirement makes this exact watch unavailable to lookup.
        let latest = helper.call(json!({"kind":"lookup","watch":watch})).await?;
        // The helper retains its original public observation when the target has
        // already selected another authorized source. Its producer closure uses
        // custody_proof in that case; validate and cache that exact same receipt.
        let selected_proof = latest["item"]
            .get("custody_proof")
            .unwrap_or(&latest["item"]["proof"]);
        anyhow::ensure!(
            latest["state_root"] == helper.state_root
                && latest["item"]["acquisition"] == launch["acquisition"]
                && latest["item"]["owner"] == launch["owner"]
                && *selected_proof == launch["proof"]
                && latest["item"]["consumer"] == launch["consumer"],
            "retiring startup helper facts changed identity or proof"
        );
        let mut latest_item = latest["item"].clone();
        latest_item["proof"] = selected_proof.clone();
        state
            .startup_proofs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(watch.clone(), latest_item);
        launch["retirement_ready"] = json!(true);
        state
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(watch.clone(), launch.clone());
    }
    helper
        .call(json!({"kind":"retire","watch":watch,"sha256":launch["consumer"]["sha256"]}))
        .await?;
    #[cfg(feature = "nexus-test-support")]
    super::test_barriers::fail_once("startup_settle", launch.clone())?;
    helper
        .journal(
            json!({"action":"settle","target":launch["target"],"coord_key":launch["coord_key"]}),
        )
        .await?;
    helper
        .call(json!({"kind":"retire_parent","parent":launch["acquisition"]["parent"]}))
        .await?;
    state
        .startups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&watch);
    let acquisition: AcquisitionId = decode(launch["acquisition"].clone())?;
    // Waitpid ends only the SDK actor; the public proof and every closure
    // above are still required before this last watch can be removed.
    let exited = state
        .bridge_exit
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    let acquisition_closed = settle_unleased_acquisition(state, &acquisition, exited)?;
    state
        .retired_open_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(acquisition.parent.operation_id.clone());
    state
        .custody_retirements
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            watch.clone(),
            json!({"acquisition":launch["acquisition"],"lease":null,"watch":watch,
                "acquisition_closed":acquisition_closed,"target":launch["target"],"coord_key":launch["coord_key"]}),
        );
    state
        .emit(json!({"event":"startup_settled","acquisition":launch["acquisition"],"watch":watch}));
    Ok(())
}

#[cfg(test)]
mod completion_contracts {
    use super::*;
    fn authority() -> (NexusEndpoint, AcquisitionId, NexusCapabilities) {
        let caps = NexusCapabilities {
            runtime: NexusRuntime {
                ida: Version(9, 5, 0),
                python: Version(3, 14, 7),
                nexus: Some(Version(0, 13, 4)),
                domain: Some(Version(0, 5, 1)),
            },
            methods: BTreeMap::new(),
        };
        let endpoint = NexusEndpoint::with_capabilities(2, Ok(caps.clone()));
        let client = ClientId::new("join-contract").expect("client");
        let parent = endpoint
            .transition(|s, t| {
                s.open(
                    &client,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new("join")?,
                        None,
                        "open",
                        json!({"timeout_secs":30}),
                    )?,
                    OpenSpec {
                        operation_id: OperationId::new("join")?,
                        path: "/private/join-contract.i64".into(),
                        options: json!({}),
                    },
                    t,
                )
            })
            .expect("N1 parent reservation");
        (
            endpoint,
            AcquisitionId {
                parent,
                purpose: AcquisitionPurpose::Final,
                ordinal: 1,
            },
            caps,
        )
    }
    #[test]
    fn other_watch_blocks_completion_and_sdk_actor_must_end_independently() {
        // Watch presence is the explicit registry boundary here, not a public
        // owner proof. The positive runtime test uses real helper closures.
        let (endpoint, id, _) = authority();
        let watches = Mutex::new(HashMap::from([
            ("one".into(), json!({"acquisition":id})),
            ("two".into(), json!({"acquisition":id})),
        ]));
        assert!(!join_acquisition_completion(&endpoint, &watches, &id, true)
            .expect("SDK ends with two watches"));
        watches.lock().expect("watch registry").remove("one");
        assert!(
            !join_acquisition_completion(&endpoint, &watches, &id, false)
                .expect("other exact watch retains capacity")
        );
        watches.lock().expect("watch registry").remove("two");
        assert!(join_acquisition_completion(&endpoint, &watches, &id, false)
            .expect("both independent facts now joined"));
        let (endpoint, id, _) = authority();
        let watches = Mutex::new(HashMap::new());
        assert!(
            !join_acquisition_completion(&endpoint, &watches, &id, false)
                .expect("resolve still running, no owner proof may end SDK")
        );
        assert!(join_acquisition_completion(&endpoint, &watches, &id, true)
            .expect("exact SDK end without watches"));
    }
    #[test]
    fn existing_lease_never_becomes_unleased_absence() {
        let (endpoint, id, caps) = authority();
        let lease = SessionLease {
            client_id: id.parent.client_id.clone(),
            lease_id: LeaseId::new("owned").expect("lease"),
            instance_id: InstanceId::new("owner").expect("owner"),
            generation: 1,
            owner: OwnerKind::Managed,
        };
        assert!(matches!(
            endpoint
                .transition(|s, _| s.opened(&id.parent, lease.clone(), caps))
                .expect("N1 lease callback boundary"),
            OpenDisposition::Ready(_)
        ));
        assert!(
            !join_acquisition_completion(&endpoint, &Mutex::new(HashMap::new()), &id, true)
                .expect("SDK completion retains physical lease")
        );
        assert_eq!(
            endpoint
                .transition(|s, _| s.acquisition_lease(&id))
                .expect("lease identity"),
            Some(lease)
        );
    }
}
