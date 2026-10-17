//! Early resource handoff and exact preparation grants, independent of pending commands.
use super::*;

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
    pub bridge_proof_ack: bool,
    pub backup: Option<Value>,
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
                    "coord_key":event["coord_key"],"consumer":event["consumer"],"bridge_consumer":event["bridge_consumer"]})).await?;
                helper
                    .call(
                        json!({"kind":"retire","watch":watch,"sha256":event["consumer"]["sha256"]}),
                    )
                    .await?;
                helper.journal(json!({"action":"settle","target":event["target"],"coord_key":event["coord_key"]})).await?;
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
                state
                    .custody_retirements
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        watch.into(),
                        json!({"acquisition":acquisition,"lease":null,"watch":watch}),
                    );
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
        }
        "observe" | "launch" | "spawned" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            state.endpoint.transition(|s, _| {
                s.open_progress(&acquisition.parent.client_id, &acquisition.parent)
            })?;
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
            helper.journal(json!({"action":if action == "observe" {"verify_observe"} else {"verify_launch"}, "target":event["target"],
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
            startups.insert(watch.into(), event.clone());
        }
        "acquired" => {
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
            let lease: SessionLease = decode(event["lease"].clone())?;
            let watch = event["watch"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("watch missing"))?;
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
            let mut verify = event.clone();
            verify["action"] = json!("verify_adopt");
            helper.journal(verify).await?;
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
                    bridge_proof_ack: false,
                    backup: None,
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
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("cleanup custody missing"))?;
            anyhow::ensure!(
                resource.acquisition == acquisition && resource.lease == lease,
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
            response["acquisition"] = serde_json::to_value(
                state
                    .endpoint
                    .transition(|s, _| s.reserve_root_retry(&parent))?,
            )?;
        }
        "cleanup_status" => {
            let lease: SessionLease = decode(event["lease"].clone())?;
            let acquisition: AcquisitionId = decode(event["acquisition"].clone())?;
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
                let (acquired, _) = state
                    .endpoint
                    .transition(|s, _| s.open_progress(&lease.client_id, &acquisition.parent))?;
                anyhow::ensure!(
                    acquired.as_ref() == Some(&lease),
                    "settled cleanup parent mismatch"
                );
            }
            let status = state
                .endpoint
                .transition(|s, _| s.status(&lease.client_id, &lease))?;
            anyhow::ensure!(
                status.phase == SessionPhase::Released,
                "cleanup has not been confirmed by N1"
            );
        }
        _ => anyhow::bail!("unknown custody request"),
    }
    Ok(response)
}

/// Independent of command pending and bridge health. A public proof is first
/// committed by the target writer, then consumed by N1, then acknowledged.
pub(super) async fn proofs(state: &Arc<State>, writer: &Writer) -> anyhow::Result<()> {
    let Some(helper) = &state.helper else {
        return Ok(());
    };
    helper
        .call(json!({"kind":"heartbeat", "summary_only":true}))
        .await?;
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
        let result = observe_launch(state, writer, helper, &resources, launch).await;
        observation_result(state, &watch, result);
    }
    for resource in resources {
        let watch = resource.watch.clone();
        let result = observe_resource(state, writer, helper, resource).await;
        observation_result(state, &watch, result);
    }
    let retirements: Vec<_> = state
        .custody_retirements
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect();
    if !state.failed.load(std::sync::atomic::Ordering::Acquire) {
        for receipt in retirements {
            send(writer, &json!({"custody_retired":receipt})).await?;
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

async fn observe_launch(
    state: &Arc<State>,
    writer: &Writer,
    helper: &helper::Helper,
    resources: &[Resource],
    launch: Value,
) -> anyhow::Result<()> {
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
        helper
            .journal(
                json!({"action":"proof", "target":resource.target,"coord_key":resource.coord_key,
                "watch":resource.watch,"proof":proof}),
            )
            .await?;
        resource.proof = Some(proof.clone());
        state
            .endpoint
            .transition(|s, _| s.public_owner_lifetime(&resource.lease))?;
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
        if !state.failed.load(std::sync::atomic::Ordering::Acquire) {
            send(writer, &json!({"owner_proof_custody":{"owner":resource.owner,"watch":resource.watch,"proof":resource.proof,"target":resource.target}})).await?;
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
    helper
        .journal(
            json!({"action":"settle", "target":resource.target,"coord_key":resource.coord_key}),
        )
        .await?;
    helper
        .call(json!({"kind":"retire_parent","parent":resource.acquisition.parent}))
        .await?;
    state
        .endpoint
        .transition(|s, _| s.settle_internal_custody(&resource.lease))?;
    state
        .custody_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&resource.lease.lease_id);
    state.custody_retirements.lock().unwrap_or_else(|e| e.into_inner()).insert(resource.watch.clone(),
            json!({"acquisition":resource.acquisition,"lease":resource.lease,"watch":resource.watch}));
    Ok(())
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
        helper
            .journal(
                json!({"action":"proof","target":launch["target"],"coord_key":launch["coord_key"],
            "watch":watch,"proof":proof}),
            )
            .await?;
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
    helper
        .call(json!({"kind":"retire","watch":watch,"sha256":launch["consumer"]["sha256"]}))
        .await?;
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
    state
        .retired_open_resources
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(acquisition.parent.operation_id);
    state
        .custody_retirements
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            watch.clone(),
            json!({"acquisition":launch["acquisition"],"lease":null,"watch":watch}),
        );
    state
        .emit(json!({"event":"startup_settled","acquisition":launch["acquisition"],"watch":watch}));
    Ok(())
}
