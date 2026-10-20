//! R3b review regressions. Models, real N1/transport and SDK/helper cases are separate.
use ida_mcp::nexus::*;
use serde_json::json;
#[allow(dead_code)]
#[path = "support/nexus_contract.rs"]
mod support;

#[tokio::test]
async fn f2_transport_notsent_returns_only_the_exact_unstarted_physical_slot() {
    use ida_mcp::router::nexus_transport::NexusEndpoint;
    let endpoint = NexusEndpoint::with_capabilities(2, Ok(support::capabilities()));
    let mut lanes = endpoint
        .take_lanes()
        .expect("actual production transport lanes");
    let client = ClientId::new("f2-capacity").expect("client");
    let open = |name: &str| {
        endpoint.transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new(name)?,
                    None,
                    "open",
                    json!({"timeout_secs":30}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new(name)?,
                    path: "/private/f2-contract.i64".into(),
                    options: json!({}),
                },
                t,
            )
        })
    };
    let failed = open("never-entered-python").expect("queued open reserves one physical slot");
    let delivery = lanes
        .business
        .recv()
        .await
        .expect("real bounded transport queue");
    drop(delivery); // No begin/write, so the production transport proves NotSent.
    let failure = endpoint
        .transition(|s, _| s.open_progress(&client, &failed))
        .expect("original parent tombstone")
        .1;
    assert!(
        failure.is_some(),
        "NotSent must preserve its original failure"
    );
    let healthy = open("healthy").expect("second logical parent");
    let mut delivery = lanes.business.recv().await.expect("healthy command");
    delivery
        .begin()
        .expect("independent healthy delivery may begin");
    delivery
        .acknowledged()
        .expect("transport receipt, not owner proof");
    let lease = SessionLease {
        client_id: client.clone(),
        lease_id: LeaseId::new("f2-live").expect("lease"),
        instance_id: InstanceId::new("f2-owner").expect("owner"),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    assert!(matches!(
        endpoint
            .transition(|s, _| s.opened(&healthy, lease.clone(), support::capabilities()))
            .expect("actual N1 session admission"),
        OpenDisposition::Ready(_)
    ));
    let auxiliary = endpoint
        .transition(|s, _| s.reserve_acquisition(&healthy, AcquisitionPurpose::Auxiliary))
        .expect(
            "one absent parent must not steal the actual healthy parent's second physical slot",
        );
    assert_eq!(auxiliary.ordinal, 2);
    assert_eq!(
        endpoint
            .transition(|s, _| s.reserve_acquisition(&healthy, AcquisitionPurpose::Auxiliary))
            .expect_err("two actual physical slots remain a hard limit")
            .code,
        NexusErrorCode::Busy
    );
    assert_eq!(
        endpoint
            .transition(|s, _| s.open_progress(&client, &failed))
            .expect("retained parent")
            .1,
        failure
    );
}

// These are N1/transport contracts, separate from SDK/helper integration below.
#[tokio::test]
async fn f2_transport_unknown_keeps_its_exact_physical_reservation() {
    use ida_mcp::router::nexus_transport::NexusEndpoint;
    let endpoint = NexusEndpoint::with_capabilities(2, Ok(support::capabilities()));
    let mut lanes = endpoint.take_lanes().expect("production transport");
    let client = ClientId::new("unknown-slot").expect("client");
    let open = |name: &str| {
        endpoint.transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new(name)?,
                    None,
                    "open",
                    json!({"timeout_secs":30}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new(name)?,
                    path: "/private/unknown-slot.i64".into(),
                    options: json!({}),
                },
                t,
            )
        })
    };
    let unknown = open("unknown").expect("first slot");
    let mut delivery = lanes.business.recv().await.expect("delivery");
    delivery.begin().expect("send may have started");
    drop(delivery);
    assert_eq!(
        endpoint
            .transition(|s, _| s.open_progress(&client, &unknown))
            .expect("retained Unknown")
            .1
            .expect("failure")
            .code,
        NexusErrorCode::UnknownOutcome
    );
    let healthy = open("healthy").expect("second slot");
    let mut delivery = lanes.business.recv().await.expect("second delivery");
    delivery.begin().expect("send");
    delivery.acknowledged().expect("receipt");
    let lease = SessionLease {
        client_id: client,
        lease_id: LeaseId::new("healthy").expect("lease"),
        instance_id: InstanceId::new("owner").expect("owner"),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    assert!(matches!(
        endpoint
            .transition(|s, _| s.opened(&healthy, lease, support::capabilities()))
            .expect("N1 callback"),
        OpenDisposition::Ready(_)
    ));
    assert_eq!(
        endpoint
            .transition(|s, _| s.reserve_acquisition(&healthy, AcquisitionPurpose::Auxiliary))
            .expect_err("Unknown must not free capacity")
            .code,
        NexusErrorCode::Busy
    );
}

#[tokio::test]
async fn f2_late_unstarted_ordinal_does_not_close_a_new_auxiliary() {
    use ida_mcp::router::nexus_transport::NexusEndpoint;
    let endpoint = NexusEndpoint::with_capabilities(2, Ok(support::capabilities()));
    let mut lanes = endpoint.take_lanes().expect("production transport");
    let client = ClientId::new("ordinal-slot").expect("client");
    let parent = endpoint
        .transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("parent")?,
                    None,
                    "open",
                    json!({"timeout_secs":30}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new("parent")?,
                    path: "/private/ordinal-slot.i64".into(),
                    options: json!({}),
                },
                t,
            )
        })
        .expect("parent");
    let mut delivery = lanes.business.recv().await.expect("delivery");
    delivery.begin().expect("send");
    delivery.acknowledged().expect("receipt");
    let lease = SessionLease {
        client_id: client,
        lease_id: LeaseId::new("live").expect("lease"),
        instance_id: InstanceId::new("owner").expect("owner"),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    assert!(matches!(
        endpoint
            .transition(|s, _| s.opened(&parent, lease, support::capabilities()))
            .expect("N1 callback"),
        OpenDisposition::Ready(_)
    ));
    let old = endpoint
        .transition(|s, _| s.reserve_acquisition(&parent, AcquisitionPurpose::Auxiliary))
        .expect("ordinal2");
    endpoint
        .transition(|s, _| s.acquisition_unstarted(&old))
        .expect("exact resource-free absence");
    let new = endpoint
        .transition(|s, _| s.reserve_acquisition(&parent, AcquisitionPurpose::Auxiliary))
        .expect("ordinal3");
    assert_eq!(new.ordinal, old.ordinal + 1);
    endpoint
        .transition(|s, _| s.acquisition_unstarted(&old))
        .expect("late old absence is idempotent");
    assert!(!endpoint
        .transition(|s, _| s.acquisition_closed(&new))
        .expect("new identity remains live"));
    assert_eq!(
        endpoint
            .transition(|s, _| s.reserve_acquisition(&parent, AcquisitionPurpose::Auxiliary))
            .expect_err("old tombstone cannot release new slot")
            .code,
        NexusErrorCode::Busy
    );
}

#[cfg(feature = "nexus-test-support")]
mod cross {
    use super::*;
    use ida_mcp::{
        preprocess::Preparation,
        router::{
            nexus_bridge::{BridgeConfig, NexusBridge},
            RouterState,
        },
    };
    use serde_json::Value;
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };
    pub(super) async fn bridge(root: &Path, mode: &str) -> (RouterState, Arc<NexusBridge>) {
        let router = RouterState::new().expect("router");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        environment.insert("R3F1_CASE".into(), mode.into());
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r3b_fix1_bridge.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("real installed bridge/helper over native HTTP inputs");
        (router, bridge)
    }
    async fn marker(path: &Path) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(4), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }
    pub(super) async fn finish(
        root: &Path,
        bridge: &NexusBridge,
        result: &anyhow::Result<Value>,
        name: &str,
    ) {
        std::fs::write(root.join("compensation.release"), b"")
            .expect("release own compensation barrier");
        for child in ["a", "b"] {
            std::fs::write(root.join(child).join("owner-release"), b"").expect("release own owner");
            std::fs::write(root.join(child).join("guard.release"), b"").expect("release own guard");
        }
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            while bridge.lifecycle_status()["resources"] != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let stopped = bridge.shutdown().await;
        let forced = if stopped.is_err() {
            Some(
                bridge
                    .test_helper_fault(true)
                    .await
                    .expect("precise owned failed-case helper cleanup"),
            )
        } else {
            None
        };
        std::fs::write(root.join(format!("{name}-result.json")),serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
            "settled":settled.is_ok(),"shutdown":format!("{stopped:?}"),"forced_failed_case_cleanup":forced})).expect("evidence")).expect("write evidence");
        if result.is_ok() {
            settled.expect("physical custody naturally settles");
            stopped.expect("all owned bridge/helper processes naturally exit");
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn nonlast_transfer_settles_real_n1_bridge_helper_and_preserves_ack() {
        let root =
            PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root")).join("nl");
        std::fs::create_dir(&root).expect("private nonlast case");
        let (_router, bridge) = bridge(&root, "nonlast-bounded").await;
        let mut events = bridge.subscribe();
        let client = ClientId::new("nonlast-client").expect("client");
        let result: anyhow::Result<Value> = async {
            let mut warm = None;
            let mut closed = Vec::new();
            let mut samples = Vec::new();
            for n in 0..5 {
                let id = format!("nonlast-{n}");
                bridge.endpoint().transition(|s, t| {
                    s.open(
                        &client,
                        AcceptedRequest::new(
                            &SystemClock,
                            RequestId::new(&id)?,
                            None,
                            "open",
                            json!({"timeout_secs":20}),
                        )?,
                        OpenSpec {
                            operation_id: OperationId::new(&id)?,
                            path: root.join("a/tiny.i64").display().to_string(),
                            options: json!({"spawn":false,"wait_analysis":false}),
                        },
                        t,
                    )
                })?;
                let opened = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let event = events.recv().await?;
                        anyhow::ensure!(
                            event["event"] != "failed" && event["event"] != "uncertain",
                            "{event}"
                        );
                        if event["event"] == "opened" {
                            break Ok::<_, anyhow::Error>(event);
                        }
                    }
                })
                .await??;
                let lease: SessionLease = serde_json::from_value(opened["lease"].clone())?;
                if n == 0 {
                    warm = Some(lease);
                    continue;
                }
                bridge
                    .endpoint()
                    .transition(|s, t| s.release(&client, &lease, t))?;
                let ack = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let event = events.recv().await?;
                        if event["event"] == "released"
                            && event["attempt"]["target"]["lease"] == json!(lease)
                        {
                            break Ok::<_, anyhow::Error>(event);
                        }
                    }
                })
                .await??;
                anyhow::ensure!(
                    ack["outcome"]["ack_kind"] == "nonlast"
                        && ack["outcome"]["lease_released"] == true,
                    "{ack}"
                );
                tokio::time::timeout(Duration::from_secs(5), async {
                    while bridge.lifecycle_status()["resources"] != 1
                        || bridge.lifecycle_status()["retirement_acks"] != 0
                    {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await?;
                let history = bridge
                    .endpoint()
                    .transition(|s, _| s.status(&client, &lease))?;
                anyhow::ensure!(
                    history.phase == SessionPhase::Released
                        && history
                            .control_delivery
                            .as_ref()
                            .is_some_and(|d| d.state == DeliveryState::Confirmed),
                    "ACK history changed"
                );
                samples.push(bridge.lifecycle_status());
                closed.push(lease);
            }
            bridge.status("bounded").await?;
            let status = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let event = events.recv().await?;
                    if event["event"] == "local_status" {
                        break Ok::<_, anyhow::Error>(event);
                    }
                }
            })
            .await??;
            anyhow::ensure!(
                status["custodians"] == 1 && status["original_instances"] == 1,
                "bridge custody/source accumulated: {status}"
            );
            let warm = warm.ok_or_else(|| anyhow::anyhow!("warm lease"))?;
            bridge
                .endpoint()
                .transition(|s, t| s.release(&client, &warm, t))?;
            let ack = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let e = events.recv().await?;
                    if e["event"] == "released" && e["attempt"]["target"]["lease"] == json!(warm) {
                        break Ok::<_, anyhow::Error>(e);
                    }
                }
            })
            .await??;
            anyhow::ensure!(ack["outcome"]["ack_kind"] == "last", "{ack}");
            std::fs::write(root.join("a/owner-release"), b"")?;
            Ok(json!({"samples":samples,"last_ack":ack,"bridge":status,"closed_leases":closed}))
        }
        .await;
        finish(&root, &bridge, &result, "nonlast-bounded").await;
        result.expect("real production Rust/N1/bridge/helper nonlast handoff");
        let status = bridge.lifecycle_status();
        assert_eq!(status["resources"], 0);
        let registry: Value = serde_json::from_slice(
            &std::fs::read(root.join("i/helper-state.json")).expect("exact exited helper registry"),
        )
        .expect("registry JSON");
        assert_eq!(registry["items"], json!({}));
        assert_eq!(registry["parents"], json!({}));
        assert_eq!(registry["finishing"], true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f2_real_gate_failure_returns_final_slot() {
        f2_gate_case(false, "f2-gate").await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f2_real_gate_failure_returns_verification_slot() {
        f2_gate_case(true, "f2-gate").await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f2_actual_probe_failure_returns_final_and_verification_slots() {
        for verification in [false, true] {
            f2_gate_case(verification, "f2-probe").await;
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f2_actual_options_failure_returns_final_and_verification_slots() {
        for verification in [false, true] {
            f2_gate_case(verification, "f2-options").await;
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f2_actual_before_resolve_failure_returns_final_and_verification_slots() {
        for verification in [false, true] {
            f2_gate_case(verification, "f2-resolve").await;
        }
    }
    async fn f2_gate_case(verification: bool, mode: &str) {
        let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
        for verification in [verification] {
            let root = base.join(format!(
                "{mode}-{}",
                if verification {
                    "verification"
                } else {
                    "final"
                }
            ));
            std::fs::create_dir(&root).expect("new case");
            let (_, bridge) = bridge(&root, mode).await;
            assert_eq!(
                bridge
                    .endpoint()
                    .transition(|s, _| Ok::<_, NexusError>(s.acquisition_status()))
                    .expect("real physical capacity")["tenant_physical_limit"],
                2
            );
            let mut events = bridge.subscribe();
            let client = ClientId::new("f2-gate").expect("client");
            std::fs::write(root.join("input"), b"input digest").expect("snapshot");
            let result:anyhow::Result<Value>=async {
                let bad=bridge.endpoint().transition(|s,t|s.open(&client,
                    AcceptedRequest::new(&SystemClock,RequestId::new("bad")?,None,"open",json!({"timeout_secs":15}))?,
                    OpenSpec{operation_id:OperationId::new("bad")?,path:if verification{root.join("b/tiny.i64")}else{root.join("rejected.i64")}.display().to_string(),
                        options:if verification{json!({"verification_idb":root.join("rejected.i64"),"verify_input_snapshot":root.join("input"),"spawn":false})}else{json!({"spawn":false})}},t))?;
                let mut evidence=Vec::new();
                let failed=tokio::time::timeout(Duration::from_secs(4),async{
                    loop{let e=events.recv().await?;let stop=e["attempt"]["target"]["identity"]["operation_id"]=="bad" && (e["event"]=="failed"||e["event"]=="uncertain"||e["event"]=="not_sent");evidence.push(e.clone());if stop{break Ok::<_,anyhow::Error>(e);}}
                }).await??;
                anyhow::ensure!(failed["event"]=="failed" || failed["event"]=="not_sent","known no-SDK failure cannot become Unknown: {failed}");
                let expected=match mode {"f2-gate"=>"corrupt custody journal","f2-probe"=>"controlled pre-SDK probe failure","f2-options"=>"controlled pre-SDK Options failure","f2-resolve"=>"controlled pre-resolver failure",_=>unreachable!("fixed test modes")};
                anyhow::ensure!(failed["error"]["message"].as_str().is_some_and(|s|s.contains(expected)),"original failure cause missing: {failed}");
                let stages=match std::fs::read_to_string(root.join("bad-sdk-stages.jsonl")){Ok(v)=>v,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>String::new(),Err(e)=>return Err(e.into())};
                anyhow::ensure!(!stages.contains("Resolved")&&!stages.contains("Attach")&&!stages.contains("LaunchIntent"),"pre-SDK failure reached side effects: {stages}");
                let good=bridge.endpoint().transition(|s,t|s.open(&client,
                    AcceptedRequest::new(&SystemClock,RequestId::new("good")?,None,"open",json!({"timeout_secs":15}))?,
                    OpenSpec{operation_id:OperationId::new("good")?,path:root.join("b/tiny.i64").display().to_string(),options:json!({"spawn":false})},t))?;
                let opened=tokio::time::timeout(Duration::from_secs(4),async{
                    loop{let e=events.recv().await?;let stop=e["event"]=="opened";evidence.push(e.clone());if stop{break Ok::<_,anyhow::Error>(e);}}
                }).await??;
                let lease:SessionLease=serde_json::from_value(opened["lease"].clone())?;
                std::fs::write(root.join("b/disconnect-primary"),b"")?;
                tokio::time::timeout(Duration::from_secs(3),async{
                    loop{let e=events.recv().await?;if e["event"]=="disconnected"{break Ok::<_,anyhow::Error>(());}}
                }).await??;
                bridge.endpoint().transition(|s,t|s.release(&client,&lease,t))?;
                let terminal=tokio::time::timeout(Duration::from_secs(4),async{
                    loop{let e=events.recv().await?;let stop=e["attempt"]["target"]["kind"]=="release";evidence.push(e.clone());if stop{break Ok::<_,anyhow::Error>(e);}}
                }).await??;
                anyhow::ensure!(terminal["event"]=="released","empty failed reservation denied real auxiliary acquisition: {terminal}");
                let members=bridge.endpoint().transition(|s,_|s.release_members(&lease))?;
                anyhow::ensure!(members.len()==2,"actual SDK auxiliary was not signed into N1");
                anyhow::ensure!(bridge.endpoint().transition(|s,_|s.open_progress(&client,&bad))?.1.is_some(),"original failure tombstone removed");
                anyhow::ensure!(bridge.endpoint().transition(|s,_|s.open_progress(&client,&good))?.0==Some(lease));
                Ok(json!({"bad_terminal":failed,"release_terminal":terminal,"members":members,"events":evidence,"physical":bridge.lifecycle_status()}))
            }.await;
            finish(&root, &bridge, &result, "f2-gate").await;
            result.expect(
                "a proven pre-SDK gate failure must return exactly its physical reservation",
            );
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f1_auxiliary_outside_gate_handoff_finishes_exact_child() {
        f1_case("f1-notsent").await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f1_auxiliary_public_proof_finishes_exact_child() {
        f1_case("f1-proof").await;
    }
    async fn f1_case(mode: &str) {
        let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
        for mode in [mode] {
            let root = base.join(mode);
            std::fs::create_dir(&root).expect("fresh case");
            let (router, bridge) = bridge(&root, mode).await;
            let mut events = bridge.subscribe();
            let result: anyhow::Result<Value> = async {
                let (_, token) = router
                    .ensure_worker_prepared(
                        root.join("a/tiny.i64").to_str().expect("path"),
                        None,
                        None,
                        Preparation::new(Duration::from_secs(15)),
                    )
                    .await?;
                let opened = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let e = events.recv().await?;
                        if e["event"] == "opened" {
                            break Ok::<_, anyhow::Error>(e);
                        }
                    }
                })
                .await??;
                let primary: SessionLease = serde_json::from_value(opened["lease"].clone())?;
                std::fs::write(root.join("a/disconnect-primary"), b"")?;
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        if events.recv().await?["event"] == "disconnected" {
                            break Ok::<_, anyhow::Error>(());
                        }
                    }
                })
                .await??;
                let closing = router.clone();
                let close_token = token.clone();
                let closed =
                    tokio::spawn(async move { closing.nexus_close_token(&close_token).await });
                marker(&root.join("compensation.arrived")).await?;
                let child: Value =
                    serde_json::from_slice(&std::fs::read(root.join("failed-child.json"))?)?;
                let acquisition: AcquisitionId =
                    serde_json::from_value(child["acquisition"].clone())?;
                if mode == "f1-proof" {
                    std::fs::write(root.join("a/owner-release"), b"")?;
                    tokio::time::timeout(Duration::from_secs(3), async {
                        loop {
                            let state: Value = serde_json::from_slice(&std::fs::read(
                                root.join("i/helper-state.json"),
                            )?)?;
                            if state["items"][child["watch"].as_str().expect("watch")]["proof"]
                                .is_object()
                            {
                                break Ok::<_, anyhow::Error>(());
                            }
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    })
                    .await??;
                }
                std::fs::write(root.join("compensation.release"), b"")?;
                let close = tokio::time::timeout(Duration::from_secs(4), closed).await??;
                std::fs::write(
                    root.join("original-close.json"),
                    serde_json::to_vec_pretty(
                        &json!({"caller":format!("{close:?}"),"child":child}),
                    )?,
                )?;
                anyhow::ensure!(
                    close.is_err(),
                    "original auxiliary failure cannot become success"
                );
                anyhow::ensure!(
                    format!("{close:?}").contains("controlled auxiliary observe NotSent"),
                    "original helper handoff cause was overwritten: {close:?}"
                );
                tokio::time::timeout(Duration::from_secs(3), async {
                    while !bridge
                        .endpoint()
                        .transition(|s, _| s.acquisition_closed(&acquisition))?
                    {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await??;
                let details = bridge
                    .endpoint()
                    .transition(|s, _| Ok::<_, NexusError>(s.acquisition_status()))?;
                anyhow::ensure!(
                    bridge
                        .endpoint()
                        .transition(|s, _| s.acquisition_lease(&acquisition))?
                        .is_none(),
                    "the failed child must not fabricate a lease"
                );
                if mode == "f1-notsent" {
                    tokio::time::timeout(Duration::from_secs(4), router.nexus_close_token(&token))
                        .await??;
                    let members = bridge
                        .endpoint()
                        .transition(|s, _| s.release_members(&primary))?;
                    anyhow::ensure!(
                        members.len() == 2,
                        "later allowed cleanup cannot reuse an unexecutable child"
                    );
                } else {
                    let _ = router.nexus_close_token(&token).await;
                }
                Ok(json!({"original_caller":format!("{close:?}"),"child":child,"n1":details}))
            }
            .await;
            finish(&root, &bridge, &result, "f1").await;
            result.expect("both actual Rust/N1/helper windows must settle an unacquired auxiliary");
        }
    }
}

#[cfg(feature = "nexus-test-support")]
#[path = "../src/router/nexus_bridge/verification.rs"]
mod actual_verification;

#[cfg(feature = "nexus-test-support")]
async fn issue_marker(directory: &std::path::Path) -> anyhow::Result<()> {
    use std::process::Stdio;
    let mut command = tokio::process::Command::new(std::env::var_os("R3A_PYTHON").expect("SDK"));
    command
        .arg("-I")
        .arg("-B")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3b_fix1_marker.py"),
        )
        .arg(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = ida_mcp::router::nexus_bridge::test_spawn_child(&mut command)?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        ida_mcp::router::nexus_bridge::test_output_child(child),
    )
    .await??;
    std::fs::write(
        directory.parent().expect("case").join("issuer.stdout"),
        &output.stdout,
    )?;
    anyhow::ensure!(
        output.status.success(),
        "production issuer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test]
async fn f3_actual_consumer_retains_a_probe_replaced_after_production_issuer() {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
    };
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    let root = root.join("f3-replacement");
    fs::create_dir(&root).expect("isolated replacement case");
    let directory = root.join("copy");
    fs::create_dir(&directory).expect("copy directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("private directory");
    fs::copy(
        std::env::var_os("R3F1_SAMPLE").expect("private copied IDB input"),
        directory.join("probe.i64"),
    )
    .expect("new sample copy");
    fs::write(
        directory.join("input"),
        b"immutable private verification input",
    )
    .expect("input");
    fs::set_permissions(
        directory.join("probe.i64"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("private probe");
    let info = fs::metadata(&directory).expect("directory identity");
    let before = fs::metadata(directory.join("probe.i64")).expect("owned original probe");
    let cleanup =
        actual_verification::Cleanup::new(directory.clone(), (info.dev(), info.ino()), None);
    issue_marker(&directory)
        .await
        .expect("actual production issuer");
    let replacement = root.join("replacement.i64");
    fs::write(
        &replacement,
        b"foreign replacement after issuer released target EX",
    )
    .expect("private negative input");
    fs::rename(&replacement, directory.join("probe.i64")).expect("same-name replacement");
    let after = fs::metadata(directory.join("probe.i64")).expect("replacement identity");
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert!(
        cleanup.validate_closure().is_err(),
        "a later probe invalidates closure before input publication"
    );
    let callback_ran = std::cell::Cell::new(false);
    assert!(
        cleanup
            .publish_with_closure(|| {
                callback_ran.set(true);
                Ok(())
            })
            .is_err(),
        "replacement must reject permission before publication"
    );
    assert!(
        !callback_ran.get(),
        "invalid closure cannot run the publication callback"
    );
    let result = cleanup.complete(true);
    fs::write(root.join("f3-replacement.json"),serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "old":[before.dev(),before.ino()],"replacement":[after.dev(),after.ino()],"replacement_exists":directory.join("probe.i64").exists(),
        "scope":"actual Rust Cleanup and production Python issuer; no live IDA owner"})).expect("encode")).expect("evidence");
    assert!(
        !matches!(result, Ok(true)),
        "historical closure cannot authorize deleting later payload"
    );
    assert_ne!(
        cleanup.status()["cleanup_complete"],
        true,
        "rejected replacement cannot be declared complete"
    );
    assert_eq!(
        fs::read(directory.join("probe.i64")).expect("foreign replacement must survive"),
        b"foreign replacement after issuer released target EX"
    );
    assert!(fs::read_dir(&directory)
        .expect("stable namespace")
        .any(|p| p
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .starts_with(".ida-cli-txn-")));
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f3_actual_consumer_retains_new_owner_and_new_journal_after_issuer_unlock() {
    use serde_json::Value;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        time::Duration,
    };
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    let root = root.join("f3-owner");
    fs::create_dir(&root).expect("isolated owner case");
    let directory = root.join("copy");
    fs::create_dir(&directory).expect("private copy");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("private mode");
    fs::copy(
        std::env::var_os("R3F1_SAMPLE").expect("copied sample"),
        root.join("source.i64"),
    )
    .expect("new source copy");
    fs::copy(root.join("source.i64"), directory.join("probe.i64")).expect("private probe");
    fs::write(
        directory.join("input"),
        b"private immutable verification input",
    )
    .expect("input");
    let info = fs::metadata(&directory).expect("identity");
    let cleanup =
        actual_verification::Cleanup::new(directory.clone(), (info.dev(), info.ino()), None);
    issue_marker(&directory)
        .await
        .expect("producer has completed its locked check before new owner exists");
    let (_router, bridge) = cross::bridge(&root, "f3-owner").await;
    let mut events = bridge.subscribe();
    let client = ClientId::new("new-owner-after-issuer").expect("client");
    let mut lease = None;
    let result:anyhow::Result<Value>=async {
        let parent=bridge.endpoint().transition(|s,t|s.open(&client,
            AcceptedRequest::new(&SystemClock,RequestId::new("new-owner")?,None,"open",json!({"timeout_secs":15}))?,
            OpenSpec{operation_id:OperationId::new("new-owner")?,path:directory.join("probe.i64").display().to_string(),options:json!({"spawn":false})},t))?;
        let ready=tokio::time::timeout(Duration::from_secs(4),async{
            loop{let e=events.recv().await?;anyhow::ensure!(e["event"]!="failed"&&e["event"]!="uncertain","{e}");if e["event"]=="opened"{break Ok::<_,anyhow::Error>(e);}}
        }).await??;
        let current:SessionLease=serde_json::from_value(ready["lease"].clone())?;lease=Some(current.clone());
        let journal=fs::read_dir(&directory)?.filter_map(Result::ok).find(|p|p.file_name().to_string_lossy().starts_with(".ida-cli-txn-"))
            .ok_or_else(||anyhow::anyhow!("stable coordination"))?.path().join("custody.json");
        let before=fs::read(&journal)?;let payload=fs::read(directory.join("probe.i64"))?;
        let consumed=cleanup.complete(true);
        let proof=json!({"actual_consumer":format!("{consumed:?}"),"new_owner_ready":ready,"probe_survived":directory.join("probe.i64").exists(),
            "journal_survived":fs::read(&journal)?==before,"scope":"actual Rust consumer, production issuer, real N1/SDK/helper over native HTTP/IDA-input owner; not real IDA analysis"});
        fs::write(root.join("new-owner-consumer.json"),serde_json::to_vec_pretty(&proof)?)?;
        anyhow::ensure!(!matches!(consumed,Ok(true)),"idle target EX cannot authorize old cleanup while new owner is active: {proof}");
        anyhow::ensure!(fs::read(directory.join("probe.i64"))?==payload,"new owner payload was deleted/replaced");
        anyhow::ensure!(bridge.endpoint().transition(|s,_|s.status(&client,&current))?.phase==SessionPhase::Active,"old cleanup changed new N1 responsibility");
        anyhow::ensure!(bridge.endpoint().transition(|s,_|s.open_progress(&client,&parent))?.0==Some(current));
        Ok(proof)
    }.await;
    if let Some(lease) = lease {
        bridge
            .endpoint()
            .transition(|s, t| s.release(&client, &lease, t))
            .expect("close exactly the new test owner lease");
    }
    cross::finish(&root, &bridge, &result, "f3-owner").await;
    result.expect("old authorization must preserve new owner and journal");
}
