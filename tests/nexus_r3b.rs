//! K2 acquisition contracts. Cross-layer cases use the production adapter below.
use ida_mcp::nexus::*;
use serde_json::json;

#[allow(dead_code)]
#[path = "support/nexus_contract.rs"]
mod support;
use support::*;

#[test]
fn verification_has_preparing_custody_without_publishing_parent_result() {
    let mut rig = Rig::new();
    let client = ClientId::new("verification-client").expect("client");
    let parent = rig
        .sessions
        .open(
            &client,
            accepted(
                &rig.clock,
                "verification",
                "open",
                json!({"timeout_secs":120}),
            ),
            OpenSpec {
                operation_id: OperationId::new("verification").expect("operation"),
                path: "/private/copy.i64".into(),
                options: json!({"verification_idb":"/private/verify.i64"}),
            },
            &mut rig.backend,
        )
        .expect("admitted parent and first physical slot");
    let acquisition = AcquisitionId {
        parent: parent.clone(),
        purpose: AcquisitionPurpose::Verification,
        ordinal: 1,
    };
    let lease = SessionLease {
        client_id: client.clone(),
        lease_id: LeaseId::new("verification-lease").expect("lease"),
        instance_id: InstanceId::new("verification-owner").expect("owner"),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    let decision = rig
        .sessions
        .acquired(&acquisition, lease.clone(), true)
        .expect("verification must enter the same actual N1 custody authority");
    assert_eq!(decision.disposition, CustodyDisposition::Prepare);
    assert_eq!(
        rig.sessions.status(&client, &lease).expect("session").phase,
        SessionPhase::Preparing
    );
    assert!(
        rig.sessions
            .open_progress(&client, &parent)
            .expect("parent")
            .0
            .is_none(),
        "verification is never the caller's final lease"
    );
    rig.sessions
        .cancel_open(&client, &parent)
        .expect("cancel parent");
    assert_eq!(
        rig.sessions
            .custody_decision(&lease)
            .expect("revocation")
            .disposition,
        CustodyDisposition::CleanupOnly
    );
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verification_owner_proof_precedes_copy_cleanup_and_final_acquisition() {
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    std::fs::write(root.join("input"), b"verification input").expect("private input snapshot");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3B_CASE".into(), "verification-held".into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r2_multi_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("production bridge/helper over independent owner inputs");
    let mut events = bridge.subscribe();
    let client = ClientId::new("verify-parent").expect("client");
    let parent = bridge.endpoint().transition(|s,t| s.open(&client,
        AcceptedRequest::new(&SystemClock, RequestId::new("verify-open")?, None, "open", json!({"timeout_secs":20}))?,
        OpenSpec { operation_id: OperationId::new("verify-open")?, path:root.join("b/tiny.i64").display().to_string(),
            options:json!({"spawn":false,"wait_analysis":false,
                "verification_idb":root.join("a/tiny.i64"), "verify_input_snapshot":root.join("input")}) }, t))
        .expect("parent reserves verification first");
    let result: anyhow::Result<Value> = async {
        tokio::time::timeout(Duration::from_secs(8), async {
            while !root.join("a/release-requested").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        bridge.status("verify-held").await?;
        let mut evidence = Vec::new();
        let held = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let event = events.recv().await?;
                evidence.push(event.clone());
                if event["event"] == "local_status" {
                    break Ok::<_, anyhow::Error>(event);
                }
            }
        })
        .await??;
        anyhow::ensure!(
            !root.join("a/closed").exists(),
            "last ACK is not owner proof or copy cleanup authority"
        );
        anyhow::ensure!(
            held["custodians"] == 1 && held["held"].as_array().is_some_and(Vec::is_empty),
            "{held}"
        );
        anyhow::ensure!(
            bridge
                .endpoint()
                .transition(|s, _| s.open_progress(&client, &parent))?
                .0
                .is_none(),
            "verification cannot publish a final parent lease"
        );
        std::fs::write(root.join("a/owner-release"), b"")?;
        let ready = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let event = events.recv().await?;
                evidence.push(event.clone());
                if (event["event"] == "opened"
                    || event["event"] == "failed"
                    || event["event"] == "uncertain")
                    && event["attempt"]["target"]["kind"] == "open"
                {
                    break Ok::<_, anyhow::Error>(event);
                }
            }
        })
        .await??;
        anyhow::ensure!(ready["event"] == "opened", "{ready}");
        anyhow::ensure!(
            root.join("a/closed").is_file(),
            "verified copy must have a proved closure before final open"
        );
        let lease: SessionLease = serde_json::from_value(ready["lease"].clone())?;
        anyhow::ensure!(
            ready["acquisition"]["purpose"] == "final" && ready["acquisition"]["ordinal"] == 2,
            "final must get a distinct acquisition: {ready}"
        );
        bridge
            .endpoint()
            .transition(|s, t| s.release(&client, &lease, t))?;
        Ok(json!({"held":held,"ready":ready,"events":evidence}))
    }
    .await;
    for name in ["a", "b"] {
        std::fs::write(root.join(name).join("guard.release"), b"").expect("finally guard");
        std::fs::write(root.join(name).join("owner-release"), b"").expect("finally owner");
    }
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let stopped = bridge.shutdown().await;
    std::fs::write(root.join("verification-result.json"),serde_json::to_vec_pretty(&json!({
        "result":format!("{result:?}"),"settled":settled.is_ok(),"shutdown":format!("{stopped:?}")})).expect("encode")).expect("evidence");
    settled.expect("all exact resources consume independent public proof");
    stopped.expect("natural shutdown");
    result.expect("actual SDK/Rust/N1/production bridge verification");
}

#[test]
fn auxiliary_is_cleanup_only_after_parent_terminal_and_two_slots_are_not_multiplied() {
    let mut rig = Rig::new();
    let (parent, primary) = rig.begin_open("two-slot", "same-owner", 1, 120);
    assert!(matches!(
        rig.sessions
            .opened(&parent, primary.clone(), capabilities())
            .expect("parent terminal success"),
        OpenDisposition::Ready(_)
    ));
    let child = rig
        .sessions
        .reserve_acquisition(&parent, AcquisitionPurpose::Auxiliary)
        .expect("second slot reserved before SDK");
    assert_eq!(child.ordinal, 2);
    assert_eq!(
        rig.sessions
            .reserve_acquisition(&parent, AcquisitionPurpose::Auxiliary)
            .expect_err("third physical slot is forbidden")
            .code,
        NexusErrorCode::Busy
    );
    let auxiliary = SessionLease {
        lease_id: LeaseId::new("auxiliary-two").expect("unique lease"),
        ..primary.clone()
    };
    let decision = rig
        .sessions
        .acquired(&child, auxiliary.clone(), true)
        .expect("late auxiliary custody");
    assert_eq!(decision.disposition, CustodyDisposition::CleanupOnly);
    assert_eq!(
        rig.sessions
            .open_progress(&primary.client_id, &parent)
            .expect("retained parent")
            .0,
        Some(primary.clone())
    );
    let identity = OperationIdentity {
        lease: auxiliary.clone(),
        task_id: None,
        request_id: RequestId::new("no-aux-prepare").expect("request"),
        operation_id: OperationId::new("no-aux-prepare").expect("operation"),
    };
    assert_eq!(
        rig.sessions
            .internal_grant(
                &child,
                identity,
                InternalPurpose::Runtime,
                decision.grant_epoch
            )
            .expect_err("auxiliary cannot revive parent preparation")
            .code,
        NexusErrorCode::Cancelled
    );
    rig.sessions
        .release(&primary.client_id, &primary, &mut rig.backend)
        .expect("primary independent attempt");
    let primary_attempt = rig
        .backend
        .attempts
        .last()
        .expect("primary attempt")
        .clone();
    rig.sessions
        .released(&primary_attempt)
        .expect("actual primary ACK");
    rig.sessions
        .release(&auxiliary.client_id, &auxiliary, &mut rig.backend)
        .expect("auxiliary independent attempt");
    let auxiliary_attempt = rig
        .backend
        .attempts
        .last()
        .expect("auxiliary attempt")
        .clone();
    rig.sessions
        .delivery_failed(
            &auxiliary_attempt,
            DispatchFailure::NotSent(NexusError::new(
                NexusErrorCode::Busy,
                "guard not dispatched",
            )),
        )
        .expect("auxiliary NotSent");
    assert_eq!(
        rig.sessions
            .status(&primary.client_id, &primary)
            .expect("primary")
            .phase,
        SessionPhase::Released
    );
    rig.sessions
        .release(&auxiliary.client_id, &auxiliary, &mut rig.backend)
        .expect("fresh auxiliary attempt");
    assert_ne!(
        rig.backend.attempts.last().expect("retry").sequence,
        auxiliary_attempt.sequence
    );
    assert_eq!(
        rig.backend
            .controls
            .iter()
            .filter(|c| matches!(c,SessionCommand::Release{lease} if lease==&primary))
            .count(),
        1,
        "auxiliary retry never replays primary"
    );
}

#[test]
fn tenant_capacity_is_reserved_before_second_parent_or_auxiliary_send() {
    let clock = TestClock::new();
    let mut sessions = NexusSessions::new(clock.clone(), Ok(capabilities()), 2);
    let mut backend = RecordingBackend::default();
    let mut parents = Vec::new();
    for name in ["first", "second"] {
        let client = ClientId::new(name).expect("client");
        parents.push(
            sessions
                .open(
                    &client,
                    accepted(&clock, name, "open", json!({})),
                    OpenSpec {
                        operation_id: OperationId::new(name).expect("operation"),
                        path: "/private/target.i64".into(),
                        options: json!({}),
                    },
                    &mut backend,
                )
                .expect("one physical slot per pending parent"),
        );
    }
    let before = backend.business.len();
    assert_eq!(
        sessions
            .reserve_acquisition(&parents[0], AcquisitionPurpose::Auxiliary)
            .expect_err("tenant has no second slot")
            .code,
        NexusErrorCode::Busy
    );
    assert_eq!(
        backend.business.len(),
        before,
        "full tenant cannot issue another SDK acquisition"
    );
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_primary_and_auxiliary_progress_independently_to_actual_caller() {
    use ida_mcp::{
        preprocess::Preparation,
        router::{nexus_bridge::BridgeConfig, RouterState},
    };
    use serde_json::Value;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    for scenario in [
        "auxiliary-healthy",
        "auxiliary-fault",
        "auxiliary-uncertain",
        "auxiliary-sibling-join",
        "auxiliary-sibling-leave",
        "primary-uncertain",
        "late-auxiliary-fault",
    ] {
        let root = base.join(scenario);
        std::fs::create_dir(&root).expect("new scenario");
        let router = RouterState::new().expect("router");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R3B_CASE".into(), scenario.into());
        environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r2_multi_bridge.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("production bridge/helper");
        let mut events = bridge.subscribe();
        let result:anyhow::Result<Value>=async {
            let (_,token)=router.ensure_worker_prepared(root.join("a/tiny.i64").to_str().expect("path"),None,None,
                Preparation::new(Duration::from_secs(15))).await?;
            let ready=tokio::time::timeout(Duration::from_secs(2),async {
                loop {let event=events.recv().await?;if event["event"]=="opened" {break Ok::<_,anyhow::Error>(event);}}
            }).await??;
            let primary:SessionLease=serde_json::from_value(ready["lease"].clone())?;
            if scenario!="late-auxiliary-fault" {
                std::fs::write(root.join("a/disconnect-primary"),b"")?;
                tokio::time::timeout(Duration::from_secs(2),async {
                    loop {let event=events.recv().await?;if event["event"]=="disconnected" {break Ok::<_,anyhow::Error>(());}}
                }).await??;
            }
            let closed=tokio::time::timeout(Duration::from_secs(12),router.nexus_close_token(&token)).await?;
            if scenario=="auxiliary-healthy" || scenario=="late-auxiliary-fault" || scenario.starts_with("auxiliary-sibling-") {anyhow::ensure!(closed.is_ok(),"{closed:?}");}
            else {anyhow::ensure!(closed.is_err(),"actual caller cannot hide auxiliary failure: {closed:?}");}
            if scenario=="late-auxiliary-fault" {
                anyhow::ensure!(bridge.endpoint().transition(|s,_|s.release_members(&primary))?.len()==1,
                    "late auxiliary must actually start after the primary caller ended");
                let context:Vec<String>=serde_json::from_slice(&std::fs::read(root.join("late-cleanup-context.json"))?)?;
                tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                    use std::io::{Read,Write};
                    let mut socket=std::os::unix::net::UnixStream::connect(&context[2])?;
                    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                    socket.write_all(format!("cleanup:{}:{}",context[0],context[1]).as_bytes())?;
                    let mut ack=[0;2];socket.read_exact(&mut ack)?;
                    anyhow::ensure!(&ack==b"ok","adapter must acknowledge actual auxiliary custody");Ok(())
                }).await??;
                tokio::time::timeout(Duration::from_secs(3),async {
                    loop {
                        let members=bridge.endpoint().transition(|s,_|s.release_members(&primary))?;
                        if let Some(child)=members.get(1) {
                            let state=bridge.endpoint().transition(|s,_|s.status(&child.client_id,child))?;
                            if state.control_delivery.as_ref().is_some_and(|d|d.state==DeliveryState::NotSent) {break Ok::<_,anyhow::Error>(());}
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }).await??;
            }
            let members=bridge.endpoint().transition(|s,_|s.release_members(&primary))?;
            anyhow::ensure!(members.len()==2,"both actual handles require independent custody: {members:?}");
            let first=bridge.endpoint().transition(|s,_|s.status(&primary.client_id,&primary))?;
            let auxiliary=&members[1];
            if scenario=="primary-uncertain" {
                tokio::time::timeout(Duration::from_secs(3),async {
                    while bridge.endpoint().transition(|s,_|s.status(&auxiliary.client_id,auxiliary))?.phase!=SessionPhase::Released {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Ok::<_,anyhow::Error>(())
                }).await??;
            }
            let second=bridge.endpoint().transition(|s,_|s.status(&auxiliary.client_id,auxiliary))?;
            if scenario=="primary-uncertain" {
                anyhow::ensure!(first.control_delivery.as_ref().is_some_and(|d|d.state==DeliveryState::Uncertain),"primary unknown history lost: {first:?}");
            } else {anyhow::ensure!(first.phase==SessionPhase::Released,"primary ACK must survive auxiliary error: {first:?}");}
            match scenario {
                "auxiliary-healthy" | "auxiliary-sibling-join" | "auxiliary-sibling-leave" | "primary-uncertain" => anyhow::ensure!(second.phase==SessionPhase::Released,"{second:?}"),
                "auxiliary-fault" | "late-auxiliary-fault" => anyhow::ensure!(second.control_delivery.as_ref().is_some_and(|d|d.state==DeliveryState::NotSent),"{second:?}"),
                _ => anyhow::ensure!(second.control_delivery.as_ref().is_some_and(|d|d.state==DeliveryState::Uncertain),"{second:?}"),
            }
            std::fs::write(root.join("a/snapshot-request"),b"")?;
            tokio::time::timeout(Duration::from_secs(2),async {
                while !root.join("a/requests.json").exists(){tokio::time::sleep(Duration::from_millis(5)).await;}
            }).await?;
            let requests:Vec<Value>=serde_json::from_slice(&std::fs::read(root.join("a/requests.json"))?)?;
            let detach_count=requests.iter().filter(|r|r["endpoint"]=="/release_lease").count();
            anyhow::ensure!(detach_count==if scenario=="auxiliary-fault" || scenario=="late-auxiliary-fault" {1}else if scenario=="auxiliary-sibling-leave"{3}else{2},"per-handle requests replayed or lost: {requests:?}");
            bridge.status("member-sets").await?;
            let local=tokio::time::timeout(Duration::from_secs(2),async {
                loop {let event=events.recv().await?;if event["event"]=="local_status" {break Ok::<_,anyhow::Error>(event);}}
            }).await??;
            let parent=local["n1_acquisitions"]["parents"].as_array().ok_or_else(||anyhow::anyhow!("actual N1 parents missing"))?
                .iter().find(|p|p["acquisitions"].as_array().is_some_and(|a|a.iter().any(|a|a["lease"]["lease_id"]==primary.lease_id.as_str())))
                .ok_or_else(||anyhow::anyhow!("primary parent missing"))?;
            let acquisitions=parent["acquisitions"].as_array().ok_or_else(||anyhow::anyhow!("acquisitions missing"))?;
            let mut remote_members=std::collections::BTreeSet::new();
            let mut pending=std::collections::BTreeSet::new();
            for acquisition in acquisitions {
                let operations=acquisition["public_operation_ids"].as_array().ok_or_else(||anyhow::anyhow!("N1 exact operation IDs missing"))?;
                let mapped=requests.iter().filter(|r|operations.contains(&r["operation_id"]))
                    .filter_map(|r|r["lease_id"].as_str()).collect::<std::collections::BTreeSet<_>>();
                anyhow::ensure!(mapped.len()==1,"public operation identity cannot map physical member: {acquisition}");
                remote_members.extend(mapped.into_iter().map(str::to_owned));
                if acquisition["physical_slot"]==true {pending.insert(acquisition["lease"]["lease_id"].as_str().unwrap_or("").to_owned());}
            }
            let held=local["held"].as_array().ok_or_else(||anyhow::anyhow!("Python owned set missing"))?;
            let held_ids=held.iter().filter_map(|h|h["lease"]["lease_id"].as_str()).map(str::to_owned).collect::<std::collections::BTreeSet<_>>();
            anyhow::ensure!(pending==held_ids && remote_members.len()==2,"physical custody sets differ: {local}");
            let server_live:Vec<String>=serde_json::from_slice(&std::fs::read(root.join("a/leases.json"))?)?;
            let third_party=requests.iter().filter(|r|r["operation_id"]=="third-party-member")
                .filter_map(|r|r["lease_id"].as_str()).map(str::to_owned).collect::<std::collections::BTreeSet<_>>();
            anyhow::ensure!(server_live.iter().all(|lease|remote_members.contains(lease) || third_party.contains(lease)),"hidden owned server member");
            if scenario.starts_with("auxiliary-sibling-") {
                anyhow::ensure!(third_party.len()==1,"external public sibling was not actually attached");
                let facts=router.status_snapshot().await.owner_observations;
                let primary_facts=facts.iter().find(|f|f["lease"]["lease_id"]==primary.lease_id.as_str()).ok_or_else(||anyhow::anyhow!("primary diagnostics"))?;
                anyhow::ensure!(primary_facts["outcome"]["ack_kind"]=="nonlast","{primary_facts}");
                let child=primary_facts["owned_members"].as_array().and_then(|a|a.first()).ok_or_else(||anyhow::anyhow!("child diagnostics"))?;
                anyhow::ensure!(child["outcome"]["ack_kind"]==if scenario=="auxiliary-sibling-join"{"nonlast"}else{"last"},"dynamic membership was not applied: {child}");
            }
            if scenario=="auxiliary-fault" || scenario=="late-auxiliary-fault" {
                anyhow::ensure!(server_live.len()==1,"NotSent member lost actual server handle");
                if scenario=="late-auxiliary-fault" {
                    let status=router.status_snapshot().await.owner_observations;
                    anyhow::ensure!(serde_json::to_string(&status)?.contains("controlled auxiliary save protection failure"),
                        "late typed cause must remain visible in the actual caller status: {status:?}");
                }
                let retried=router.nexus_close_token(&token).await?;
                anyhow::ensure!(retried.is_some(),"released primary token must retain cleanup-only auxiliary access");
                let after=bridge.endpoint().transition(|s,_|s.status(&auxiliary.client_id,auxiliary))?;
                anyhow::ensure!(after.phase==SessionPhase::Released,"fresh auxiliary attempt did not detach: {after:?}");
            } else if scenario=="auxiliary-uncertain" || scenario=="primary-uncertain" {
                anyhow::ensure!(server_live.is_empty() && held.iter().all(|h|h["responsibility"]=="InFlight"),"unknown difference lacks explicit InFlight: {local}");
                anyhow::ensure!(router.nexus_close_token(&token).await.is_err(),"unknown member cannot be silently retried or forgotten");
            } else if scenario=="auxiliary-sibling-join" {anyhow::ensure!(server_live.len()==1 && third_party.contains(&server_live[0]),"sibling live set lost");}
            else {anyhow::ensure!(server_live.is_empty(),"healthy own server set not empty");}
            let (_,other)=router.ensure_worker_prepared(root.join("b/tiny.i64").to_str().expect("path"),None,None,
                Preparation::new(Duration::from_secs(10))).await?;
            tokio::time::timeout(Duration::from_secs(2),router.nexus_close_token(&other)).await??;
            Ok(json!({"caller":format!("{closed:?}"),"primary":first,"auxiliary":second,"requests":requests,"physical_sets":local,"server_live":server_live}))
        }.await;
        for name in ["a", "b"] {
            std::fs::write(root.join(name).join("guard.release"), b"").expect("finally guard");
            std::fs::write(root.join(name).join("owner-release"), b"").expect("finally owner");
        }
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            while bridge.lifecycle_status()["resources"] != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let stopped = bridge.shutdown().await;
        std::fs::write(
            root.join("auxiliary-result.json"),
            serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
            "settled":settled.is_ok(),"shutdown":format!("{stopped:?}")}))
            .expect("encode"),
        )
        .expect("evidence");
        if scenario == "auxiliary-uncertain" || scenario == "primary-uncertain" {
            let final_requests: Vec<Value> = serde_json::from_slice(
                &std::fs::read(root.join("a/requests.json")).expect("final HTTP ledger"),
            )
            .expect("requests");
            assert_eq!(
                final_requests
                    .iter()
                    .filter(|r| r["endpoint"] == "/release_lease")
                    .count(),
                2,
                "unknown member must never replay after repeated close or public proof; {result:?}"
            );
        }
        settled.expect("each independent resource settles");
        stopped.expect("natural shutdown");
        result.expect("physical members and actual Tools caller");
    }
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test]
async fn r9_three_attempts_share_parent_and_third_failure_keeps_original_cause() {
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    for failures in 1..=3 {
        let root = base.join(format!("failures-{failures}"));
        std::fs::create_dir(&root).expect("new scenario");
        let router = RouterState::new().expect("router");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R3A_SCENARIO".into(), "r9-multiple".into());
        environment.insert("R3B_R9_FAILURES".into(), failures.to_string());
        environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r3a_bridge_fixture.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("actual N1/production bridge/helper/SDK");
        let mut events = bridge.subscribe();
        let client = ClientId::new("r9-parent").expect("client");
        let parent = bridge
            .endpoint()
            .transition(|s, t| {
                s.open(
                    &client,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new("r9-open")?,
                        None,
                        "open",
                        json!({"timeout_secs":25}),
                    )?,
                    OpenSpec {
                        operation_id: OperationId::new("r9-open")?,
                        path: root.join("tiny.i64").display().to_string(),
                        options: json!({"spawn":false,"wait_analysis":false}),
                    },
                    t,
                )
            })
            .expect("original parent admission");
        let result: anyhow::Result<Value> = async {
            let mut evidence = Vec::new();
            let terminal = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let event = events.recv().await?;
                    evidence.push(event.clone());
                    if event["attempt"]["target"]["kind"] == "open"
                        && ["opened", "failed", "uncertain"]
                            .iter()
                            .any(|kind| event["event"] == *kind)
                    {
                        break Ok::<_, anyhow::Error>(event);
                    }
                }
            })
            .await??;
            if failures < 3 {
                anyhow::ensure!(terminal["event"] == "opened", "{terminal}");
                anyhow::ensure!(
                    terminal["acquisition"]["ordinal"] == failures + 1,
                    "{terminal}"
                );
                let lease: SessionLease = serde_json::from_value(terminal["lease"].clone())?;
                bridge
                    .endpoint()
                    .transition(|s, t| s.release(&client, &lease, t))?;
            } else {
                anyhow::ensure!(
                    terminal["event"] == "failed"
                        && terminal["error"]["message"]
                            .as_str()
                            .is_some_and(|s| s.contains("after 3 attempts")),
                    "{terminal}"
                );
                anyhow::ensure!(
                    bridge
                        .endpoint()
                        .transition(|s, _| s.open_progress(&client, &parent))?
                        .1
                        .is_some(),
                    "original parent failure missing after resource settlement"
                );
            }
            std::fs::write(root.join("snapshot-request"), b"")?;
            tokio::time::timeout(Duration::from_secs(2), async {
                while !root.join("snapshot.json").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            let snapshot: Value =
                serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
            let attaches = snapshot["requests"]
                .as_array()
                .expect("actual HTTP ledger")
                .iter()
                .filter(|r| r["endpoint"] == "lease")
                .count();
            anyhow::ensure!(
                attaches == usize::min(failures as usize + 1, 3),
                "unexpected replay/fourth acquisition: {snapshot}"
            );
            Ok(json!({"terminal":terminal,"snapshot":snapshot,"events":evidence}))
        }
        .await;
        std::fs::write(root.join("r9-release.release"), b"").expect("finally release barrier");
        std::fs::write(root.join("owner-release"), b"").expect("finally owner");
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            while bridge.lifecycle_status()["resources"] != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let stopped = bridge.shutdown().await;
        std::fs::write(
            root.join("r9-result.json"),
            serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
            "settled":settled.is_ok(),"shutdown":format!("{stopped:?}")}))
            .expect("encode"),
        )
        .expect("evidence");
        settled.expect("no old physical responsibility lost");
        stopped.expect("natural shutdown");
        result.expect("bounded managed root retries");
    }
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verification_failure_cancel_and_acquired_initialization_failure_keep_copy_custody() {
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    for scenario in [
        "verification-failure",
        "verification-cancel",
        "verification-init-failure",
    ] {
        let root = base.join(scenario);
        std::fs::create_dir(&root).expect("new scenario");
        std::fs::write(root.join("input"), b"verification input").expect("input snapshot");
        let router = RouterState::new().expect("router");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R3B_CASE".into(), scenario.into());
        environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r2_multi_bridge.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("actual adapter/helper");
        let mut events = bridge.subscribe();
        let client = ClientId::new("verification-failed-parent").expect("client");
        let parent=bridge.endpoint().transition(|s,t|s.open(&client,
            AcceptedRequest::new(&SystemClock,RequestId::new("verify-open")?,None,"open",json!({"timeout_secs":20}))?,
            OpenSpec{operation_id:OperationId::new("verify-open")?,path:root.join("b/tiny.i64").display().to_string(),
                options:json!({"spawn":false,"verification_idb":root.join("a/tiny.i64"),"verify_input_snapshot":root.join("input")})},t))
            .expect("original parent");
        let result: anyhow::Result<Value> = async {
            tokio::time::timeout(Duration::from_secs(8), async {
                while !root.join("a/release-requested").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            anyhow::ensure!(!root.join("a/closed").exists(), "unproved copy removed");
            if scenario == "verification-cancel" {
                bridge
                    .endpoint()
                    .transition(|s, _| s.cancel_open(&client, &parent))?;
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let event = events.recv().await?;
                        if event["event"] == "failed"
                            && event["attempt"]["target"]["kind"] == "open"
                        {
                            break Ok::<_, anyhow::Error>(());
                        }
                    }
                })
                .await??;
                anyhow::ensure!(
                    !root.join("a/closed").exists(),
                    "caller ending cannot delete the unproved copy"
                );
            }
            bridge.status("before-proof").await?;
            let held = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let event = events.recv().await?;
                    if event["event"] == "local_status" {
                        break Ok::<_, anyhow::Error>(event);
                    }
                }
            })
            .await??;
            anyhow::ensure!(
                held["custodians"] == 1,
                "actual acquired resource must remain owned: {held}"
            );
            std::fs::write(root.join("a/owner-release"), b"")?;
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    let (_, failure) = bridge
                        .endpoint()
                        .transition(|s, _| s.open_progress(&client, &parent))?;
                    if failure.is_some() && root.join("a/closed").is_file() {
                        break Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await??;
            let (lease, failure) = bridge
                .endpoint()
                .transition(|s, _| s.open_progress(&client, &parent))?;
            anyhow::ensure!(
                lease.is_none(),
                "verification may never become a final parent lease"
            );
            let failure =
                failure.ok_or_else(|| anyhow::anyhow!("original error missing after cleanup"))?;
            if scenario == "verification-failure" {
                anyhow::ensure!(
                    format!("{failure:?}").contains("controlled original verification error"),
                    "{failure:?}"
                );
            }
            if scenario == "verification-init-failure" {
                anyhow::ensure!(
                    failure
                        .message
                        .contains("controlled monitor thread start failure"),
                    "{failure:?}"
                );
            }
            Ok(json!({"failure":failure,"held":held,"copy_closed":true}))
        }
        .await;
        for name in ["a", "b"] {
            std::fs::write(root.join(name).join("guard.release"), b"").expect("finally guard");
            std::fs::write(root.join(name).join("owner-release"), b"").expect("finally owner");
        }
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            while bridge.lifecycle_status()["resources"] != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let stopped = bridge.shutdown().await;
        std::fs::write(
            root.join("verification-failure-result.json"),
            serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
            "settled":settled.is_ok(),"shutdown":format!("{stopped:?}")}))
            .expect("encode"),
        )
        .expect("evidence");
        settled.expect("all exact custody settles");
        stopped.expect("natural shutdown");
        result.expect("original error and copy closure responsibility");
    }
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test]
async fn gui_root_failure_and_retry_deadline_never_create_another_acquisition() {
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    for scenario in ["r9-gui", "r9-expired-after-cleanup"] {
        let root = base.join(scenario);
        std::fs::create_dir(&root).expect("private case");
        let router = RouterState::new().expect("router");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
        environment.insert("R3A_SCENARIO".into(), scenario.into());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r3a_bridge_fixture.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("actual Rust/SDK/bridge/helper with GUI or clock inputs");
        let mut events = bridge.subscribe();
        let client = ClientId::new("r9-single").expect("client");
        bridge
            .endpoint()
            .transition(|s, t| {
                s.open(
                    &client,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new("single-open")?,
                        None,
                        "open",
                        json!({"timeout_secs":20}),
                    )?,
                    OpenSpec {
                        operation_id: OperationId::new("single-open")?,
                        path: root.join("tiny.i64").display().to_string(),
                        options: json!({"spawn":false,"wait_analysis":false}),
                    },
                    t,
                )
            })
            .expect("parent");
        let result:anyhow::Result<Value>=async {
            let terminal=tokio::time::timeout(Duration::from_secs(8),async {
                loop {let event=events.recv().await?;if event["attempt"]["target"]["kind"]=="open"
                    && ["opened","failed","uncertain"].iter().any(|e|event["event"]==*e) {break Ok::<_,anyhow::Error>(event);}}
            }).await??;
            anyhow::ensure!(terminal["event"]=="failed","{terminal}");
            if scenario=="r9-gui" {
                anyhow::ensure!(!root.join("owner-released").exists() && !root.join("r9-public-exit").exists(),"product closed shared GUI owner");
                anyhow::ensure!(terminal["error"]["message"].as_str().is_some_and(|s|s.contains("no initial Root retry")),"{terminal}");
            } else {
                anyhow::ensure!(root.join("r9-expiry.json").is_file(),"original deadline fence not reached after accepted cleanup");
                anyhow::ensure!(terminal["error"]["message"].as_str().is_some_and(|s|s.contains("original open budget exhausted")),"{terminal}");
            }
            std::fs::write(root.join("snapshot-request"),b"")?;
            tokio::time::timeout(Duration::from_secs(2),async {while !root.join("snapshot.json").exists(){tokio::time::sleep(Duration::from_millis(5)).await;}}).await?;
            let snapshot:Value=serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
            let requests=snapshot["requests"].as_array().ok_or_else(||anyhow::anyhow!("HTTP ledger"))?;
            anyhow::ensure!(requests.iter().filter(|r|r["endpoint"]=="lease").count()==1,"a forbidden next acquisition was attached");
            anyhow::ensure!(requests.iter().filter(|r|r["endpoint"]=="/release_lease").count()==1,"own detach was replayed");
            anyhow::ensure!(!requests.iter().any(|r|r["endpoint"]=="/shutdown_database"),"GUI/shared owner shutdown requested");
            Ok(json!({"terminal":terminal,"snapshot":snapshot,"scope":"GUI/stub or exact adapter-clock input, not real GUI/reboot"}))
        }.await;
        std::fs::write(root.join("owner-release"), b"").expect("finally external owner");
        std::fs::write(root.join("r9-release.release"), b"").expect("finally barrier");
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            while bridge.lifecycle_status()["resources"] != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let stopped = bridge.shutdown().await;
        std::fs::write(
            root.join("r9-boundary-result.json"),
            serde_json::to_vec_pretty(
                &json!({"result":format!("{result:?}"),"settled":settled.is_ok(),
            "shutdown":format!("{stopped:?}")}),
            )
            .expect("encode"),
        )
        .expect("evidence");
        settled.expect("old exact custody settled");
        stopped.expect("natural teardown");
        result.expect("no GUI reopen or expired next side effect");
    }
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acquired_ack_loss_then_public_proof_never_reallocates_the_physical_lease() {
    late_custody_proof_case("custody-ack-lost").await;
    late_custody_proof_case("custody-before-callback").await;
}

#[cfg(feature = "nexus-test-support")]
async fn late_custody_proof_case(scenario: &str) {
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let root =
        PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root")).join(scenario);
    std::fs::create_dir(&root).expect("scenario");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3B_CASE".into(), scenario.into());
    environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r2_multi_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("actual adapter/helper");
    let mut events = bridge.subscribe();
    let client = ClientId::new("ack-loss-parent").expect("client");
    let parent = bridge
        .endpoint()
        .transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("ack-loss-open")?,
                    None,
                    "open",
                    json!({"timeout_secs":20}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new("ack-loss-open")?,
                    path: root.join("a/tiny.i64").display().to_string(),
                    options: json!({"spawn":false}),
                },
                t,
            )
        })
        .expect("parent");
    let result: anyhow::Result<Value> = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !root.join("custody-dropped.json").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let leases: Vec<SessionLease> =
            serde_json::from_slice(&std::fs::read(root.join("custody-dropped.json"))?)?;
        anyhow::ensure!(
            leases.len() == 1,
            "exact physical lease must precede lost custody ACK"
        );
        let acquisition = AcquisitionId {
            parent: parent.clone(),
            purpose: AcquisitionPurpose::Final,
            ordinal: 1,
        };
        let registered = bridge
            .endpoint()
            .transition(|s, _| s.acquisition_lease(&acquisition))?;
        anyhow::ensure!(
            registered
                == if scenario == "custody-ack-lost" {
                    Some(leases[0].clone())
                } else {
                    None
                }
        );
        std::fs::write(root.join("a/owner-release"), b"")?;
        let mut evidence = Vec::new();
        if scenario == "custody-before-callback" {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let event = events.recv().await?;
                    let settled = event["event"] == "startup_settled";
                    evidence.push(event);
                    if settled {
                        break Ok::<_, anyhow::Error>(());
                    }
                }
            })
            .await??;
            std::fs::write(root.join("acquired-resume"), b"")?;
        }
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let event = events.recv().await?;
                use std::io::Write;
                writeln!(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(root.join("ack-loss-events.jsonl"))?,
                    "{}",
                    serde_json::to_string(&event)?
                )?;
                let finished = event["event"] == "failed"
                    && event["error"]["message"].as_str().is_some_and(|m| {
                        m.contains(if scenario == "custody-ack-lost" {
                            "custody IPC acknowledgement missing"
                        } else {
                            "cleanup-only"
                        })
                    });
                evidence.push(event);
                if finished {
                    break Ok::<_, anyhow::Error>(());
                }
            }
        })
        .await??;
        anyhow::ensure!(
            bridge
                .endpoint()
                .transition(|s, _| s.acquisition_lease(&acquisition))?
                == Some(leases[0].clone()),
            "late SDK callback may never assign a new LeaseKey"
        );
        anyhow::ensure!(
            bridge
                .endpoint()
                .transition(|s, _| s.status(&client, &leases[0]))?
                .phase
                == SessionPhase::Released
        );
        std::fs::write(root.join("a/snapshot-request"), b"")?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !root.join("a/requests.json").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let requests: Vec<Value> =
            serde_json::from_slice(&std::fs::read(root.join("a/requests.json"))?)?;
        anyhow::ensure!(
            !requests
                .iter()
                .any(|r| r["endpoint"] == "/execute_python" || r["endpoint"] == "/release_lease"),
            "no preparation, cleanup RPC, or fabricated detach after owner exit: {requests:?}"
        );
        Ok(json!({"lease":leases[0],"events":evidence,"requests":requests}))
    }
    .await;
    std::fs::write(root.join("acquired-resume"), b"").expect("finally callback");
    for name in ["a", "b"] {
        std::fs::write(root.join(name).join("owner-release"), b"").expect("finally owner");
    }
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let stopped = bridge.shutdown().await;
    std::fs::write(
        root.join("ack-loss-result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "settled":settled.is_ok(),"shutdown":format!("{stopped:?}")}))
        .expect("encode"),
    )
    .expect("evidence");
    settled.expect("exact ownership settles");
    stopped.expect("natural shutdown");
    result.expect("ACK loss and public proof keep one physical LeaseKey and original error");
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_root_retry_restores_accepted_snapshot_after_parent_terminal() {
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::os::fd::AsRawFd;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"))
        .join("restore-parent");
    std::fs::create_dir(&root).expect("private restore case");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_SCENARIO".into(), "r9-restore-held".into());
    environment.insert("R3A_MANAGED".into(), "1".into());
    environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("actual bridge/helper and native state inputs");
    let mut events = bridge.subscribe();
    let client = ClientId::new("cancelled-restore").expect("client");
    let target = root.join("cache/generations/g-fixed/input.i64");
    let parent = bridge
        .endpoint()
        .transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("restore-open")?,
                    None,
                    "open",
                    json!({"timeout_secs":20}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new("restore-open")?,
                    path: target.display().to_string(),
                    options: json!({"spawn":false}),
                },
                t,
            )
        })
        .expect("original parent");
    let result: anyhow::Result<Value> = async {
        tokio::time::timeout(Duration::from_secs(8), async {
            while !root.join("release-requested").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        bridge
            .endpoint()
            .transition(|s, _| s.cancel_open(&client, &parent))?;
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let e = events.recv().await?;
                use std::io::Write;
                writeln!(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(root.join("restore-events.jsonl"))?,
                    "{}",
                    serde_json::to_string(&e)?
                )?;
                if e["event"] == "failed" && e["attempt"]["target"]["kind"] == "open" {
                    break Ok::<_, anyhow::Error>(());
                }
            }
        })
        .await??;
        let snapshot = PathBuf::from(std::fs::read_to_string(root.join("snapshot-ready"))?);
        anyhow::ensure!(target.exists() && std::fs::read(&target)? == b"failed recovered packed");
        let before: Value =
            serde_json::from_slice(&std::fs::read(snapshot.join("recovery.json"))?)?;
        anyhow::ensure!(before["status"] == "failed-owner-held", "{before}");
        std::fs::write(root.join("owner-release"), b"")?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while bridge.lifecycle_status()["resources"] != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let cache_lock = std::fs::File::open(root.join("cache/.cache.lock"))?;
        // SAFETY: independent descriptor probes EX without changing another OFD's lock.
        anyhow::ensure!(
            unsafe { libc::flock(cache_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0,
            "file recovery must retain root SH after physical custody has settled"
        );
        std::fs::write(root.join("restore.release"), b"")?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let data: Value =
                    serde_json::from_slice(&std::fs::read(snapshot.join("recovery.json"))?)?;
                if data["status"] == "restored" {
                    break Ok::<_, anyhow::Error>(data);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        anyhow::ensure!(std::fs::read(&target)? == b"R0 external database-state input");
        anyhow::ensure!(
            std::fs::read(target.with_extension("id0"))?
                == [vec![0; 18], b"\x01B-tree v2original component".to_vec()].concat()
        );
        let (_, failure) = bridge
            .endpoint()
            .transition(|s, _| s.open_progress(&client, &parent))?;
        anyhow::ensure!(
            failure.is_some(),
            "restoration may not revive the cancelled user operation"
        );
        std::fs::write(root.join("snapshot-request"), b"")?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !root.join("snapshot.json").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let requests: Value = serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
        anyhow::ensure!(
            requests["requests"]
                .as_array()
                .expect("HTTP ledger")
                .iter()
                .filter(|r| r["endpoint"] == "lease")
                .count()
                == 1,
            "cancelled parent cannot perform its next acquisition"
        );
        Ok(json!({"snapshot":snapshot,"before":before,"failure":failure,"requests":requests}))
    }
    .await;
    std::fs::write(root.join("restore.release"), b"").expect("finally restore");
    std::fs::write(root.join("owner-release"), b"").expect("finally owner");
    let stopped = bridge.shutdown().await;
    std::fs::write(
        root.join("restore-result.json"),
        serde_json::to_vec_pretty(
            &json!({"result":format!("{result:?}"),"shutdown":format!("{stopped:?}")}),
        )
        .expect("encode"),
    )
    .expect("evidence");
    stopped.expect("natural shutdown");
    result.expect("accepted snapshot outlives cancelled parent and retains exact locks");
}
