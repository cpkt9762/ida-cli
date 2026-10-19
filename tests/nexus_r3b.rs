//! K2 acquisition contracts. Cross-layer cases use the production adapter below.
use ida_mcp::nexus::*;
#[cfg(feature = "nexus-test-support")]
use ida_mcp::process_spawn::AsyncOutputFenced;
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
                "verification_idb":root.join("vcopy/probe.i64"), "verify_input_snapshot":root.join("input")}) }, t))
        .expect("parent reserves verification first");
    let result: anyhow::Result<Value> = async {
        tokio::time::timeout(Duration::from_secs(8), async {
            let verification = AcquisitionId {
                parent: parent.clone(),
                purpose: AcquisitionPurpose::Verification,
                ordinal: 1,
            };
            loop {
                // The HTTP fixture's marker precedes the ACK. Observe N1's
                // exact member terminal before asserting the post-ACK view.
                let detached = bridge.endpoint().transition(|sessions, _| {
                    let Some(lease) = sessions.acquisition_lease(&verification)? else {
                        return Ok::<_, NexusError>(false);
                    };
                    Ok(sessions.status(&client, &lease)?.phase == SessionPhase::Released)
                })?;
                if root.join("a/release-requested").exists() && detached {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
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
            !root.join("vcopy/closed").exists(),
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
            root.join("vcopy/closed").is_file(),
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
        "result":format!("{result:?}"),"actual":result.as_ref().ok(),"settled":settled.is_ok(),"shutdown":format!("{stopped:?}")})).expect("encode")).expect("evidence");
    settled.expect("all exact resources consume independent public proof");
    stopped.expect("natural shutdown");
    result.expect("actual SDK/Rust/N1/production bridge verification");
    if std::env::var_os("R4_PARENT_SCHEDULE").is_some() {
        let reserved: Value = serde_json::from_slice(
            &std::fs::read(root.join("successor-reserved.json"))
                .expect("scheduled successor evidence"),
        )
        .expect("structured reservation evidence");
        assert_eq!(
            reserved["retirement_still_paused"], false,
            "successor reserved before predecessor helper retirement"
        );
        assert_eq!(reserved["acquisition"]["ordinal"], 2);
        assert_eq!(reserved["acquisition"]["purpose"], "final");
    }
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
        "auxiliary-deadline",
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
                "auxiliary-fault" | "late-auxiliary-fault" | "auxiliary-deadline" => anyhow::ensure!(second.control_delivery.as_ref().is_some_and(|d|d.state==DeliveryState::NotSent),"{second:?}"),
                _ => anyhow::ensure!(second.control_delivery.as_ref().is_some_and(|d|d.state==DeliveryState::Uncertain),"{second:?}"),
            }
            std::fs::write(root.join("a/snapshot-request"),b"")?;
            tokio::time::timeout(Duration::from_secs(2),async {
                while !root.join("a/requests.json").exists(){tokio::time::sleep(Duration::from_millis(5)).await;}
            }).await?;
            let requests:Vec<Value>=serde_json::from_slice(&std::fs::read(root.join("a/requests.json"))?)?;
            let detach_count=requests.iter().filter(|r|r["endpoint"]=="/release_lease").count();
            anyhow::ensure!(detach_count==if scenario=="auxiliary-fault" || scenario=="late-auxiliary-fault" || scenario=="auxiliary-deadline" {1}else if scenario=="auxiliary-sibling-leave"{3}else{2},"per-handle requests replayed or lost: {requests:?}");
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
            if scenario=="auxiliary-fault" || scenario=="late-auxiliary-fault" || scenario=="auxiliary-deadline" {
                anyhow::ensure!(server_live.len()==1,"NotSent member lost actual server handle");
                if scenario=="late-auxiliary-fault" {
                    let status=router.status_snapshot().await.owner_observations;
                    anyhow::ensure!(serde_json::to_string(&status)?.contains("controlled auxiliary save protection failure"),
                        "late typed cause must remain visible in the actual caller status: {status:?}");
                }
                if scenario=="auxiliary-deadline" {
                    let protection:Value=serde_json::from_slice(&std::fs::read(root.join("deadline-after-guard.json"))?)?;
                    anyhow::ensure!(protection["protection"]["close_safe"]==true && protection["detach_called"]==false,
                        "deadline boundary must follow a real healthy guard");
                    anyhow::ensure!(second.control_delivery.as_ref().and_then(|d|d.error.as_ref())
                        .is_some_and(|e|e.message.contains("original close budget exhausted")),"late deadline lost its cause: {second:?}");
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
            let transitions:Vec<Value>=serde_json::from_slice(&std::fs::read(root.join("a/transitions.json"))?)?;
            for edge in &transitions {
                if edge["edge"]=="detach" {
                    let remaining=edge["after"].as_array().ok_or_else(||anyhow::anyhow!("missing real successor set"))?;
                    anyhow::ensure!(edge["ack_kind"]==if remaining.is_empty(){"last"}else{"nonlast"},
                        "ACK must be derived from the actual detach successor, never prefilled: {edge}");
                }
            }
            for member in &remote_members {
                anyhow::ensure!(requests.iter().filter(|r|r["endpoint"]=="/release_lease" && r["lease_id"]==*member).count()<=1,
                    "I2: physical member detach replayed");
            }
            let (_,other)=router.ensure_worker_prepared(root.join("b/tiny.i64").to_str().expect("path"),None,None,
                Preparation::new(Duration::from_secs(10))).await?;
            tokio::time::timeout(Duration::from_secs(2),router.nexus_close_token(&other)).await??;
            // I5 was inapplicable while the real owner lifetime lock was held.
            // Continue this SAME router/run after releasing that exact barrier.
            for name in ["a","b"] {std::fs::write(root.join(name).join("owner-release"),b"")?;}
            tokio::time::timeout(Duration::from_secs(8),async {
                while bridge.lifecycle_status()["resources"]!=0 || bridge.lifecycle_status()["retirement_acks"]!=0
                    || bridge.lifecycle_status()["startup_and_pre_attach"]!=0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await?;
            let final_primary=bridge.endpoint().transition(|s,_|s.status(&primary.client_id,&primary))?;
            let final_auxiliary=bridge.endpoint().transition(|s,_|s.status(&auxiliary.client_id,auxiliary))?;
            anyhow::ensure!(final_primary.phase==SessionPhase::Released && final_auxiliary.phase==SessionPhase::Released,
                "I5: actual owner release must settle both members: {final_primary:?}/{final_auxiliary:?}");
            for (before,after) in [(&first,&final_primary),(&second,&final_auxiliary)] {
                if before.control_delivery.as_ref().is_some_and(|d|d.state==DeliveryState::Uncertain) {
                    anyhow::ensure!(serde_json::to_value(&before.control_delivery)?==serde_json::to_value(&after.control_delivery)?,
                        "I3/C4: owner proof rewrote original uncertain command history");
                }
            }
            Ok(json!({"caller":format!("{closed:?}"),"primary":first,"auxiliary":second,"requests":requests,"physical_sets":local,"server_live":server_live,
                "reachable_edges":transitions,"excluded_edges":[],"I5_before_barrier":{"applicable":false,"reason":"owner lifetime held"},
                "I5_after_barrier":{"primary":final_primary,"auxiliary":final_auxiliary},
                "trace_count":1,"scenario":scenario}))
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
            serde_json::to_vec_pretty(
                &json!({"result":format!("{result:?}"),"trace":result.as_ref().ok(),
            "settled":settled.is_ok(),"shutdown":format!("{stopped:?}")}),
            )
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
                options:json!({"spawn":false,"verification_idb":root.join("vcopy/probe.i64"),"verify_input_snapshot":root.join("input")})},t))
            .expect("original parent");
        let result: anyhow::Result<Value> = async {
            tokio::time::timeout(Duration::from_secs(8), async {
                while !root.join("a/release-requested").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            anyhow::ensure!(!root.join("vcopy/closed").exists(), "unproved copy removed");
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
                    !root.join("vcopy/closed").exists(),
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
                    if failure.is_some() && root.join("vcopy/closed").is_file() {
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
    retained_file_job_case(None).await;
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_job_sender_exits_preserve_frozen_authority_and_next_gate() {
    for fault in [
        "source_before_prepare",
        "source_after_prepare",
        "source_prepared",
        "source_before_send",
        "source_sent",
    ] {
        retained_file_job_case(Some(fault)).await;
    }
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_job_receiver_exits_resume_exact_transaction() {
    for fault in [
        "receiver_start",
        "receiver_ready",
        "receiver_received",
        "receiver_before_accept",
        "receiver_accepted",
        "receiver_first_intent",
        "receiver_after_rename",
    ] {
        retained_file_job_case(Some(fault)).await;
    }
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_job_lost_ack_does_not_revoke_accepted_executor() {
    retained_file_job_case(Some("receiver_drop_ack")).await;
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_job_rejects_wrong_epoch_closes_duplicates_and_fences_both_exits() {
    for fault in ["source_bad_epoch", "source_duplicate", "both_exit"] {
        retained_file_job_case(Some(fault)).await;
    }
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn boot_retired_file_job_keeps_unknown_and_requires_current_vacancy() {
    retained_file_job_case(Some("u6_no_ack")).await;
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_job_late_prepare_reply_preserves_control_and_next_exact_gate() {
    retained_file_job_case(Some("ready_reply_late")).await;
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_epoch_gate_restores_via_rust_job_before_new_sdk_attach() {
    device_epoch_n1_case(false).await;
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_device_epoch_uses_verified_current_root_and_original_authority() {
    device_epoch_n1_case(true).await;
}

#[cfg(feature = "nexus-test-support")]
async fn device_epoch_n1_case(managed: bool) {
    use ida_mcp::preprocess::Preparation;
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::os::unix::fs::MetadataExt;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case root")).join(
        if managed {
            "managed-device-gate"
        } else {
            "device-gate"
        },
    );
    std::fs::create_dir(&root).expect("new isolated case");
    let python = PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK"));
    let produced = tokio::process::Command::new("timeout")
        .arg("12s")
        .arg(&python)
        .arg("-B")
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/nexus_bridge/test_volume_identity.py"),
        )
        .arg(if managed {
            "--produce-managed"
        } else {
            "--produce"
        })
        .arg(&root)
        .output_fenced()
        .await
        .expect("old device input process");
    std::fs::write(root.join("producer.stdout"), &produced.stdout).expect("producer evidence");
    std::fs::write(root.join("producer.stderr"), &produced.stderr).expect("producer evidence");
    assert!(
        produced.status.success(),
        "{}",
        String::from_utf8_lossy(&produced.stderr)
    );
    let reference: Value =
        serde_json::from_slice(&std::fs::read(root.join("reference.json")).expect("reference"))
            .expect("JSON");
    let target = PathBuf::from(reference["target"].as_str().expect("target"));
    let source = root.join("os-source.json");
    std::fs::write(
        &source,
        serde_json::to_vec(&json!({"creator":{"boot_id":"00000000-0000-4000-8000-000000000001"}}))
            .expect("OS input"),
    )
    .expect("OS input");
    std::fs::write(
        source.with_extension("json.boot"),
        b"00000000-0000-4000-8000-000000000001",
    )
    .expect("the new helper observes the same current OS boot input");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    environment.insert("R4_FILE_GATE_RELOCATE".into(), target.display().to_string());
    environment.insert("R2_BOOT_SOURCE_INPUT".into(), source.display().to_string());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python,
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("actual bridge/helper");
    let events = FileJobEventLog::new(&bridge, &root);
    let result: Result<(), anyhow::Error> = async {
        let (_, token) = router
            .ensure_worker_prepared(
                target.to_str().expect("path"),
                None,
                None,
                Preparation::new(Duration::from_secs(10)),
            )
            .await?;
        let before_attach: Value =
            serde_json::from_slice(&std::fs::read(root.join("r4-device-before-attach.json"))?)?;
        anyhow::ensure!(
            before_attach["status"] == "restored" && before_attach["job"]["state"] == "Completed"
        );
        anyhow::ensure!(
            before_attach["coord_key"] == reference["coord_key"],
            "no replacement target authority"
        );
        let actual_device = std::fs::metadata(&target)?.dev();
        anyhow::ensure!(
            before_attach["job"]["transfer"]["directory"][0] == actual_device,
            "Rust must verify the actual current FD, not the old logical device"
        );
        anyhow::ensure!(
            before_attach["coord_key"][if managed { "root" } else { "parent" }][0] != actual_device,
            "must actually exercise device translation"
        );
        anyhow::ensure!(
            std::fs::metadata(
                PathBuf::from(reference["directory"].as_str().expect("coord")).join("lock")
            )?
            .ino()
                == reference["lock_inode"].as_u64().expect("original inode")
        );
        anyhow::ensure!(std::fs::read(&target)? == b"exact original before device epoch");
        router.nexus_close_token(&token).await?;
        Ok(())
    }
    .await;
    std::fs::write(root.join("owner-release"), b"").expect("release own native input");
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0
            || bridge.lifecycle_status()["helper"]["file_jobs_pending"] != 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let stopped = bridge.shutdown().await;
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "settled":format!("{settled:?}"),"shutdown":format!("{stopped:?}"),
        "scope":"actual Rust/N1/SDK/helper/job, controlled native/device/boot inputs"}))
        .expect("JSON"),
    )
    .expect("evidence");
    stopped.expect("natural shutdown");
    settled.expect("natural exact native job/resource closure");
    events.check().expect("no Lagged or event-log failure");
    result.expect("gate must restore before the new SDK attach");
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_constructor_failure_archives_no_sdk_obligation_and_returns_exact_slot() {
    snapshot_constructor_case("unchanged").await;
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_constructor_changed_source_keeps_blocked_scene_and_status() {
    snapshot_constructor_case("changed-source").await;
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_constructor_saved_component_is_archived_without_rollback() {
    snapshot_constructor_case("saved-component").await;
}

#[cfg(feature = "nexus-test-support")]
async fn snapshot_constructor_case(variant: &str) {
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case root"))
        .join(format!("snapshot-constructor-{variant}"));
    std::fs::create_dir(&root).expect("new private case");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_SCENARIO".into(), "r9-restore-held".into());
    environment.insert("R3A_MANAGED".into(), "1".into());
    environment.insert("R4_SNAPSHOT_CONSTRUCTOR_FAILURE".into(), variant.into());
    environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("installed bridge/helper");
    let events = FileJobEventLog::new(&bridge, &root);
    let client = ClientId::new("snapshot-constructor").expect("client");
    let target = root.join("cache/generations/g-fixed/input.i64");
    let parent = bridge
        .endpoint()
        .transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("snapshot-constructor")?,
                    None,
                    "open",
                    json!({"timeout_secs":10}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new("snapshot-constructor")?,
                    path: target.display().to_string(),
                    options: json!({"spawn":false,"wait_analysis":false}),
                },
                t,
            )
        })
        .expect("original parent");
    let result:Result<Value,anyhow::Error>=async {
        events.wait_parent_failure(true).await?;
        let (_,failure)=bridge.endpoint().transition(|s,_|s.open_progress(&client,&parent))?;
        let failure=failure.ok_or_else(||anyhow::anyhow!("missing original failure"))?;
        let cause=serde_json::to_value(&failure)?;
        anyhow::ensure!(cause.to_string().contains("controlled snapshot constructor copy failure"),"original cause lost: {failure:?}");
        let acquisition=AcquisitionId{parent:parent.clone(),purpose:AcquisitionPurpose::Final,ordinal:1};
        let closed=bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?;
        let pointer:Value=serde_json::from_slice(&std::fs::read(root.join("snapshot-constructor-failed.json"))?)?;
        let path=PathBuf::from(pointer["path"].as_str().expect("transaction"));
        let record:Value=serde_json::from_slice(&std::fs::read(path.join("recovery.json"))?)?;
        std::fs::write(root.join("snapshot-request"),b"")?;
        tokio::time::timeout(Duration::from_secs(2),async {
            while !root.join("snapshot.json").exists(){tokio::time::sleep(Duration::from_millis(5)).await;}
        }).await?;
        let requests:Value=serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
        bridge.status("snapshot-constructor-status").await?;
        let status=tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                if let Some(value)=events.values.lock().expect("event sink").iter().find(|e|
                    e["event"]=="local_status" && e["id"]=="snapshot-constructor-status").cloned() {return value;}
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await?;
        std::fs::write(root.join("before-assertions.json"),serde_json::to_vec_pretty(&json!({
            "closed":closed,"record":record,"requests":requests,"failure":failure,"local_status":status,
            "lifecycle":bridge.lifecycle_status()}))?)?;
        if variant=="changed-source" {
            anyhow::ensure!(!closed && record["status"]=="snapshotting" && record["failure_intent"]==false,
                "changed source cannot be silently archived or release file responsibility");
            let pending=&status["recovery_cleanup"][0];
            anyhow::ensure!(pending["job_id"]==record["recovery_id"] && pending["blocked"]==true
                && pending["phase"]=="snapshotting" && pending["cause"]["code"]=="operation_failed",
                "blocked constructor file responsibility/cause disappeared from status: {status}");
            anyhow::ensure!(std::fs::read(target.parent().expect("parent").join("foreign-component"))?
                ==b"unknown component before SDK");
            anyhow::ensure!(std::fs::read(&target)?==b"R0 external database-state input");
        } else {
            anyhow::ensure!(closed,"no SDK effect may keep an exact physical slot after no-failure file archive");
            anyhow::ensure!(failure.code==NexusErrorCode::OperationFailed,"no-SDK snapshot I/O must retain its known typed cause");
            anyhow::ensure!(record["status"]=="archived" && record["failure_intent"]==false);
            anyhow::ensure!(status["recovery_cleanup"].as_array().expect("file status").is_empty());
            anyhow::ensure!(std::fs::read(&target)?==if variant=="saved-component" {
                b"independent saved component before SDK".as_slice()
            } else {b"R0 external database-state input".as_slice()});
        }
        anyhow::ensure!(requests["requests"].as_array().expect("HTTP ledger").is_empty(),"snapshot failure must precede every SDK call");
        Ok(json!({"failure":failure,"closed":closed,"phase":record["status"]}))
    }.await;
    std::fs::write(root.join("owner-release"), b"").expect("release own fixture");
    std::fs::write(root.join("restore.release"), b"").expect("release own test barrier");
    let stopped = bridge.shutdown().await;
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "shutdown":format!("{stopped:?}"),"lifecycle":bridge.lifecycle_status()}))
        .expect("JSON"),
    )
    .expect("evidence");
    stopped.expect("no-SDK failure must naturally shut down");
    events.check().expect("no Lagged or missing events");
    result.expect("snapshot constructor cause, exact file obligation and physical slot");
}

#[cfg(feature = "nexus-test-support")]
struct FileJobEventLog {
    values: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    task: tokio::task::JoinHandle<()>,
}
#[cfg(feature = "nexus-test-support")]
impl FileJobEventLog {
    fn new(bridge: &ida_mcp::router::nexus_bridge::NexusBridge, root: &std::path::Path) -> Self {
        let mut receiver = bridge.subscribe();
        let values = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let error = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = values.clone();
        let failure = error.clone();
        let path = root.join("restore-events.jsonl");
        let task = tokio::spawn(async move {
            use std::io::Write;
            loop {
                let result: Result<bool, anyhow::Error> = async {
                    match receiver.recv().await {
                        Ok(event) => {
                            let mut events = sink.lock().expect("test event sink");
                            anyhow::ensure!(events.len() < 4096, "test event sink overflow");
                            let mut log = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&path)?;
                            writeln!(log, "{}", serde_json::to_string(&event)?)?;
                            events.push(event);
                            Ok(true)
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => Ok(false),
                        Err(error) => Err(error.into()),
                    }
                }
                .await;
                match result {
                    Ok(true) => (),
                    Ok(false) => break,
                    Err(error) => {
                        *failure.lock().expect("event failure") = Some(error.to_string());
                        break;
                    }
                }
            }
        });
        Self {
            values,
            error,
            task,
        }
    }
    fn check(&self) -> anyhow::Result<()> {
        let error = self.error.lock().expect("event failure").clone();
        anyhow::ensure!(
            error.is_none(),
            "continuous EventLog failed/Lagged: {error:?}"
        );
        Ok(())
    }
    async fn status(
        &self,
        bridge: &ida_mcp::router::nexus_bridge::NexusBridge,
        id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        bridge.status(id).await?;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                self.check()?;
                if let Some(value) = self
                    .values
                    .lock()
                    .expect("event sink")
                    .iter()
                    .rev()
                    .find(|e| e["event"] == "local_status" && e["id"] == id)
                    .cloned()
                {
                    return Ok(value);
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await?
    }
    async fn failed_parent(&self) -> anyhow::Result<()> {
        self.wait_parent_failure(false).await
    }
    async fn wait_parent_failure(&self, allow_uncertain: bool) -> anyhow::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                self.check()?;
                if self.values.lock().expect("events").iter().any(|e| {
                    (e["event"] == "failed" || (allow_uncertain && e["event"] == "uncertain"))
                        && e["attempt"]["target"]["kind"] == "open"
                }) {
                    return Ok(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await?
    }
}
#[cfg(feature = "nexus-test-support")]
impl Drop for FileJobEventLog {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(feature = "nexus-test-support")]
async fn retained_file_job_case(fault: Option<&str>) {
    use ida_mcp::router::{nexus_bridge::BridgeConfig, RouterState};
    use serde_json::Value;
    use std::os::fd::AsRawFd;
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"))
        .join(fault.unwrap_or("restore-parent"));
    std::fs::create_dir(&root).expect("private restore case");
    let barrier =
        PathBuf::from(std::env::var_os("R3F2_BARRIER_ROOT").expect("private barrier root"));
    if fault == Some("ready_reply_late") {
        std::fs::write(barrier.join("file_job_ready_reply.arm"), b"")
            .expect("arm exact Ready delivery window");
    }
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_SCENARIO".into(), "r9-restore-held".into());
    environment.insert("R3A_MANAGED".into(), "1".into());
    if fault == Some("u6_no_ack") {
        environment.insert("R4_U6_FILE_JOB".into(), "1".into());
        environment.insert(
            "R2_BOOT_SOURCE_INPUT".into(),
            root.join("os-source.json").display().to_string(),
        );
    } else if fault == Some("ready_reply_late") {
        environment.insert("R4_RESUME_RETAINED_FILE".into(), "1".into());
    } else if let Some(fault) = fault {
        environment.insert("R4_FILE_JOB_FAULT".into(), fault.into());
    }
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
    let events = FileJobEventLog::new(&bridge, &root);
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
        events.failed_parent().await?;
        let snapshot = PathBuf::from(std::fs::read_to_string(root.join("snapshot-ready"))?);
        anyhow::ensure!(target.exists() && std::fs::read(&target)? == b"failed recovered packed");
        let before: Value =
            serde_json::from_slice(&std::fs::read(snapshot.join("recovery.json"))?)?;
        anyhow::ensure!(before["status"] == "failed-owner-held", "{before}");
        std::fs::write(root.join("snapshot-request"), b"")?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !root.join("snapshot.json").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let old_history = if fault == Some("u6_no_ack") {
            let lifecycle = bridge.lifecycle_status();
            let lease: SessionLease =
                serde_json::from_value(lifecycle["resource_details"][0]["lease"].clone())?;
            let history = bridge
                .endpoint()
                .transition(|s, _| s.status(&client, &lease))?;
            anyhow::ensure!(
                history
                    .control_delivery
                    .as_ref()
                    .is_some_and(|d| d.state == DeliveryState::Uncertain),
                "real lost release ACK must remain Uncertain: {history:?}"
            );
            std::fs::write(
                root.join("os-source.json"),
                serde_json::to_vec(&json!({
                "creator":{"boot_id":"00000000-0000-4000-8000-000000000001"}}))?,
            )?;
            bridge.test_boot_resource_projection().await?;
            Some((lease, history))
        } else {
            std::fs::write(root.join("owner-release"), b"")?;
            None
        };
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
        if fault == Some("ready_reply_late") {
            tokio::time::timeout(Duration::from_secs(3), async {
                while !barrier.join("file_job_ready_reply.arrived").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            let pending = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let value = events.status(&bridge, "prepare-still-pending").await?;
                    if value["recovery_cleanup"][0]["blocked"] == true {
                        return Ok::<_, anyhow::Error>(value);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await??;
            std::fs::write(
                root.join("before-late-ready.json"),
                serde_json::to_vec_pretty(&pending)?,
            )?;
            anyhow::ensure!(
                pending["recovery_cleanup"][0]["execution_error"]
                    .as_str()
                    .is_some_and(|s| s.contains("custody IPC acknowledgement missing")),
                "must reach the original IPC budget"
            );
            std::fs::write(barrier.join("file_job_ready_reply.release"), b"")?;
            let old_nonce = pending["recovery_cleanup"][0]["job"]["job_nonce"].clone();
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if events.values.lock().expect("event sink").iter().any(|e| {
                        e["event"] == "file_job_reply_consumed" && e["job_nonce"] == old_nonce
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            let after = events.status(&bridge, "after-late-ready").await?;
            std::fs::write(
                root.join("after-late-ready.json"),
                serde_json::to_vec_pretty(&after)?,
            )?;
            anyhow::ensure!(
                after["recovery_cleanup"][0]["blocked"] == true,
                "late Ready cannot grant file execution or erase its original error"
            );
            anyhow::ensure!(
                after["custody_replies_pending"] == 0,
                "late Ready must close only its exact reply cache responsibility: {after}"
            );
            std::fs::write(root.join("r4-gate.request"), b"")?;
        }
        if let Some((lease, history)) = &old_history {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !root.join("r4-file-blocked").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            anyhow::ensure!(
                std::fs::read(&target)? == b"failed recovered packed",
                "boot retirement cannot bypass a current occupied target"
            );
            let blocked: Value =
                serde_json::from_slice(&std::fs::read(snapshot.join("recovery.json"))?)?;
            std::fs::write(
                root.join("u6-file-blocked.json"),
                serde_json::to_vec_pretty(&blocked)?,
            )?;
            anyhow::ensure!(blocked["status"] == "failed-owner-held");
            anyhow::ensure!(
                blocked["last_error"]
                    .as_str()
                    .is_some_and(|s| s.contains("public owner holds database")),
                "must block on actual current occupancy, not an OS/setup error: {blocked}"
            );
            let certificates = blocked["certified_resources"]
                .as_object()
                .expect("resource custody");
            anyhow::ensure!(!certificates.is_empty());
            for reference in certificates.values() {
                let certificate: Value = serde_json::from_slice(&std::fs::read(
                    snapshot.join(
                        reference["name"]
                            .as_str()
                            .expect("exact retained certificate"),
                    ),
                )?)?;
                anyhow::ensure!(
                    certificate["evidence"]["scope"] == "verified_boot_change_resource_retirement",
                    "file restoration must use U6, not a late public ACK/proof"
                );
            }
            std::fs::write(root.join("owner-release"), b"")?;
            std::fs::write(root.join("r4-gate.request"), b"")?;
            let current = bridge
                .endpoint()
                .transition(|s, _| s.status(&client, lease))?;
            anyhow::ensure!(
                serde_json::to_value(history)? == serde_json::to_value(current)?,
                "resource retirement may not rewrite command delivery/phase/stop history"
            );
        }
        if let Some(fault) = fault.filter(|f| {
            *f != "receiver_drop_ack"
                && *f != "u6_no_ack"
                && *f != "source_duplicate"
                && *f != "ready_reply_late"
        }) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !root.join("file-fault-fired.json").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            if fault == "both_exit" {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !root.join("file-fault-fired-source.json").exists()
                        || !root.join("file-fault-fired-receiver.json").exists()
                    {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await?;
            }
            let failed_record: Value =
                serde_json::from_slice(&std::fs::read(snapshot.join("recovery.json"))?)?;
            std::fs::write(
                root.join("record-after-exit.json"),
                serde_json::to_vec_pretty(&failed_record)?,
            )?;
            anyhow::ensure!(failed_record["recovery_id"] == before["recovery_id"]);
            if fault.starts_with("source_") {
                if matches!(fault, "source_before_prepare" | "source_after_prepare") {
                    anyhow::ensure!(
                        failed_record["executor"]["state"] == "LocalExecuting"
                            || failed_record["executor"]["state"] == "Resumed"
                    );
                } else {
                    anyhow::ensure!(
                        failed_record["executor"]["state"] == "FrozenOffer"
                            || failed_record["executor"]["state"] == "Accepted"
                    );
                }
            }
            let output = tokio::process::Command::new("timeout")
                .arg("15s")
                .arg(std::env::var_os("R3A_PYTHON").expect("SDK"))
                .arg("-I")
                .arg("-B")
                .arg(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/r4_file_gate.py"),
                )
                .arg(root.join("i/installation"))
                .arg(&target)
                .output_fenced()
                .await?;
            std::fs::write(root.join("fresh-gate.stdout"), &output.stdout)?;
            std::fs::write(root.join("fresh-gate.stderr"), &output.stderr)?;
            anyhow::ensure!(
                output.status.success(),
                "fresh gate failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
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
        if fault == Some("receiver_drop_ack") {
            anyhow::ensure!(
                root.join("file-ack-dropped").exists(),
                "must exercise lost ACK"
            );
        }
        if fault == Some("source_duplicate") {
            anyhow::ensure!(
                root.join("file-fault-fired.json").exists(),
                "must deliver duplicate rights"
            );
            let completed: Value =
                serde_json::from_slice(&std::fs::read(snapshot.join("recovery.json"))?)?;
            anyhow::ensure!(
                completed["executor"]["epoch"] == 1,
                "duplicate cannot spawn another executor"
            );
        }
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
    if fault == Some("ready_reply_late") {
        std::fs::write(barrier.join("file_job_ready_reply.release"), b"")
            .expect("finally Ready delivery");
    }
    std::fs::write(root.join("owner-release"), b"").expect("finally owner");
    let supervision = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["helper"]["file_jobs_pending"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let stopped = bridge.shutdown().await;
    std::fs::write(
        root.join("restore-result.json"),
        serde_json::to_vec_pretty(
            &json!({"result":format!("{result:?}"),"shutdown":format!("{stopped:?}"),"supervision":format!("{supervision:?}")}),
        )
        .expect("encode"),
    )
    .expect("evidence");
    stopped.expect("natural shutdown");
    supervision.expect("every file-job native child naturally reaped before test runtime ends");
    events
        .check()
        .expect("continuous exact EventLog has no Lagged or I/O failure");
    result.expect("accepted snapshot outlives cancelled parent and retains exact locks");
}
