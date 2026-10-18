//! Ordinary release uses production Tools/N1/bridge/helper and the pinned SDK.
#![cfg(feature = "nexus-test-support")]
use ida_mcp::{
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_ordinary_release_queue_is_bounded_and_other_owner_still_progresses() {
    use ida_mcp::nexus::{NexusErrorCode, SessionLease};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    let router = RouterState::new().expect("router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r2_multi_bridge.py"),
            directory: root.join("i"),
            environment: std::env::vars().collect(),
        })
        .await
        .expect("production bridge/helper");
    let mut events = bridge.subscribe();
    let result: anyhow::Result<Value> = async {
        let mut leases = Vec::<SessionLease>::new();
        for name in ["b", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a"] {
            router
                .ensure_worker_prepared(
                    root.join(name).join("tiny.i64").to_str().expect("utf8"),
                    None,
                    None,
                    Preparation::new(Duration::from_secs(10)),
                )
                .await?;
            loop {
                let event = events.recv().await?;
                if event["event"] == "opened" {
                    leases.push(serde_json::from_value(event["lease"].clone())?);
                    break;
                }
            }
        }
        std::fs::write(root.join("a/guard-block"), b"")?;
        bridge
            .endpoint()
            .transition(|s, t| s.release(&leases[1].client_id, &leases[1], t))?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !root.join("a/guard.arrived").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        // B is accepted before the bounded queue is deliberately saturated.
        bridge
            .endpoint()
            .transition(|s, t| s.release(&leases[0].client_id, &leases[0], t))?;
        let mut refused = Vec::new();
        for lease in leases.iter().skip(2) {
            if let Err(error) = bridge
                .endpoint()
                .transition(|s, t| s.release(&lease.client_id, lease, t))
            {
                anyhow::ensure!(
                    error.code == NexusErrorCode::Busy,
                    "unexpected queue refusal: {error}"
                );
                refused.push(json!({"lease":lease,"error":error}));
            }
        }
        anyhow::ensure!(
            !refused.is_empty(),
            "ordinary control queue silently grew beyond admission capacity"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while !root.join("b/release-requested").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        anyhow::ensure!(
            !root.join("a/release-requested").exists(),
            "busy A reached detach before guard returned"
        );
        Ok(json!({"refused":refused,"status":router.status_snapshot().await.owner_observations}))
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
    let shutdown = bridge.shutdown().await;
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")}))
        .expect("encode"),
    )
    .expect("evidence");
    settled.expect("all references independently consumed public lifetime");
    shutdown.expect("natural input/bridge/helper teardown");
    result.expect("production bounded ordinary queue/fairness assertions");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timed_out_guard_cannot_detach_or_replay_before_actual_stop() {
    use ida_mcp::nexus::{DeliveryState, SessionLease};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    let router = RouterState::new().expect("router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r2_multi_bridge.py"),
            directory: root.join("i"),
            environment: std::env::vars().collect(),
        })
        .await
        .expect("production bridge/helper");
    let mut events = bridge.subscribe();
    let result: anyhow::Result<Value> = async {
        let mut tokens = Vec::new();
        let mut leases = Vec::<SessionLease>::new();
        for name in ["a", "a", "b"] {
            let (_, token) = router.ensure_worker_prepared(root.join(name).join("tiny.i64").to_str().expect("utf8"),
                None, None, Preparation::new(Duration::from_secs(10))).await?;
            tokens.push(token);
            loop {
                let event = events.recv().await?;
                if event["event"] == "opened" {
                    leases.push(serde_json::from_value(event["lease"].clone())?);
                    break;
                }
            }
        }
        std::fs::write(root.join("a/guard-block"), b"")?;
        let first_router = router.clone();
        let first_token = tokens[0].clone();
        let first = tokio::spawn(async move { first_router.nexus_close_token(&first_token).await });
        tokio::time::timeout(Duration::from_secs(2),async {
            while !root.join("a/guard.arrived").exists() {tokio::time::sleep(Duration::from_millis(5)).await;}
        }).await?;
        // Admit directly through the production N1 control lane: Tools' path
        // gate intentionally serializes callers before a second request exists.
        bridge.endpoint().transition(|s,t|s.release(&leases[1].client_id,&leases[1],t))?;
        let closed = tokio::time::timeout(Duration::from_secs(12), first).await??;
        anyhow::ensure!(closed.is_err(), "timed-out actual HTTP guard cannot succeed");
        let short = tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                let snapshot = bridge.endpoint().transition(|s,_|s.status(&leases[1].client_id,&leases[1]))?;
                if snapshot.control_delivery.as_ref().is_some_and(|d|d.state == DeliveryState::NotSent) {
                    break Ok::<_,anyhow::Error>(snapshot);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await??;
        anyhow::ensure!(short.control_delivery.as_ref().and_then(|d|d.error.as_ref())
            .is_some_and(|e|e.to_string().contains("insufficient public HTTP allowance")),
            "queued close did not account for original budget and public HTTP margin: {short:?}");
        let retried = router.nexus_close_token(&tokens[0]).await;
        anyhow::ensure!(retried.is_err(), "cancel acceptance is not an execution-stop proof");
        let other = tokio::time::timeout(Duration::from_secs(2), router.nexus_close_token(&tokens[2])).await??;
        anyhow::ensure!(other.is_some(), "B blocked on A's unresolved HTTP");
        let calls: Vec<Value> = serde_json::from_slice(&std::fs::read(root.join("a/guard-calls.json"))?)?;
        anyhow::ensure!(calls.len() == 1 && !root.join("a/release-requested").exists(),
            "unproven operation replayed guard/detach: {calls:?}");
        Ok(json!({"close":format!("{closed:?}"),"queued_short_budget":format!("{short:?}"),"retry":format!("{retried:?}"),
            "status":router.status_snapshot().await.owner_observations,"guard_calls":calls}))
    }.await;
    for name in ["a", "b"] {
        std::fs::write(root.join(name).join("guard.release"), b"")
            .expect("finally actual guard return");
        std::fs::write(root.join(name).join("owner-release"), b"")
            .expect("finally own public lifetime");
    }
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let shutdown = bridge.shutdown().await;
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")}))
        .expect("encode"),
    )
    .expect("evidence");
    settled.expect("public proof settles exact unresolved guard");
    shutdown.expect("natural shutdown and actual input children reaped");
    result.expect("production guard HTTP timeout/stop gate assertions");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_owner_preflight_keeps_other_owner_and_status_available_after_caller_drop() {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    let router = RouterState::new().expect("router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r2_multi_bridge.py"),
            directory: root.join("i"),
            environment: std::env::vars().collect(),
        })
        .await
        .expect("production bridge/helper over independent native owners");
    let result: anyhow::Result<Value> = async {
        let mut tokens = Vec::new();
        for name in ["a", "a", "b"] {
            let (_, token) = router
                .ensure_worker_prepared(
                    root.join(name).join("tiny.i64").to_str().expect("utf8"),
                    None,
                    None,
                    Preparation::new(Duration::from_secs(10)),
                )
                .await?;
            tokens.push(token);
        }
        std::fs::write(root.join("a/guard-block"), b"")?;
        let first_router = router.clone();
        let first_token = tokens[0].clone();
        let caller =
            tokio::spawn(async move { first_router.nexus_close_token(&first_token).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !root.join("a/guard.arrived").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        caller.abort();
        let _cancelled = caller.await;
        let second_router = router.clone();
        let second_token = tokens[1].clone();
        let second =
            tokio::spawn(async move { second_router.nexus_close_token(&second_token).await });
        let other =
            tokio::time::timeout(Duration::from_secs(2), router.nexus_close_token(&tokens[2]))
                .await??;
        anyhow::ensure!(
            other.is_some(),
            "unrelated B close did not complete while A guard blocked"
        );
        let status =
            tokio::time::timeout(Duration::from_millis(500), router.status_snapshot()).await?;
        anyhow::ensure!(
            !root.join("a/release-requested").exists(),
            "A detached before actual guard return"
        );
        std::fs::write(root.join("a/guard.release"), b"")?;
        second.await??;
        let completed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let observations = router.status_snapshot().await.owner_observations;
                if observations.len() == 3
                    && observations.iter().all(|v| v["lease_detached"] == true)
                {
                    break observations;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        Ok(json!({"while_blocked":status.owner_observations,"completed":completed,"other":other}))
    }
    .await;
    for name in ["a", "b"] {
        std::fs::write(root.join(name).join("guard.release"), b"").expect("finally guard");
        std::fs::write(root.join(name).join("owner-release"), b"").expect("finally owned lifetime");
    }
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let shutdown = bridge.shutdown().await;
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")}))
        .expect("encode"),
    )
    .expect("evidence");
    settled.expect("all three owner references naturally settle");
    shutdown.expect("natural shutdown with both native input children reaped");
    result.expect("production preflight fairness and dropped-caller assertions");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn boot_source_retires_unleased_unknown_attach_without_rewriting_open_history() {
    use ida_mcp::nexus::OpenIdentity;
    use ida_mcp::router::nexus_bridge::cache_lock;
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    let source = root.join("os-source.json");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_SCENARIO".into(), "attach-eof".into());
    environment.insert("R2_BOOT_SOURCE_INPUT".into(), source.display().to_string());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("production bridge/helper");
    let opened = router
        .ensure_worker_prepared(
            root.join("tiny.i64").to_str().expect("utf8"),
            None,
            None,
            Preparation::new(Duration::from_secs(10)),
        )
        .await;
    assert!(
        opened.is_err(),
        "unknown attach cannot invent business success"
    );
    let current = bridge.lifecycle_status();
    let identity: OpenIdentity =
        serde_json::from_value(current["startup_details"][0]["acquisition"]["parent"].clone())
            .expect("actual pre-attach identity");
    let before = router
        .nexus_endpoint()
        .transition(|s, _| s.open_progress(&identity.client_id, &identity))
        .expect("open history");
    assert!(
        cache_lock::try_exclusive(&ida_mcp::idb_store::idb_root()).is_err(),
        "unknown open keeps actual rootSH"
    );
    let result: Result<Value,anyhow::Error> = async {
        anyhow::ensure!(bridge.test_boot_resource_projection().await.is_err(), "sameboot must reject");
        std::fs::write(&source, serde_json::to_vec(&json!({"creator":{"boot_id":"00000000-0000-4000-8000-000000000001"}}))?)?;
        bridge.test_boot_resource_projection().await?;
        tokio::time::timeout(Duration::from_secs(3),async {
            while cache_lock::try_exclusive(&ida_mcp::idb_store::idb_root()).is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await?;
        let after = router.nexus_endpoint().transition(|s,_|s.open_progress(&identity.client_id,&identity))?;
        anyhow::ensure!(serde_json::to_value(&before)? == serde_json::to_value(&after)?, "startup U6 changed original UnknownOutcome");
        Ok(json!({"scope":"OS-source injection, not an actual reboot", "before":before,"after":after,
            "lifecycle":bridge.lifecycle_status()}))
    }.await;
    std::fs::write(root.join("owner-release"), b"").expect("finally private owner");
    tokio::time::timeout(Duration::from_secs(3), async {
        while bridge.lifecycle_status()["retirement_acks"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("exact retirement receipt accepted");
    let shutdown = bridge.shutdown().await;
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "shutdown":format!("{shutdown:?}")}))
        .expect("encode"),
    )
    .expect("evidence");
    shutdown.expect("natural helper shutdown after resource retirement");
    result.expect("production startup resource-only U6");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_guard_errors_reach_close_caller_and_remain_after_proof() {
    for scenario in ["r2-save-refused", "lost-ack", "r2-protection-failed"] {
        let root =
            PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root")).join(scenario);
        std::fs::create_dir_all(&root).expect("case");
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
            .expect("production chain");
        let result: Result<Value, anyhow::Error> =
            async {
                let (_, token) = router
                    .ensure_worker_prepared(
                        root.join("tiny.i64").to_str().expect("utf8"),
                        None,
                        None,
                        Preparation::new(Duration::from_secs(10)),
                    )
                    .await?;
                std::fs::write(root.join("poison-root"), b"")?;
                let closed = router.nexus_close_token(&token).await;
                anyhow::ensure!(
                    closed.is_err(),
                    "real guard failure must reach caller: {closed:?}"
                );
                let before = router.status_snapshot().await.owner_observations;
                anyhow::ensure!(before.len() == 1, "error observation missing: {before:?}");
                let detached = scenario == "r2-save-refused";
                anyhow::ensure!(
                    before[0]["lease_detached"] == detached,
                    "lease ACK/history wrong: {before:?}"
                );
                if scenario != "r2-protection-failed" {
                    anyhow::ensure!(
                        before[0]["save_guard_error"]
                            .as_str()
                            .is_some_and(|s| s.contains("saving refused")),
                        "durably signed guard error missing: {before:?}"
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
                let count = snapshot["requests"]
                    .as_array()
                    .expect("requests")
                    .iter()
                    .filter(|r| r["endpoint"] == "/release_lease")
                    .count();
                anyhow::ensure!(count == usize::from(scenario != "r2-protection-failed"),
                "protection failure must be NotSent and detach exactly once otherwise: {snapshot}");
                Ok(json!({"close":format!("{closed:?}"),"before":before,"snapshot":snapshot}))
            }
            .await;
        std::fs::write(root.join("owner-release"), b"").expect("release private lifetime");
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let current = bridge.lifecycle_status();
                if current["resources"] == 0
                    && current["startup_and_pre_attach"] == 0
                    && current["retirement_acks"] == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let after = router.status_snapshot().await.owner_observations;
        let shutdown = bridge.shutdown().await;
        std::fs::write(
            root.join("result.json"),
            serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
            "after":after,"settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")}))
            .expect("encode"),
        )
        .expect("evidence");
        settled.expect("public proof naturally settles obligations");
        shutdown.expect("natural shutdown");
        result.expect("actual guard/caller/durable error assertions");
        if scenario != "r2-protection-failed" {
            assert!(
                after[0]["save_guard_error"]
                    .as_str()
                    .is_some_and(|s| s.contains("saving refused")),
                "proof/status must never destructively consume unreported save error: {after:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_exit_resolves_once_and_unknown_attach_never_replays() {
    for scenario in ["post-exit-success", "post-exit-final503", "attach-eof"] {
        let root =
            PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root")).join(scenario);
        std::fs::create_dir_all(&root).expect("scenario directory");
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
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("formal SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r3a_bridge_fixture.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("production bridge/helper");
        let result: Result<Value, anyhow::Error> = async {
            let opened = router.ensure_worker_prepared(root.join("tiny.i64").to_str().expect("utf8"), None, None,
                Preparation::new(Duration::from_secs(12))).await;
            if scenario == "post-exit-success" {
                let (_, token) = opened?;
                router.nexus_close_token(&token).await?;
            } else {
                anyhow::ensure!(opened.is_err(), "final failure must reach caller: {opened:?}");
            }
            let stages: Vec<Value> = std::fs::read_to_string(root.join("public-stages.jsonl"))?
                .lines().map(serde_json::from_str).collect::<Result<_,_>>()?;
            let resolves = stages.iter().filter(|v|v["stage"] == "BeforeResolve").count();
            let attaches = stages.iter().filter(|v|v["stage"] == "AttachMayBeSent").count();
            let expected = if scenario == "attach-eof" { 1 } else { 3 };
            anyhow::ensure!(resolves == expected && attaches == expected,
                "actual public resolver/attach counts {resolves}/{attaches}, expected {expected}: {stages:?}");
            Ok(json!({"scenario":scenario,"public_stages":stages,"resolvers":resolves,"attaches":attaches}))
        }.await;
        std::fs::write(
            root.join("call-result.json"),
            serde_json::to_vec_pretty(&json!({"result":format!("{result:?}")})).expect("encode"),
        )
        .expect("evidence before teardown");
        std::fs::write(root.join("owner-release"), b"")
            .expect("release only private owner lifetime");
        let settlement = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let current = bridge.lifecycle_status();
                if current["resources"] == 0
                    && current["startup_and_pre_attach"] == 0
                    && current["retirement_acks"] == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        // Natural shutdown itself checks that every accepted watch and parent
        // obligation was durably closed; no forced cleanup can make this green.
        let shutdown = bridge.shutdown().await;
        std::fs::write(
            root.join("result.json"),
            serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
            "shutdown":format!("{shutdown:?}")}))
            .expect("encode"),
        )
        .expect("evidence");
        shutdown.expect("all pre-attach/resource custody naturally settled");
        settlement.expect("all observations settled before shutdown");
        result.expect("production post-exit/unknown counts and caller assertions");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_ack_finishes_lease_before_owner_exit() {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private R2 case root"));
    std::fs::create_dir_all(&root).expect("private scenario root");
    let router = RouterState::new().expect("real RouterState");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
    environment.insert("R3A_SCENARIO".into(), "slow-owner".into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed prepared SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("verified installed production bridge and independent helper");
    let mut events = bridge.subscribe();
    let path = root.join("tiny.i64");
    let opened = router
        .ensure_worker_prepared(
            path.to_str().expect("UTF8 path"),
            None,
            None,
            Preparation::new(Duration::from_secs(10)),
        )
        .await;
    let close = match &opened {
        Ok((_, token)) => router.nexus_close_token(token).await,
        Err(error) => Err(ida_mcp::error::ToolError::IdaError(format!(
            "open failed: {error}"
        ))),
    };
    let before_exit = router.status_snapshot().await.owner_observations;
    let old_token = if let Ok((_, token)) = &opened {
        router.nexus_close_token(token).await
    } else {
        Ok(None)
    };
    // Always release only this private real lifetime lock, then await reliable
    // custody settlement before natural shutdown. A baseline failure cannot
    // skip reaping its own helper.
    std::fs::write(root.join("owner-release"), b"").expect("release private owner barrier");
    let mut evidence = Vec::<Value>::new();
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let event = events.recv().await.expect("production lifecycle event");
            let done = event["event"] == "custody_settled";
            evidence.push(event);
            if done {
                break;
            }
        }
    })
    .await;
    let shutdown = bridge.shutdown().await;
    let forced = if shutdown.is_err() {
        Some(
            bridge
                .test_helper_fault(true)
                .await
                .expect("exact owned failed-case helper cleanup"),
        )
    } else {
        None
    };
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&json!({
            "scope":"R2-current-production", "close":format!("{close:?}"),
            "settled":settled.is_ok(), "shutdown":format!("{shutdown:?}"),
            "forced":forced, "events":evidence,
            "before_owner_exit":before_exit,"old_token":format!("{old_token:?}"),
        }))
        .expect("encode evidence"),
    )
    .expect("save raw facts");
    settled.expect("public proof must durably settle custody before teardown");
    shutdown.expect("natural bridge/helper shutdown; forced cleanup is never a pass");
    opened.expect("real Tools open");
    assert!(
        close.is_ok(),
        "a valid last ACK must detach without waiting for owner: {close:?}"
    );
    assert_eq!(
        before_exit.len(),
        1,
        "last ACK retains a separately visible owner"
    );
    assert_eq!(before_exit[0]["lease_detached"], true);
    assert_eq!(before_exit[0]["owner_pending"], true);
    assert_eq!(
        before_exit[0]["root_shared_guard"], true,
        "last ACK keeps physical root SH"
    );
    assert!(
        matches!(old_token, Ok(None)),
        "old close token is invalid immediately after ACK"
    );
    assert!(
        router
            .status_snapshot()
            .await
            .owner_observations
            .iter()
            .all(|s| s["root_shared_guard"] == false),
        "durable public proof releases retained SH"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nonlast_ack_drops_only_its_guard_and_unknown_never_replays() {
    for scenario in ["slow-owner", "lost-ack"] {
        let root =
            PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root")).join(scenario);
        std::fs::create_dir_all(&root).expect("isolated scenario");
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
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("formal SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r3a_bridge_fixture.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("production bridge");
        let mut events = bridge.subscribe();
        let result:Result<Value,anyhow::Error>=async {
            let path=root.join("tiny.i64");
            let (_,one)=router.ensure_worker_prepared(path.to_str().expect("utf8"),None,None,
                Preparation::new(Duration::from_secs(10))).await?;
            let (_,two)=router.ensure_worker_prepared(path.to_str().expect("utf8"),None,None,
                Preparation::new(Duration::from_secs(10))).await?;
            let first=router.nexus_close_token(&one).await;
            let first_status=router.status_snapshot().await.owner_observations;
            let second=router.nexus_close_token(&two).await;
            if scenario == "slow-owner" {
                anyhow::ensure!(first.is_ok() && second.is_ok(),"valid ACK close {first:?}/{second:?}");
                anyhow::ensure!(first_status.len() == 1 && first_status[0]["outcome"]["ack_kind"] == "nonlast"
                    && first_status[0]["root_shared_guard"] == false,"nonlast must not keep an extra rootSH: {first_status:?}");
            } else {
                anyhow::ensure!(first.is_err() && second.is_err(),"lost ACK must stay an error");
                let retry=router.nexus_close_token(&one).await;
                anyhow::ensure!(retry.is_err(),"Uncertain retry must remain uncertain");
            }
            std::fs::write(root.join("snapshot-request"),b"")?;
            tokio::time::timeout(Duration::from_secs(2),async {
                while !root.join("snapshot.json").exists() {tokio::time::sleep(Duration::from_millis(5)).await;}
            }).await?;
            let snapshot:Value=serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
            anyhow::ensure!(snapshot["requests"].as_array().expect("requests").iter()
                .filter(|r|r["endpoint"] == "/release_lease").count() == 2,"each lease detached exactly once");
            Ok(json!({"first":format!("{first:?}"),"second":format!("{second:?}"),"status":first_status,"snapshot":snapshot}))
        }.await;
        std::fs::write(root.join("owner-release"), b"").expect("finally release private owner");
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            let mut count = 0;
            while count < 2 {
                if events.recv().await.expect("event stream")["event"] == "custody_settled" {
                    count += 1;
                }
            }
        })
        .await;
        let shutdown = bridge.shutdown().await;
        std::fs::write(root.join("result.json"),serde_json::to_vec_pretty(&json!({
            "result":format!("{result:?}"),"settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")
        })).expect("encode")).expect("raw evidence");
        settled.expect("both exact observations settle");
        shutdown.expect("natural shutdown");
        result.expect("production state/count assertions");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_reopen_same_and_cross_router_uses_new_request_budget() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    for cross in [false, true] {
        let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"))
            .join(if cross { "cross" } else { "same" });
        std::fs::create_dir_all(&root).expect("private root");
        let first = RouterState::new().expect("first router");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
        environment.insert("R3A_SCENARIO".into(), "slow-owner".into());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let configuration = |script: &str, dir: &str| BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(script),
            directory: root.join(dir),
            environment: environment.clone(),
        };
        let bridge = first
            .connect_nexus(configuration("tests/support/r3a_bridge_fixture.py", "a"))
            .await
            .expect("first bridge");
        let second = if cross {
            RouterState::new().expect("second router")
        } else {
            first.clone()
        };
        let second_bridge = if cross {
            Some(
                second
                    .connect_nexus(configuration("tests/support/r2_client_bridge.py", "b"))
                    .await
                    .expect("second bridge"),
            )
        } else {
            None
        };
        let mut events = bridge.subscribe();
        let mut next_events = second_bridge.as_ref().map(|b| b.subscribe());
        let result: Result<Value, anyhow::Error> = async {
            let path = root.join("tiny.i64");
            let (_, token) = first
                .ensure_worker_prepared(
                    path.to_str().expect("utf8"),
                    None,
                    None,
                    Preparation::new(Duration::from_secs(10)),
                )
                .await?;
            first.nexus_close_token(&token).await?;
            std::fs::write(root.join("first-close-returned"), b"")?;
            let next_path = path.clone();
            let next_router = second.clone();
            let next = tokio::spawn(async move {
                next_router
                    .ensure_worker_prepared(
                        next_path.to_str().expect("utf8"),
                        None,
                        None,
                        Preparation::new(Duration::from_secs(10)),
                    )
                    .await
            });
            // The new request starts while the last owner still holds its real
            // public lifetime. Only then permit exit and a new public owner.
            tokio::task::yield_now().await;
            std::fs::write(root.join("next-owner"), b"1")?;
            std::fs::write(root.join("owner-release"), b"")?;
            let reopened = next.await??;
            std::fs::write(root.join("reopen-returned"), b"")?;
            second.nexus_close_token(&reopened.1).await?;
            Ok(json!({"cross":cross,"reopened":reopened.0}))
        }
        .await;
        std::fs::write(
            root.join("call-result.json"),
            serde_json::to_vec_pretty(&json!({"result":format!("{result:?}")}))
                .expect("encode caller result"),
        )
        .expect("save caller result before teardown");
        std::fs::write(root.join("owner-release"), b"").expect("finally owner release");
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            let mut done = 0;
            while done < if cross { 1 } else { 2 } {
                if events.recv().await.expect("event")["event"] == "custody_settled" {
                    done += 1;
                }
            }
            if let Some(events) = next_events.as_mut() {
                loop {
                    if events.recv().await.expect("second event")["event"] == "custody_settled" {
                        break;
                    }
                }
            }
        })
        .await;
        let next_shutdown = if let Some(b) = second_bridge {
            b.shutdown().await
        } else {
            Ok(())
        };
        let shutdown = bridge.shutdown().await;
        std::fs::write(
            root.join("result.json"),
            serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
            "settled":settled.is_ok(),"shutdown":format!("{shutdown:?}/{next_shutdown:?}")}))
            .expect("encode"),
        )
        .expect("evidence");
        settled.expect("exact public observation settlement");
        next_shutdown.expect("second natural shutdown");
        shutdown.expect("first natural shutdown");
        result.expect("one new open request must succeed within its original budget");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn boot_source_injection_retires_only_current_resources_and_preserves_unknown_history() {
    use ida_mcp::nexus::SessionLease;
    use ida_mcp::router::nexus_bridge::cache_lock;
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    let source = root.join("os-source.json");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_SCENARIO".into(), "lost-ack".into());
    environment.insert("R2_BOOT_SOURCE_INPUT".into(), source.display().to_string());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("formal SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("production bridge/helper");
    let mut events = bridge.subscribe();
    let path = root.join("tiny.i64");
    let (_, token) = router
        .ensure_worker_prepared(
            path.to_str().expect("utf8"),
            None,
            None,
            Preparation::new(Duration::from_secs(10)),
        )
        .await
        .expect("real open");
    let lease: SessionLease = loop {
        let event = events.recv().await.expect("opened event");
        if event["event"] == "opened" {
            break serde_json::from_value(event["lease"].clone()).expect("exact lease");
        }
    };
    let closed = router.nexus_close_token(&token).await;
    assert!(closed.is_err(), "lost ACK caller error must remain visible");
    let original_release_facts = router
        .status_snapshot()
        .await
        .owner_observations
        .into_iter()
        .find(|value| value["lease"] == json!(lease))
        .expect("original owner diagnostics");
    let before = router
        .nexus_endpoint()
        .transition(|s, _| s.status(&lease.client_id, &lease))
        .expect("history");
    let result:Result<Value,anyhow::Error>=async {
        anyhow::ensure!(cache_lock::try_exclusive(&ida_mcp::idb_store::idb_root()).is_err(),"unknown keeps physical root SH");
        if std::env::var("IDA_CLI_MAX_PENDING_PER_TENANT").as_deref() == Ok("1") {
            anyhow::ensure!(bridge.lifecycle_status()["live_limit"] == 1,"test must use actual one-slot capacity");
            let refused=router.ensure_worker_prepared(path.to_str().expect("utf8"),None,None,
                Preparation::new(Duration::from_secs(2))).await;
            anyhow::ensure!(refused.as_ref().err().is_some_and(|e|e.to_string().contains("capacity")),
                "old unknown obligation must occupy the actual slot: {refused:?}");
        }
        anyhow::ensure!(bridge.test_boot_resource_projection().await.is_err(),"same boot must be rejected");
        let new_boot=json!({"creator":{"boot_id":"00000000-0000-4000-8000-000000000001"}});
        let bad_inputs=[json!({"host_domain":"namespace-only"}),json!({"virtualized":true}),
            json!({"local_internal":false}),json!({"machine_sha256":"0".repeat(64)}),
            json!({"volume_sha256":"0".repeat(64)}),json!({"file_id":0}),json!({"uid":0}),
            json!({"creator":{"kind":"unverified-native-source","boot_id":"00000000-0000-4000-8000-000000000001"}})];
        for input in bad_inputs {
            let mut overrides=new_boot.clone();
            overrides.as_object_mut().expect("object").extend(input.as_object().expect("object").clone());
            std::fs::write(&source,serde_json::to_vec(&overrides)?)?;
            anyhow::ensure!(bridge.test_boot_resource_projection().await.is_err(),"unqualified OS input accepted: {overrides}");
            anyhow::ensure!(router.nexus_endpoint().transition(|s,_|s.resource_retirement(&lease))?.is_none(),"rejection mutated disposition");
            anyhow::ensure!(cache_lock::try_exclusive(&ida_mcp::idb_store::idb_root()).is_err(),"rejection dropped real rootSH");
        }
        std::fs::write(&source,serde_json::to_vec(&new_boot)?)?;
        bridge.test_boot_resource_projection().await?;
        let observed=router.status_snapshot().await.owner_observations;
        anyhow::ensure!(observed.len()==1 && observed[0]["resource_disposition"] == "RetiredByBootChange"
            && observed[0]["root_shared_guard"] == false && observed[0]["lease_detached"] == false,
            "U6 must release old guard without forging ACK: {observed:?}");
        let after=router.nexus_endpoint().transition(|s,_|s.status(&lease.client_id,&lease))?;
        anyhow::ensure!(serde_json::to_value(&before)? == serde_json::to_value(&after)?,"U6 changed historical phase/delivery/stop");
        anyhow::ensure!(router.nexus_endpoint().transition(|s,_|s.public_owner_lifetime(&lease)).is_err(),
            "late public result must not replace retired boot history");
        let late_history=router.nexus_endpoint().transition(|s,_|s.status(&lease.client_id,&lease))?;
        anyhow::ensure!(serde_json::to_value(&before)? == serde_json::to_value(&late_history)?,
            "late lifetime result rewrote original historical fields");
        let retired_release_facts=&observed[0];
        for field in ["outcome","preflight","command_error"] {
            anyhow::ensure!(!original_release_facts[field].is_null()
                && original_release_facts[field] == retired_release_facts[field],
                "U6 replaced historical release {field}: before={original_release_facts:?}, after={retired_release_facts:?}");
        }
        anyhow::ensure!(cache_lock::try_exclusive(&ida_mcp::idb_store::idb_root()).is_ok(),"old resource still blocks physical root EX");
        anyhow::ensure!(matches!(router.nexus_close_token(&token).await,Ok(None)),"retired token revived");
        // A new physical owner must not inherit old proof or retirement. The
        // injected OS input is removed before creating this native obligation.
        std::fs::remove_file(&source)?;
        std::fs::write(root.join("owner-release"),b"")?;
        tokio::time::timeout(Duration::from_secs(2),async {
            while !root.join("owner-released").exists() {tokio::time::sleep(Duration::from_millis(5)).await;}
        }).await?;
        std::fs::write(root.join("next-owner"),b"1")?;
        tokio::time::timeout(Duration::from_secs(2),async {
            while std::fs::read_to_string(root.join("owner-generation")).ok().as_deref() != Some("1") {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await?;
        let (_,fresh)=router.ensure_worker_prepared(path.to_str().expect("utf8"),None,None,
            Preparation::new(Duration::from_secs(10))).await?;
        anyhow::ensure!(cache_lock::try_exclusive(&ida_mcp::idb_store::idb_root()).is_err(),
            "new owner did not acquire its own real rootSH");
        anyhow::ensure!(bridge.test_boot_resource_projection().await.is_err(),
            "old boot evidence retired a new native owner");
        anyhow::ensure!(cache_lock::try_exclusive(&ida_mcp::idb_store::idb_root()).is_err(),
            "rejected old evidence dropped new owner's rootSH");
        let old_now=router.nexus_endpoint().transition(|s,_|s.status(&lease.client_id,&lease))?;
        anyhow::ensure!(serde_json::to_value(&before)? == serde_json::to_value(&old_now)?,
            "old resource history changed when new owner opened");
        let fresh_close=router.nexus_close_token(&fresh).await;
        anyhow::ensure!(fresh_close.is_err(),"new lost-ACK input cannot inherit old release success");
        Ok(json!({"scope":"production OS-source injection; no actual reboot","close":format!("{closed:?}"),
            "history_before":before,"history_after":after,"observed":observed,"negative_inputs":8,
            "new_owner_close":format!("{fresh_close:?}"),"live_limit":bridge.lifecycle_status()["live_limit"]}))
    }.await;
    std::fs::write(
        root.join("call-result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}")})).expect("encode"),
    )
    .expect("evidence");
    std::fs::write(root.join("owner-release"), b"").expect("finally release private lifetime");
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let current = bridge.lifecycle_status();
            if current["resources"] == 0
                && current["startup_and_pre_attach"] == 0
                && current["retirement_acks"] == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let shutdown = bridge.shutdown().await;
    settled.expect("new owner public proof durably accepted before shutdown");
    shutdown.expect("natural bridge/helper shutdown");
    result.expect("strict U6 resource-only projection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_ida95_saved_modification_immediate_reopen_and_shared_lease() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    let path = root.join("tiny");
    std::fs::copy(
        std::env::var_os("R2_REAL_INPUT").expect("private prepared sample"),
        &path,
    )
    .expect("fresh sample copy");
    let first = RouterState::new().expect("first router");
    let second = RouterState::new().expect("independent router");
    let configuration = |name: &str| BridgeConfig {
        python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("formal SDK")),
        script: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("nexus_bridge/bridge.py"),
        directory: root.join(name),
        environment: std::env::vars().collect(),
    };
    let a = first
        .connect_nexus(configuration("a"))
        .await
        .expect("real production bridge");
    let b = second
        .connect_nexus(configuration("b"))
        .await
        .expect("real second bridge");
    let mut ae = a.subscribe();
    let mut be = b.subscribe();
    let mut tokens = Vec::new();
    let result:Result<Value,anyhow::Error>=async {
        let open=||Preparation::new(Duration::from_secs(30));
        let (one,t1)=first.ensure_worker_prepared(path.to_str().expect("utf8"),None,None,open()).await?;
        tokens.push((false,t1.clone()));
        let (two,t2)=second.ensure_worker_prepared(path.to_str().expect("utf8"),None,None,open()).await?;
        tokens.push((true,t2.clone()));
        let version=first.route_request_prepared(Some(&one),"run_script",
            json!({"code":"import ida_kernwin\nprint(ida_kernwin.get_kernel_version())"}),open()).await?;
        anyhow::ensure!(version["success"] == true && version["stdout"] == "9.5\n","actual IDA version: {version}");
        let wrote=first.route_request_prepared(Some(&one),"run_script",json!({"code":
            "import ida_ida, ida_bytes\nassert ida_bytes.set_cmt(ida_ida.inf_get_min_ea(), 'r2_saved_20261018', False)\nprint('saved modification')"}),open()).await?;
        anyhow::ensure!(wrote["success"] == true && wrote["stdout"] == "saved modification\n","real modification: {wrote}");
        first.nexus_close_token(&t1).await?;
        let status=first.status_snapshot().await.owner_observations;
        anyhow::ensure!(status.len()==1 && status[0]["outcome"]["ack_kind"] == "nonlast"
            && status[0]["root_shared_guard"] == false,"third-party lease requires nonlast: {status:?}");
        let read_code=json!({"code":"import ida_ida, ida_bytes\nprint(ida_bytes.get_cmt(ida_ida.inf_get_min_ea(), False))"});
        let shared=second.route_request_prepared(Some(&two),"run_script",read_code.clone(),open()).await?;
        anyhow::ensure!(shared["success"] == true && shared["stdout"] == "r2_saved_20261018\n","nonlast close damaged other client: {shared}");
        second.nexus_close_token(&t2).await?;
        let (three,t3)=first.ensure_worker_prepared(path.to_str().expect("utf8"),None,None,open()).await?;
        tokens.push((false,t3.clone()));
        let read=first.route_request_prepared(Some(&three),"run_script",read_code,open()).await?;
        anyhow::ensure!(read["success"] == true && read["stdout"] == "r2_saved_20261018\n","saved bytes lost on immediate reopen: {read}");
        first.nexus_close_token(&t3).await?;
        Ok(json!({"version":version,"write":wrote,"shared_read":shared,"reopen_read":read,"nonlast":status}))
    }.await;
    std::fs::write(
        root.join("call-result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}")})).expect("encode"),
    )
    .expect("evidence before teardown");
    let expected_a = tokens.iter().filter(|(other, _)| !*other).count();
    let expected_b = tokens.len() - expected_a;
    for (other, token) in tokens {
        let _result = if other {
            second.nexus_close_token(&token).await
        } else {
            first.nexus_close_token(&token).await
        };
    }
    let settled = tokio::time::timeout(Duration::from_secs(12), async {
        let mut done = 0;
        while done < expected_a {
            if ae.recv().await.expect("first lifecycle")["event"] == "custody_settled" {
                done += 1;
            }
        }
        let mut done = 0;
        while done < expected_b {
            if be.recv().await.expect("second lifecycle")["event"] == "custody_settled" {
                done += 1;
            }
        }
    })
    .await;
    let bs = b.shutdown().await;
    let ash = a.shutdown().await;
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "settled":settled.is_ok(),"shutdown":format!("{ash:?}/{bs:?}")}))
        .expect("encode"),
    )
    .expect("evidence");
    settled.expect("all real owner proofs naturally settle");
    ash.expect("first natural shutdown");
    bs.expect("second natural shutdown");
    result.expect("production IDA9.5 shared close and immediate saved readback");
}
