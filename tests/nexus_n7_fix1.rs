//! S1 uses production custody, SDK, owner watcher and real private lifetime locks.
use ida_mcp::{
    nexus::{SessionLease, SessionPhase},
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_dropped_close_releases_root_without_another_close() {
    production_case(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_expired_observer_next_open_consumes_exact_proof() {
    production_case(false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_expired_uncertain_open_observer_consumes_exact_proof() {
    production_case(true, true).await;
}

async fn marker(path: &Path) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

async fn production_case(open_drop: bool, expire: bool) {
    let root =
        PathBuf::from(std::env::var_os("F1_ROOT").expect("new private root")).join(if open_drop {
            "unknown"
        } else if expire {
            "late"
        } else {
            "drop"
        });
    std::fs::create_dir_all(&root).expect("private S1 root");
    let router = RouterState::new().expect("production router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
    environment.insert(
        "R3A_SCENARIO".into(),
        if open_drop {
            "tools-barrier"
        } else {
            "slow-owner"
        }
        .into(),
    );
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("IDA_NEXUS_PYTHON").expect("fresh SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("installed bridge and real proof helper");
    let result: anyhow::Result<Value> = async {
        let path = root.join("tiny.i64");
        let opening_router = router.clone();
        let input = path.clone();
        let opening = tokio::spawn(async move {
            opening_router
                .ensure_worker_prepared(
                    input.to_str().expect("UTF8 path"),
                    None,
                    None,
                    Preparation::new(Duration::from_secs(15)),
                )
                .await
        });
        if open_drop {
            marker(&root.join("analysis.arrived")).await?;
            opening.abort();
            anyhow::ensure!(
                opening.await.is_err_and(|e| e.is_cancelled()),
                "open caller did not drop"
            );
            std::fs::write(root.join("analysis.release"), b"")?;
        } else {
            let (_, token) = opening.await??;
            std::fs::write(root.join("r6-close.arm"), b"")?;
            let closing_router = router.clone();
            let closing =
                tokio::spawn(async move { closing_router.nexus_close_token(&token).await });
            marker(&root.join("r6-close.arrived")).await?;
            closing.abort();
            anyhow::ensure!(
                closing.await.is_err_and(|e| e.is_cancelled()),
                "close caller did not drop"
            );
            std::fs::write(root.join("r6-close.release"), b"")?;
        }
        marker(&root.join("release-requested")).await?;
        let lease: SessionLease = serde_json::from_value(
            bridge.lifecycle_status()["resource_details"][0]["lease"].clone(),
        )?;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let status = bridge
                    .endpoint()
                    .transition(|s, _| s.status(&lease.client_id, &lease))?;
                if status.phase == SessionPhase::Released {
                    break Ok::<_, anyhow::Error>(status);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        let held = bridge.lifecycle_status();
        anyhow::ensure!(
            held["resources"] == 1 && held["resource_details"][0]["public_proof_adopted"] == false,
            "ACK may not retire the held owner: {held}"
        );
        anyhow::ensure!(
            ida_mcp::router::nexus_bridge::cache_lock::try_exclusive(
                &ida_mcp::idb_store::idb_root()
            )
            .is_err(),
            "held owner lost its actual shared root guard"
        );
        if expire {
            // Exercise the actual historical observer boundary, independently
            // of owner proof. Scheduling the proof still uses the owner barrier.
            tokio::time::sleep(Duration::from_secs(122)).await;
            anyhow::ensure!(
                bridge.lifecycle_status()["resources"] == 1,
                "observer expiry fabricated an owner exit"
            );
        }
        let before_proof = bridge
            .endpoint()
            .transition(|s, _| s.status(&lease.client_id, &lease))?;
        std::fs::write(root.join("owner-release"), b"")?;
        tokio::time::timeout(Duration::from_secs(8), async {
            while bridge.lifecycle_status()["resources"] != 0
                || bridge.lifecycle_status()["retirement_acks"] != 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let after_proof = bridge
            .endpoint()
            .transition(|s, _| s.status(&lease.client_id, &lease))?;
        anyhow::ensure!(
            after_proof.phase == SessionPhase::Released,
            "I5: production proof did not converge"
        );
        anyhow::ensure!(
            serde_json::to_value(&before_proof.control_delivery)?
                == serde_json::to_value(&after_proof.control_delivery)?,
            "public proof rewrote the original command/ACK history"
        );
        std::fs::write(root.join("snapshot-request"), b"")?;
        marker(&root.join("snapshot.json")).await?;
        let snapshot: Value = serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
        anyhow::ensure!(
            snapshot["requests"]
                .as_array()
                .expect("HTTP requests")
                .iter()
                .filter(|r| r["endpoint"] == "/release_lease")
                .count()
                == 1,
            "I2: detach replayed: {snapshot}"
        );
        let old_owners = router.status_snapshot().await.owner_observations;
        anyhow::ensure!(
            old_owners.iter().all(|s| s["root_shared_guard"] == false),
            "old physical guard remains"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while ida_mcp::router::nexus_bridge::cache_lock::try_exclusive(
                &ida_mcp::idb_store::idb_root(),
            )
            .is_err()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        if expire {
            std::fs::write(root.join("next-owner"), b"1")?;
            marker(&root.join("owner-generation")).await?;
            let (_, next) = router
                .ensure_worker_prepared(
                    path.to_str().expect("path"),
                    None,
                    None,
                    Preparation::new(Duration::from_secs(10)),
                )
                .await?;
            router.nexus_close_token(&next).await?;
            std::fs::write(root.join("owner-release"), b"")?;
        }
        Ok(
            json!({"scope":"production Rust/N1/bridge/helper/SDK; controlled HTTP/IDA inputs",
            "held":held,"before_proof":before_proof,"after_proof":after_proof,
            "requests":snapshot,"old_owner_guards":old_owners,"I5_after_barrier":true}),
        )
    }
    .await;
    for name in ["analysis.release", "r6-close.release", "owner-release"] {
        std::fs::write(root.join(name), b"").expect("finally release owned inputs");
    }
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0
            || bridge.lifecycle_status()["startup_and_pre_attach"] != 0
            || bridge.lifecycle_status()["retirement_acks"] != 0
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let shutdown = bridge.shutdown().await;
    std::fs::write(
        root.join("s1-result.json"),
        serde_json::to_vec_pretty(&json!({
        "result":result.as_ref().ok(),"error":result.as_ref().err().map(ToString::to_string),
        "settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")}))
        .expect("JSON"),
    )
    .expect("evidence");
    settled.expect("all exact resources must settle");
    shutdown.expect("natural bridge/helper shutdown");
    result.expect("S1 production proof and no replay");
}
