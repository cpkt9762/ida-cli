//! Actual close_token cancellation and exact late Released through the bridge.
use ida_mcp::{
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use std::{collections::BTreeMap, os::fd::AsRawFd, path::PathBuf, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_dropped_close_releases_root_without_another_close() {
    close_drop(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_expired_observer_next_open_consumes_exact_proof() {
    close_drop(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_expired_uncertain_open_observer_consumes_exact_proof() {
    let root =
        PathBuf::from(std::env::var_os("F1_ROOT").expect("private short root")).join("unknown");
    std::fs::create_dir_all(&root).unwrap();
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("F1_ROOT".into(), root.display().to_string());
    environment.insert("F1_SCENARIO".into(), "n7-open-drop".into());
    let router = RouterState::new().unwrap();
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("IDA_NEXUS_PYTHON").unwrap()),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/nexus_race_fixture.py"),
            directory: root.join("ipc"),
            environment,
        })
        .await
        .unwrap();
    let source = root.join("raw");
    std::fs::write(&source, b"uncertain opening").unwrap();
    let opener = router.clone();
    let input = source.clone();
    let task = tokio::spawn(async move {
        opener
            .ensure_worker_prepared(
                input.to_str().unwrap(),
                None,
                None,
                Preparation::new(Duration::from_secs(10)),
            )
            .await
    });
    marker(&root.join("n7-open-proof.arrived")).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    std::fs::write(root.join("n7-open-proof.release"), b"").unwrap();
    marker(&root.join("n7-release-proof.arrived")).await;
    assert!(
        !root_is_exclusive(),
        "unknown open retains root and content protection"
    );
    tokio::time::sleep(Duration::from_secs(122)).await;
    assert!(
        !root_is_exclusive(),
        "observer expiry cannot stand in for Released"
    );
    let mut events = bridge.subscribe();
    std::fs::write(root.join("n7-release-proof.release"), b"").unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if events.recv().await.unwrap()["event"] == "released" {
                break;
            }
        }
    })
    .await
    .expect("exact cleanup proof reached N1");
    let (_, token) = router
        .ensure_worker_prepared(
            source.to_str().unwrap(),
            None,
            None,
            Preparation::new(Duration::from_secs(10)),
        )
        .await
        .unwrap();
    router.nexus_close_token(&token).await.unwrap();
    let exclusive = tokio::time::timeout(Duration::from_secs(2), async {
        while !root_is_exclusive() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok();
    bridge.shutdown().await.unwrap();
    assert!(
        exclusive,
        "next open consumes retained opening's same exact proof after 120s"
    );
}

async fn marker(path: &std::path::Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("release reached deterministic pre-proof barrier");
}
fn root_is_exclusive() -> bool {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(ida_mcp::idb_store::idb_root().join(".cache.lock"))
        .unwrap();
    // SAFETY: nonblocking flock of this test's own live cache descriptor.
    let acquired = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if acquired {
        // SAFETY: unlock the same live descriptor before dropping it.
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
    }
    acquired
}
async fn close_drop(expire: bool) {
    assert_eq!(std::env::var("IDA_CLI_NEXUS_DEV").unwrap(), "1");
    let root = PathBuf::from(std::env::var_os("F1_ROOT").expect("private short root"))
        .join(if expire { "late" } else { "drop" });
    std::fs::create_dir_all(&root).unwrap();
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("F1_ROOT".into(), root.display().to_string());
    environment.insert("F1_SCENARIO".into(), "n7-close-drop".into());
    let router = RouterState::new().unwrap();
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("IDA_NEXUS_PYTHON").unwrap()),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/nexus_race_fixture.py"),
            directory: root.join("ipc"),
            environment,
        })
        .await
        .unwrap();
    let mut events = bridge.subscribe();
    let source = root.join("raw");
    std::fs::write(&source, b"close drop test input").unwrap();
    let (_, token) = router
        .ensure_worker_prepared(
            source.to_str().unwrap(),
            None,
            None,
            Preparation::new(Duration::from_secs(10)),
        )
        .await
        .unwrap();
    let lease: ida_mcp::nexus::SessionLease = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let event = events.recv().await.unwrap();
            if event["event"] == "opened" {
                break serde_json::from_value(event["lease"].clone()).unwrap();
            }
        }
    })
    .await
    .unwrap();
    assert!(!root_is_exclusive());
    let closer = router.clone();
    let task = tokio::spawn(async move { closer.nexus_close_token(&token).await });
    marker(&root.join("n7-release-proof.arrived")).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        !root_is_exclusive(),
        "dropping/ACK alone never unlocks the root"
    );
    if expire {
        tokio::time::sleep(Duration::from_secs(122)).await;
    }
    // Only this exact pending release proof may converge the old cache guard.
    std::fs::write(root.join("n7-release-proof.release"), b"").unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while bridge
            .endpoint()
            .transition(|s, _| s.status(&lease.client_id, &lease))
            .unwrap()
            .phase
            != ida_mcp::nexus::SessionPhase::Released
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("matching Released consumed by N1");
    if expire {
        // A status barrier ensures N1 has consumed Released before next open.
        let (_, next) = router
            .ensure_worker_prepared(
                source.to_str().unwrap(),
                None,
                None,
                Preparation::new(Duration::from_secs(10)),
            )
            .await
            .unwrap();
        router.nexus_close_token(&next).await.unwrap();
    }
    let exclusive = tokio::time::timeout(Duration::from_secs(2), async {
        while !root_is_exclusive() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok();
    // No second close/shutdown is used before observing the original guard.
    bridge.shutdown().await.unwrap();
    assert!(
        exclusive,
        "exact late Released must release the old root guard"
    );
}
