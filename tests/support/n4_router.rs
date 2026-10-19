use crate::preprocess::OutputRecorded as _;
use crate::preprocess::SpawnRecorded as _;
pub(crate) async fn isolated(name: &str) -> bool {
    if std::env::var("IDA_N4_FIX_CASE").as_deref() == Ok(name) {
        return true;
    }
    let home = std::env::temp_dir().join(format!(
        "n4-fix-{}-{}",
        std::process::id(),
        name.rsplit("::").next().unwrap()
    ));
    std::fs::create_dir(&home).unwrap();
    let child = tokio::process::Command::new("timeout")
        .arg("25s")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("IDA_N4_FIX_CASE", name)
        .env("IDA_CLI_NEXUS_DEV", "1")
        .env("IDA_CLI_MAX_IDB_CACHE_BYTES", "0")
        .env("IDA_CLI_HOME", &home)
        .env("IDA_NEXUS_STATE_DIR", home.join("state"))
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn_recorded()
        .unwrap();
    crate::preprocess::record_owned_fixture(child.id().unwrap(), false, "n4-isolated-libtest");
    let result = child.output_recorded().await.unwrap();
    std::fs::remove_dir_all(home).unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    false
}
use super::*;

#[tokio::test]
async fn n4_fix_gc_preserves_nexus_idb_at_zero_limit() {
    if !isolated("router::n4_fix_regressions::n4_fix_gc_preserves_nexus_idb_at_zero_limit").await {
        return;
    }
    assert_eq!(std::env::var("IDA_CLI_NEXUS_DEV").unwrap(), "1");
    assert_eq!(std::env::var("IDA_CLI_MAX_IDB_CACHE_BYTES").unwrap(), "0");
    let router = RouterState::new().unwrap();
    let root = crate::idb_store::idb_root();
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("active.0123456789abcdef.i64");
    std::fs::write(&database, b"owned test database").unwrap();
    use crate::nexus::*;
    let caps = NexusCapabilities {
        runtime: NexusRuntime {
            ida: Version(9, 5, 0),
            python: Version(3, 14, 7),
            nexus: Some(Version(0, 13, 4)),
            domain: Some(Version(0, 5, 1)),
        },
        methods: std::collections::BTreeMap::new(),
    };
    router.install_nexus_capabilities(caps.clone()).unwrap();
    let endpoint = router.nexus_endpoint();
    let lease = SessionLease {
        client_id: ClientId::new("gc-client").unwrap(),
        lease_id: LeaseId::new("gc-lease").unwrap(),
        instance_id: InstanceId::new("gc-owner").unwrap(),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    endpoint.transition(|sessions, backend| {
        let identity = sessions
            .open(
                &lease.client_id,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("gc-open").unwrap(),
                    None,
                    "open",
                    serde_json::json!({}),
                )
                .unwrap(),
                OpenSpec {
                    operation_id: OperationId::new("gc-open").unwrap(),
                    path: database.display().to_string(),
                    options: serde_json::json!({}),
                },
                backend,
            )
            .unwrap();
        assert!(matches!(
            sessions.opened(&identity, lease.clone(), caps).unwrap(),
            OpenDisposition::Ready(_)
        ));
        assert_eq!(
            sessions.status(&lease.client_id, &lease).unwrap().phase,
            SessionPhase::Active
        );
    });
    router.prune_caches().await;
    assert!(
        database.is_file(),
        "Nexus GC must defer deletion until N7 ownership/lock proof"
    );
    let store = crate::idb_store::IdbStore::with_root(root);
    assert_eq!(store.evict_to_limit(0, &HashSet::new()).evicted_files, 0);
    assert!(!store.remove("0123456789abcdef"));
    assert!(
        database.is_file(),
        "explicit GC cannot prove external owner/lock absence either"
    );
    std::fs::remove_file(database).unwrap();
}

#[tokio::test]
async fn n4_fix_enqueue_rejects_before_queue_or_open() {
    if !isolated("router::n4_fix_regressions::n4_fix_enqueue_rejects_before_queue_or_open").await {
        return;
    }
    let router = RouterState::new().unwrap();
    for federated in [false, true] {
        let result = if federated {
            router
                .enqueue_federated_task(
                    "/missing-test-copy",
                    "open_dsc",
                    serde_json::json!({}),
                    None,
                    0,
                    None,
                )
                .await
        } else {
            router
                .enqueue_route_task(
                    "/missing-test-copy",
                    "open_dsc",
                    serde_json::json!({}),
                    None,
                    0,
                    None,
                )
                .await
        };
        let error = result
            .expect_err("unsupported Nexus method must not be queued")
            .to_string();
        assert!(error.contains("UnsupportedCapability"), "{error}");
        assert!(error.contains("method open_dsc"), "{error}");
        assert!(error.contains("no legacy fallback"), "{error}");
        assert!(router.list_task_states().is_empty());
        assert!(router.nexus_tools.handles().is_empty());
    }
}
