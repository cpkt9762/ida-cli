//! R5 startup rejection and one real tiny IDA chain. Fresh isolated roots only.
use ida_mcp::{
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[tokio::test]
async fn readiness_rejects_before_any_grant_and_reaps_exact_child() {
    let base = PathBuf::from(std::env::var_os("R5_ROOT").expect("private R5 root"));
    let mut records = Vec::new();
    for fault in [
        "missing-wire",
        "missing-schema",
        "missing-release",
        "missing-open",
        "missing-owner_observation",
        "missing-client_hash",
        "missing-sdk_boundary",
        "missing-client_modules",
        "sdk_boundary",
        "module-handle",
        "module-resolver",
        "module-options",
        "module-missing",
        "module-extra",
        "missing-capabilities",
        "wire",
        "schema",
        "release",
        "open",
        "owner_observation",
        "wrong-hash",
        "unknown-capability",
        "missing-capability",
        "duplicate-capability",
        "wrong-home",
        "old-wire",
        "bool-wire",
        "unknown-field",
        "relative-state",
        "sdk-version",
        "domain-version",
    ] {
        let root = base.join(fault);
        std::fs::create_dir(&root).expect("new case");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R5_ROOT".into(), root.display().to_string());
        environment.insert("R5_FAULT".into(), fault.into());
        let router = RouterState::new().expect("router");
        let result = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("F1_PYTHON").expect("prepared Python")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r5_readiness_fixture.py"),
                directory: root.join("ipc"),
                environment,
            })
            .await;
        let error = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("incompatible readiness accepted: {fault}"),
        };
        assert!(
            error.contains("ProtocolMismatch"),
            "wrong rejection boundary for {fault}: {error}"
        );
        let process: Value = serde_json::from_slice(
            &std::fs::read(root.join("process.json")).expect("registered own child"),
        )
        .expect("process identity");
        let pid = i32::try_from(process["pid"].as_i64().expect("pid")).expect("native pid");
        tokio::time::timeout(Duration::from_secs(3), async {
            // SAFETY: signal zero only queries our registered child; no signal is sent.
            loop {
                if unsafe { libc::kill(pid, 0) } != 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("exact rejected child reaped");
        tokio::time::timeout(Duration::from_secs(3), async {
            while ["b", "c", "l"]
                .iter()
                .any(|n| root.join("ipc").join(n).exists())
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("own startup endpoints removed");
        records.push(json!({"fault":fault,"rejected":error,"pid":pid,"reaped":true,"grants":0,"physical_acquisitions":0}));
    }
    std::fs::write(
        base.join("readiness-rejections.json"),
        serde_json::to_vec_pretty(&records).expect("encode cases"),
    )
    .expect("write evidence");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_tiny_default_home_open_query_close() {
    let root = PathBuf::from(std::env::var_os("R5_ROOT").expect("private real root"));
    let sample = root.join("tiny");
    let envroot = PathBuf::from(std::env::var_os("R5_ENV").expect("fresh prepared environment"));
    std::fs::copy(envroot.join("fixtures/mini"), &sample).expect("private tiny sample copy");
    let router = RouterState::new().expect("real RouterState");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.remove("IDA_CLI_HOME");
    environment.insert("N3_ENV_ROOT".into(), envroot.display().to_string());
    environment.insert(
        "IDAPYTHON_VENV_EXECUTABLE".into(),
        envroot.join("venv/bin/python").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: envroot.join("venv/bin/python"),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/nexus_client_fixture.py"),
            directory: root.join("ipc"),
            environment,
        })
        .await
        .expect("production Rust readiness with unset IDA_CLI_HOME");
    // Tools must agree with the startup default. This test process has no explicit home.
    let (handle, token) = router
        .ensure_worker_prepared(
            sample.to_str().expect("path"),
            None,
            None,
            Preparation::new(Duration::from_secs(60)),
        )
        .await
        .expect("production Tools real IDA open");
    let result = router
        .route_request(Some(&handle), "get_database_info", json!({}))
        .await
        .expect("production real IDA query");
    router
        .nexus_close_token(&token)
        .await
        .expect("production real tiny close");
    bridge.shutdown().await.expect("normal bridge shutdown");
    std::fs::write(root.join("real-result.json"),serde_json::to_vec_pretty(&json!({"scope":"R5-production-tiny","query":result,"default_home":ida_mcp::idb_store::ida_home()})).expect("encode evidence")).expect("write evidence");
}
