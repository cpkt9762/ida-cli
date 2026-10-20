//! Real N3 acceptance: each test uses fresh sample copies and public Nexus clients.
#[path = "support/nexus_env.rs"]
mod env;
use env::*;
use ida_mcp::nexus::*;
use ida_mcp::process_spawn::SpawnFenced;
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn owner_exited(pid: u32) {
    tokio::time::timeout(Duration::from_secs(12), async {
        let mut poll = tokio::time::interval(Duration::from_millis(20));
        loop {
            // Read-only existence observation; never signals a foreign process.
            let exists = unsafe { libc::kill(pid as i32, 0) };
            if exists == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            poll.tick().await;
        }
    })
    .await
    .expect("test owner process exit barrier");
}
async fn rename(client: &mut Client, lease: &SessionLease, name: &str) -> u64 {
    let info = client.value(lease, "database_info", json!({})).await;
    let address = info["address"].as_u64().unwrap();
    assert_eq!(
        client
            .value(
                lease,
                "rename_address",
                json!({"address":address,"name":name})
            )
            .await,
        true
    );
    address
}
async fn name(client: &mut Client, lease: &SessionLease, address: u64) -> Value {
    client
        .value(lease, "read_name", json!({"address":address}))
        .await
}
#[tokio::test]
async fn e02_readiness_dependencies_versions_and_runtime() {
    let client = Client::new().await;
    let cfg = config();
    assert!(client.bridge.pid > 0);
    client.shutdown().await.unwrap();
    let mut missing = cfg.clone();
    missing.directory = cfg.directory.with_file_name(id());
    let shell = root().join("no-site-python");
    std::fs::write(
        &shell,
        format!("#!/bin/sh\nexec '{}' -S \"$@\"\n", cfg.python.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700)).unwrap();
    missing.python = shell;
    let mut rejected_directories = vec![missing.directory.clone()];
    let router = ida_mcp::router::RouterState::new().unwrap();
    let error = router
        .connect_nexus(missing)
        .await
        .err()
        .expect("missing dependency rejected")
        .to_string();
    assert!(error.contains("dependency_unavailable"), "{error}");
    let mut wrong = cfg.clone();
    wrong.directory = cfg.directory.with_file_name(id());
    wrong
        .environment
        .insert("N3_WRONG_VERSION".into(), "1".into());
    rejected_directories.push(wrong.directory.clone());
    let router = ida_mcp::router::RouterState::new().unwrap();
    let error = router
        .connect_nexus(wrong)
        .await
        .err()
        .expect("wrong version rejected")
        .to_string();
    assert!(
        error.contains("0.13.3") && error.contains("0.13.4") && error.contains("0.5.1"),
        "{error}"
    );
    let fake = root().join("unsupported/Contents/MacOS");
    std::fs::create_dir_all(&fake).unwrap();
    std::fs::write(fake.parent().unwrap().join("Info.plist"), b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleShortVersionString</key><string>9.3</string></dict></plist>").unwrap();
    let mut unsupported = cfg;
    unsupported.directory = unsupported.directory.with_file_name(id());
    unsupported
        .environment
        .insert("IDADIR".into(), fake.to_string_lossy().into_owned());
    rejected_directories.push(unsupported.directory.clone());
    let router = ida_mcp::router::RouterState::new().unwrap();
    let error = router
        .connect_nexus(unsupported)
        .await
        .err()
        .expect("unsupported runtime rejected")
        .to_string();
    assert!(error.contains("runtime_unavailable"), "{error}");
    // StartupGuard reaps on a native thread. Keep this test runtime alive until
    // its precise rejected launches have finished their own socket cleanup.
    tokio::time::timeout(Duration::from_secs(5), async {
        while rejected_directories.iter().any(|directory| {
            ["b", "c", "l"]
                .iter()
                .any(|name| directory.join(name).exists())
        }) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("rejected startup reapers finish exact socket cleanup");
    record(json!({"case":"E02", "status":"PASS", "assertions":4}));
}
#[tokio::test]
async fn e03_raw_and_existing_idb_save_close_reopen() {
    let source = sample("e03");
    let mut a = Client::new().await;
    let (lease, opened) = a.open(&source, json!({})).await;
    let path = opened["idb_path"].as_str().unwrap().to_string();
    assert!(path.starts_with(root().join("cli-home/idb").to_str().unwrap()));
    let address = rename(&mut a, &lease, "N3_SAVED_E03").await;
    let deadline = a
        .execute(
            &lease,
            "execute_python",
            json!({"timeout_secs":1,"code":"while True:\n    pass"}),
        )
        .await;
    assert_eq!(deadline.status, OperationStatus::TimedOut);
    assert!(
        deadline.execution_stopped,
        "only the execution cancellation response proves stop"
    );
    assert_eq!(name(&mut a, &lease, address).await, "N3_SAVED_E03");
    a.release(&lease).await;
    owner_exited(opened["pid"].as_u64().unwrap() as u32).await;
    assert!(std::path::Path::new(&path).is_file());
    let (lease, reopened) = a.open(std::path::Path::new(&path), json!({})).await;
    assert_eq!(name(&mut a, &lease, address).await, "N3_SAVED_E03");
    assert_ne!(
        opened["lease"]["instance_id"],
        reopened["lease"]["instance_id"]
    );
    a.release(&lease).await;
    a.shutdown().await.unwrap();
    record(json!({"case":"E03", "status":"PASS", "saved_name":"N3_SAVED_E03", "idb_path":path}));
}
#[tokio::test]
async fn e05_two_client_processes_share_and_release_independently() {
    let source = sample("e05");
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    assert_ne!(a.bridge.pid, b.bridge.pid);
    let (la, oa) = a.open(&source, json!({})).await;
    let (lb, ob) = b
        .open(&source, json!({"attach_instance":la.instance_id.as_str()}))
        .await;
    assert_eq!(la.instance_id, lb.instance_id);
    assert_eq!(oa["pid"], ob["pid"]);
    let address = rename(&mut a, &la, "N3_A_SHARED").await;
    assert_eq!(name(&mut b, &lb, address).await, "N3_A_SHARED");
    a.release(&la).await;
    assert_eq!(name(&mut b, &lb, address).await, "N3_A_SHARED");
    rename(&mut b, &lb, "N3_B_AFTER_A_RELEASE").await;
    b.release(&lb).await;
    owner_exited(oa["pid"].as_u64().unwrap() as u32).await;
    let (la, _) = a.open(&source, json!({})).await;
    assert_eq!(name(&mut a, &la, address).await, "N3_B_AFTER_A_RELEASE");
    a.release(&la).await;
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    record(
        json!({"case":"E05", "status":"PASS", "same_owner":oa["pid"], "persisted":"N3_B_AFTER_A_RELEASE"}),
    );
}
struct External {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    opened: Value,
}
impl External {
    async fn start(source: &std::path::Path) -> Self {
        let cfg = config();
        let mut child = tokio::process::Command::new(cfg.python)
            .arg(cfg.script)
            .arg("external")
            .arg(source)
            .env_clear()
            .envs(cfg.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn_fenced()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
        let opened = serde_json::from_str(
            &tokio::time::timeout(Duration::from_secs(15), output.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        Self {
            child,
            input,
            output,
            opened,
        }
    }
    async fn call(&mut self, request: Value) -> Value {
        self.input
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let line = tokio::time::timeout(Duration::from_secs(15), self.output.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }
}
#[tokio::test]
async fn e06_client_killed_shared_owner_survives_and_last_release_saves() {
    let source = sample("e06-client");
    let mut a = Client::new().await;
    let (lease, opened) = a.open(&source, json!({})).await;
    let mut external = External::start(
        &std::path::PathBuf::from(opened["idb_path"].as_str().unwrap()).with_extension(""),
    )
    .await;
    assert_eq!(external.opened["instance_id"], lease.instance_id.as_str());
    #[cfg(feature = "nexus-test-support")]
    let pid = external.child.id().expect("owned external client PID");
    external.child.kill().await.unwrap();
    let status = external
        .child
        .wait()
        .await
        .expect("actual killed external status");
    #[cfg(feature = "nexus-test-support")]
    ida_mcp::router::nexus_bridge::test_record_child_exit(
        pid,
        &status,
        "E06.Child.wait.cached_after_kill",
    );
    assert!(
        !status.success(),
        "controlled client kill must have a native terminal"
    );
    let address = rename(&mut a, &lease, "N3_SURVIVES_CLIENT_KILL").await;
    assert_eq!(
        name(&mut a, &lease, address).await,
        "N3_SURVIVES_CLIENT_KILL"
    );
    a.release(&lease).await;
    owner_exited(opened["pid"].as_u64().unwrap() as u32).await;
    let (lease, _) = a.open(&source, json!({})).await;
    assert_eq!(
        name(&mut a, &lease, address).await,
        "N3_SURVIVES_CLIENT_KILL"
    );
    a.release(&lease).await;
    a.shutdown().await.unwrap();
    record(json!({"case":"E06-client", "status":"PASS"}));
}
#[tokio::test]
async fn e06_bridge_killed_external_lease_survives() {
    let source = sample("e06-bridge");
    let mut a = Client::new().await;
    let (lease, opened) = a.open(&source, json!({})).await;
    let mut external = External::start(
        &std::path::PathBuf::from(opened["idb_path"].as_str().unwrap()).with_extension(""),
    )
    .await;
    assert_eq!(external.opened["instance_id"], lease.instance_id.as_str());
    a.bridge.terminate().await.unwrap();
    let snapshot = a
        .bridge
        .endpoint()
        .transition(|s, _| s.status(&a.client, &lease))
        .unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Disconnected);
    let response=external.call(json!({"command":"execute", "code":"import ida_ida, ida_name\nea = ida_ida.inf_get_min_ea()\nassert ida_name.set_name(ea, 'N3_EXTERNAL_SURVIVES', ida_name.SN_CHECK)\nresult = ida_name.get_name(ea)"})).await;
    assert_eq!(response["result"], "N3_EXTERNAL_SURVIVES");
    assert_eq!(
        external.call(json!({"command":"close"})).await["event"],
        "external_closed"
    );
    #[cfg(feature = "nexus-test-support")]
    let pid = external
        .child
        .id()
        .expect("owned closing external client PID");
    let status = external
        .child
        .wait()
        .await
        .expect("actual external close status");
    #[cfg(feature = "nexus-test-support")]
    ida_mcp::router::nexus_bridge::test_record_child_exit(
        pid,
        &status,
        "E06.Child.wait.external_close",
    );
    assert!(status.success(), "external close must exit successfully");
    owner_exited(opened["pid"].as_u64().unwrap() as u32).await;
    tokio::time::timeout(Duration::from_secs(20), async {
        while a.bridge.lifecycle_status()["resources"] != 0
            || a.bridge.lifecycle_status()["startup_and_pre_attach"] != 0
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("dead bridge's public proof and producer closures");
    a.bridge
        .shutdown()
        .await
        .expect("finish exact dead bridge helper after public proof");
    let mut b = Client::new().await;
    let (lease, _) = b.open(&source, json!({})).await;
    let info = b.value(&lease, "database_info", json!({})).await;
    assert_eq!(info["name"], "N3_EXTERNAL_SURVIVES");
    b.release(&lease).await;
    b.shutdown().await.unwrap();
    record(json!({"case":"E06-bridge", "status":"PASS"}));
}
async fn crash_recovery(packed: bool) {
    let source = sample(if packed { "e07-packed" } else { "e07-unpacked" });
    let mut a = Client::new().await;
    let (old, opened) = a.open(&source, json!({"auto_analysis":false})).await;
    let address = rename(&mut a, &old, "N3_BASE").await;
    let idb = std::path::PathBuf::from(opened["idb_path"].as_str().unwrap());
    if packed {
        assert_eq!(a.value(&old,"execute_python",json!({"code":"import ida_loader\nresult = bool(ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0))"})).await,true);
    }
    assert_eq!(idb.exists(), packed, "packed base precondition");
    assert_eq!(a.value(&old,"execute_python",json!({"code":format!("import ida_name, ida_loader\nassert ida_name.set_name({address}, 'N3_FLUSHED', ida_name.SN_CHECK)\nida_loader.flush_buffers()\nresult = True")})).await,true);
    let marker = root().join(if packed {
        "crash-packed-count"
    } else {
        "crash-unpacked-count"
    });
    let mut crash_events = a.bridge.subscribe();
    let result=a.execute(&old,"execute_python",json!({"code":format!("import os\nwith open({:?}, 'a') as stream:\n    stream.write('once\\n')\nos._exit(73)",marker.to_string_lossy())})).await;
    assert_eq!(result.status, OperationStatus::UnknownOutcome);
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "once\n");
    owner_exited(opened["pid"].as_u64().unwrap() as u32).await;
    tokio::time::timeout(Duration::from_secs(20), async {
        let (mut disconnected, mut released) = (false, false);
        while !disconnected || !released {
            let event = crash_events.recv().await.expect("exact crash event stream");
            if event["lease"] == json!(old) {
                disconnected |= event["event"] == "disconnected";
                released |= event["event"] == "owner_released";
            }
        }
    })
    .await
    .expect("disconnect and public proof barriers");
    assert_eq!(
        a.bridge
            .endpoint()
            .transition(|s, _| s.status(&a.client, &old))
            .unwrap()
            .phase,
        SessionPhase::Released,
        "public owner proof advances the disconnected lease to Released"
    );
    assert!(
        a.bridge
            .endpoint()
            .transition(|s, _| s.queue(
                &a.client,
                &old,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new(id()).unwrap(),
                    None,
                    "database_info",
                    json!({})
                )
                .unwrap(),
                OperationId::new(id()).unwrap()
            ))
            .is_err(),
        "old disconnected handle rejects new operations"
    );
    if packed {
        std::fs::write(root().join("e07-reopen-root-loss.arm"), b"one R9 retry")
            .expect("arm exact post-crash acquisition");
    }
    let (replacement, reopened) = a.open(&source, json!({"auto_analysis":false})).await;
    if packed {
        assert!(root().join("e07-reopen-root-loss.observed").is_file());
        assert!(!root().join("e07-reopen-root-loss.arm").exists());
        let ordinal = reopened["acquisition"]["ordinal"]
            .as_u64()
            .expect("actual acquisition ordinal");
        assert!(
            (2..=3).contains(&ordinal),
            "one injected failure within the accepted three-attempt R9 budget"
        );
        assert_eq!(reopened["acquisition"]["purpose"], "initial_root_retry");
    }
    assert_ne!(old.instance_id, replacement.instance_id);
    assert_eq!(
        reopened["recovery"],
        if packed { "restored" } else { "repaired" }
    );
    assert_eq!(
        name(&mut a, &replacement, address).await,
        if packed { "N3_BASE" } else { "N3_FLUSHED" }
    );
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "once\n",
        "crash write never replays"
    );
    assert!(idb.exists(), "recovery creates packed database");
    let backups: Vec<_> = std::fs::read_dir(idb.parent().unwrap())
        .unwrap()
        .map(|x| x.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!(
                    "{}.crash-",
                    idb.file_name().unwrap().to_string_lossy()
                ))
        })
        .collect();
    assert_eq!(
        backups.len(),
        if packed {
            usize::try_from(
                reopened["acquisition"]["ordinal"]
                    .as_u64()
                    .expect("actual recovery acquisition"),
            )
            .expect("bounded ordinal")
        } else {
            0
        },
        "exactly one backup per actual accepted restore acquisition; no extra or missing backup"
    );
    a.release(&replacement).await;
    a.shutdown().await.unwrap();
    record(
        json!({"case":if packed {"E07-packed"} else {"E07-unpacked"},"status":"PASS","recovery":reopened["recovery"],"crash_count":1,"backups":backups}),
    );
}
#[tokio::test]
async fn e07_crash_without_packed_base_repairs() {
    crash_recovery(false).await;
}
#[tokio::test]
async fn e07_crash_with_packed_base_restores_backup() {
    crash_recovery(true).await;
}

#[tokio::test]
async fn e05_concurrent_ordinary_open_shares_owner_without_explicit_attach() {
    let source = sample("e05-concurrent-open");
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    assert_ne!(a.bridge.pid, b.bridge.pid);
    // Both normal opens enter via separate bridge processes, sharing only the
    // canonical snapshot published by the production cache preparation path.
    let ((la, oa), (lb, ob)) = tokio::join!(a.open(&source, json!({})), b.open(&source, json!({})));
    assert_eq!(la.instance_id, lb.instance_id);
    assert_eq!(oa["pid"], ob["pid"]);
    let address = rename(&mut a, &la, "F1_CONCURRENT_OPEN").await;
    assert_eq!(name(&mut b, &lb, address).await, "F1_CONCURRENT_OPEN");
    a.release(&la).await;
    assert_eq!(name(&mut b, &lb, address).await, "F1_CONCURRENT_OPEN");
    b.release(&lb).await;
    owner_exited(oa["pid"].as_u64().unwrap() as u32).await;
    let (reopened, _) = a.open(&source, json!({})).await;
    assert_eq!(name(&mut a, &reopened, address).await, "F1_CONCURRENT_OPEN");
    a.release(&reopened).await;
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    record(
        json!({"case":"E05-concurrent-open", "status":"PASS", "instance_id":la.instance_id, "owner_pid":oa["pid"], "saved_name":"F1_CONCURRENT_OPEN"}),
    );
}

#[tokio::test]
async fn e06_same_router_lease_sse_fault_preserves_sibling_operation() {
    let source = sample("e06-lease-fault");
    let mut cfg = config();
    cfg.environment.insert("N3_LEASE_FAULT".into(), "1".into());
    let mut a = Client::configured(cfg).await;
    let (idle, opened) = a.open(&source, json!({})).await;
    let (healthy, peer) = a.open(&source, json!({})).await;
    assert_eq!(idle.instance_id, healthy.instance_id);
    assert_eq!(opened["pid"], peer["pid"]);
    let started = root().join("lease-fault-sibling.started");
    let release = root().join("lease-fault-sibling.release");
    let operation = a.begin(&healthy, "execute_python", json!({"timeout_secs":12,
        "code":format!("from pathlib import Path\nimport time\nPath({:?}).touch()\ndeadline = time.monotonic() + 10\nwhile not Path({:?}).exists():\n    assert time.monotonic() < deadline, 'sibling release barrier'\n    time.sleep(0.01)\nresult = 'sibling_survived_lease_fault'",started.to_string_lossy(),release.to_string_lossy())}));
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut poll = tokio::time::interval(Duration::from_millis(10));
        while !started.exists() {
            poll.tick().await;
        }
    })
    .await
    .expect("healthy operation entered IDA barrier before injected SSE failure");
    std::fs::write(root().join("lease-fault.inject"), b"inject first SSE only").unwrap();
    let disconnected = a
        .event(|event| {
            event["event"] == "disconnected" && event["lease"]["lease_id"] == idle.lease_id.as_str()
        })
        .await;
    assert!(
        disconnected["reason"]
            .as_str()
            .unwrap()
            .contains("injected isolated first-lease SSE failure"),
        "{disconnected}"
    );
    let (dead, live, active) = a.bridge.endpoint().transition(|s, _| {
        (
            s.status(&a.client, &idle).unwrap(),
            s.status(&a.client, &healthy).unwrap(),
            s.operation_status(&a.client, &operation).unwrap(),
        )
    });
    assert_eq!(dead.phase, SessionPhase::Disconnected);
    assert_eq!(live.phase, SessionPhase::Active);
    assert_eq!(active.status, OperationStatus::Running);
    std::fs::write(&release, b"release").unwrap();
    let result = a.finish(&operation).await;
    assert_eq!(result.status, OperationStatus::Succeeded);
    assert_eq!(
        result.result.unwrap()["result"],
        "sibling_survived_lease_fault"
    );
    let address = rename(&mut a, &healthy, "F1_HEALTHY_AFTER_LEASE_FAULT").await;
    a.release(&idle).await;
    assert_eq!(
        name(&mut a, &healthy, address).await,
        "F1_HEALTHY_AFTER_LEASE_FAULT"
    );
    a.release(&healthy).await;
    owner_exited(opened["pid"].as_u64().unwrap() as u32).await;
    a.shutdown().await.unwrap();
    record(
        json!({"case":"E06-lease-fault", "status":"PASS", "expired_lease":idle, "healthy_lease":healthy, "reason":disconnected["reason"], "active_operation":operation}),
    );
}
