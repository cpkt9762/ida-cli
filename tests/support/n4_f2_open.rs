use super::*;
static FIXTURE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
async fn run_case(fault: &str) {
    let name = format!("router::nexus_tools::n4_f2_regressions::open_{fault}").replace('-', "_");
    if std::env::var("N4_F2_CHILD").as_deref() != Ok(&name) {
        // Fault injection is independent per subprocess; avoid adding seven
        // simultaneous startup jobs to the parallel library's existing fixtures.
        let _fixture = FIXTURE_GATE.lock().await;
        let root = std::env::temp_dir().join(format!("n4f2-{}-{fault}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("ipc")).unwrap();
        let child = tokio::process::Command::new("timeout")
            .arg("25s")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env("N4_F2_CHILD", &name)
            .env("N4_F2_OPEN_FAULT", fault)
            .env("IDA_CLI_HOME", &root)
            .env("IDA_NEXUS_STATE_DIR", root.join("state"))
            .env("IDA_CLI_NEXUS_DEV", "1")
            .env("IDA_NEXUS_PYTHON", "/usr/bin/python3")
            .env("IDA_NEXUS_IPC_ROOT", root.join("ipc"))
            .env(
                "IDA_NEXUS_BRIDGE_SCRIPT",
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/n4_open_fixture.py"),
            )
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        crate::preprocess::record_owned_fixture(
            child.id().unwrap(),
            false,
            "n4-f2-isolated-libtest",
        );
        let output = child.wait_with_output().await.unwrap();
        // fixture child is also reaped by production bridge.shutdown below.
        let process_file = root.join("bridge-process.json");
        if process_file.exists() {
            let value: Value =
                serde_json::from_slice(&std::fs::read(&process_file).unwrap()).unwrap();
            crate::preprocess::record_owned_fixture(
                value["pid"].as_u64().unwrap() as u32,
                false,
                "n4-f2-bridge",
            );
        }
        std::fs::remove_dir_all(root).unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let router = RouterState::new().unwrap();
    let bridge = Tools::bridge(&router).await.unwrap(); // startup budget is separate
    let tools = Arc::new(Tools::new(1).unwrap());
    let path = PathBuf::from(std::env::var_os("IDA_CLI_HOME").unwrap()).join("copy.i64");
    std::fs::write(&path, b"isolated IDB stand-in").unwrap();
    let preparation = Preparation::new(Duration::from_secs(if fault.starts_with("deadline") {
        2
    } else {
        10
    }));
    let cancellation = preparation.cancel.clone();
    let mut events = bridge.subscribe();
    let mut control = if fault == "release-busy" {
        Some(bridge.endpoint().transition(|_, t| t.test_hold_control()))
    } else {
        None
    };
    let owned_tools = tools.clone();
    let owned_router = router.clone();
    let path_string = path.display().to_string();
    let mut open = tokio::spawn(async move {
        owned_tools
            .open(&owned_router, &path_string, preparation)
            .await
    });
    if matches!(fault, "cancel" | "deadline" | "deadline-fallback") {
        let marker = path.parent().unwrap().join("before-grant");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !marker.exists() {
                tokio::task::yield_now().await
            }
        })
        .await
        .unwrap();
        if fault == "cancel" {
            cancellation.cancel();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        if fault == "deadline" {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        if fault != "deadline-fallback" {
            std::fs::write(path.parent().unwrap().join("grant-release"), b"").unwrap();
        }
    }
    let returned = tokio::time::timeout(Duration::from_secs(4), &mut open).await;
    let timely = returned.is_ok();
    let failed = returned.is_ok_and(|result| result.unwrap().is_err());
    std::fs::write(path.parent().unwrap().join("grant-release"), b"").unwrap();
    drop(control.take());
    let resources = tools.capacity.available_permits() == 1 && bridge.test_reply_count() == 0;
    let mut acquired = None;
    while let Ok(event) = events.try_recv() {
        if event["event"] == "opened" {
            acquired =
                Some(serde_json::from_value::<SessionLease>(event["lease"].clone()).unwrap());
        }
    }
    if timely && fault == "deadline-fallback" {
        acquired = Some(
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let event = events.recv().await.unwrap();
                    if event["event"] == "opened" {
                        break serde_json::from_value::<SessionLease>(event["lease"].clone())
                            .unwrap();
                    }
                }
            })
            .await
            .expect("late acquired lease must remain tracked"),
        );
    }
    let acquired_required = fault == "release-busy" || fault == "deadline-fallback";
    let acquired_observed = acquired.is_some();
    let mut released = true;
    if let Some(lease) = acquired {
        released = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if bridge
                    .endpoint()
                    .transition(|s, _| s.status(&lease.client_id, &lease))
                    .unwrap()
                    .phase
                    == SessionPhase::Released
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
    }
    let reopened = if timely && resources {
        tokio::time::timeout(
            Duration::from_secs(5),
            tools.open(
                &router,
                &path.display().to_string(),
                Preparation::new(Duration::from_secs(5)),
            ),
        )
        .await
        .ok()
        .and_then(Result::ok)
    } else {
        None
    };
    let closed = if let Some((_, token)) = &reopened {
        tools.close_token(&router, token).await.is_ok()
    } else {
        false
    };
    bridge.shutdown().await.unwrap();
    if !timely {
        open.abort();
    }
    assert!(
        timely && failed,
        "open_owned must return its actual terminal failure within the response budget"
    );
    assert!(
        resources,
        "capacity permit and reply slot must both be released"
    );
    assert!(
        !acquired_required || acquired_observed,
        "fault must exercise an actually acquired lease"
    );
    assert!(
        released,
        "an acquired lease must not be left Active or ownerless"
    );
    assert!(
        reopened.is_some() && closed,
        "same-path open/close must recover capacity and path gate"
    );
}
#[tokio::test]
async fn open_cancel() {
    run_case("cancel").await;
}
#[tokio::test]
async fn open_deadline() {
    run_case("deadline").await;
}
#[tokio::test]
async fn open_deadline_fallback() {
    run_case("deadline-fallback").await;
}
#[tokio::test]
async fn open_not_sent() {
    run_case("not-sent").await;
}
#[tokio::test]
async fn open_remote_error() {
    run_case("remote-error").await;
}
#[tokio::test]
async fn open_zero_byte() {
    run_case("zero-byte").await;
}
#[tokio::test]
async fn open_release_busy() {
    run_case("release-busy").await;
}
