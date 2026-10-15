use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

async fn isolated_c1(name: &str, work: impl std::future::Future<Output = ()>) {
    if std::env::var("IDA_N2_F5_CASE").as_deref() == Ok(name) {
        work.await;
    } else {
        let home =
            std::env::temp_dir().join(format!("n2-f5-harness-{}-{name}", std::process::id()));
        std::fs::create_dir(&home).unwrap();
        let child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("server::n2_f1_regressions::{name}"))
            .arg("--nocapture")
            .env("IDA_N2_F5_CASE", name)
            .env("IDA_CLI_HOME", &home)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        crate::preprocess::record_owned_fixture(child.id().unwrap(), false, "f5-isolated-libtest");
        let output = child.wait_with_output().await.unwrap();
        std::fs::remove_dir_all(home).unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains("1 passed"),
            "isolated case must execute all assertions: {stdout}\n{stderr}"
        );
    }
}

async fn c1_open_case(case: &str) {
    use crate::router::n2_f1_regressions::{first_open_fixture, fixture_reference_count};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let directory = std::env::temp_dir().join(format!("n2-f5-open-{}-{case}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let blocked = match case {
        "cancel" | "deadline" | "drop-open" | "shared-error" => Some("open"),
        "drop-detect" => Some("get_function_by_name"),
        _ => None,
    };
    let (router, path) = first_open_fixture(&directory, "none", blocked).await;
    std::fs::write(directory.join("worker.py"), include_str!("n2_f5_worker.py")).unwrap();
    if case != "drop-detect" {
        // Still an isolated .i64 fixture, but not sBPF; never invoke real IDA.
        std::fs::write(&path, b"plain synthetic database fixture").unwrap();
    }
    let reused = case.starts_with("reuse-");
    let fail_open = match case {
        "error" | "shared-error" => 1,
        "reuse-held" | "reuse-zero" => 2,
        _ => 0,
    };
    let config_path = directory.join("worker.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    config["case"] = case.into();
    config["fail_open"] = fail_open.into();
    if case == "non-object" {
        config["open_result"] = json!(["opened", 7]);
    }
    std::fs::write(config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let listener = if blocked.is_some() {
        Some(tokio::net::UnixListener::bind(directory.join("ready.sock")).unwrap())
    } else {
        None
    };
    let mut other_token = None;
    if reused {
        let (_, token) = router.ensure_worker_with_ref(&path, None).await.unwrap();
        if case == "reuse-held" {
            other_token = Some(token);
        } else {
            assert_eq!(router.release_ref_token(&token).await.unwrap().1, 0);
        }
    }
    let before_refs = fixture_reference_count(&router);
    let before_workers = router.worker_count().await;
    let (unused_sender, _unused_receiver) = std::sync::mpsc::sync_channel(1);
    let server = IdaMcpServer::new(
        Arc::new(IdaWorker::new(unused_sender)),
        ServerMode::Router(router.clone()),
    );
    let request = serde_json::from_value(json!({"path":path})).unwrap();
    let preparation =
        crate::preprocess::Preparation::new(Duration::from_secs(if case == "deadline" {
            2
        } else {
            10
        }));
    let cancel = preparation.cancel.clone();
    let deadline = preparation.deadline;
    let owned = router.clone();
    let inherit = matches!(case, "cancel" | "deadline");
    let mut call = tokio::spawn(async move {
        if inherit {
            preparation
                .scope(server.open_idb_routed(&owned, &request))
                .await
        } else {
            server.open_idb_routed(&owned, &request).await
        }
    });
    let mut barrier = if let Some(listener) = listener {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        assert_eq!(line, "started\n");
        Some(stream)
    } else {
        None
    };
    if case == "shared-error" {
        other_token = Some(
            router
                .issue_ref_for_handle(&router.active_handle().await.unwrap())
                .await,
        );
        barrier
            .as_mut()
            .unwrap()
            .get_mut()
            .write_all(b"x")
            .await
            .unwrap();
    }
    if case == "cancel" {
        assert!(cancel.cancel());
    }
    if case == "deadline" {
        tokio::time::sleep_until(deadline.into()).await;
    }
    let dropped = case.starts_with("drop-");
    if dropped {
        call.abort();
    }
    let first = tokio::time::timeout(Duration::from_millis(700), &mut call).await;
    let timely = first.is_ok();
    // On the red baseline, cancellation/deadline are not consumed by this
    // entry; release its pipe before asserting so no fixture is stranded.
    let output = match first {
        Ok(output) => output,
        Err(_) => {
            barrier
                .as_mut()
                .expect("only a deliberately blocked case may time out")
                .get_mut()
                .write_all(b"x")
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), call)
                .await
                .unwrap()
        }
    };
    let after_refs = fixture_reference_count(&router);
    let handles = router.all_handles().await;
    let other_preserved = if let Some(token) = &other_token {
        router.handle_for_token(token).await.is_some()
    } else {
        true
    };
    let tool = if dropped {
        assert!(output.unwrap_err().is_cancelled());
        None
    } else {
        Some(output.unwrap().unwrap())
    };
    let payload = tool.as_ref().map(|tool| {
        let encoded = serde_json::to_value(tool).unwrap();
        encoded["content"][0]["text"].as_str().unwrap().to_string()
    });
    let value: Option<Value> = payload
        .as_ref()
        .and_then(|text| serde_json::from_str(text).ok());
    let returned_token = value.as_ref().and_then(|v| v["close_token"].as_str());
    let transferred = if let Some(token) = returned_token {
        let matching = router.handle_for_token(token).await.as_deref()
            == value.as_ref().unwrap()["db_handle"].as_str();
        assert_eq!(router.release_ref_token(token).await.unwrap().1, 0);
        matching
    } else {
        false
    };
    if let Some(token) = other_token {
        router.release_ref_token(&token).await;
    }
    for handle in &handles {
        router.close_worker(handle).await.unwrap();
    }
    drop(barrier);
    let methods = std::fs::read_to_string(directory.join("methods.log")).unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    let observed = json!({"case":case,"before_refs":before_refs,"after_refs":after_refs,
        "before_workers":before_workers,"after_workers":handles.len(),"other_preserved":other_preserved,
        "token_transferred":transferred,"timely":timely,"methods":methods});
    if let Some(root) = std::env::var_os("IDA_N2_F5_EVIDENCE") {
        std::fs::write(
            std::path::PathBuf::from(root)
                .join(format!("fixture-{}-{case}.json", std::process::id())),
            serde_json::to_vec_pretty(&observed).unwrap(),
        )
        .unwrap();
    }
    assert!(
        timely,
        "entry must consume cancellation/total deadline: {observed}"
    );
    assert!(
        other_preserved,
        "must preserve other client's reference: {observed}"
    );
    let expected_refs =
        usize::from(case == "success" || case == "reuse-held" || case == "shared-error");
    assert_eq!(
        after_refs, expected_refs,
        "entry must release or transfer exactly its own token: {observed}"
    );
    let closed = matches!(case, "error" | "cancel" | "deadline");
    assert_eq!(
        handles.len(),
        usize::from(!closed),
        "only a new unreferenced failed open may close: {observed}"
    );
    match case {
        "error" | "reuse-held" | "reuse-zero" | "shared-error" => {
            assert!(tool.unwrap().is_error.unwrap_or(false));
            assert_eq!(payload.unwrap(), "IDA error: fixture open error");
        }
        "cancel" => {
            assert!(tool.unwrap().is_error.unwrap_or(false));
            assert_eq!(payload.unwrap(), "Offline preparation: UnknownOutcome: cancelled waiter after possible send; never replay (execution_stopped=false)");
        }
        "deadline" => {
            assert!(tool.unwrap().is_error.unwrap_or(false));
            assert_eq!(payload.unwrap(), "Operation timed out after 120 seconds; outcome unknown, execution_stopped=false; never replay");
        }
        "non-object" => {
            assert!(!tool.unwrap().is_error.unwrap_or(false));
            assert_eq!(value.unwrap(), json!(["opened", 7]));
            assert!(!transferred);
        }
        "success" => {
            assert!(!tool.unwrap().is_error.unwrap_or(false));
            assert!(transferred);
            assert_eq!(value.unwrap()["opened"], true);
        }
        _ => assert!(dropped),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_error_releases_reference_and_closes_new_worker() {
    isolated_c1(
        "c1_mcp_open_error_releases_reference_and_closes_new_worker",
        c1_open_case("error"),
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_cancel_releases_reference_without_false_stop() {
    isolated_c1(
        "c1_mcp_open_cancel_releases_reference_without_false_stop",
        c1_open_case("cancel"),
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_deadline_releases_reference_without_false_stop() {
    isolated_c1(
        "c1_mcp_open_deadline_releases_reference_without_false_stop",
        c1_open_case("deadline"),
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_future_drop_releases_before_and_after_open_response() {
    isolated_c1(
        "c1_mcp_open_future_drop_releases_before_and_after_open_response",
        async {
            c1_open_case("drop-open").await;
        },
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_non_object_result_releases_untransferable_reference() {
    isolated_c1(
        "c1_mcp_open_non_object_result_releases_untransferable_reference",
        c1_open_case("non-object"),
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_success_transfers_reference_in_response() {
    isolated_c1(
        "c1_mcp_open_success_transfers_reference_in_response",
        c1_open_case("success"),
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_reused_worker_error_preserves_worker_and_original_reference() {
    isolated_c1(
        "c1_mcp_open_reused_worker_error_preserves_worker_and_original_reference",
        async {
            for case in ["reuse-held", "reuse-zero"] {
                c1_open_case(case).await;
            }
        },
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_new_worker_error_preserves_late_client_reference() {
    isolated_c1(
        "c1_mcp_open_new_worker_error_preserves_late_client_reference",
        c1_open_case("shared-error"),
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn script_file_read_uses_admission_deadline_and_retains_job_after_waiter_exits() {
    let base = std::env::temp_dir().join(format!("n2-script-read-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("blocked.py");
    std::fs::write(&path, b"print('fixture')").unwrap();
    let (started, start) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    SCRIPT_READ_BARRIERS
        .lock()
        .unwrap()
        .insert(path.display().to_string(), (started, released));
    let (tx, rx) = std::sync::mpsc::sync_channel(2);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let native = std::thread::spawn(move || {
        while let Ok(request) = rx.recv() {
            count.fetch_add(1, Ordering::SeqCst);
            let crate::ida::EnqueuedRequest { request, .. } = request;
            if let crate::ida::IdaRequest::RunScript { resp, .. } = request {
                resp.send(Ok(json!({"success":true}))).unwrap();
            } else {
                panic!("unexpected native call");
            }
        }
    });
    let server = Arc::new(IdaMcpServer::new(
        Arc::new(IdaWorker::new(tx)),
        ServerMode::Stdio,
    ));
    let preparation = crate::preprocess::Preparation::new(Duration::from_millis(150));
    let observed = preparation.clone();
    let request = serde_json::from_value(json!({"file":path,"timeout_secs":1})).unwrap();
    let owned = server.clone();
    let mut task = tokio::spawn(async move {
        preparation
            .scope(owned.run_script(Parameters(request)))
            .await
    });
    start.await.unwrap(); // Actual regular-file read closure entered its controlled boundary.
    let result = tokio::time::timeout(Duration::from_millis(400), &mut task).await;
    let tracked = observed.active_input_jobs();
    release.send(()).unwrap();
    let timely = result.is_ok();
    let result = match result {
        Ok(result) => result,
        Err(_) => task.await,
    };
    drop(server);
    native.join().unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while observed.active_input_jobs() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    std::fs::remove_dir_all(base).unwrap();
    assert!(timely, "script read must consume original total deadline");
    assert!(result.unwrap().unwrap().is_error.unwrap_or(false));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "expired read must not enqueue a later script"
    );
    assert_eq!(
        tracked, 1,
        "abandoned file closure retains its owned tracking/permit until EOF"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn dsc_publish_wins_but_cancel_before_phase2_prevents_new_native_open() {
    let base = std::env::temp_dir().join(format!("n2-dsc-phase2-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let final_path = base.join("final.i64");
    let mut stage = crate::preprocess::StagedArtifact::create(&final_path).unwrap();
    let cleanup = stage.cleanup_receipt();
    let (started, start) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    stage.cleanup_barrier(started, released);
    let preparation = crate::preprocess::Preparation::new(Duration::from_secs(5));
    let cancel = preparation.cancel.clone();
    let registry = task::TaskRegistry::new();
    let id = registry.create("phase2", "offline");
    registry.set_cancellation(&id, cancel);
    let (tx, rx) = std::sync::mpsc::sync_channel(2);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let native = std::thread::spawn(move || {
        while let Ok(request) = rx.recv() {
            count.fetch_add(1, Ordering::SeqCst);
            let crate::ida::EnqueuedRequest { request, .. } = request;
            if let crate::ida::IdaRequest::Open { resp, .. } = request {
                resp.send(Err(ToolError::IdaError(
                    "fixture native open reached".into(),
                )))
                .unwrap();
            } else {
                panic!("unexpected native call");
            }
        }
    });
    let worker = Arc::new(IdaWorker::new(tx));
    let args = vec![
        "-c".into(),
        "printf published > \"$1\"".into(),
        "fixture".into(),
        stage.output.display().to_string(),
    ];
    let context = DscBackgroundCtx {
        idat: "/bin/sh".into(),
        idat_args: args,
        preparation,
        stage,
        script_path: base.join("offline.py"),
        log_path: None,
        out_i64: final_path.clone(),
        module: "fixture".into(),
        frameworks: vec![],
    };
    let task = tokio::spawn(IdaMcpServer::run_dsc_background(
        id.clone(),
        registry.clone(),
        worker,
        ServerMode::Stdio,
        context,
    ));
    tokio::task::spawn_blocking(move || start.recv_timeout(Duration::from_secs(3)).unwrap())
        .await
        .unwrap();
    let accepted = registry.cancel(&id);
    release.send(()).unwrap();
    task.await.unwrap();
    cleanup.wait().await.unwrap();
    native.join().unwrap();
    assert_eq!(
        std::fs::read(&final_path).unwrap_or_else(|error| panic!(
            "published artifact: {error}; task={:?}",
            registry.get(&id)
        )),
        b"published"
    );
    std::fs::remove_dir_all(base).unwrap();
    assert!(
        accepted,
        "publication cannot disable later phase cancellation"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "cancelled post-publication preparation must not enqueue native Open"
    );
    assert_eq!(
        registry.get(&id).unwrap().status,
        task::TaskStatus::Cancelled
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mcp_script_large_unicode_success_and_error_keep_external_content() {
    let (tx, rx) = std::sync::mpsc::sync_channel(2);
    let native = std::thread::spawn(move || {
        for success in [true, false] {
            let enqueued: crate::ida::EnqueuedRequest = rx.recv().unwrap();
            let crate::ida::IdaRequest::RunScript { resp, .. } = enqueued.request else {
                panic!("script request")
            };
            resp.send(Ok(json!({"success":success,"stdout":"λ".repeat(9*1024*1024),"stderr":if success {""} else {"fixture failure"},"result":{"unicode":"完整"}}))).unwrap();
        }
    });
    let server = IdaMcpServer::new(Arc::new(IdaWorker::new(tx)), ServerMode::Stdio);
    for success in [true, false] {
        let request = serde_json::from_value(json!({"code":"fixture","timeout_secs":10})).unwrap();
        let response = server.run_script(Parameters(request)).await.unwrap();
        assert_eq!(response.is_error.unwrap_or(false), !success);
        let value = serde_json::to_value(response).unwrap();
        let content = value["content"][0]["text"].as_str().unwrap();
        if success {
            let result: Value = serde_json::from_str(content).unwrap();
            assert_eq!(result["stdout"].as_str().unwrap().len(), 18 * 1024 * 1024);
            assert_eq!(result["result"]["unicode"], "完整");
        } else {
            assert!(content.contains("fixture failure"));
        }
    }
    drop(server);
    native.join().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn c1_mcp_open_detect_future_drop_releases_unreturned_reference() {
    isolated_c1(
        "c1_mcp_open_detect_future_drop_releases_unreturned_reference",
        c1_open_case("drop-detect"),
    )
    .await;
}
