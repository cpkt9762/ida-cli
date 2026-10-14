use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

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
