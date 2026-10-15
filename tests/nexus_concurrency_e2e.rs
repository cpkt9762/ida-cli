//! Real N5 concurrency acceptance. Barriers are explicit files/native FIFO, with
//! separate startup and response deadlines. No latency benchmark or QPS claim.
#[path = "support/nexus_env.rs"]
mod env;
use env::*;
use ida_mcp::nexus::*;
use ida_mcp::router::nexus_bridge::NexusBridge;
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

async fn barrier(path: &Path) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        while !path.exists() {
            tick.tick().await;
        }
    })
    .await
    .expect("explicit startup/barrier budget");
}
async fn response<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("independent response deadline")
}
fn snapshot(bridge: &NexusBridge, op: &OperationIdentity) -> OperationSnapshot {
    bridge
        .endpoint()
        .transition(|s, _| s.operation_status(&op.lease.client_id, op))
        .unwrap()
}
fn queued(a: &Client, lease: &SessionLease, method: &str, params: Value) -> OperationIdentity {
    a.bridge
        .endpoint()
        .transition(|s, _| {
            s.queue(
                &lease.client_id,
                lease,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new(id()).unwrap(),
                    None,
                    method,
                    params,
                )
                .unwrap(),
                OperationId::new(id()).unwrap(),
            )
        })
        .unwrap()
}
fn dispatch(bridge: &NexusBridge, op: &OperationIdentity) {
    bridge
        .endpoint()
        .transition(|s, t| s.dispatch(&op.lease.client_id, op, t))
        .unwrap();
}
fn cancel(bridge: &NexusBridge, op: &OperationIdentity) -> OperationSnapshot {
    bridge
        .endpoint()
        .transition(|s, t| s.cancel(&op.lease.client_id, op, CancelReason::Client, t))
        .unwrap()
}
async fn terminal(bridge: &NexusBridge, op: &OperationIdentity) -> OperationSnapshot {
    let mut events = bridge.subscribe();
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut tick=tokio::time::interval(Duration::from_millis(10));
        loop {
            bridge.endpoint().transition(|s,t|s.expire(&op.lease.client_id,op,t)).unwrap();
            let state=snapshot(bridge,op);
            if state.status.is_terminal() { return state; }
            if state.status==OperationStatus::Queued {
                match bridge.endpoint().transition(|s,t|s.dispatch(&op.lease.client_id,op,t)) {
                    Ok(())=>{}, Err(e) if e.code==NexusErrorCode::Busy=>{}, Err(e)=>panic!("dispatch {e}"),
                }
            }
            tokio::select! { _=tick.tick()=>{}, event=events.recv()=>{event.expect("bridge event");} }
        }
    }).await.expect("operation completion budget")
}
async fn settled(a: &mut Client, lease: &SessionLease) {
    let op = a.begin(lease, "run_auto_analysis", json!({"_n5_job":id()}));
    assert_eq!(
        terminal(&a.bridge, &op).await.status,
        OperationStatus::Succeeded
    );
}
async fn start(
    a: &mut Client,
    lease: &SessionLease,
    label: &str,
) -> (OperationIdentity, std::path::PathBuf) {
    let marker = root().join(format!("{label}.started"));
    let gate = root().join(format!("{label}.release"));
    let code=format!("from pathlib import Path\nPath({:?}).touch()\nwhile not Path({:?}).exists():\n    pass\nresult='released'",marker.to_str().unwrap(),gate.to_str().unwrap());
    let op = a.begin(lease, "execute_python", json!({"code":code}));
    barrier(&marker).await;
    (op, gate)
}
async fn close(a: &mut Client, lease: &SessionLease) {
    a.release(lease).await;
    a.bridge.shutdown().await.unwrap();
}
fn passed(case: &str, assertions: Value) {
    record(json!({"case":case,"status":"PASS","assertions":assertions}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e08_control_router_task_and_other_database_during_long_call() {
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    let (la, _) = a.open(&sample("n5-e08-a"), json!({})).await;
    let (lb, _) = b.open(&sample("n5-e08-b"), json!({})).await;
    let (op, gate) = start(&mut a, &la, "e08").await;
    response(a._router.status_snapshot()).await;
    assert_eq!(snapshot(&a.bridge, &op).status, OperationStatus::Running);
    response(a.bridge.status("e08-status")).await.unwrap();
    response(a.event(|v| v["event"] == "local_status")).await;
    response(b.value(&lb, "database_info", json!({}))).await;
    assert!(!gate.exists());
    std::fs::write(gate, "").unwrap();
    assert_eq!(
        terminal(&a.bridge, &op).await.status,
        OperationStatus::Succeeded
    );
    // F2: real Nexus result contains a surrogate, then both leases remain usable.
    let (sibling, _) = a.open(&sample("n5-e08-a"), json!({})).await;
    for (label, code) in [
        ("surrogate", "result=chr(0xd800)"),
        (
            "depth",
            "result=0\nfor _ in range(128):\n    result=[result]",
        ),
    ] {
        let bad = a.begin(&la, "execute_python", json!({"code":code}));
        let failed = terminal(&a.bridge, &bad).await;
        assert_eq!(failed.status, OperationStatus::Failed);
        assert!(failed.execution_stopped);
        let encoding_error = failed.error.unwrap();
        assert!(encoding_error
            .cause
            .expect("N1 retains request-local cause")
            .message
            .contains("response encoding failed"));
        response(a.value(&la, "database_info", json!({}))).await;
        response(a.value(&sibling, "database_info", json!({}))).await;
        record(
            json!({"event":"F2-encoding-isolated","fault":label,"operation":bad,"same_bridge_two_leases":true}),
        );
    }
    a.release(&sibling).await;
    close(&mut a, &la).await;
    close(&mut b, &lb).await;
    passed(
        "E08",
        json!("router, operation status and B completed before A release"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e09_same_database_short_request_queues_without_result_mixup() {
    let mut a = Client::new().await;
    let (lease, _) = a.open(&sample("n5-e09"), json!({})).await;
    let (long, gate) = start(&mut a, &lease, "e09").await;
    let short = queued(&a, &lease, "read_name", json!({"address":0}));
    assert_eq!(
        a.bridge
            .endpoint()
            .transition(|s, t| s.dispatch(&lease.client_id, &short, t))
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    assert_eq!(snapshot(&a.bridge, &short).status, OperationStatus::Queued);
    std::fs::write(gate, "").unwrap();
    assert_eq!(
        terminal(&a.bridge, &long).await.result.unwrap()["result"],
        "released"
    );
    assert_eq!(
        terminal(&a.bridge, &short).await.result.unwrap()["result"],
        ""
    );
    close(&mut a, &lease).await;
    passed("E09", json!("queued; exact result identities"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e10_actual_router_batch_yields_to_short_query() {
    let router = ida_mcp::router::RouterState::new().unwrap();
    assert!(router.uses_nexus());
    let mut b = Client::new().await;
    let (lb, _) = b.open(&sample("n5-e10-b"), json!({})).await;
    let many = root().join("fixtures/e10-many");
    std::fs::copy(root().join("fixtures/n5_hold.dylib"), &many).unwrap();
    let (handle, token) = router
        .ensure_worker_with_ref(many.to_str().unwrap(), None)
        .await
        .unwrap();
    let functions = router
        .route_request(Some(&handle), "list_functions", json!({}))
        .await
        .unwrap();
    let ea = functions["functions"][0]["address"].clone();
    router
        .route_request(Some(&handle), "run_auto_analysis", json!({}))
        .await
        .unwrap();
    std::fs::write(root().join("n5-boundary.arm"), "").unwrap();
    let r = router.clone();
    let h = handle.clone();
    let long = tokio::spawn(async move {
        r.route_request(
            Some(&h),
            "batch_decompile",
            json!({"addresses":vec![ea;40]}),
        )
        .await
    });
    barrier(&root().join("n5-boundary.observed")).await;
    let r = router.clone();
    let h = handle.clone();
    let short = tokio::spawn(async move {
        r.route_request(Some(&h), "get_analysis_status", json!({}))
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            if router
                .status_snapshot()
                .await
                .workers
                .iter()
                .any(|w| w.pending_requests >= 2)
            {
                break;
            }
            tick.tick().await;
        }
    })
    .await
    .expect("short request admission barrier");
    response(b.value(&lb, "database_info", json!({}))).await;
    assert!(
        !long.is_finished(),
        "B returned during the held batch slice"
    );
    std::fs::write(root().join("n5-boundary.release"), "").unwrap();
    assert!(response(short).await.unwrap().unwrap()["auto_is_ok"]
        .as_bool()
        .unwrap());
    assert!(
        !long.is_finished(),
        "short request completed before full batch"
    );
    let batch = long.await.unwrap().unwrap();
    assert_eq!(batch.as_array().unwrap().len(), 40);
    assert!(batch
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["success"] == true));
    std::fs::remove_file(root().join("n5-boundary.observed")).unwrap();
    std::fs::remove_file(root().join("n5-boundary.release")).unwrap();
    std::fs::write(root().join("n5-boundary.arm"), "").unwrap();
    let r = router.clone();
    let h = handle.clone();
    let search = tokio::spawn(async move {
        r.route_request(
            Some(&h),
            "search_pseudocode",
            json!({"pattern":"N5_NO_MATCH"}),
        )
        .await
    });
    barrier(&root().join("n5-boundary.observed")).await;
    let r = router.clone();
    let h = handle.clone();
    let short = tokio::spawn(async move {
        r.route_request(Some(&h), "get_analysis_status", json!({}))
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        while !router
            .status_snapshot()
            .await
            .workers
            .iter()
            .any(|w| w.pending_requests >= 2)
        {
            tick.tick().await;
        }
    })
    .await
    .expect("search short admission barrier");
    response(b.value(&lb, "database_info", json!({}))).await;
    assert!(
        !search.is_finished(),
        "B returned during the held search slice"
    );
    std::fs::write(root().join("n5-boundary.release"), "").unwrap();
    assert_eq!(response(short).await.unwrap().unwrap()["auto_is_ok"], true);
    assert!(
        !search.is_finished(),
        "short completed before full pseudocode search"
    );
    let output = search.await.unwrap().unwrap();
    assert_eq!(output["matches"], json!([]));
    assert!(output["total_searched"].as_u64().unwrap() >= 80);
    router_cancelled_slice_cleanup(&router, &handle).await;
    router.nexus_close_token(&token).await.unwrap();
    router.shutdown_all().await;
    close(&mut b, &lb).await;
    passed(
        "E10",
        json!({"batch":40,"search_functions":output["total_searched"],"short_before_completion":true,"b_during_batch_and_search":true}),
    );
}

// Exercise SliceCleanup::drop through the actual router, retaining its lease.
async fn router_cancelled_slice_cleanup(router: &ida_mcp::router::RouterState, handle: &str) {
    for name in ["n5-boundary.observed", "n5-boundary.release"] {
        std::fs::remove_file(root().join(name)).unwrap();
    }
    std::fs::write(root().join("n5-boundary.arm"), "").unwrap();
    let r = router.clone();
    let h = handle.to_owned();
    let long = tokio::spawn(async move {
        r.route_request(
            Some(&h),
            "batch_decompile",
            json!({"addresses":["bad","bad"]}),
        )
        .await
    });
    barrier(&root().join("n5-boundary.observed")).await;
    let operation: OperationIdentity = serde_json::from_str(
        &std::fs::read_to_string(root().join("n5-boundary.identity")).unwrap(),
    )
    .unwrap();
    let r = router.clone();
    let h = handle.to_owned();
    let marker = root().join("cleanup-blocker.started");
    let release = root().join("cleanup-blocker.release");
    let code = format!(
        "from pathlib import Path\nPath({:?}).touch()\nwhile not Path({:?}).exists():\n    pass",
        marker.to_str().unwrap(),
        release.to_str().unwrap()
    );
    let blocker = tokio::spawn(async move {
        r.route_request(Some(&h), "run_script", json!({"code":code}))
            .await
    });
    response(async {
        while router
            .status_snapshot()
            .await
            .workers
            .iter()
            .all(|w| w.pending_requests < 2)
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    std::fs::write(root().join("n5-boundary.release"), "").unwrap();
    barrier(&marker).await;
    assert!(!long.is_finished(), "continuation queued behind blocker");
    let state = router
        .nexus_endpoint()
        .transition(|s, _| s.operation_progress(&operation.lease.client_id, &operation))
        .unwrap();
    assert_eq!(state.status, OperationStatus::Queued);
    assert!(state.execution_stopped, "previous slice confirmed stopped");
    long.abort();
    assert!(long.await.unwrap_err().is_cancelled());
    std::fs::write(release, "").unwrap();
    assert_eq!(response(blocker).await.unwrap().unwrap()["success"], true);
    response(async {
        loop {
            let state = router.route_request(Some(handle), "run_script", json!({"code":"import sys,json\nm=sys.modules['_ida_cli_nexus_slices_v1']\nprint(json.dumps([len(m.jobs),m.counter is None]))"})).await.unwrap();
            if state["stdout"] == "[0, true]\n" { break; }
            tokio::task::yield_now().await;
        }
    }).await;
    assert_eq!(router.status_snapshot().await.workers[0].ref_count, 1);
    assert!(std::fs::read_to_string(root().join("n5-cleanup-executed"))
        .unwrap()
        .contains("_n5_job"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e11_background_analysis_has_public_slices_and_frontend_progress() {
    let mut a = Client::new().await;
    let marker = root().join("e11-background.started");
    let gate = root().join("e11-background.release");
    let script = root().join("fixtures/e11-startup.py");
    // Public import script keeps real analysis work queued until foreground
    // progress is observed. It delegates every step to IDA's real analyser.
    std::fs::write(&script, format!("import ida_auto, ida_ida, ida_bytes, os\nfrom pathlib import Path\nn5_root=Path(os.environ['N3_ENV_ROOT'])\nida_auto._n5_background_step=ida_auto.auto_make_step\ndef n5_background_step(*args):\n    if not Path({:?}).exists():\n        ida_auto.auto_mark_range(ida_ida.inf_get_min_ea(),ida_ida.inf_get_max_ea(),ida_auto.AU_CODE)\n        Path({:?}).touch()\n    if (n5_root/'e11-mutate.arm').exists() and not (n5_root/'e11-mutate.done').exists():\n        assert ida_bytes.set_cmt(ida_ida.inf_get_min_ea(),'N5 background notification',False)\n        (n5_root/'e11-mutate.done').touch()\n    return ida_auto._n5_background_step(*args)\nida_auto.auto_make_step=n5_background_step\n",gate.to_str().unwrap(),marker.to_str().unwrap())).unwrap();
    let (lease, _) = a
        .open(
            &sample("n5-e11"),
            json!({"auto_analysis":true,"script_file":script}),
        )
        .await;
    barrier(&marker).await;
    let query = response(a.value(&lease, "get_analysis_status", json!({}))).await;
    assert_eq!(
        query["value"]["auto_is_ok"], false,
        "startup background work is pending"
    );
    assert!(
        !gate.exists(),
        "foreground completed before background release"
    );
    let slicing = a.begin(
        &lease,
        "batch_decompile",
        json!({"_n5_job":id(),"addresses":["bad","bad"]}),
    );
    a.event(|v| v["event"] == "yielded").await;
    std::fs::write(root().join("e11-mutate.arm"), "").unwrap();
    barrier(&root().join("e11-mutate.done")).await;
    let changed = terminal(&a.bridge, &slicing).await.result.unwrap()["result"].clone();
    assert_eq!(changed["ok"], false);
    assert!(
        changed["error"].as_str().unwrap().contains("数据库已变化"),
        "{changed}"
    );
    std::fs::write(&gate, "").unwrap();
    // Exactly one public wait observes completion; this is not the separate
    // adapter explicit-wait cancellation scenario E12.
    let done=a.value(&lease,"execute_python",json!({"code":"import ida_auto\nida_auto.auto_make_step=ida_auto._n5_background_step\nresult=True"})).await;
    assert_eq!(done, true);
    settled(&mut a, &lease).await;
    close(&mut a, &lease).await;
    passed("E11",json!("real initial background analysis step barrier; foreground status completed while analysis pending"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e12_explicit_analysis_wait_cancel_and_total_deadline() {
    let mut a = Client::new().await;
    let (lease, _) = a
        .open(&sample("n5-e12"), json!({"auto_analysis":false}))
        .await;
    for (label, seconds, expected) in [
        ("cancel", 120, OperationStatus::Cancelled),
        ("deadline", 1, OperationStatus::TimedOut),
    ] {
        let marker = root().join(format!("e12-{label}.started"));
        let gate = root().join(format!("e12-{label}.release"));
        let code=format!("import ida_auto\nfrom pathlib import Path\nida_auto._n5_original_step=ida_auto.auto_make_step\ndef n5_wait(*args):\n    Path({:?}).touch()\n    while not Path({:?}).exists():\n        pass\n    return ida_auto._n5_original_step(*args)\nida_auto.auto_make_step=n5_wait\nresult=True",marker.to_str().unwrap(),gate.to_str().unwrap());
        assert_eq!(
            a.value(&lease, "execute_python", json!({"code":code}))
                .await,
            true
        );
        let wait = a.begin(
            &lease,
            "run_auto_analysis",
            json!({"_n5_job":id(),"timeout_secs":seconds}),
        );
        barrier(&marker).await;
        if label == "cancel" {
            assert_eq!(
                cancel(&a.bridge, &wait).status,
                OperationStatus::CancelRequested
            );
        }
        let stopped = terminal(&a.bridge, &wait).await;
        assert_eq!(stopped.status, expected);
        assert!(stopped.execution_stopped);
        assert_eq!(a.value(&lease,"execute_python",json!({"code":"import ida_auto\nida_auto.auto_make_step=ida_auto._n5_original_step\ndel ida_auto._n5_original_step\nresult=True"})).await,true);
    }
    settled(&mut a, &lease).await;
    response(a.value(&lease, "database_info", json!({}))).await;
    close(&mut a, &lease).await;
    passed(
        "E12",
        json!(
            "real explicit-wait operation receives running cancellation/deadline; service recovers"
        ),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e13_running_cooperative_cancel_confirms_before_service_resumes() {
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    let (lease, _) = a.open(&sample("n5-e13-a"), json!({})).await;
    let (lb, _) = b.open(&sample("n5-e13-b"), json!({})).await;
    let (long, _gate) = start(&mut a, &lease, "e13").await;
    let requested = cancel(&a.bridge, &long);
    assert_eq!(requested.status, OperationStatus::CancelRequested);
    assert!(!requested.execution_stopped);
    let stopped = terminal(&a.bridge, &long).await;
    assert_eq!(stopped.status, OperationStatus::Cancelled);
    assert!(stopped.execution_stopped);
    response(a.value(&lease, "database_info", json!({}))).await;
    response(b.value(&lb, "database_info", json!({}))).await;
    close(&mut a, &lease).await;
    close(&mut b, &lb).await;
    passed(
        "E13",
        json!("cancel_requested -> confirmed cancelled; A/B query success"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e14_queued_write_expires_without_marker_or_database_effect() {
    let mut a = Client::new().await;
    let (lease, _) = a.open(&sample("n5-e14"), json!({})).await;
    let (long, gate) = start(&mut a, &lease, "e14").await;
    let marker = root().join("e14-forbidden");
    let write = queued(
        &a,
        &lease,
        "run_script",
        json!({"timeout_secs":1,"code":format!("from pathlib import Path\nPath({:?}).touch()\nimport ida_bytes\nida_bytes.set_cmt(0, 'FORBIDDEN', False)",marker.to_str().unwrap())}),
    );
    let expired = terminal(&a.bridge, &write).await;
    assert_eq!(expired.status, OperationStatus::TimedOut);
    assert!(expired.execution_stopped);
    assert!(!marker.exists());
    std::fs::write(gate, "").unwrap();
    terminal(&a.bridge, &long).await;
    assert_eq!(
        a.value(
            &lease,
            "execute_python",
            json!({"code":"import ida_bytes\nresult=ida_bytes.get_cmt(0,False)"})
        )
        .await,
        Value::Null
    );
    assert!(!marker.exists());
    let mut peer = Client::new().await;
    let (lp, _) = peer
        .open(
            &sample("n5-e14"),
            json!({"attach_instance":lease.instance_id.as_str()}),
        )
        .await;
    let (blocker, release) = start(&mut peer, &lp, "e14-public-queue").await;
    let forbidden = root().join("e14-external-forbidden");
    let delayed=a.begin(&lease,"run_script",json!({"timeout_secs":1,"code":format!("from pathlib import Path\nPath({:?}).touch()",forbidden.to_str().unwrap())}));
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            let state = a
                .bridge
                .endpoint()
                .transition(|s, t| s.expire(&lease.client_id, &delayed, t))
                .unwrap();
            if state.cancel_reason == Some(CancelReason::Deadline)
                || state.status == OperationStatus::TimedOut
            {
                break;
            }
            tick.tick().await;
        }
    })
    .await
    .expect("total deadline expires while queued behind another public client");
    assert!(!forbidden.exists());
    std::fs::write(release, "").unwrap();
    assert_eq!(
        terminal(&peer.bridge, &blocker).await.status,
        OperationStatus::Succeeded
    );
    let expired = terminal(&a.bridge, &delayed).await;
    assert_eq!(expired.status, OperationStatus::TimedOut);
    assert!(expired.execution_stopped);
    response(a.value(&lease, "database_info", json!({}))).await;
    assert!(
        !forbidden.exists(),
        "public remote queue never executes expired write"
    );
    close(&mut peer, &lp).await;
    close(&mut a, &lease).await;
    passed(
        "E14",
        json!("queued deadline expired; no marker/comment after blocker returned"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e15_queue_cancel_completion_race_and_late_response_do_not_replay() {
    let mut a = Client::new().await;
    let (lease, _) = a.open(&sample("n5-e15"), json!({})).await;
    let (long, gate) = start(&mut a, &lease, "e15").await;
    let marker = root().join("e15-forbidden");
    let write = queued(
        &a,
        &lease,
        "run_script",
        json!({"code":format!("from pathlib import Path\nPath({:?}).touch()",marker.to_str().unwrap())}),
    );
    assert_eq!(cancel(&a.bridge, &write).status, OperationStatus::Cancelled);
    std::fs::write(gate, "").unwrap();
    let done = terminal(&a.bridge, &long).await;
    assert_eq!(done.status, OperationStatus::Succeeded);
    assert_eq!(cancel(&a.bridge, &long).status, OperationStatus::Succeeded);
    assert!(!a
        .bridge
        .endpoint()
        .transition(|s, _| s.complete(&long, Completion::Cancelled))
        .unwrap());
    assert_eq!(
        snapshot(&a.bridge, &long).status,
        OperationStatus::Succeeded
    );
    response(a.value(&lease, "database_info", json!({}))).await;
    assert!(!marker.exists());
    close(&mut a, &lease).await;
    passed(
        "E15",
        json!("completion barrier wins; late cancel/result immutable; queued write absent"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e18_real_stalled_bridge_output_has_bounded_backpressure() {
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    let (la, _) = a.open(&sample("n5-e18-a"), json!({})).await;
    let (lb, _) = b.open(&sample("n5-e18-b"), json!({})).await;
    std::fs::write(root().join("n5-backpressure.arm"), a.bridge.pid.to_string()).unwrap();
    let op = a.begin(&la, "execute_python", json!({"code":"result='界'*1000000"}));
    barrier(&root().join("n5-backpressure.observed")).await;
    let evidence: Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("n5-backpressure.observed")).unwrap(),
    )
    .unwrap();
    assert!(evidence["capacity"].as_u64().unwrap() > 0);
    assert!(evidence["queued"].as_u64().unwrap() <= evidence["capacity"].as_u64().unwrap());
    assert_eq!(
        evidence["queued"], evidence["capacity"],
        "real queue must fill"
    );
    assert!(evidence["blocked_send_bytes"].as_u64().unwrap() > 1000000);
    assert_eq!(evidence["producer_returned"], false);
    assert_eq!(evidence["consumer_paused"], true);
    response(a._router.status_snapshot()).await;
    response(a.bridge.status("e18-status")).await.unwrap();
    response(a.event(|v| v["event"] == "local_status")).await;
    response(b.value(&lb, "database_info", json!({}))).await;
    // Drain every synthetic event concurrently, preserving strict no-loss checks.
    let mut events = std::mem::replace(&mut a.events, a.bridge.subscribe());
    let capacity = evidence["capacity"].as_u64().unwrap();
    let drain = tokio::spawn(async move {
        for index in 0..=capacity {
            loop {
                let event = events
                    .recv()
                    .await
                    .expect("no lag or event loss after resume");
                if event["event"] == "local_status" && event["id"] == "n5-pressure" {
                    assert_eq!(event["index"], index);
                    break;
                }
            }
        }
    });
    std::fs::remove_file(root().join("n5-backpressure.arm")).unwrap();
    std::fs::write(root().join("n5-backpressure.release"), "").unwrap();
    assert_eq!(
        terminal(&a.bridge, &op).await.result.unwrap()["result"]
            .as_str()
            .unwrap()
            .chars()
            .count(),
        1000000
    );
    response(drain).await.unwrap();
    a.events = a.bridge.subscribe();
    response(a.value(&la, "database_info", json!({}))).await;
    close(&mut a, &la).await;
    close(&mut b, &lb).await;
    passed("E18", evidence);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e26_pydll_holds_gil_without_false_stop_or_conflicting_write() {
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    let (la, _) = a.open(&sample("n5-e26-a"), json!({})).await;
    let (lb, _) = b.open(&sample("n5-e26-b"), json!({})).await;
    let marker = root().join("e26-native.started");
    let fifo = root().join("e26-native.fifo");
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    settled(&mut a, &la).await;
    let ea = a
        .value(
            &la,
            "execute_python",
            json!({"code":"import ida_funcs\nresult=ida_funcs.getn_func(0).start_ea"}),
        )
        .await;
    let code=format!("import ctypes, ida_hexrays\nida_hexrays._n5_original=ida_hexrays.decompile\nlib=ctypes.PyDLL({:?})\nlib.n5_hold.argtypes=[ctypes.c_char_p,ctypes.c_char_p]\nlib.n5_hold.restype=None\ndef n5_native(*args, **kwargs):\n    import sys\n    assert len(sys.modules['_ida_cli_nexus_slices_v1'].jobs)==1\n    lib.n5_hold({:?}.encode(), {:?}.encode())\n    while True:\n        pass\nida_hexrays.decompile=n5_native\nresult=True",root().join("fixtures/n5_hold.dylib").to_str().unwrap(),marker.to_str().unwrap(),fifo.to_str().unwrap());
    assert_eq!(
        a.value(&la, "execute_python", json!({"code":code})).await,
        true
    );
    let long = a.begin(
        &la,
        "batch_decompile",
        json!({"_n5_job":id(),"addresses":[ea.clone(),ea]}),
    );
    barrier(&marker).await;
    let pending = cancel(&a.bridge, &long);
    assert!(!pending.execution_stopped);
    assert_eq!(pending.status, OperationStatus::CancelRequested);
    let write = queued(
        &a,
        &la,
        "rename_address",
        json!({"address":0,"name":"MUST_WAIT"}),
    );
    assert_eq!(
        a.bridge
            .endpoint()
            .transition(|s, t| s.dispatch(&la.client_id, &write, t))
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    response(a._router.status_snapshot()).await;
    response(b.value(&lb, "database_info", json!({}))).await;
    assert!(!snapshot(&a.bridge, &long).execution_stopped);
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&fifo)
        .unwrap()
        .write_all(b"x")
        .unwrap();
    let stopped = terminal(&a.bridge, &long).await;
    assert_eq!(stopped.status, OperationStatus::Cancelled);
    assert!(stopped.execution_stopped);
    assert_eq!(
        terminal(&a.bridge, &write).await.status,
        OperationStatus::Succeeded
    );
    assert_eq!(a.value(&la,"execute_python",json!({"code":"import ida_hexrays,sys\nida_hexrays.decompile=ida_hexrays._n5_original\nm=sys.modules['_ida_cli_nexus_slices_v1']\nimport sys\nm=sys.modules['_ida_cli_nexus_slices_v1']\nresult=[len(m.jobs),m.counter is None]"})).await,json!([0,true]));
    response(a.value(&la, "database_info", json!({}))).await;
    close(&mut a, &la).await;
    close(&mut b, &lb).await;
    passed(
        "E26",
        json!("PyDLL native FIFO boundary only; no claim about arbitrary Hex-Rays GIL behavior"),
    );
}

#[path = "support/n5_hooks.rs"]
mod hooks;

#[test]
fn n5_batch_and_search_match_fixed_legacy_binary() {
    let status = std::process::Command::new("timeout")
        .arg("30s")
        .arg(root().join("venv/bin/python"))
        .arg(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/n5_compare.py"),
        )
        .arg(root())
        .arg(std::env::var_os("N4_BASELINE").expect("fixed N0 binary"))
        .arg(env!("CARGO_BIN_EXE_ida-cli"))
        .env_clear()
        .envs(variables())
        .status()
        .unwrap();
    assert!(status.success(), "N5 strict comparison: {status}");
    let evidence: Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("N5-compare-result.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(evidence["comparisons"], 76);
    passed("N5-compare", evidence);
}
