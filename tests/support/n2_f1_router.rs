use super::*;
use tokio::io::AsyncWriteExt;

async fn first_open_fixture(
    directory: &std::path::Path,
    failure: &str,
    blocked: Option<&str>,
) -> (RouterState, String) {
    use std::os::unix::fs::PermissionsExt;
    let worker = directory.join("worker.py");
    std::fs::write(&worker, include_str!("n2_f2_worker.py")).unwrap();
    std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        worker.with_extension("json"),
        serde_json::to_vec(&serde_json::json!({
            "failure":failure, "blocked":blocked,
            "socket":directory.join("ready.sock"), "methods":directory.join("methods.log")
        }))
        .unwrap(),
    )
    .unwrap();
    // The .i64 extension bypasses offline translation. Only its synthetic ELF
    // header is inspected by this router fixture; no IDA code is executed.
    let binary = directory.join("synthetic.i64");
    let mut header = [0u8; 20];
    header[..4].copy_from_slice(&ELF_MAGIC);
    header[18..].copy_from_slice(&EM_BPF.to_le_bytes());
    std::fs::write(&binary, header).unwrap();
    let router = RouterState::new().unwrap();
    router.inner.lock().await.exe_path = worker;
    *router.cached_probe.lock().await = Some(
        serde_json::from_value(serde_json::json!({
            "runtime":{"major":9,"minor":5,"build":261001},
            "backend":"native-linked", "supported":true,"reason":null,"supported_methods":[]
        }))
        .unwrap(),
    );
    (router, binary.to_str().unwrap().into())
}

#[tokio::test(flavor = "current_thread")]
async fn sbpf_first_open_keeps_handle_on_ordinary_post_open_error() {
    isolated_f3_case(
        "sbpf_first_open_keeps_handle_on_ordinary_post_open_error",
        async {
            for phase in ["get_function_by_name", "build_callgraph", "rename_symbol"] {
                let directory =
                    std::env::temp_dir().join(format!("n2-f2-open-{}-{phase}", std::process::id()));
                std::fs::create_dir(&directory).unwrap();
                let (router, path) = first_open_fixture(&directory, phase, None).await;
                let result = router
                    .ensure_worker_prepared(
                        &path,
                        None,
                        None,
                        crate::preprocess::Preparation::new(Duration::from_secs(3)),
                    )
                    .await;
                let handles: Vec<_> = router.inner.lock().await.workers.keys().cloned().collect();
                for handle in &handles {
                    let pid = router.inner.lock().await.workers[handle]
                        .child
                        .id()
                        .unwrap();
                    crate::preprocess::record_owned_fixture(pid, false, "f2-first-open");
                }
                let reused = if result.is_ok() {
                    Some(
                        router
                            .ensure_worker_prepared(
                                &path,
                                None,
                                None,
                                crate::preprocess::Preparation::new(Duration::from_secs(3)),
                            )
                            .await
                            .unwrap()
                            .0,
                    )
                } else {
                    None
                };
                for handle in handles {
                    router.close_worker(&handle).await.unwrap();
                }
                let methods = std::fs::read_to_string(directory.join("methods.log")).unwrap();
                std::fs::remove_dir_all(directory).unwrap();
                let (handle, _) = result
                    .expect("ordinary sBPF post-open failure must preserve successful first open");
                assert_eq!(
                    Some(handle),
                    reused,
                    "same path safely reuses the open worker"
                );
                assert_eq!(
                    methods.lines().filter(|method| *method == "open").count(),
                    1
                );
                assert!(methods.lines().any(|method| method == phase));
            }
        },
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn sbpf_first_open_transport_error_strings_are_not_optional_business_failures() {
    isolated_f3_case(
        "sbpf_first_open_transport_error_strings_are_not_optional_business_failures",
        async {
            for (index, message) in [
        "UnknownOutcome (execution_stopped=false; never replay): response EOF / read failure",
        "NotSent: writer stopped",
        "Worker channel closed",
    ]
    .into_iter()
    .enumerate()
    {
        let directory = std::env::temp_dir().join(format!(
            "n2-f2-transport-open-{}-{index}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let (router, path) = first_open_fixture(&directory, "get_function_by_name", None).await;
        let config = directory.join("worker.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        value["error"] = message.into();
        std::fs::write(config, serde_json::to_vec(&value).unwrap()).unwrap();
        let result = router
            .ensure_worker_prepared(
                &path,
                None,
                None,
                crate::preprocess::Preparation::new(Duration::from_secs(3)),
            )
            .await;
        let handles: Vec<_> = router.inner.lock().await.workers.keys().cloned().collect();
        let empty = handles.is_empty();
        for handle in handles {
            router.close_worker(&handle).await.unwrap();
        }
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            matches!(result,Err(crate::error::ToolError::IdaError(ref error)) if error==message),
            "{result:?}"
        );
        assert!(
            empty,
            "propagated transport error cleans failed-open worker"
        );
    }
        },
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn sbpf_first_open_cancellation_propagates_and_cleans_worker() {
    isolated_f3_case(
        "sbpf_first_open_cancellation_propagates_and_cleans_worker",
        async {
            let directory =
                std::env::temp_dir().join(format!("n2-f2-cancel-open-{}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let listener = tokio::net::UnixListener::bind(directory.join("ready.sock")).unwrap();
            let (router, path) =
                first_open_fixture(&directory, "none", Some("get_function_by_name")).await;
            let preparation = crate::preprocess::Preparation::new(Duration::from_secs(3));
            let cancel = preparation.cancel.clone();
            let owned = router.clone();
            let call = tokio::spawn(async move {
                owned
                    .ensure_worker_prepared(&path, None, None, preparation)
                    .await
            });
            let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(line, "started\n");
            let handles: Vec<_> = router.inner.lock().await.workers.keys().cloned().collect();
            for handle in &handles {
                crate::preprocess::record_owned_fixture(
                    router.inner.lock().await.workers[handle]
                        .child
                        .id()
                        .unwrap(),
                    false,
                    "f2-cancel-open",
                );
            }
            assert!(cancel.cancel());
            // Keep the native simulation blocked until the caller has classified it.
            let result = tokio::time::timeout(Duration::from_secs(2), call)
                .await
                .unwrap()
                .unwrap();
            let empty = {
                let inner = router.inner.lock().await;
                inner.workers.is_empty()
                    && inner.path_to_handle.is_empty()
                    && router.references.lock().unwrap().ref_tokens.is_empty()
                    && router.references.lock().unwrap().token_to_handle.is_empty()
            };
            for handle in handles {
                router.close_worker(&handle).await.unwrap();
            }
            drop(stream);
            std::fs::remove_dir_all(directory).unwrap();
            assert!(
                matches!(
                    result,
                    Err(crate::error::ToolError::Preparation {
                        execution_stopped: false,
                        ..
                    })
                ),
                "{result:?}"
            );
            assert!(
                empty,
                "failed first-open follow-up must remove worker/path ownership"
            );
        },
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn sbpf_post_open_queries_and_rename_share_preparation_cancellation() {
    isolated_f3_case("sbpf_post_open_queries_and_rename_share_preparation_cancellation", async {
    for phase in ["get_function_by_name", "build_callgraph"] {
        let router = RouterState::new().unwrap();
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (read, write) = client.into_split();
        let connection = transport::RpcConnection::start(read, write, 2);
        let child = Command::new("/usr/bin/true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        crate::preprocess::record_owned_fixture(child.id().unwrap(), false, "router-sbpf-probe");
        router.inner.lock().await.workers.insert(
            "fixture".into(),
            WorkerProcess {
                backend: WorkerBackendKind::NativeLinked,
                tenant_id: "fixture".into(),
                child,
                connection: connection.clone(),
                close_token: None,
                open_path: None,
                last_active: Instant::now(),
            },
        );
        let preparation = crate::preprocess::Preparation::new(Duration::from_secs(2));
        let cancel = preparation.cancel.clone();
        let methods = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = methods.clone();
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let responder = tokio::spawn(async move {
            let (read, mut write) = server.into_split();
            let mut reader = BufReader::new(read);
            let mut line = String::new();
            let mut started = Some(started);
            let mut released = Some(released);
            loop {
                line.clear();
                if reader.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let request: RpcRequest = serde_json::from_str(&line).unwrap();
                captured.lock().unwrap().push(request.method.clone());
                if request.method == phase {
                    started.take().unwrap().send(()).unwrap();
                    released.take().unwrap().await.unwrap();
                }
                let value = match request.method.as_str() {
                    "get_function_by_name" => serde_json::json!({"address":"0x100"}),
                    "build_callgraph" => {
                        serde_json::json!({"edges":[{"from":"0x100","to":"0x200"},{"from":"0x100","to":"0x300"},{"from":"0x200","to":"0x400"}],"nodes":[]})
                    }
                    "rename_symbol" => serde_json::json!({"renamed":true}),
                    other => panic!("unexpected {other}"),
                };
                write
                    .write_all(
                        format!(
                            "{}\n",
                            serde_json::to_string(&protocol::RpcResponse::ok(request.id, value))
                                .unwrap()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let owned = router.clone();
        let call = tokio::spawn(async move {
            owned
                .detect_and_rename_sbpf_entry("fixture", preparation)
                .await
        });
        start.await.unwrap();
        assert!(cancel.cancel());
        release.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), call)
            .await
            .unwrap()
            .unwrap();
        connection.close();
        responder.await.unwrap();
        let mut worker = router.inner.lock().await.workers.remove("fixture").unwrap();
        worker.child.wait().await.unwrap();
        let methods = methods.lock().unwrap();
        assert!(
            result.is_err(),
            "cancelled {phase} must not become a successful preparation"
        );
        let expected = if phase == "get_function_by_name" {
            vec!["get_function_by_name"]
        } else {
            vec!["get_function_by_name", "build_callgraph"]
        };
        assert_eq!(
            *methods, expected,
            "cancelled post-open phase must not send a new query/rename"
        );
        assert_eq!(connection.pending_len(), 0);
    }

    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn f3_corrupt_index_preserves_successful_open_and_original_bytes() {
    isolated_f3_case(
        "f3_corrupt_index_preserves_successful_open_and_original_bytes",
        async {
            let directory =
                std::env::temp_dir().join(format!("n2-f3-index-{}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let (router, path) = first_open_fixture(&directory, "none", None).await;
            let index = crate::idb_store::idb_root().join("index.json");
            std::fs::create_dir_all(index.parent().unwrap()).unwrap();
            let original = std::fs::read(&index).ok();
            let corrupt = b"{ diagnostic: invalid index JSON }\n";
            std::fs::write(&index, corrupt).unwrap();
            let output = directory.join("output.i64");
            let result = router
                .ensure_worker_prepared(
                    &path,
                    Some(output.to_str().unwrap()),
                    None,
                    crate::preprocess::Preparation::new(Duration::from_secs(3)),
                )
                .await;
            let unchanged = std::fs::read(&index).unwrap() == corrupt;
            let handles: Vec<_> = router.inner.lock().await.workers.keys().cloned().collect();
            let alive = !handles.is_empty();
            for handle in handles {
                router.close_worker(&handle).await.unwrap();
            }
            match original {
                Some(bytes) => std::fs::write(&index, bytes).unwrap(),
                None => std::fs::remove_file(&index).unwrap(),
            }
            std::fs::remove_dir_all(directory).unwrap();
            assert!(unchanged, "corrupt index must remain byte-for-byte intact");
            assert!(
                result.is_ok(),
                "successful open must survive ordinary index error: {result:?}"
            );
            assert!(alive, "successful open worker must remain registered");
        },
    )
    .await;
}

async fn f3_post_open_busy(phase: &str, class: crate::blocking::WorkClass, count: usize) {
    let directory = std::env::temp_dir().join(format!("n2-f3-busy-{}-{phase}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let listener = tokio::net::UnixListener::bind(directory.join("ready.sock")).unwrap();
    let (router, path) = first_open_fixture(&directory, "none", Some(phase)).await;
    let owned = router.clone();
    let output = directory.join("out.i64");
    let call = tokio::spawn(async move {
        owned
            .ensure_worker_prepared(
                &path,
                Some(output.to_str().unwrap()),
                None,
                crate::preprocess::Preparation::new(Duration::from_secs(4)),
            )
            .await
    });
    let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    stream.read_line(&mut line).await.unwrap();
    assert_eq!(line, "started\n");
    let mut releases = Vec::new();
    let mut jobs = Vec::new();
    for _ in 0..count {
        let (release, released) = std::sync::mpsc::channel();
        let (start, started) = tokio::sync::oneshot::channel();
        jobs.push(tokio::spawn(crate::blocking::run(class, move || {
            start.send(()).unwrap();
            released.recv().unwrap();
        })));
        started.await.unwrap();
        releases.push(release);
    }
    stream.get_mut().write_all(b"x").await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), call).await;
    // Always release running jobs before assertions/runtime teardown.
    for release in releases {
        release.send(()).unwrap();
    }
    for job in jobs {
        job.await.unwrap().unwrap();
    }
    let handles: Vec<_> = router.inner.lock().await.workers.keys().cloned().collect();
    let mut alive = false;
    for handle in &handles {
        alive |= router
            .inner
            .lock()
            .await
            .workers
            .get_mut(handle)
            .unwrap()
            .child
            .try_wait()
            .unwrap()
            .is_none();
    }
    for handle in handles {
        router.close_worker(&handle).await.unwrap();
    }
    let methods = std::fs::read_to_string(directory.join("methods.log")).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    let result = result.unwrap().unwrap();
    assert!(
        result.is_ok(),
        "optional post-open {phase} capacity cannot invalidate open: {result:?}"
    );
    assert!(
        alive,
        "already-open worker must survive optional capacity rejection"
    );
    if phase == "open" {
        assert_eq!(
            methods.trim(),
            "open",
            "both optional Prepare steps skipped while capacity remained full"
        );
    }
    if phase == "get_function_by_name" {
        assert!(
            !methods.lines().any(|method| method == "build_callgraph"),
            "Busy query was provably not sent"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn f3_post_open_prepare_busy_keeps_worker() {
    isolated_f3_case("f3_post_open_prepare_busy_keeps_worker", async {
        f3_post_open_busy("open", crate::blocking::WorkClass::Prepare, 4).await;
    })
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn f3_post_open_query_busy_keeps_worker() {
    isolated_f3_case("f3_post_open_query_busy_keeps_worker", async {
        f3_post_open_busy(
            "get_function_by_name",
            crate::blocking::WorkClass::Encode,
            2,
        )
        .await;
    })
    .await;
}

#[test]
fn optional_sbpf_error_classification_covers_legacy_failure_producers() {
    use crate::error::ToolError;
    assert!(optional_sbpf_failure(&ToolError::Busy));
    assert!(optional_sbpf_failure(&ToolError::IdaError(
        "Function not found: entrypoint".into()
    )));
    // fail_one: queue expiry, zero write, partial write. fail_all: close, EOF.
    for message in [
        "NotSent: expired or dropped in queue",
        "NotSent: zero write / broken pipe",
        "UnknownOutcome (execution_stopped=false; never replay): pipe write: fixture",
        "NotSent: connection closed",
        "UnknownOutcome (execution_stopped=false; never replay): response EOF / read failure",
        "Worker channel closed",
    ] {
        assert!(
            !optional_sbpf_failure(&ToolError::IdaError(message.into())),
            "{message}"
        );
    }
    // wait_inner: sender drop, deadline (zero/possible), cancellation (zero/possible).
    for error in [
        ToolError::WorkerClosed,
        ToolError::Timeout(0),
        ToolError::RequestOutcome { seconds: 1 },
        ToolError::Preparation {
            message: "NotSent: total deadline expired in transport queue".into(),
            execution_stopped: true,
        },
        ToolError::Preparation {
            message: "NotSent: cancelled in transport queue".into(),
            execution_stopped: true,
        },
        ToolError::Preparation {
            message: "UnknownOutcome: cancelled waiter after possible send; never replay".into(),
            execution_stopped: false,
        },
    ] {
        assert!(!optional_sbpf_failure(&error), "{error}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn f3_pre_open_capacity_still_rejects_busy_without_spawning_worker() {
    isolated_f3_case(
        "f3_pre_open_capacity_still_rejects_busy_without_spawning_worker",
        async {
            let directory =
                std::env::temp_dir().join(format!("n2-f3-admit-{}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let (router, path) = first_open_fixture(&directory, "none", None).await;
            let mut releases = Vec::new();
            let mut jobs = Vec::new();
            for _ in 0..4 {
                let (release, released) = std::sync::mpsc::channel();
                let (start, started) = tokio::sync::oneshot::channel();
                jobs.push(tokio::spawn(crate::blocking::run(
                    crate::blocking::WorkClass::Prepare,
                    move || {
                        start.send(()).unwrap();
                        released.recv().unwrap();
                    },
                )));
                started.await.unwrap();
                releases.push(release);
            }
            let result = router
                .ensure_worker_prepared(
                    &path,
                    None,
                    None,
                    crate::preprocess::Preparation::new(Duration::from_secs(2)),
                )
                .await;
            for release in releases {
                release.send(()).unwrap();
            }
            for job in jobs {
                job.await.unwrap().unwrap();
            }
            assert!(
                matches!(result, Err(crate::error::ToolError::Busy)),
                "{result:?}"
            );
            assert!(router.inner.lock().await.workers.is_empty());
            assert!(!directory.join("methods.log").exists());
            std::fs::remove_dir_all(directory).unwrap();
        },
    )
    .await;
}

// Open fixtures and fault injection need deterministic Prepare/Encode admission.
// Each case runs in a disposable libtest process, retaining all behavior assertions
// without consuming the global permits of unrelated concurrently running tests.
async fn isolated_f3_case(name: &str, work: impl std::future::Future<Output = ()>) {
    if std::env::var("IDA_N2_F3_CASE").as_deref() == Ok(name) {
        work.await;
    } else {
        let directory =
            std::env::temp_dir().join(format!("n2-f3-harness-{}-{name}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("router::n2_f1_regressions::{name}"))
            .arg("--nocapture")
            .env("IDA_N2_F3_CASE", name)
            .env("IDA_CLI_HOME", &directory)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        crate::preprocess::record_owned_fixture(child.id().unwrap(), false, "f3-isolated-libtest");
        let output = child.wait_with_output().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("running 1 test") && stdout.contains("1 passed"),
            "exact child case must run its assertions: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "isolated {name}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn f3_index_cancellation_retains_pending_input_evidence() {
    isolated_f3_case(
        "f3_index_cancellation_retains_pending_input_evidence",
        async {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let directory =
                std::env::temp_dir().join(format!("n2-f3-index-cancel-{}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let (router, path) = first_open_fixture(&directory, "none", None).await;
            let index = crate::idb_store::idb_root().join("index.json");
            std::fs::create_dir_all(index.parent().unwrap()).unwrap();
            let cpath = std::ffi::CString::new(index.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: a private fixture path in this child process's isolated home.
            assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
            let preparation = crate::preprocess::Preparation::new(Duration::from_secs(4));
            let tracked = preparation.clone();
            let owned = router.clone();
            let output = directory.join("out.i64");
            let call = tokio::spawn(async move {
                owned
                    .ensure_worker_prepared(
                        &path,
                        Some(output.to_str().unwrap()),
                        None,
                        preparation,
                    )
                    .await
            });
            // O_NONBLOCK writer succeeds only when the real index reader is open.
            let mut writer = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&index)
                    {
                        Ok(writer) => break writer,
                        Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                            tokio::task::yield_now().await
                        }
                        Err(error) => panic!("FIFO handshake: {error}"),
                    }
                }
            })
            .await
            .unwrap();
            assert!(tracked.active_input_jobs() > 0);
            assert!(tracked.cancel.cancel());
            let result = tokio::time::timeout(Duration::from_secs(1), call).await;
            let retained = tracked.active_input_jobs() > 0;
            // Release the real blocking read before any result assertion.
            writer.write_all(b"invalid fixture index").unwrap();
            drop(writer);
            tokio::time::timeout(Duration::from_secs(1), async {
                while tracked.active_input_jobs() > 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let remaining: Vec<_> = router.inner.lock().await.workers.keys().cloned().collect();
            for handle in remaining {
                router.close_worker(&handle).await.unwrap();
            }
            std::fs::remove_file(index).unwrap();
            std::fs::remove_dir_all(directory).unwrap();
            let result = result.unwrap().unwrap();
            assert!(
                matches!(
                    result,
                    Err(crate::error::ToolError::Preparation {
                        execution_stopped: false,
                        ..
                    })
                ),
                "must preserve bounded-input cancellation evidence: {result:?}"
            );
            assert!(
                retained,
                "cancelled waiter must retain blocking input tracking until actual FIFO EOF"
            );
        },
    )
    .await;
}

async fn f4_prewarm_fault(keep_warm: bool, already_open: bool, fault: &str) {
    let directory = std::env::temp_dir().join(format!(
        "n2-f4-prewarm-{}-{keep_warm}-{already_open}-{fault}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let listener = tokio::net::UnixListener::bind(directory.join("ready.sock")).unwrap();
    let (router, path) = first_open_fixture(&directory, "none", Some("get_database_info")).await;
    let existing = if already_open {
        Some(router.ensure_worker_with_ref(&path, None).await.unwrap())
    } else {
        None
    };
    let baseline = usize::from(already_open) + usize::from(fault == "new-client");
    let preparation = crate::preprocess::Preparation::new(Duration::from_secs(4));
    let cancel = preparation.cancel.clone();
    let deadline = preparation.deadline;
    let worker = router.clone();
    let input = path.clone();
    let call = tokio::spawn(async move {
        preparation
            .scope(worker.prewarm_path_with_options(&input, keep_warm, "default"))
            .await
    });
    let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    stream.read_line(&mut line).await.unwrap();
    assert_eq!(line, "started\n");
    let handles = router.all_handles().await;
    for handle in &handles {
        crate::preprocess::record_owned_fixture(
            router.inner.lock().await.workers[handle]
                .child
                .id()
                .unwrap(),
            false,
            "f4-prewarm",
        );
    }
    let mut jobs = Vec::new();
    let mut releases = Vec::new();
    if fault == "busy" {
        for _ in 0..4 {
            let (release, released) = std::sync::mpsc::channel();
            let (start, started) = tokio::sync::oneshot::channel();
            jobs.push(tokio::spawn(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || {
                    start.send(()).unwrap();
                    released.recv().unwrap();
                },
            )));
            started.await.unwrap();
            releases.push(release);
        }
    }
    if fault == "io" {
        std::fs::remove_file(&path).unwrap();
    }
    let new_client = if fault == "new-client" {
        Some(router.issue_ref_for_handle(&handles[0]).await)
    } else {
        None
    };
    let dropped = fault == "drop";
    if fault == "cancel" {
        assert!(cancel.cancel());
    }
    if fault == "deadline" {
        tokio::time::sleep_until(deadline.into()).await;
    }
    if dropped {
        call.abort();
    }
    stream.get_mut().write_all(b"x").await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(2), call).await;
    for release in releases {
        release.send(()).unwrap();
    }
    for job in jobs {
        job.await.unwrap().unwrap();
    }
    let refs: usize = router
        .references
        .lock()
        .unwrap()
        .ref_tokens
        .values()
        .map(HashSet::len)
        .sum();
    let warm = router.warm_pool.lock().await.len();
    let count = router.worker_count().await;
    if let Some(token) = new_client {
        router.release_ref_token(&token).await;
    }
    if let Some((_, token)) = existing {
        router.release_ref_token(&token).await;
    }
    for handle in handles {
        router.close_worker(&handle).await.unwrap();
    }
    std::fs::remove_dir_all(&directory).unwrap();
    if dropped {
        assert!(outcome.unwrap().unwrap_err().is_cancelled());
        assert_eq!(
            refs, baseline,
            "dropping prewarm must release only its own reference"
        );
        assert_eq!(warm, 0);
    } else {
        let outcome = outcome.unwrap().unwrap();
        if fault == "cancel" || fault == "deadline" {
            assert!(
                outcome.is_err(),
                "prewarm must propagate cancellation: {outcome:?}"
            );
            assert_eq!(refs, baseline);
            assert_eq!(warm, 0);
        } else {
            let value = outcome.expect("post-open cache observation must be best effort");
            assert_eq!(value["cached_after"], false);
            assert!(value["cache_path"].is_null());
            assert_eq!(refs, baseline + usize::from(keep_warm));
            assert_eq!(warm, usize::from(keep_warm));
            assert_eq!(
                count,
                usize::from(keep_warm || already_open || fault == "new-client"),
                "must keep another client's worker"
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn f4_prewarm_busy_observation_releases_or_transfers_reference() {
    isolated_f3_case(
        "f4_prewarm_busy_observation_releases_or_transfers_reference",
        async {
            for keep in [false, true] {
                for opened in [false, true] {
                    f4_prewarm_fault(keep, opened, "busy").await;
                }
            }
        },
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn f4_prewarm_io_observation_keeps_existing_client() {
    isolated_f3_case("f4_prewarm_io_observation_keeps_existing_client", async {
        for keep in [false, true] {
            for opened in [false, true] {
                f4_prewarm_fault(keep, opened, "io").await;
            }
        }
    })
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn f4_prewarm_drop_releases_own_reference() {
    isolated_f3_case("f4_prewarm_drop_releases_own_reference", async {
        for keep in [false, true] {
            for opened in [false, true] {
                f4_prewarm_fault(keep, opened, "drop").await;
            }
        }
    })
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn f4_prewarm_cancel_propagates_without_ref_leak() {
    isolated_f3_case("f4_prewarm_cancel_propagates_without_ref_leak", async {
        f4_prewarm_fault(true, true, "cancel").await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn f4_prewarm_deadline_propagates_without_ref_leak() {
    isolated_f3_case("f4_prewarm_deadline_propagates_without_ref_leak", async {
        f4_prewarm_fault(true, true, "deadline").await;
    })
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn f4_prewarm_preserves_client_arriving_after_open() {
    isolated_f3_case("f4_prewarm_preserves_client_arriving_after_open", async {
        f4_prewarm_fault(false, false, "new-client").await;
    })
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn f4_repeated_warm_lease_retains_exactly_one_reference() {
    isolated_f3_case(
        "f4_repeated_warm_lease_retains_exactly_one_reference",
        async {
            let directory =
                std::env::temp_dir().join(format!("n2-f4-rewarm-{}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let (router, path) = first_open_fixture(&directory, "none", None).await;
            let first = router
                .prewarm_path_with_options(&path, true, "default")
                .await
                .unwrap();
            let second = router
                .prewarm_path_with_options(&path, true, "default")
                .await
                .unwrap();
            let refs: usize = router
                .references
                .lock()
                .unwrap()
                .ref_tokens
                .values()
                .map(HashSet::len)
                .sum();
            let warm = router.warm_pool.lock().await.len();
            let handle = router.active_handle().await.unwrap();
            // Drop must work while the async state locks are held. It cannot wait
            // for them, acquire a new task/queue permit, or remove another token.
            let token = router.issue_ref_for_handle(&handle).await;
            let guard = router.scoped_ref(token);
            let inner = router.inner.lock().await;
            let pool = router.warm_pool.lock().await;
            drop(guard);
            let after_drop: usize = router
                .references
                .lock()
                .unwrap()
                .ref_tokens
                .values()
                .map(HashSet::len)
                .sum();
            drop(pool);
            drop(inner);
            router
                .release_warm_lease(&std::fs::canonicalize(&path).unwrap())
                .await
                .unwrap();
            let count = router.worker_count().await;
            std::fs::remove_dir_all(directory).unwrap();
            assert_eq!(first["kept_warm"], true);
            assert_eq!(second["already_open"], true);
            assert_eq!(refs, 1, "replacing lease releases its previous token");
            assert_eq!(warm, 1);
            assert_eq!(after_drop, 1);
            assert_eq!(count, 0);
        },
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn f4_first_open_cancel_preserves_other_client_reference() {
    isolated_f3_case(
        "f4_first_open_cancel_preserves_other_client_reference",
        async {
            let directory =
                std::env::temp_dir().join(format!("n2-f4-shared-open-{}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let listener = tokio::net::UnixListener::bind(directory.join("ready.sock")).unwrap();
            let (router, path) =
                first_open_fixture(&directory, "none", Some("get_function_by_name")).await;
            let preparation = crate::preprocess::Preparation::new(Duration::from_secs(4));
            let cancel = preparation.cancel.clone();
            let owned = router.clone();
            let call = tokio::spawn(async move {
                owned
                    .ensure_worker_prepared(&path, None, None, preparation)
                    .await
            });
            let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(line, "started\n");
            let handle = router.active_handle().await.unwrap();
            let other = router.issue_ref_for_handle(&handle).await;
            assert!(cancel.cancel());
            let result = tokio::time::timeout(Duration::from_secs(2), call)
                .await
                .unwrap()
                .unwrap();
            let other_handle = router.handle_for_token(&other).await;
            let still_open = router.worker_count().await;
            let refs = router
                .references
                .lock()
                .unwrap()
                .ref_tokens
                .get(&handle)
                .map_or(0, HashSet::len);
            router.release_ref_token(&other).await;
            router.close_worker(&handle).await.unwrap();
            drop(stream);
            std::fs::remove_dir_all(directory).unwrap();
            assert!(
                matches!(
                    result,
                    Err(crate::error::ToolError::Preparation {
                        execution_stopped: false,
                        ..
                    })
                ),
                "{result:?}"
            );
            assert_eq!(
                other_handle,
                Some(handle),
                "failed opener must not revoke another client token"
            );
            assert_eq!(still_open, 1);
            assert_eq!(refs, 1, "only failed opener ref is released");
        },
    )
    .await;
}
