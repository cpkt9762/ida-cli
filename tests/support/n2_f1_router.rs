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
        let (handle, _) =
            result.expect("ordinary sBPF post-open failure must preserve successful first open");
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
}

#[tokio::test(flavor = "current_thread")]
async fn sbpf_first_open_transport_error_strings_are_not_optional_business_failures() {
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
}

#[tokio::test(flavor = "current_thread")]
async fn sbpf_first_open_cancellation_propagates_and_cleans_worker() {
    let directory = std::env::temp_dir().join(format!("n2-f2-cancel-open-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let listener = tokio::net::UnixListener::bind(directory.join("ready.sock")).unwrap();
    let (router, path) = first_open_fixture(&directory, "none", Some("get_function_by_name")).await;
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
            && inner.ref_tokens.is_empty()
            && inner.token_to_handle.is_empty()
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
}

#[tokio::test(flavor = "current_thread")]
async fn sbpf_post_open_queries_and_rename_share_preparation_cancellation() {
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
}
