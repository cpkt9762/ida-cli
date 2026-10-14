use super::*;
use tokio::io::AsyncWriteExt;

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
