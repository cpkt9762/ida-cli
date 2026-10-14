use ida_mcp::nexus::*;
use ida_mcp::router::{nexus_transport::NexusEndpoint, transport::RpcConnection};
use ida_mcp::{error, preprocess};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
// Public cancellation-aware waiter preserves the original failure assertion.
use ida_mcp::router::transport as transport_source;
fn caps() -> NexusCapabilities {
    NexusCapabilities {
        runtime: NexusRuntime {
            ida: Version(9, 5, 0),
            python: Version(3, 14, 7),
            nexus: Some(Version(0, 13, 4)),
            domain: Some(Version(0, 5, 1)),
        },
        methods: BTreeMap::from([("fixture".into(), MethodEffect::MayWrite)]),
    }
}
#[tokio::test(flavor = "current_thread")]
async fn sent_history_survives_pending_clear_before_cancelled_wait() {
    let _fixture_gate = super::FIXTURE_GATE.lock().await;
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (read, write) = client.into_split();
    let connection = transport_source::RpcConnection::start(read, write, 2);
    let response = connection
        .enqueue(
            "sent".into(),
            b"{\"jsonrpc\":\"2.0\",\"id\":\"sent\",\"method\":\"fixture\",\"params\":{}}\n"
                .to_vec(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    let mut reader = BufReader::new(server);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(!line.is_empty(), "physical send barrier");
    connection.close();
    assert_eq!(connection.pending_len(), 0);
    let preparation = preprocess::Preparation::new(Duration::from_secs(3));
    preparation.cancel.cancel();
    let result = response.wait_prepared(3, &preparation.cancel).await;
    eprintln!("sent -> close -> cancel -> wait: {result:?}");
    assert!(
        !matches!(
            result,
            Err(error::ToolError::Preparation {
                execution_stopped: true,
                ..
            })
        ),
        "missing pending cannot prove no send or execution stopped"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_open_delivery_must_not_begin_remote_acquisition() {
    let _fixture_gate = super::FIXTURE_GATE.lock().await;
    let endpoint = NexusEndpoint::with_capabilities(8, Ok(caps()));
    let mut lanes = endpoint.take_lanes().unwrap();
    let client = ClientId::new("cancel-open-client").unwrap();
    let request = AcceptedRequest::new(
        &SystemClock,
        RequestId::new("cancel-open-r").unwrap(),
        None,
        "open",
        json!({}),
    )
    .unwrap();
    let identity = endpoint
        .transition(|s, b| {
            s.open(
                &client,
                request,
                OpenSpec {
                    operation_id: OperationId::new("cancel-open-o").unwrap(),
                    path: "/fixture.i64".into(),
                    options: json!({}),
                },
                b,
            )
        })
        .unwrap();
    endpoint
        .transition(|s, _| s.cancel_open(&client, &identity))
        .unwrap();
    let mut delivery = lanes.business.recv().await.unwrap();
    let result = delivery.begin();
    eprintln!("cancelled unsent Open begin: {result:?}");
    assert!(
        result.is_err(),
        "cancelled unsent Open cannot reach adapter as valid new work"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn successful_publication_must_not_disable_cancellation_of_later_task_phases() {
    let _fixture_gate = super::FIXTURE_GATE.lock().await;
    let base = std::path::PathBuf::from(std::env::var_os("TMPDIR").unwrap())
        .join(format!("root-publication-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let destination = base.join("output.i64");
    let stage = preprocess::StagedArtifact::create(&destination).unwrap();
    std::fs::write(&stage.output, b"published fixture").unwrap();
    let preparation = preprocess::Preparation::new(Duration::from_secs(3));
    let registry = ida_mcp::server::task::TaskRegistry::new();
    let id = registry.create("phase", "later open is still running");
    registry.set_cancellation(&id, preparation.cancel.clone());
    stage.publish(&preparation).unwrap();
    let accepted = registry.cancel(&id);
    let preserved = std::fs::read(&destination).unwrap() == b"published fixture";
    eprintln!(
        "published file preserved={preserved}; later running task cancellation accepted={accepted}"
    );
    let cleanup = stage.cleanup_receipt();
    drop(stage);
    cleanup.wait().await.unwrap();
    std::fs::remove_dir_all(&base).unwrap();
    assert!(preserved);
    assert!(
        accepted,
        "artifact commit should protect the artifact without immunizing subsequent task phases"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn valid_large_response_must_not_close_before_output_caching() {
    let _fixture_gate = super::FIXTURE_GATE.lock().await;
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (read, write) = client.into_split();
    let connection = RpcConnection::start(read, write, 2);
    let response = connection
        .enqueue(
            "large".into(),
            b"{\"jsonrpc\":\"2.0\",\"id\":\"large\",\"method\":\"run_script\",\"params\":{}}\n"
                .to_vec(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let sender = tokio::spawn(async move {
        let (read, mut write) = server.into_split();
        let mut read = BufReader::new(read);
        let mut line = String::new();
        read.read_line(&mut line).await.unwrap();
        let output =
            json!({"jsonrpc":"2.0","id":"large","result":{"stdout":"x".repeat(16*1024*1024+128)}});
        let mut bytes = serde_json::to_vec(&output).unwrap();
        bytes.push(b'\n');
        write.write_all(&bytes).await
    });
    let result = tokio::time::timeout(Duration::from_secs(5), response.wait(5)).await;
    let sent = sender.await.unwrap();
    let closed = connection.is_closed();
    connection.close();
    eprintln!("valid oversized result sent={sent:?}; reply={result:?}; closed={closed}");
    assert!(matches!(result,Ok(Ok(_))),"legal response needs a compatible bounded transfer/cache path instead of connection destruction");
}
