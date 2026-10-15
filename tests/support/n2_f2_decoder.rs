use ida_mcp::router::transport::RpcConnection;
use serde_json::json;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader, ReadBuf};
struct ReadBarrier {
    inner: tokio::net::unix::OwnedReadHalf,
    seen: usize,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
}
impl AsyncRead for ReadBarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.seen += buf.filled().len() - before;
        if self.seen > 96 * 1024 {
            if let Some(ready) = self.ready.take() {
                let _ = ready.send(());
            }
        }
        result
    }
}
async fn accepted(
    connection: &RpcConnection,
    id: &str,
    deadline: Instant,
) -> ida_mcp::router::transport::WaitingReply {
    let bytes =
        format!("{{\"jsonrpc\":\"2.0\",\"id\":\"{id}\",\"method\":\"fixture\",\"params\":{{}}}}\n")
            .into_bytes();
    connection.enqueue(id.into(), bytes, deadline).unwrap()
}
async fn incomplete_peers(expire: bool) {
    let mut incomplete = Vec::new();
    for id in ["incomplete-a", "incomplete-b"] {
        let (client, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let (read, write) = client.into_split();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let connection = RpcConnection::start(
            ReadBarrier {
                inner: read,
                seen: 0,
                ready: Some(tx),
            },
            write,
            2,
        );
        let waiter = accepted(
            &connection,
            id,
            Instant::now()
                + if expire {
                    Duration::from_millis(300)
                } else {
                    Duration::from_secs(3)
                },
        )
        .await;
        {
            let mut reader = BufReader::new(&mut peer);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
        }
        let partial = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"{id}\",\"result\":\"{}",
            "x".repeat(128 * 1024)
        );
        peer.write_all(partial.as_bytes()).await.unwrap();
        rx.await
            .expect("actual read beyond decoder admission threshold");
        incomplete.push((connection, peer, waiter));
    }
    let mut held = Vec::new();
    for (connection, peer, waiter) in incomplete {
        let waiter = if expire {
            assert!(
                waiter.wait(1).await.is_err(),
                "original waiters have expired"
            );
            None
        } else {
            Some(waiter)
        };
        held.push((connection, peer, waiter));
    }
    let (client, mut peer) = tokio::net::UnixStream::pair().unwrap();
    let (read, write) = client.into_split();
    let healthy = RpcConnection::start(read, write, 2);
    let waiter = accepted(&healthy, "healthy", Instant::now() + Duration::from_secs(3)).await;
    {
        let mut reader = BufReader::new(&mut peer);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
    }
    let result = json!({"jsonrpc":"2.0","id":"healthy","result":"z".repeat(128*1024)});
    // Adaptation: write in a background task. A blocked reader stops draining the
    // socket, so an inline write_all would hang the probe instead of asserting.
    let payload = format!("{result}\n");
    let writer = tokio::spawn(async move {
        let _ = peer.write_all(payload.as_bytes()).await;
        peer
    });
    let mut waiting = Box::pin(waiter.wait(3));
    let before_close = tokio::time::timeout(Duration::from_millis(400), &mut waiting).await;
    let progressed = matches!(before_close, Ok(Ok(_)));
    for (connection, _, waiter) in &held {
        if waiter.is_some() {
            assert_eq!(connection.pending_len(), 1, "stalled frame is still live");
        }
        connection.close();
    }
    drop(held);
    let recovered = if progressed {
        true
    } else {
        matches!(
            tokio::time::timeout(Duration::from_secs(1), waiting).await,
            Ok(Ok(_))
        )
    };
    healthy.close();
    writer.abort();
    let _ = writer.await;
    eprintln!("healthy progressed after peer waiters expired={progressed}; recovered only after explicit stalled-connection close={recovered}");
    assert!(
        progressed,
        "expired incomplete frames still hold both global decoders"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn expired_incomplete_frames_must_release_decoder_capacity_for_healthy_large_reply() {
    incomplete_peers(true).await;
}
#[tokio::test(flavor = "current_thread")]
async fn live_incomplete_frames_do_not_hold_decoder_capacity() {
    incomplete_peers(false).await;
}
// Control: identical healthy large reply with no stalled peers must complete within the same 400 ms window.
#[tokio::test(flavor = "current_thread")]
async fn control_healthy_large_reply_without_stalled_peers() {
    let (client, mut peer) = tokio::net::UnixStream::pair().unwrap();
    let (read, write) = client.into_split();
    let healthy = RpcConnection::start(read, write, 2);
    let waiter = accepted(&healthy, "healthy", Instant::now() + Duration::from_secs(3)).await;
    {
        let mut reader = BufReader::new(&mut peer);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
    }
    let result = json!({"jsonrpc":"2.0","id":"healthy","result":"z".repeat(128*1024)});
    let payload = format!("{result}\n");
    let writer = tokio::spawn(async move {
        let _ = peer.write_all(payload.as_bytes()).await;
        peer
    });
    let outcome = tokio::time::timeout(Duration::from_millis(400), waiter.wait(3)).await;
    healthy.close();
    writer.abort();
    let _ = writer.await;
    eprintln!("control progressed={}", matches!(outcome, Ok(Ok(_))));
    assert!(
        matches!(outcome, Ok(Ok(_))),
        "control large reply must decode without stalled peers"
    );
}
