//! Legacy worker input, serial execution and output are separate bounded tasks.
//! This path cannot preempt native IDA. Nexus uses its separate control lane.
use super::{
    protocol::{RpcRequest, RpcResponse},
    transport::read_frame,
};
use crate::blocking::{self, WorkClass};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
struct StopOnDrop(CancellationToken);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub async fn serve<R, W, F, Fut>(reader: R, writer: W, mut dispatch: F) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    F: FnMut(RpcRequest) -> Fut + Send + 'static,
    Fut: Future<Output = Result<serde_json::Value, crate::error::ToolError>> + Send,
{
    serve_responses(reader, writer, move |request| {
        let id = request.id.clone();
        let result = dispatch(request);
        async move {
            match result.await {
                Ok(value) => RpcResponse::ok(id, value),
                Err(error) => RpcResponse::err(id, -32000, error.to_string()),
            }
        }
    })
    .await
}

pub async fn serve_responses<R, W, F, Fut>(
    reader: R,
    mut writer: W,
    mut dispatch: F,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    F: FnMut(RpcRequest) -> Fut + Send + 'static,
    Fut: Future<Output = RpcResponse> + Send,
{
    let (business, mut requests) = mpsc::channel::<(RpcRequest, Instant)>(64);
    let (responses, mut output) = mpsc::channel::<RpcResponse>(32);
    let stop = CancellationToken::new();
    let executor_stop = stop.clone();
    let executor_output = responses.clone();
    let executor = tokio::spawn(async move {
        while let Some((mut request, deadline)) = requests.recv().await {
            if executor_stop.is_cancelled() {
                break;
            }
            let id = request.id.clone();
            let shutdown = request.method == "shutdown";
            let remaining = deadline.saturating_duration_since(Instant::now());
            let response = if remaining < Duration::from_millis(1) {
                RpcResponse::err(&id, -32000, "NotSent: expired in worker queue")
            } else {
                if let Some(params) = request.params.as_object_mut() {
                    params.insert("timeout_secs".into(), remaining.as_secs().into());
                }
                dispatch(request).await
            };
            if executor_output.send(response).await.is_err() || shutdown {
                break;
            }
        }
        executor_stop.cancel();
    });
    let writer_stop = stop.clone();
    let output_task = tokio::spawn(async move {
        let _stop_on_error = StopOnDrop(writer_stop);
        while let Some(response) = output.recv().await {
            let encoded =
                blocking::run(WorkClass::Encode, move || serde_json::to_vec(&response)).await??;
            tokio::time::timeout(Duration::from_secs(5), async {
                writer.write_all(&encoded).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await
            })
            .await
            .map_err(|_| {
                anyhow::anyhow!("worker physical output blocked; delivery unconfirmed")
            })??;
        }
        Ok::<_, anyhow::Error>(())
    });
    let mut reader = BufReader::new(reader);
    let read_result = async {
        loop {
            let mut bytes = Vec::new();
            let exists = tokio::select! { _ = stop.cancelled() => break, read = read_frame(&mut reader, &mut bytes) => read? };
            if !exists { break; }
            let request = blocking::run(WorkClass::Encode, move || serde_json::from_slice::<RpcRequest>(&bytes)).await?;
            let request = match request { Ok(r) => r, Err(e) => { responses.send(RpcResponse::err("null", -32700, format!("Parse error: {e}"))).await?; continue; } };
            if request.method == "__transport_status" || request.method == "__cancel" {
                let response = if request.method == "__transport_status" {
                    RpcResponse::ok(&request.id, serde_json::json!({"business_queued": 64-business.capacity(), "native_preemption": false}))
                } else { RpcResponse::err(&request.id, -32000, "NotSupported: legacy native cancellation is not confirmed; execution_stopped=false") };
                responses.send(response).await?;
                continue;
            }
            let limit = if request.method == "open" { 3600 } else { 600 };
            let seconds = request.params.get("timeout_secs").and_then(serde_json::Value::as_u64).unwrap_or(120).min(limit);
            let id = request.id.clone();
            if business.try_send((request, Instant::now()+Duration::from_secs(seconds))).is_err() {
                responses.send(RpcResponse::err(&id, -32000, "Busy: worker business queue full")).await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    stop.cancel();
    drop(business);
    drop(responses);
    executor.await?;
    // A stopped physical output cannot guarantee control delivery. Report its error.
    output_task.await??;
    read_result
}
