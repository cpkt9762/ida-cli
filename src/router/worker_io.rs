//! Legacy worker input, serial execution and output are separate bounded tasks.
//! This path cannot preempt native IDA. Nexus uses its separate control lane.
use super::{
    protocol::{RpcRequest, RpcResponse},
    transport::read_frame,
};
use crate::blocking;
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
            let response = if remaining.is_zero() {
                RpcResponse::err(&id, -32000, "NotSent: expired in worker queue")
            } else {
                if let Some(params) = request.params.as_object_mut() {
                    params.insert(
                        "timeout_secs".into(),
                        remaining
                            .as_secs()
                            .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                            .into(),
                    );
                }
                let preparation = crate::preprocess::Preparation {
                    deadline,
                    cancel: crate::preprocess::Preparation::new(remaining).cancel,
                };
                match preparation
                    .native(async { Ok(dispatch(request).await) })
                    .await
                {
                    Ok(response) => response,
                    Err(error) => RpcResponse::err(&id, -32000, error.to_string()),
                }
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
            let encoded = blocking::response(move || serde_json::to_vec(&response)).await??;
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
            let request = if bytes.len()<=64*1024 {serde_json::from_slice::<RpcRequest>(&bytes)} else {blocking::request_decode(move || serde_json::from_slice::<RpcRequest>(&bytes)).await?};
            let mut request = match request { Ok(r) => r, Err(e) => { responses.send(RpcResponse::err("null", -32700, format!("Parse error: {e}"))).await?; continue; } };
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
            let deadline = match super::protocol::take_deadline(&mut request.params, Instant::now()+Duration::from_secs(seconds)) {
                Ok(deadline)=>deadline,
                Err(error)=>{responses.send(RpcResponse::err(&id,-32000,error.to_string())).await?;continue;}
            };
            if business.try_send((request, deadline)).is_err() {
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

#[cfg(test)]
mod budget_regressions {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    #[tokio::test(flavor = "current_thread")]
    async fn zero_and_positive_subsecond_budgets_keep_internal_precision() {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (read, write) = server.into_split();
        let serving = tokio::spawn(serve(read, write, |request| async move {
            let preparation =
                crate::preprocess::current().expect("worker internal acceptance deadline");
            Ok(
                serde_json::json!({"seconds":request.params["timeout_secs"],"ms":preparation.deadline.saturating_duration_since(Instant::now()).as_millis()}),
            )
        }));
        let (read, mut write) = client.into_split();
        let mut reader = BufReader::new(read);
        for ms in [0, 100, 1000] {
            let mut request = RpcRequest::new(
                format!("r-{ms}"),
                "fixture",
                serde_json::json!({"timeout_secs":1}),
            );
            super::super::protocol::attach_deadline(
                &mut request.params,
                Instant::now() + Duration::from_millis(ms),
            )
            .unwrap();
            write
                .write_all(format!("{}\n", serde_json::to_string(&request).unwrap()).as_bytes())
                .await
                .unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let response: RpcResponse = serde_json::from_str(&line).unwrap();
            if ms == 0 {
                assert!(response.error.is_some());
            } else {
                let result = response.result.unwrap();
                assert_eq!(result["seconds"], 1);
                assert!(result["ms"].as_u64().unwrap() > 0 && result["ms"].as_u64().unwrap() <= ms);
            }
        }
        drop(write);
        serving.await.unwrap().unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn queued_budget_keeps_original_deadline_below_one_second_and_rejects_expiry() {
        for expire in [false, true] {
            let (client, server) = tokio::net::UnixStream::pair().unwrap();
            let (read, write) = server.into_split();
            let (started, entered) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let mut first = Some((started, released));
            let serving = tokio::spawn(serve(read, write, move |request| {
                let barrier = if request.id == "block" {
                    first.take()
                } else {
                    None
                };
                async move {
                    if let Some((started, released)) = barrier {
                        started.send(()).unwrap();
                        released.await.unwrap();
                    }
                    let preparation = crate::preprocess::current().unwrap();
                    Ok(
                        serde_json::json!({"seconds":request.params["timeout_secs"],"remaining_ns":preparation.deadline.saturating_duration_since(Instant::now()).as_nanos() as u64}),
                    )
                }
            }));
            let (read, mut write) = client.into_split();
            let mut reader = BufReader::new(read);
            write
                .write_all(
                    b"{\"jsonrpc\":\"2.0\",\"id\":\"block\",\"method\":\"fixture\",\"params\":{\"timeout_secs\":5}}\n",
                )
                .await
                .unwrap();
            entered.await.unwrap();
            let deadline = Instant::now() + Duration::from_millis(if expire { 50 } else { 900 });
            let mut queued =
                RpcRequest::new("queued", "fixture", serde_json::json!({"timeout_secs":1}));
            super::super::protocol::attach_deadline(&mut queued.params, deadline).unwrap();
            write
                .write_all(format!("{}\n", serde_json::to_string(&queued).unwrap()).as_bytes())
                .await
                .unwrap();
            write
                .write_all(
                    b"{\"jsonrpc\":\"2.0\",\"id\":\"barrier\",\"method\":\"__transport_status\",\"params\":{}}\n",
                )
                .await
                .unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let status: RpcResponse = serde_json::from_str(&line).unwrap();
            assert_eq!(status.id, "barrier");
            assert_eq!(status.result.unwrap()["business_queued"], 1);
            if expire {
                tokio::time::sleep_until(deadline.into()).await;
            }
            release.send(()).unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<RpcResponse>(&line).unwrap().id,
                "block"
            );
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let response: RpcResponse = serde_json::from_str(&line).unwrap();
            assert_eq!(response.id, "queued");
            if expire {
                assert!(response
                    .error
                    .unwrap()
                    .message
                    .contains("expired in worker queue"));
            } else {
                let result = response.result.unwrap();
                assert_eq!(result["seconds"], 1);
                assert!(result["remaining_ns"].as_u64().unwrap() > 0);
                assert!(result["remaining_ns"].as_u64().unwrap() < 900_000_000);
            }
            drop(write);
            serving.await.unwrap().unwrap();
        }
    }
}
