//! Connection-owned bounded JSON-RPC transport. The router lock never owns I/O.
use super::protocol::{RpcRequest, RpcResponse};
use crate::blocking::{self, WorkClass};
use crate::error::ToolError;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
type Reply = Result<Value, String>;
struct Pending {
    reply: Option<oneshot::Sender<Reply>>,
    bytes: Arc<AtomicUsize>,
}
struct State {
    pending: HashMap<String, Pending>,
    closed: bool,
}
struct Frame {
    id: String,
    bytes: Vec<u8>,
    deadline: Instant,
    cancelled: CancellationToken,
    written: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub struct RpcConnection {
    sender: mpsc::Sender<Frame>,
    state: Arc<Mutex<State>>,
    stop: CancellationToken,
    capacity: usize,
}

pub struct WaitingReply {
    id: String,
    receiver: Option<oneshot::Receiver<Reply>>,
    state: Arc<Mutex<State>>,
    cancelled: CancellationToken,
    deadline: Instant,
    written: Arc<AtomicUsize>,
}
impl Drop for WaitingReply {
    fn drop(&mut self) {
        self.cancelled.cancel();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pending) = state.pending.get_mut(&self.id) {
            // Keep possibly executing occupancy until response/EOF, even if the client left.
            if pending.bytes.load(Ordering::SeqCst) == 0 {
                state.pending.remove(&self.id);
            } else {
                pending.reply = None;
            }
        }
    }
}
impl WaitingReply {
    pub async fn wait(mut self, timeout_secs: u64) -> Result<Value, ToolError> {
        self.wait_inner(timeout_secs, None).await
    }
    pub async fn wait_prepared(
        mut self,
        timeout_secs: u64,
        cancel: &crate::preprocess::PreparationCancellation,
    ) -> Result<Value, ToolError> {
        self.wait_inner(timeout_secs, Some(cancel)).await
    }
    async fn wait_inner(
        &mut self,
        timeout_secs: u64,
        cancel: Option<&crate::preprocess::PreparationCancellation>,
    ) -> Result<Value, ToolError> {
        let receiver = self.receiver.take().ok_or(ToolError::WorkerClosed)?;
        let result = tokio::select! {biased;
            result=tokio::time::timeout_at(self.deadline.into(), receiver)=>result,
            _=async {match cancel {Some(token)=>token.cancelled().await,None=>std::future::pending().await}}=>{
                let possible=self.written.load(Ordering::SeqCst)!=0;
                return Err(ToolError::Preparation {message:if possible {"UnknownOutcome: cancelled waiter after possible send; never replay"} else {"NotSent: cancelled in transport queue"}.into(),execution_stopped:!possible});
            },
        };
        match result {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(e))) => Err(ToolError::IdaError(e)),
            Ok(Err(_)) => Err(ToolError::WorkerClosed),
            Err(_) => {
                let sent = self.written.load(Ordering::SeqCst) != 0;
                if sent {
                    Err(ToolError::RequestOutcome {
                        seconds: timeout_secs,
                    })
                } else {
                    Err(ToolError::Preparation {
                        message: "NotSent: total deadline expired in transport queue".into(),
                        execution_stopped: true,
                    })
                }
            }
        }
    }
}
impl RpcConnection {
    pub fn start<R, W>(reader: R, writer: W, capacity: usize) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let capacity = capacity.max(1);
        let (sender, receiver) = mpsc::channel(capacity);
        let state = Arc::new(Mutex::new(State {
            pending: HashMap::new(),
            closed: false,
        }));
        let stop = CancellationToken::new();
        tokio::spawn(write_loop(writer, receiver, state.clone(), stop.clone()));
        tokio::spawn(read_loop(reader, state.clone(), stop.clone()));
        Self {
            sender,
            state,
            stop,
            capacity,
        }
    }
    pub async fn closed(&self) {
        self.stop.cancelled().await;
    }
    pub fn is_closed(&self) -> bool {
        self.stop.is_cancelled()
    }
    pub fn pending_len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .len()
    }
    pub fn close(&self) {
        self.stop.cancel();
        fail_all(&self.state, "connection closed");
    }
    pub async fn encode(request: RpcRequest) -> Result<Vec<u8>, ToolError> {
        blocking::run(WorkClass::Encode, move || {
            let mut bytes = serde_json::to_vec(&request)
                .map_err(|e| ToolError::InvalidParams(format!("request encoding: {e}")))?;
            if bytes.len() >= MAX_FRAME_BYTES {
                return Err(ToolError::InvalidParams(
                    "request frame exceeds 16 MiB".into(),
                ));
            }
            bytes.push(b'\n');
            Ok(bytes)
        })
        .await?
    }
    /// Nonblocking admission; reserve response identity before making the frame visible.
    pub fn enqueue(
        &self,
        id: String,
        bytes: Vec<u8>,
        deadline: Instant,
    ) -> Result<WaitingReply, ToolError> {
        if bytes.len() > MAX_FRAME_BYTES || bytes.last() != Some(&b'\n') {
            return Err(ToolError::InvalidParams(
                "invalid or oversized transport frame".into(),
            ));
        }
        if deadline <= Instant::now() {
            return Err(ToolError::Timeout(0));
        }
        let permit = self.sender.try_reserve().map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => ToolError::Busy,
            _ => ToolError::WorkerClosed,
        })?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(ToolError::WorkerClosed);
        }
        if state.pending.len() >= self.capacity {
            return Err(ToolError::Busy);
        }
        if state.pending.contains_key(&id) {
            return Err(ToolError::InvalidParams(
                "duplicate request identity".into(),
            ));
        }
        let (reply, receiver) = oneshot::channel();
        let written = Arc::new(AtomicUsize::new(0));
        let cancelled = CancellationToken::new();
        state.pending.insert(
            id.clone(),
            Pending {
                reply: Some(reply),
                bytes: written.clone(),
            },
        );
        permit.send(Frame {
            id: id.clone(),
            bytes,
            deadline,
            cancelled: cancelled.clone(),
            written: written.clone(),
        });
        Ok(WaitingReply {
            id,
            receiver: Some(receiver),
            state: self.state.clone(),
            cancelled,
            deadline,
            written,
        })
    }
}
fn fail_one(state: &Arc<Mutex<State>>, id: &str, message: String) {
    if let Some(pending) = state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pending
        .remove(id)
    {
        if let Some(reply) = pending.reply {
            let _ = reply.send(Err(message));
        }
    }
}
fn fail_all(state: &Arc<Mutex<State>>, reason: &str) {
    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
    state.closed = true;
    for (_, pending) in state.pending.drain() {
        let delivery = if pending.bytes.load(Ordering::SeqCst) == 0 {
            "NotSent"
        } else {
            "UnknownOutcome (execution_stopped=false; never replay)"
        };
        if let Some(reply) = pending.reply {
            let _ = reply.send(Err(format!("{delivery}: {reason}")));
        }
    }
}
async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut receiver: mpsc::Receiver<Frame>,
    state: Arc<Mutex<State>>,
    stop: CancellationToken,
) {
    loop {
        let frame = tokio::select! { biased; _ = stop.cancelled() => break, frame = receiver.recv() => match frame { Some(f) => f, None => break } };
        let mut offset = 0;
        {
            let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
            if frame.cancelled.is_cancelled() || frame.deadline <= Instant::now() {
                drop(shared);
                fail_one(
                    &state,
                    &frame.id,
                    "NotSent: expired or dropped in queue".into(),
                );
                continue;
            }
            if let Some(pending) = shared.pending.get_mut(&frame.id) {
                pending.bytes.store(usize::MAX, Ordering::SeqCst);
            } else {
                continue;
            }
        }
        let result = loop {
            // Poll cancellation before every write; byte accounting and write polling share this task.
            let count = tokio::select! { biased;
                _ = stop.cancelled() => break Err("connection closed".to_string()),
                _ = frame.cancelled.cancelled() => break Err("request waiter dropped".to_string()),
                _ = tokio::time::sleep_until(frame.deadline.into()) => break Err("total deadline expired".to_string()),
                count = writer.write(&frame.bytes[offset..]) => count,
            };
            match count {
                Ok(0) => break Err("zero write / broken pipe".into()),
                Ok(n) => {
                    offset += n;
                    frame.written.store(offset, Ordering::SeqCst);
                    if offset == frame.bytes.len() {
                        break Ok(());
                    }
                }
                Err(e) => break Err(format!("pipe write: {e}")),
            }
        };
        if let Err(reason) = result {
            frame.written.store(offset, Ordering::SeqCst);
            let classification = if offset == 0 {
                "NotSent"
            } else {
                "UnknownOutcome (execution_stopped=false; never replay)"
            };
            fail_one(&state, &frame.id, format!("{classification}: {reason}"));
            // A partial frame corrupts a byte stream; never append a successor to it.
            if offset > 0 || !frame.cancelled.is_cancelled() && Instant::now() < frame.deadline {
                break;
            }
        }
    }
    stop.cancel();
    fail_all(&state, "writer stopped");
}
async fn read_loop<R: AsyncRead + Unpin>(
    reader: R,
    state: Arc<Mutex<State>>,
    stop: CancellationToken,
) {
    let mut reader = BufReader::new(reader);
    loop {
        let read = tokio::select! { _ = stop.cancelled() => break, read = read_response(&mut reader) => read };
        match read {
            Ok(None) => break,
            Ok(Some(response)) => match response {
                Ok(response) => {
                    let result = match (response.result, response.error) {
                        (Some(value), _) => Ok(value),
                        (_, Some(error)) => Err(error.message),
                        _ => Ok(Value::Null),
                    };
                    if let Some(pending) = state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .pending
                        .remove(&response.id)
                    {
                        if let Some(reply) = pending.reply {
                            let _ = reply.send(result);
                        }
                    }
                }
                other => {
                    tracing::warn!(error = ?other, "invalid worker response");
                    break;
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "worker response read failed");
                break;
            }
        }
    }
    stop.cancel();
    fail_all(&state, "response EOF / read failure");
}
// Only complete frames may occupy the two CPU decoders. A peer stalled in the
// middle of a response owns its received chunks, never a parser thread/permit.
const INLINE_RESPONSE_BYTES: usize = 64 * 1024;
static DECODERS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));
struct ChunkReader {
    chunks: std::vec::IntoIter<Vec<u8>>,
    chunk: std::io::Cursor<Vec<u8>>,
}
impl std::io::Read for ChunkReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let n = std::io::Read::read(&mut self.chunk, output)?;
            if n != 0 || output.is_empty() {
                return Ok(n);
            }
            match self.chunks.next() {
                Some(chunk) => self.chunk = std::io::Cursor::new(chunk),
                None => return Ok(0),
            }
        }
    }
}
async fn read_response<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<Result<RpcResponse, serde_json::Error>>> {
    let mut initial = Vec::new();
    let mut chunks = Vec::new();
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if total == 0 {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "partial response",
                ))
            };
        }
        let length = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1)
            .min(INLINE_RESPONSE_BYTES);
        total = total
            .checked_add(length)
            .ok_or_else(|| std::io::Error::other("response size overflow"))?;
        let finished = available[length - 1] == b'\n';
        if total <= INLINE_RESPONSE_BYTES {
            initial.extend_from_slice(&available[..length]);
        } else {
            chunks.push(available[..length].to_vec());
        }
        reader.consume(length);
        if finished {
            break;
        }
        // A continuously ready large pipe must also yield to local control.
        tokio::task::consume_budget().await;
    }
    if chunks.is_empty() {
        return Ok(Some(serde_json::from_slice(&initial)));
    }
    // One complete frame per admitted connection waits here. Legal response
    // memory follows received result size; no new response byte limit is imposed.
    let permit = DECODERS
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| std::io::Error::other("response decoder closed"))?;
    let (done, result) = oneshot::channel();
    std::thread::Builder::new()
        .name("ida-response-decode".into())
        .spawn(move || {
            let _permit = permit;
            let reader = ChunkReader {
                chunks: chunks.into_iter(),
                chunk: std::io::Cursor::new(initial),
            };
            let _ = done.send(serde_json::from_reader::<_, RpcResponse>(reader));
        })?;
    Ok(Some(result.await.map_err(|_| {
        std::io::Error::other("response decoder panicked")
    })?))
}
pub async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    bytes: &mut Vec<u8>,
) -> std::io::Result<bool> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(false)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "partial frame",
                ))
            };
        }
        let length = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if bytes.len() + length > MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame exceeds 16 MiB",
            ));
        }
        let finished = available[length - 1] == b'\n';
        bytes.extend_from_slice(&available[..length]);
        reader.consume(length);
        if finished {
            return Ok(true);
        }
    }
}
