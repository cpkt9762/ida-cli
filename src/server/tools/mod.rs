//! AsyncTool<W: WorkerDispatch> implementations for IDA dispatch tools.
//! Each tool uses invoke_dispatch to go through the existing JSON dispatch layer,
//! making them testable with MockWorker.

use crate::error::ToolError;
use crate::ida::worker_trait::WorkerDispatch;
use crate::router::protocol::RpcRequest;
use serde::Serialize;
use serde_json::Value;

pub mod analysis;
pub mod decompile;
pub mod disasm;
pub mod editing;
pub mod functions;
pub mod memory;
pub mod misc;
pub mod search;
pub mod xrefs;

pub use analysis::*;
pub use decompile::*;
pub use disasm::*;
pub use editing::*;
pub use functions::*;
pub use memory::*;
pub use misc::*;
pub use search::*;
pub use xrefs::*;

/// Call the existing JSON dispatch layer for any tool.
/// The method name must match what `dispatch_rpc_request` recognizes.
pub(crate) fn invoke_dispatch<'w, W, P>(
    worker: &'w W,
    method: &str,
    req: P,
) -> impl std::future::Future<Output = Result<Value, ToolError>> + 'w
where
    W: WorkerDispatch + Send + Sync + 'static,
    P: Serialize,
{
    let params = serde_json::to_value(req).unwrap_or(Value::Null);
    let method = method.to_owned();
    async move {
        let rpc = RpcRequest::new("async-tool", &method, params);
        crate::rpc_dispatch::dispatch_rpc(&rpc, worker).await
    }
}

/// Wraps a future and unsafely marks it as Send.
/// Used to satisfy AsyncTool's + Send requirement when calling WorkerDispatch
/// methods whose futures are not declared Send (AFIT limitation).
/// SAFETY: WorkerDispatch impls (IdaWorker, MockWorker) are all Send + Sync,
/// and their internal state is protected by Mutex/channels. The futures they
/// produce do not escape across threads during polling.
pub(crate) struct Sendified<F>(pub F);

unsafe impl<F> Send for Sendified<F> {}

impl<F: std::future::Future> std::future::Future for Sendified<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
    }
}

pub(crate) fn force_send<F: std::future::Future>(future: F) -> Sendified<F> {
    Sendified(future)
}
