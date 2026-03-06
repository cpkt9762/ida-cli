use std::{borrow::Cow, sync::Arc};

use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::JsonObject;
use serde_json::Value;

use crate::error::ToolError;
use crate::server::requests::*;

macro_rules! impl_dispatch_tool {
    ($tool:ident, $param:ty, $tool_name:literal, $method:literal) => {
        pub struct $tool;

        impl ToolBase for $tool {
            type Parameter = $param;
            type Output = Value;
            type Error = ToolError;

            fn name() -> Cow<'static, str> {
                $tool_name.into()
            }

            fn output_schema() -> Option<Arc<JsonObject>> {
                None
            }
        }

        impl<W: crate::ida::worker_trait::WorkerDispatch + Send + Sync + 'static> AsyncTool<W>
            for $tool
        {
            async fn invoke(worker: &W, req: Self::Parameter) -> Result<Value, ToolError> {
                crate::server::tools::force_send(crate::server::tools::invoke_dispatch(
                    worker, $method, req,
                ))
                .await
            }
        }
    };
}

macro_rules! impl_empty_tool {
    ($tool:ident, $tool_name:literal, $method:literal) => {
        pub struct $tool;

        impl ToolBase for $tool {
            type Parameter = EmptyParams;
            type Output = Value;
            type Error = ToolError;

            fn name() -> Cow<'static, str> {
                $tool_name.into()
            }

            fn input_schema() -> Option<Arc<JsonObject>> {
                None
            }

            fn output_schema() -> Option<Arc<JsonObject>> {
                None
            }
        }

        impl<W: crate::ida::worker_trait::WorkerDispatch + Send + Sync + 'static> AsyncTool<W>
            for $tool
        {
            async fn invoke(worker: &W, _req: Self::Parameter) -> Result<Value, ToolError> {
                crate::server::tools::force_send(crate::server::tools::invoke_dispatch(
                    worker,
                    $method,
                    serde_json::json!({}),
                ))
                .await
            }
        }
    };
}

impl_dispatch_tool!(
    BuildCallgraphTool,
    CallGraphRequest,
    "build_callgraph",
    "build_callgraph"
);
impl_dispatch_tool!(
    BuildXrefMatrixTool,
    XrefMatrixRequest,
    "build_xref_matrix",
    "build_xref_matrix"
);

#[cfg(test)]
mod tests {
    use rmcp::handler::server::router::tool::AsyncTool;
    use serde_json::json;

    use crate::rpc_dispatch::mock::MockWorker;

    #[tokio::test]
    async fn test_build_callgraph() {
        use super::*;
        let mock = MockWorker::new();
        let req = CallGraphRequest {
            roots: json!("0x0"),
            ..Default::default()
        };
        let result = BuildCallgraphTool::invoke(&mock, req).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }

    #[tokio::test]
    async fn test_build_xref_matrix() {
        use super::*;
        let mock = MockWorker::new();
        let req = XrefMatrixRequest {
            addrs: json!("0x0"),
            ..Default::default()
        };
        let result = BuildXrefMatrixTool::invoke(&mock, req).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }
}
