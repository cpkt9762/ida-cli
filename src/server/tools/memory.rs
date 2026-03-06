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

impl_dispatch_tool!(ReadBytesTool, GetBytesRequest, "read_bytes", "read_bytes");
impl_dispatch_tool!(ReadByteTool, AddressRequest, "read_byte", "read_byte");
impl_dispatch_tool!(ReadWordTool, AddressRequest, "read_word", "read_word");
impl_dispatch_tool!(ReadDwordTool, AddressRequest, "read_dword", "read_dword");
impl_dispatch_tool!(ReadQwordTool, AddressRequest, "read_qword", "read_qword");
impl_dispatch_tool!(
    ReadStringTool,
    GetStringRequest,
    "read_string",
    "read_string"
);
impl_dispatch_tool!(
    ReadGlobalVariableTool,
    GetGlobalValueRequest,
    "read_global_variable",
    "read_global_variable"
);
impl_dispatch_tool!(
    ScanMemoryTableTool,
    TableScanRequest,
    "scan_memory_table",
    "scan_memory_table"
);

#[cfg(test)]
mod tests {
    use rmcp::handler::server::router::tool::AsyncTool;
    use serde_json::json;

    use crate::rpc_dispatch::mock::MockWorker;

    #[tokio::test]
    async fn test_read_bytes() {
        use super::*;
        let mock = MockWorker::new();
        let req = GetBytesRequest {
            address: Some(json!("0x0")),
            size: Some(4),
            ..Default::default()
        };
        let result = ReadBytesTool::invoke(&mock, req).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }

    #[tokio::test]
    async fn test_scan_memory_table() {
        use super::*;
        let mock = MockWorker::new();
        let req = TableScanRequest {
            base_address: json!("0x0"),
            count: Some(2),
            ..Default::default()
        };
        let result = ScanMemoryTableTool::invoke(&mock, req).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }
}
