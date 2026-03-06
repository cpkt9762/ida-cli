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

impl_empty_tool!(ListSegmentsTool, "list_segments", "list_segments");
impl_dispatch_tool!(
    ListStringsTool,
    ListStringsRequest,
    "list_strings",
    "list_strings"
);
impl_dispatch_tool!(
    ListImportsTool,
    PaginatedRequest,
    "list_imports",
    "list_imports"
);
impl_dispatch_tool!(
    ListExportsTool,
    PaginatedRequest,
    "list_exports",
    "list_exports"
);
impl_empty_tool!(
    ListEntryPointsTool,
    "list_entry_points",
    "list_entry_points"
);
impl_dispatch_tool!(
    ListGlobalsTool,
    ListGlobalsRequest,
    "list_globals",
    "list_globals"
);
impl_dispatch_tool!(
    GetBasicBlocksTool,
    AddressRequest,
    "get_basic_blocks",
    "get_basic_blocks"
);
impl_dispatch_tool!(GetCallersTool, AddressRequest, "get_callers", "get_callers");
impl_dispatch_tool!(GetCalleesTool, AddressRequest, "get_callees", "get_callees");
impl_dispatch_tool!(
    FindControlFlowPathsTool,
    FindPathsRequest,
    "find_control_flow_paths",
    "find_control_flow_paths"
);
impl_dispatch_tool!(
    ConvertNumberTool,
    IntConvertRequest,
    "convert_number",
    "convert_number"
);
impl_dispatch_tool!(
    ListLocalTypesTool,
    LocalTypesRequest,
    "list_local_types",
    "list_local_types"
);
impl_dispatch_tool!(
    ListStructsTool,
    StructsRequest,
    "list_structs",
    "list_structs"
);
impl_dispatch_tool!(
    GetStructInfoTool,
    StructInfoRequest,
    "get_struct_info",
    "get_struct_info"
);
impl_dispatch_tool!(
    ReadStructAtAddressTool,
    ReadStructRequest,
    "read_struct_at_address",
    "read_struct_at_address"
);
impl_dispatch_tool!(
    SearchStructsTool,
    StructsRequest,
    "search_structs",
    "search_structs"
);
impl_dispatch_tool!(ListEnumsTool, ListEnumsRequest, "list_enums", "list_enums");

#[cfg(test)]
mod tests {
    use rmcp::handler::server::router::tool::AsyncTool;
    use serde_json::json;

    use crate::rpc_dispatch::mock::MockWorker;

    #[tokio::test]
    async fn test_list_segments() {
        use super::*;
        let mock = MockWorker::new();
        let result = ListSegmentsTool::invoke(&mock, Default::default()).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }

    #[tokio::test]
    async fn test_get_basic_blocks() {
        use super::*;
        let mock = MockWorker::new();
        let req = AddressRequest {
            address: json!("0x0"),
            ..Default::default()
        };
        let result = GetBasicBlocksTool::invoke(&mock, req).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }
}
