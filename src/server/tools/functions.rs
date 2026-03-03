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
    ListFunctionsTool,
    ListFunctionsRequest,
    "list_functions",
    "list_functions"
);
impl_dispatch_tool!(
    GetFunctionByNameTool,
    ResolveFunctionRequest,
    "get_function_by_name",
    "get_function_by_name"
);
impl_dispatch_tool!(
    GetFunctionPrototypeTool,
    GetFunctionPrototypeRequest,
    "get_function_prototype",
    "get_function_prototype"
);
impl_dispatch_tool!(
    GetAddressInfoTool,
    AddrInfoRequest,
    "get_address_info",
    "get_address_info"
);
impl_dispatch_tool!(
    GetFunctionAtAddressTool,
    FunctionAtRequest,
    "get_function_at_address",
    "get_function_at_address"
);
impl_dispatch_tool!(
    BatchLookupFunctionsTool,
    LookupFuncsRequest,
    "batch_lookup_functions",
    "batch_lookup_functions"
);
impl_dispatch_tool!(
    ExportFunctionsTool,
    ExportFuncsRequest,
    "export_functions",
    "export_functions"
);
impl_dispatch_tool!(
    AnalyzeFuncsTool,
    AnalyzeFuncsRequest,
    "run_auto_analysis",
    "analyze_funcs"
);
impl_empty_tool!(GetDatabaseInfoTool, "get_database_info", "idb_meta");
impl_empty_tool!(
    GetAnalysisStatusTool,
    "get_analysis_status",
    "get_analysis_status"
);

#[cfg(test)]
mod tests {
    use rmcp::handler::server::router::tool::AsyncTool;

    use crate::rpc_dispatch::mock::MockWorker;

    #[tokio::test]
    async fn test_list_functions() {
        use super::*;
        let mock = MockWorker::new();
        let result = ListFunctionsTool::invoke(&mock, Default::default()).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }

    #[tokio::test]
    async fn test_get_database_info() {
        use super::*;
        let mock = MockWorker::new();
        let result = GetDatabaseInfoTool::invoke(&mock, Default::default()).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }
}
