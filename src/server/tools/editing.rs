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
    RenameSymbolTool,
    RenameRequest,
    "rename_symbol",
    "rename_symbol"
);
impl_dispatch_tool!(
    BatchRenameTool,
    BatchRenameRequest,
    "batch_rename",
    "batch_rename"
);
impl_dispatch_tool!(
    RenameLocalVariableTool,
    RenameLvarRequest,
    "rename_local_variable",
    "rename_local_variable"
);
impl_dispatch_tool!(
    SetLocalVariableTypeTool,
    SetLvarTypeRequest,
    "set_local_variable_type",
    "set_local_variable_type"
);
impl_dispatch_tool!(
    SetDecompilerCommentTool,
    SetDecompilerCommentRequest,
    "set_decompiler_comment",
    "set_decompiler_comment"
);
impl_dispatch_tool!(
    SetCommentTool,
    SetCommentsRequest,
    "set_comment",
    "set_comment"
);
impl_dispatch_tool!(
    SetFunctionCommentTool,
    SetFunctionCommentRequest,
    "set_function_comment",
    "set_function_comment"
);
impl_dispatch_tool!(
    PatchAssemblyTool,
    PatchAsmRequest,
    "patch_assembly",
    "patch_assembly"
);
impl_dispatch_tool!(PatchBytesTool, PatchRequest, "patch_bytes", "patch_bytes");
impl_dispatch_tool!(
    DeclareCTypeTool,
    DeclareTypeRequest,
    "declare_c_type",
    "declare_c_type"
);
impl_dispatch_tool!(ApplyTypeTool, ApplyTypesRequest, "apply_type", "apply_type");
impl_dispatch_tool!(
    SetFunctionPrototypeTool,
    SetFunctionPrototypeRequest,
    "set_function_prototype",
    "set_function_prototype"
);
impl_dispatch_tool!(InferTypeTool, InferTypesRequest, "infer_type", "infer_type");
impl_dispatch_tool!(
    GetStackFrameTool,
    AddressRequest,
    "get_stack_frame",
    "get_stack_frame"
);
impl_dispatch_tool!(
    CreateStackVariableTool,
    DeclareStackRequest,
    "create_stack_variable",
    "create_stack_variable"
);
impl_dispatch_tool!(
    DeleteStackVariableTool,
    DeleteStackRequest,
    "delete_stack_variable",
    "delete_stack_variable"
);
impl_dispatch_tool!(
    RenameStackVariableTool,
    RenameStackVariableRequest,
    "rename_stack_variable",
    "rename_stack_variable"
);
impl_dispatch_tool!(
    SetStackVariableTypeTool,
    SetStackVariableTypeRequest,
    "set_stack_variable_type",
    "set_stack_variable_type"
);
impl_dispatch_tool!(
    CreateEnumTool,
    CreateEnumRequest,
    "create_enum",
    "create_enum"
);

#[cfg(test)]
mod tests {
    use rmcp::handler::server::router::tool::AsyncTool;
    use serde_json::json;

    use crate::rpc_dispatch::mock::MockWorker;

    #[tokio::test]
    async fn test_rename_symbol() {
        use super::*;
        let mock = MockWorker::new();
        let req = RenameRequest {
            address: Some(json!("0x0")),
            name: "new_name".to_string(),
            ..Default::default()
        };
        let result = RenameSymbolTool::invoke(&mock, req).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }

    #[tokio::test]
    async fn test_patch_bytes() {
        use super::*;
        let mock = MockWorker::new();
        let req = PatchRequest {
            address: Some(json!("0x0")),
            bytes: json!("90"),
            ..Default::default()
        };
        let result = PatchBytesTool::invoke(&mock, req).await;
        assert!(result.is_ok(), "expected ok: {:?}", result);
    }
}
