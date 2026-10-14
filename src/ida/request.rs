//! Request types for the IDA worker.

use crate::error::ToolError;
use crate::ida::types::*;
use serde_json::Value;
use tokio::sync::oneshot;

/// Request types for the IDA worker
pub enum IdaRequest {
    Open {
        path: String,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        extra_args: Vec<String>,
        resp: oneshot::Sender<Result<DbInfo, ToolError>>,
    },
    Close {
        resp: oneshot::Sender<()>,
    },
    LoadDebugInfo {
        path: Option<String>,
        verbose: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    AnalysisStatus {
        resp: oneshot::Sender<Result<AnalysisStatus, ToolError>>,
    },
    ListFunctions {
        offset: usize,
        limit: usize,
        filter: Option<String>,
        resp: oneshot::Sender<Result<FunctionListResult, ToolError>>,
    },
    ResolveFunction {
        name: String,
        resp: oneshot::Sender<Result<FunctionInfo, ToolError>>,
    },
    GetFunctionPrototype {
        addr: Option<u64>,
        name: Option<String>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    DisasmByName {
        name: String,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    Disasm {
        addr: u64,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    Decompile {
        addr: u64,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    DecompileLines {
        addr: u64,
        resp: oneshot::Sender<Result<DecompiledLines, ToolError>>,
    },
    Segments {
        resp: oneshot::Sender<Result<Vec<SegmentInfo>, ToolError>>,
    },
    Strings {
        offset: usize,
        limit: usize,
        filter: Option<String>,
        resp: oneshot::Sender<Result<StringListResult, ToolError>>,
    },
    LocalTypes {
        offset: usize,
        limit: usize,
        filter: Option<String>,
        resp: oneshot::Sender<Result<LocalTypeListResult, ToolError>>,
    },
    DeclareType {
        decl: String,
        relaxed: bool,
        replace: bool,
        multi: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ApplyTypes {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        stack_offset: Option<i64>,
        stack_name: Option<String>,
        decl: Option<String>,
        type_name: Option<String>,
        relaxed: bool,
        delay: bool,
        strict: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    InferTypes {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        resp: oneshot::Sender<Result<GuessTypeResult, ToolError>>,
    },
    AddrInfo {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        resp: oneshot::Sender<Result<AddressInfo, ToolError>>,
    },
    FunctionAt {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        resp: oneshot::Sender<Result<FunctionRangeInfo, ToolError>>,
    },
    DisasmFunctionAt {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    DeclareStack {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        var_name: Option<String>,
        decl: String,
        relaxed: bool,
        resp: oneshot::Sender<Result<StackVarResult, ToolError>>,
    },
    DeleteStack {
        addr: Option<u64>,
        name: Option<String>,
        offset: Option<i64>,
        var_name: Option<String>,
        resp: oneshot::Sender<Result<StackVarResult, ToolError>>,
    },
    StackFrame {
        addr: u64,
        resp: oneshot::Sender<Result<FrameInfo, ToolError>>,
    },
    Structs {
        offset: usize,
        limit: usize,
        filter: Option<String>,
        resp: oneshot::Sender<Result<StructListResult, ToolError>>,
    },
    StructInfo {
        ordinal: Option<u32>,
        name: Option<String>,
        resp: oneshot::Sender<Result<StructInfo, ToolError>>,
    },
    ReadStruct {
        addr: u64,
        ordinal: Option<u32>,
        name: Option<String>,
        resp: oneshot::Sender<Result<StructReadResult, ToolError>>,
    },
    XRefsTo {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<XRefInfo>, ToolError>>,
    },
    XRefsFrom {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<XRefInfo>, ToolError>>,
    },
    XRefsToField {
        ordinal: Option<u32>,
        name: Option<String>,
        member_index: Option<u32>,
        member_name: Option<String>,
        limit: usize,
        resp: oneshot::Sender<Result<XrefsToFieldResult, ToolError>>,
    },
    Imports {
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Vec<ImportInfo>, ToolError>>,
    },
    Exports {
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Vec<ExportInfo>, ToolError>>,
    },
    Entrypoints {
        resp: oneshot::Sender<Result<Vec<String>, ToolError>>,
    },
    GetBytes {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        size: usize,
        resp: oneshot::Sender<Result<BytesResult, ToolError>>,
    },
    SetComments {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        comment: String,
        repeatable: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SetFunctionComment {
        addr: Option<u64>,
        name: Option<String>,
        comment: String,
        repeatable: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    Rename {
        addr: Option<u64>,
        current_name: Option<String>,
        new_name: String,
        flags: i32,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    BatchRename {
        entries: Vec<(Option<u64>, Option<String>, String)>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SetFunctionPrototype {
        addr: Option<u64>,
        name: Option<String>,
        prototype: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    RenameStackVariable {
        func_addr: Option<u64>,
        func_name: Option<String>,
        old_name: String,
        new_name: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SetStackVariableType {
        func_addr: Option<u64>,
        func_name: Option<String>,
        var_name: String,
        type_decl: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ListEnums {
        filter: Option<String>,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    CreateEnum {
        decl: String,
        replace: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    PatchBytes {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        bytes: Vec<u8>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    PatchAsm {
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        line: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    BasicBlocks {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<BasicBlockInfo>, ToolError>>,
    },
    Callees {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<FunctionInfo>, ToolError>>,
    },
    Callers {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<FunctionInfo>, ToolError>>,
    },
    IdbMeta {
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    LookupFunctions {
        queries: Vec<String>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ListGlobals {
        query: Option<String>,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    AnalyzeStrings {
        query: Option<String>,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindString {
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<StringListResult, ToolError>>,
    },
    XrefsToString {
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        max_xrefs: usize,
        resp: oneshot::Sender<Result<StringXrefsResult, ToolError>>,
    },
    AnalyzeFuncs {
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindBytes {
        pattern: String,
        max_results: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SearchText {
        text: String,
        max_results: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SearchImm {
        imm: u64,
        max_results: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindInsns {
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindInsnOperands {
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ReadInt {
        addr: u64,
        size: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetString {
        addr: u64,
        max_len: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetGlobalValue {
        query: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindPaths {
        start: u64,
        end: u64,
        max_paths: usize,
        max_depth: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    CallGraph {
        addr: u64,
        max_depth: usize,
        max_nodes: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    XrefMatrix {
        addrs: Vec<u64>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ExportFuncs {
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<FunctionListResult, ToolError>>,
    },
    PseudocodeAt {
        addr: u64,
        end_addr: Option<u64>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SearchPseudocode {
        pattern: String,
        limit: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    RunScript {
        code: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    RenameLvar {
        func_addr: u64,
        lvar_name: String,
        new_name: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SetLvarType {
        func_addr: u64,
        lvar_name: String,
        type_str: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SetDecompilerComment {
        func_addr: u64,
        addr: u64,
        itp: i32,
        comment: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    Shutdown,
}

/// Wrapper that records when a request was enqueued, enabling server-side
/// deadline checking. If a request has been sitting in the queue too long,
/// the worker can skip it instead of wasting time on work nobody will receive.
pub struct EnqueuedRequest {
    pub request: IdaRequest,
    pub enqueued_at: std::time::Instant,
}

impl EnqueuedRequest {
    pub fn new(request: IdaRequest) -> Self {
        Self {
            request,
            enqueued_at: std::time::Instant::now(),
        }
    }
}

// ── Request inspection methods ───────────────────────────────────────────────
//
// Generated via macro to avoid manually listing every variant twice.
// Each variant with a `resp` field gets `is_resp_closed()` via `oneshot::Sender::is_closed()`.

macro_rules! impl_request_inspection {
    ($($variant:ident),+ $(,)?) => {
        impl IdaRequest {
            /// Check if the response channel has been closed (caller disconnected/timed out).
            pub fn is_resp_closed(&self) -> bool {
                match self {
                    Self::Shutdown => false,
                    $(Self::$variant { resp, .. } => resp.is_closed(),)+
                }
            }

            /// Request type name for logging.
            pub fn type_name(&self) -> &'static str {
                match self {
                    Self::Shutdown => "Shutdown",
                    $(Self::$variant { .. } => stringify!($variant),)+
                }
            }
        }
    };
}

impl_request_inspection!(
    Open,
    Close,
    LoadDebugInfo,
    AnalysisStatus,
    ListFunctions,
    ResolveFunction,
    GetFunctionPrototype,
    DisasmByName,
    Disasm,
    Decompile,
    DecompileLines,
    Segments,
    Strings,
    LocalTypes,
    DeclareType,
    ApplyTypes,
    InferTypes,
    AddrInfo,
    FunctionAt,
    DisasmFunctionAt,
    DeclareStack,
    DeleteStack,
    StackFrame,
    Structs,
    StructInfo,
    ReadStruct,
    XRefsTo,
    XRefsFrom,
    XRefsToField,
    Imports,
    Exports,
    Entrypoints,
    GetBytes,
    SetComments,
    SetFunctionComment,
    Rename,
    BatchRename,
    SetFunctionPrototype,
    RenameStackVariable,
    SetStackVariableType,
    ListEnums,
    CreateEnum,
    PatchBytes,
    PatchAsm,
    BasicBlocks,
    Callees,
    Callers,
    IdbMeta,
    LookupFunctions,
    ListGlobals,
    AnalyzeStrings,
    FindString,
    XrefsToString,
    AnalyzeFuncs,
    FindBytes,
    SearchText,
    SearchImm,
    FindInsns,
    FindInsnOperands,
    ReadInt,
    GetString,
    GetGlobalValue,
    FindPaths,
    CallGraph,
    XrefMatrix,
    ExportFuncs,
    PseudocodeAt,
    SearchPseudocode,
    RunScript,
    RenameLvar,
    SetLvarType,
    SetDecompilerComment,
);

impl IdaRequest {
    /// Returns true for control requests that should never be skipped,
    /// even if the caller has disconnected.
    pub fn is_control(&self) -> bool {
        matches!(self, Self::Close { .. } | Self::Shutdown)
    }
}
