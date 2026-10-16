//! Trait abstraction over [`IdaWorker`] for testable RPC dispatch.
//!
//! [`WorkerDispatch`] mirrors every async method that [`super::worker::IdaWorker`]
//! exposes to [`crate::dispatch_rpc_request`], enabling mock-based unit tests
//! without a live IDA instance.

use crate::error::ToolError;
use crate::ida::types::*;
use serde_json::Value;

/// Async trait covering all worker methods used by `dispatch_rpc_request`.
///
/// Uses Rust AFIT (async fn in trait, stable since 1.75) — no `async-trait`
/// crate required. The trait is **not** object-safe by design; consumers should
/// be generic over `W: WorkerDispatch`.
#[allow(clippy::too_many_arguments, async_fn_in_trait)]
pub trait WorkerDispatch {
    // ── Database management ─────────────────────────────────────────────

    async fn open(
        &self,
        path: &str,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        extra_args: Vec<String>,
    ) -> Result<DbInfo, ToolError>;

    async fn close(&self) -> Result<(), ToolError>;

    async fn shutdown(&self) -> Result<(), ToolError>;

    async fn load_debug_info(
        &self,
        path: Option<String>,
        verbose: bool,
    ) -> Result<Value, ToolError>;

    async fn analysis_status(&self) -> Result<AnalysisStatus, ToolError>;

    // ── Functions ───────────────────────────────────────────────────────

    async fn list_functions(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<FunctionListResult, ToolError>;

    async fn resolve_function(&self, name: &str) -> Result<FunctionInfo, ToolError>;

    async fn get_function_prototype(
        &self,
        addr: Option<u64>,
        name: Option<String>,
    ) -> Result<Value, ToolError>;

    async fn function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
    ) -> Result<FunctionRangeInfo, ToolError>;

    async fn lookup_funcs(&self, queries: Vec<String>) -> Result<Value, ToolError>;

    async fn export_funcs(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<FunctionListResult, ToolError>;

    // ── Disassembly / Decompilation ─────────────────────────────────────

    async fn disasm(&self, addr: u64, count: usize) -> Result<String, ToolError>;

    async fn disasm_by_name(&self, name: &str, count: usize) -> Result<String, ToolError>;

    async fn disasm_function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        count: usize,
    ) -> Result<String, ToolError>;

    async fn decompile(&self, addr: u64) -> Result<String, ToolError>;

    async fn decompile_lines(&self, addr: u64) -> Result<DecompiledLines, ToolError>;

    async fn pseudocode_at(&self, addr: u64, end_addr: Option<u64>) -> Result<Value, ToolError>;

    // ── Segments ────────────────────────────────────────────────────────

    async fn segments(&self) -> Result<Vec<SegmentInfo>, ToolError>;

    // ── Strings ─────────────────────────────────────────────────────────

    async fn strings(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError>;

    async fn find_string(
        &self,
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError>;

    async fn analyze_strings(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError>;

    async fn xrefs_to_string(
        &self,
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        max_xrefs: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringXrefsResult, ToolError>;

    // ── Types ───────────────────────────────────────────────────────────

    async fn local_types(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<LocalTypeListResult, ToolError>;

    async fn declare_type(
        &self,
        decl: String,
        relaxed: bool,
        replace: bool,
        multi: bool,
    ) -> Result<Value, ToolError>;

    async fn apply_types(
        &self,
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
    ) -> Result<Value, ToolError>;

    async fn infer_types(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
    ) -> Result<GuessTypeResult, ToolError>;

    async fn set_function_prototype(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        prototype: String,
    ) -> Result<Value, ToolError>;

    async fn list_enums(
        &self,
        filter: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<Value, ToolError>;

    async fn create_enum(&self, decl: String, replace: bool) -> Result<Value, ToolError>;

    // ── Address info ────────────────────────────────────────────────────

    async fn addr_info(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
    ) -> Result<AddressInfo, ToolError>;

    // ── Stack ───────────────────────────────────────────────────────────

    async fn declare_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        var_name: Option<String>,
        decl: String,
        relaxed: bool,
    ) -> Result<StackVarResult, ToolError>;

    async fn delete_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: Option<i64>,
        var_name: Option<String>,
    ) -> Result<StackVarResult, ToolError>;

    async fn stack_frame(&self, addr: u64) -> Result<FrameInfo, ToolError>;

    async fn rename_stack_variable(
        &self,
        func_addr: Option<u64>,
        func_name: Option<String>,
        old_name: String,
        new_name: String,
    ) -> Result<Value, ToolError>;

    async fn set_stack_variable_type(
        &self,
        func_addr: Option<u64>,
        func_name: Option<String>,
        var_name: String,
        type_decl: String,
    ) -> Result<Value, ToolError>;

    // ── Structs ─────────────────────────────────────────────────────────

    async fn structs(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<StructListResult, ToolError>;

    async fn struct_info(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructInfo, ToolError>;

    async fn read_struct(
        &self,
        addr: u64,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructReadResult, ToolError>;

    // ── Cross-references ────────────────────────────────────────────────

    async fn xrefs_to(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError>;

    async fn xrefs_from(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError>;

    async fn xrefs_to_field(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
        member_index: Option<u32>,
        member_name: Option<String>,
        limit: usize,
    ) -> Result<XrefsToFieldResult, ToolError>;

    // ── Imports / Exports / Entrypoints ─────────────────────────────────

    async fn imports(&self, offset: usize, limit: usize) -> Result<Vec<ImportInfo>, ToolError>;

    async fn exports(&self, offset: usize, limit: usize) -> Result<Vec<ExportInfo>, ToolError>;

    async fn entrypoints(&self) -> Result<Vec<String>, ToolError>;

    // ── Memory ──────────────────────────────────────────────────────────

    async fn get_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        size: usize,
    ) -> Result<BytesResult, ToolError>;

    async fn read_int(&self, addr: u64, size: usize) -> Result<Value, ToolError>;

    async fn get_string(&self, addr: u64, max_len: usize) -> Result<Value, ToolError>;

    async fn get_global_value(&self, query: String) -> Result<Value, ToolError>;

    // ── Annotations ─────────────────────────────────────────────────────

    async fn set_comments(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        comment: String,
        repeatable: bool,
    ) -> Result<Value, ToolError>;

    async fn set_function_comment(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        comment: String,
        repeatable: bool,
    ) -> Result<Value, ToolError>;

    async fn rename(
        &self,
        addr: Option<u64>,
        current_name: Option<String>,
        new_name: String,
        flags: i32,
    ) -> Result<Value, ToolError>;

    async fn batch_rename(
        &self,
        entries: Vec<(Option<u64>, Option<String>, String)>,
    ) -> Result<Value, ToolError>;

    async fn rename_lvar(
        &self,
        func_addr: u64,
        lvar_name: String,
        new_name: String,
    ) -> Result<Value, ToolError>;

    async fn set_lvar_type(
        &self,
        func_addr: u64,
        lvar_name: String,
        type_str: String,
    ) -> Result<Value, ToolError>;

    async fn set_decompiler_comment(
        &self,
        func_addr: u64,
        addr: u64,
        itp: i32,
        comment: String,
    ) -> Result<Value, ToolError>;

    // ── Patching ────────────────────────────────────────────────────────

    async fn patch_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<Value, ToolError>;

    async fn patch_asm(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        line: String,
    ) -> Result<Value, ToolError>;

    // ── Control / Call flow ─────────────────────────────────────────────

    async fn basic_blocks(&self, addr: u64) -> Result<Vec<BasicBlockInfo>, ToolError>;

    async fn callees(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError>;

    async fn callers(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError>;

    async fn callgraph(
        &self,
        addr: u64,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Value, ToolError>;

    async fn find_paths(
        &self,
        start: u64,
        end: u64,
        max_paths: usize,
        max_depth: usize,
    ) -> Result<Value, ToolError>;

    async fn xref_matrix(&self, addrs: Vec<u64>) -> Result<Value, ToolError>;

    // ── Metadata ────────────────────────────────────────────────────────

    async fn idb_meta(&self) -> Result<Value, ToolError>;

    // ── Globals ─────────────────────────────────────────────────────────

    async fn list_globals(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError>;

    // ── Analysis ────────────────────────────────────────────────────────

    async fn analyze_funcs(&self, timeout_secs: Option<u64>) -> Result<Value, ToolError>;

    // ── Search ──────────────────────────────────────────────────────────

    async fn find_bytes(
        &self,
        pattern: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError>;

    async fn search_text(
        &self,
        text: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError>;

    async fn search_imm(
        &self,
        imm: u64,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError>;

    async fn find_insns(
        &self,
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError>;

    async fn find_insn_operands(
        &self,
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError>;

    // ── Search ───────────────────────────────────────────────────────────

    async fn search_pseudocode(
        &self,
        pattern: &str,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError>;

    // ── IDAPython script ────────────────────────────────────────────────

    async fn run_script(&self, code: &str, timeout_secs: Option<u64>) -> Result<Value, ToolError>;
}
