//! MCP tool request types.
//!
//! These structs define the parameters for each MCP tool exposed by the server.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct OpenIdbRequest {
    #[schemars(
        description = "Path to an IDA database (.i64/.idb) or raw binary. Call close_idb when finished to release locks; in multi-client mode coordinate before closing."
    )]
    pub path: String,
    #[schemars(description = "If true, load external debug info (dSYM/DWARF) after open")]
    #[serde(alias = "load_dsym")]
    pub load_debug_info: Option<bool>,
    #[schemars(
        description = "Optional debug info path (dSYM DWARF). If omitted, tries sibling .dSYM"
    )]
    #[serde(alias = "dsym_path")]
    pub debug_info_path: Option<String>,
    #[schemars(description = "Verbose debug-info loading (default: false)")]
    pub debug_info_verbose: Option<bool>,
    #[schemars(
        description = "If true, clean up stale lock files from crashed sessions before opening. \
        Use this when a previous ida-cli session crashed and left behind lock files."
    )]
    #[serde(alias = "recover")]
    pub force: Option<bool>,
    #[schemars(
        description = "IDA file type selector (-T flag). Used to choose a specific loader, \
        e.g. 'Apple DYLD cache for arm64e (single module(s))'. Only applies to raw binaries."
    )]
    pub file_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloseIdbRequest {
    #[schemars(description = "Ownership token returned by open_idb (required for HTTP/SSE).")]
    #[serde(alias = "close_token", alias = "owner_token")]
    pub token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct LoadDebugInfoRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(
        description = "Path to debug info file (e.g., dSYM DWARF). If omitted, tries sibling .dSYM for the current database."
    )]
    pub path: Option<String>,
    #[schemars(description = "Whether to emit verbose load status (default: false)")]
    pub verbose: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EmptyParams {}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListFunctionsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum functions to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Optional filter - only return functions containing this text")]
    #[serde(alias = "query", alias = "queries", alias = "filter")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AnalyzeFuncsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ResolveFunctionRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function name to resolve (exact or partial match)")]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct GetFunctionPrototypeRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: Option<Value>,
    #[schemars(description = "Function name (alternative to address)")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SetFunctionPrototypeRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: Option<Value>,
    #[schemars(description = "Function name (alternative to address)")]
    pub name: Option<String>,
    #[schemars(description = "C prototype string, e.g. 'int __fastcall foo(void *ctx, int len)'")]
    pub prototype: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddrInfoRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct FunctionAtRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DisasmFunctionAtRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Number of instructions (1-5000, default: 200)")]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DisasmRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address(es) to disassemble (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Number of instructions (1-1000, default: 10)")]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DisasmByNameRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function name to disassemble (exact or partial match)")]
    pub name: String,
    #[schemars(description = "Number of instructions (1-1000, default: 10)")]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DecompileRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address(es) of function to decompile (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DecompileStructuredRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,

    #[schemars(description = "Address of function to decompile (string/number)")]
    #[serde(alias = "addr")]
    pub address: Value,

    #[schemars(
        description = "Maximum AST depth to serialize (default: 20, max: 50). Deeper nodes are truncated to {op: '...', truncated: true}"
    )]
    #[serde(default)]
    pub max_depth: Option<u32>,

    #[schemars(
        description = "Include expression type info on every node (default: false). Adds 'type' field to each cexpr_t node."
    )]
    #[serde(default)]
    pub include_types: Option<bool>,

    #[schemars(description = "Include raw address (ea) on every node (default: true)")]
    #[serde(default)]
    pub include_addresses: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct BatchDecompileRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,

    #[schemars(
        description = "List of addresses to decompile (array of strings/numbers, or JSON array string)"
    )]
    #[serde(alias = "addrs", alias = "address", alias = "addresses")]
    pub addresses: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SearchPseudocodeRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,

    #[schemars(
        description = "Text pattern to search for in decompiled pseudocode (case-sensitive substring match)"
    )]
    pub pattern: String,

    #[schemars(
        description = "Maximum number of matching functions to return (default: 20, max: 100)"
    )]
    #[serde(default)]
    pub limit: Option<usize>,

    #[schemars(description = "Timeout in seconds for the entire search (default: 60)")]
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TableScanRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,

    #[schemars(description = "Base address of the table (hex string or number)")]
    #[serde(alias = "addr", alias = "base")]
    pub base_address: Value,

    #[schemars(description = "Stride between entries in bytes (default: 8)")]
    #[serde(default)]
    pub stride: Option<u64>,

    #[schemars(description = "Number of entries to read (default: 16, max: 256)")]
    #[serde(default)]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DiffFunctionsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,

    #[schemars(description = "Address of the first function to compare (hex string or number)")]
    #[serde(alias = "address1", alias = "func1")]
    pub addr1: Value,

    #[schemars(description = "Address of the second function to compare (hex string or number)")]
    #[serde(alias = "address2", alias = "func2")]
    pub addr2: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListStringsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Substring search query")]
    pub query: Option<String>,
    #[schemars(description = "Alias for query")]
    pub filter: Option<String>,
    #[schemars(description = "Exact match mode (default: false)")]
    pub exact: Option<bool>,
    #[schemars(description = "Case insensitive search (default: true)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StringsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Optional filter - only return strings containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct FindStringRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "String to search for")]
    pub query: String,
    #[schemars(description = "Exact match (default: false)")]
    pub exact: Option<bool>,
    #[schemars(description = "Case-insensitive match (default: true)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct XrefsToStringRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "String to search for")]
    pub query: String,
    #[schemars(description = "Exact match (default: false)")]
    pub exact: Option<bool>,
    #[schemars(description = "Case-insensitive match (default: true)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Maximum xrefs per string (default: 64, max: 1024)")]
    pub max_xrefs: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct LocalTypesRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum types to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Optional filter - only return types containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeclareTypeRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "C declaration(s) to add to the local type library")]
    pub decl: String,
    #[schemars(description = "Relaxed parsing (allow unknown namespaces)")]
    pub relaxed: Option<bool>,
    #[schemars(description = "Replace existing type if it already exists")]
    pub replace: Option<bool>,
    #[schemars(description = "Parse multiple declarations in one input string")]
    pub multi: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StructsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum structs to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Optional filter - only return structs containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StructInfoRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Struct ordinal (numeric)")]
    pub ordinal: Option<u32>,
    #[schemars(description = "Struct name (exact match)")]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ReadStructRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address of struct instance (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Struct ordinal (numeric)")]
    pub ordinal: Option<u32>,
    #[schemars(description = "Struct name (exact match)")]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ApplyTypesRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address to apply type (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Stack variable offset (negative for locals)")]
    pub stack_offset: Option<i64>,
    #[schemars(description = "Stack variable name (when applying to stack var)")]
    pub stack_name: Option<String>,
    #[schemars(description = "Named type to apply")]
    pub type_name: Option<String>,
    #[schemars(description = "C declaration to parse and apply")]
    pub decl: Option<String>,
    #[schemars(description = "Relaxed parsing for decl")]
    pub relaxed: Option<bool>,
    #[schemars(description = "Delay function creation if missing")]
    pub delay: Option<bool>,
    #[schemars(description = "Strict application (no type conversion)")]
    pub strict: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct InferTypesRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address to infer type (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeclareStackRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function name (alternative to address)")]
    #[serde(alias = "function", alias = "name")]
    pub target_name: Option<String>,
    #[schemars(description = "Stack offset in bytes (negative for locals, positive for args)")]
    pub offset: i64,
    #[schemars(description = "Stack variable name (optional)")]
    pub var_name: Option<String>,
    #[schemars(description = "C declaration for the variable type")]
    pub decl: String,
    #[schemars(description = "Relaxed parsing for decl")]
    pub relaxed: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteStackRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function name (alternative to address)")]
    #[serde(alias = "function", alias = "name")]
    pub target_name: Option<String>,
    #[schemars(description = "Stack offset in bytes (negative for locals, positive for args)")]
    pub offset: Option<i64>,
    #[schemars(description = "Stack variable name (optional)")]
    pub var_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RenameStackVariableRequest {
    pub func_address: Option<Value>,
    pub func_name: Option<String>,
    pub name: String,
    pub new_name: String,
    pub db_handle: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SetStackVariableTypeRequest {
    pub func_address: Option<Value>,
    pub func_name: Option<String>,
    pub name: String,
    pub type_decl: String,
    pub db_handle: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ListEnumsRequest {
    pub filter: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub db_handle: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct CreateEnumRequest {
    pub decl: String,
    pub replace: Option<bool>,
    pub db_handle: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct XrefsToFieldRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Struct ordinal (numeric)")]
    pub ordinal: Option<u32>,
    #[schemars(description = "Struct name (exact match)")]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
    #[schemars(description = "Struct member index (0-based)")]
    pub member_index: Option<u32>,
    #[schemars(description = "Struct member name (exact match)")]
    #[serde(alias = "member", alias = "field", alias = "field_name")]
    pub member_name: Option<String>,
    #[schemars(description = "Maximum xrefs to return (default: 1000, max: 10000)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddressRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address(es) (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetBytesRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address(es) to read from (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name to read from (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Number of bytes to read (1-65536, default: 256)")]
    #[serde(alias = "count")]
    pub size: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SetCommentsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address to comment (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name to comment (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Comment text (empty string clears comment)")]
    #[serde(alias = "text", alias = "comment")]
    pub comment: String,
    #[schemars(description = "Repeatable comment (default: false)")]
    #[serde(alias = "rptble", alias = "repeatable")]
    pub repeatable: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SetFunctionCommentRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: Option<Value>,
    #[schemars(description = "Function name (alternative to address)")]
    pub name: Option<String>,
    #[schemars(description = "Comment text")]
    pub comment: String,
    #[schemars(description = "If true, comment is visible in all views (default: false)")]
    pub repeatable: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RenameRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address to rename (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Current name to resolve (alternative to address)")]
    #[serde(alias = "current", alias = "old_name", alias = "from")]
    pub current_name: Option<String>,
    #[schemars(description = "New name for the symbol")]
    #[serde(alias = "new_name", alias = "name")]
    pub name: String,
    #[schemars(description = "IDA set_name flags (optional)")]
    pub flags: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct BatchRenameEntry {
    #[schemars(description = "Address to rename (string/number)")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: Option<Value>,
    #[schemars(description = "Current name to resolve (alternative to address)")]
    pub current_name: Option<String>,
    #[schemars(description = "New name for the symbol")]
    pub new_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct BatchRenameRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "List of rename operations")]
    pub renames: Vec<BatchRenameEntry>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RenameLvarRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address containing the local variable (string/number)")]
    #[serde(alias = "func_ea", alias = "func_addr")]
    pub func_address: Value,
    #[schemars(description = "Current local variable name")]
    #[serde(alias = "old_name", alias = "variable")]
    pub lvar_name: String,
    #[schemars(description = "New name for the local variable")]
    #[serde(alias = "name")]
    pub new_name: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SetLvarTypeRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address containing the local variable (string/number)")]
    #[serde(alias = "func_ea", alias = "func_addr")]
    pub func_address: Value,
    #[schemars(description = "Local variable name to retype")]
    #[serde(alias = "variable", alias = "name")]
    pub lvar_name: String,
    #[schemars(description = "C type declaration string (e.g. \"int *\", \"DWORD\")")]
    #[serde(alias = "type", alias = "decl")]
    pub type_str: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SetDecompilerCommentRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "func_ea", alias = "func_addr")]
    pub func_address: Value,
    #[schemars(
        description = "Address within the function to attach the comment to (string/number)"
    )]
    #[serde(alias = "ea")]
    pub address: Value,
    #[schemars(
        description = "ITP position value: 69=ITP_SEMI (end of line, default), 74=ITP_BLOCK1 (before item)"
    )]
    #[serde(default)]
    pub itp: Option<i32>,
    #[schemars(description = "Comment text (empty string clears comment)")]
    #[serde(alias = "text", alias = "cmt")]
    pub comment: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PatchRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address to patch (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name to patch (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(
        description = "Bytes to patch (hex string like '90 90' or array of ints/hex strings)"
    )]
    #[serde(alias = "data", alias = "bytes")]
    pub bytes: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PatchAsmRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address to patch (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name to patch (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Assembly text to assemble and patch")]
    #[serde(alias = "asm", alias = "instruction")]
    pub line: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PaginatedRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum items to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct LookupFuncsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function queries (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "names")]
    pub queries: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListGlobalsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Optional filter for globals")]
    #[serde(alias = "filter")]
    pub query: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum globals to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AnalyzeStringsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Optional filter for strings")]
    #[serde(alias = "filter")]
    pub query: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct FindBytesRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Pattern(s) to search for (string or array)")]
    #[serde(alias = "pattern", alias = "patterns")]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SearchRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Targets to search for (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "targets")]
    pub targets: Value,
    #[schemars(description = "Search type: text or imm (optional)")]
    #[serde(alias = "type")]
    pub kind: Option<String>,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct FindInsnsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Instruction mnemonic(s) or sequence (string/number or array)")]
    #[serde(
        alias = "pattern",
        alias = "patterns",
        alias = "query",
        alias = "queries",
        alias = "mnemonic",
        alias = "mnemonics"
    )]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Case-insensitive match (default: false)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct FindInsnOperandsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Operand substring(s) to match (string/number or array)")]
    #[serde(
        alias = "pattern",
        alias = "patterns",
        alias = "query",
        alias = "queries",
        alias = "operands"
    )]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Case-insensitive match (default: false)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct FindPathsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Start address (string/number)")]
    pub start: Value,
    #[schemars(description = "End address (string/number)")]
    pub end: Value,
    #[schemars(description = "Maximum paths to return (default: 8)")]
    pub max_paths: Option<usize>,
    #[schemars(description = "Maximum path depth (default: 64)")]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CallGraphRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Root function address(es) (string/number or array)")]
    #[serde(
        alias = "root",
        alias = "roots",
        alias = "addr",
        alias = "address",
        alias = "addrs"
    )]
    pub roots: Value,
    #[schemars(description = "Maximum depth (default: 2)")]
    pub max_depth: Option<usize>,
    #[schemars(description = "Maximum nodes (default: 256)")]
    pub max_nodes: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct XrefMatrixRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Addresses to include in matrix (string/number or array)")]
    #[serde(alias = "addr", alias = "address", alias = "addresses")]
    pub addrs: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExportFuncsRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Function address(es) to export (optional)")]
    #[serde(
        alias = "addrs",
        alias = "addr",
        alias = "address",
        alias = "functions"
    )]
    pub addrs: Option<Value>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum functions to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Export format (only json supported)")]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetStringRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address(es) to read string from (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Maximum length to read (default: 256)")]
    pub max_len: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetGlobalValueRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Global name(s) or address(es) (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "names", alias = "addrs")]
    pub query: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct IntConvertRequest {
    #[schemars(description = "Values to convert (string/number or array)")]
    #[serde(alias = "input", alias = "inputs")]
    pub inputs: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PseudocodeAtRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address(es) to get pseudocode for (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Optional end address for range query (for basic blocks)")]
    pub end_address: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ToolCatalogRequest {
    #[schemars(
        description = "What you're trying to accomplish (e.g., 'find all callers of a function')"
    )]
    pub query: Option<String>,
    #[schemars(
        description = "Filter by category: core, functions, disassembly, decompile, xrefs, control_flow, memory, search, metadata, types, editing, debug, ui, scripting"
    )]
    pub category: Option<String>,
    #[schemars(description = "Maximum number of tools to return (default: 7)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ToolHelpRequest {
    #[schemars(description = "Name of the tool to get help for")]
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RunScriptRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(
        description = "Python code to execute via IDAPython. Has full access to ida_* modules, \
        idc, idautils. stdout/stderr are captured and returned. \
        Provide either 'code' (inline) or 'file' (path to .py), not both."
    )]
    pub code: Option<String>,
    #[schemars(description = "Path to a .py file to execute via IDAPython. \
        Alternative to 'code' for longer scripts. The file is read server-side.")]
    pub file: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TaskStatusRequest {
    #[schemars(description = "Task ID returned by open_dsc (e.g. 'dsc-abc123')")]
    pub task_id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct OpenDscRequest {
    #[schemars(description = "Path to the dyld_shared_cache file")]
    pub path: String,
    #[schemars(description = "CPU architecture (e.g. 'arm64e', 'arm64', 'x86_64h')")]
    pub arch: String,
    #[schemars(description = "Primary dylib to load (e.g. '/usr/lib/libobjc.A.dylib')")]
    pub module: String,
    #[schemars(description = "Additional frameworks to load after opening \
        (e.g. ['/System/Library/Frameworks/Foundation.framework/Foundation'])")]
    pub frameworks: Option<Vec<String>>,
    #[schemars(description = "IDA version: 8 or 9. Determines the -T format string. Default: 9")]
    pub ida_version: Option<u8>,
    #[schemars(description = "Path to write idat's log file (-L flag). \
        If omitted, no log is created. Useful for debugging DSC loading failures.")]
    pub log_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct OpenSbpfRequest {
    #[schemars(
        description = "Path to the Solana sBPF .so program. `sbx aot i64` will AOT-compile it \
        and produce a fully-analysed `.i64` database which the server opens directly."
    )]
    pub path: String,
    #[schemars(
        description = "Explicit path to the sbx binary. If omitted, searches PATH and ~/.cargo/bin."
    )]
    pub sbx_path: Option<String>,
    #[schemars(
        description = "Skip automatic import of sbpf_runtime.h types (SbpfContext, etc). \
        Default: false (types are imported automatically on first open)."
    )]
    #[serde(default)]
    pub skip_runtime_types: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DscAddDylibRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(
        description = "DSC-internal dylib path to load (e.g. '/usr/lib/libSystem.B.dylib'). \
        Must be an absolute path inside the dyld_shared_cache."
    )]
    pub module: String,
    #[schemars(
        description = "Execution timeout in seconds (default: 300, max: 600). \
        Large frameworks may need more time."
    )]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Default)]
pub struct DscAddRegionRequest {
    #[schemars(
        description = "Optional database handle for multi-IDB routing. If omitted, uses the active database."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(
        description = "Exactly one region address to load from the currently open DSC database (string/number). \
        Accepts hex (e.g. '0x180116000') or decimal."
    )]
    #[serde(alias = "ea", alias = "addr")]
    pub address: Value,
    #[schemars(
        description = "Execution timeout in seconds (default: 300, max: 600). \
        Use this for loading data/GOT/stub regions on-demand from DSC."
    )]
    pub timeout_secs: Option<u64>,
}

// ==================== DEBUG TOOL REQUEST TYPES ====================

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgLoadDebuggerRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(
        description = "Debugger module name: 'mac', 'linux', 'win32', 'gdb', 'windbg'. Defaults to platform-native."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debugger_name: Option<String>,
    #[schemars(description = "Use remote debugger (default: false)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_remote: Option<bool>,
    #[schemars(description = "Execution timeout in seconds (default: 30, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgStartProcessRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(
        description = "Path to the executable to debug. Defaults to the currently open IDB's target."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[schemars(description = "Command-line arguments for the process")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    #[schemars(description = "Working directory for the process")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_dir: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 60, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgAttachProcessRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "PID of the process to attach to")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
    #[schemars(description = "Execution timeout in seconds (default: 30, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgDetachProcessRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 30, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgExitProcessRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 30, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgGetStateRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgAddBreakpointRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(
        description = "Address to set breakpoint (hex string like '0x100001234' or decimal)"
    )]
    pub address: String,
    #[schemars(description = "Breakpoint size in bytes (default: 0 for software breakpoint)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[schemars(description = "Breakpoint type: 'soft' (default), 'exec', 'write', 'read', 'rdwr'")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpt_type: Option<String>,
    #[schemars(description = "Optional breakpoint condition expression")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgDelBreakpointRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address of breakpoint to delete (hex string or decimal)")]
    pub address: String,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgEnableBreakpointRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Address of breakpoint to enable/disable (hex string or decimal)")]
    pub address: String,
    #[schemars(description = "true to enable, false to disable (default: true)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgListBreakpointsRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgContinueRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 30, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgStepIntoRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 30, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgStepOverRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 30, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgStepUntilRetRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 60, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgRunToRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Target address to run to (hex string or decimal)")]
    pub address: String,
    #[schemars(description = "Execution timeout in seconds (default: 60, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgGetRegistersRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(
        description = "Optional list of register names to read (e.g. ['rax', 'rip']). If omitted, reads all registers."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_names: Option<Vec<String>>,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgSetRegisterRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Name of register to set (e.g. 'rax', 'rip')")]
    pub register_name: String,
    #[schemars(description = "New value for the register (hex string '0x...' or decimal)")]
    pub value: String,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgReadMemoryRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Start address to read from (hex string or decimal)")]
    pub address: String,
    #[schemars(description = "Number of bytes to read (max: 4096)")]
    pub size: u64,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgWriteMemoryRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Target address to write to (hex string or decimal)")]
    pub address: String,
    #[schemars(description = "Hex-encoded bytes to write (e.g. '4889c7' or '48 89 c7')")]
    pub data: String,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgGetMemoryInfoRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgListThreadsRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgSelectThreadRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Thread ID to select as current thread")]
    pub thread_id: u64,
    #[schemars(description = "Execution timeout in seconds (default: 10, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbgWaitEventRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,
    #[schemars(description = "Timeout in seconds to wait for an event (default: 30, max: 600)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    #[schemars(
        description = "WFNE flags as hex string (e.g. '0x5' for WFNE_SUSP|WFNE_SILENT). Default: WFNE_SILENT."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
}
