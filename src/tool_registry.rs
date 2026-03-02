//! Tool registry for dynamic tool discovery.
//!
//! All tools are exposed in tools/list by default to support MCP clients that only
//! register tools at connection time. `tool_catalog` is still recommended for discovery.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Tool category for grouping related tools
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// Core database operations (always available)
    Core,
    /// Function navigation and discovery
    Functions,
    /// Disassembly tools
    Disassembly,
    /// Decompilation tools (requires Hex-Rays)
    Decompile,
    /// Cross-reference analysis
    Xrefs,
    /// Control flow and call graph analysis
    ControlFlow,
    /// Memory and data reading
    Memory,
    /// Search and pattern matching
    Search,
    /// Metadata and structure info
    Metadata,
    /// Type/struct/stack information and type application
    Types,
    /// Editing and patching operations
    Editing,
    /// Debugger operations
    Debug,
    /// UI/cursor helpers
    Ui,
    /// Scripting/eval helpers
    Scripting,
}

impl ToolCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Functions => "functions",
            Self::Disassembly => "disassembly",
            Self::Decompile => "decompile",
            Self::Xrefs => "xrefs",
            Self::ControlFlow => "control_flow",
            Self::Memory => "memory",
            Self::Search => "search",
            Self::Metadata => "metadata",
            Self::Types => "types",
            Self::Editing => "editing",
            Self::Debug => "debug",
            Self::Ui => "ui",
            Self::Scripting => "scripting",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Core => "Database open/close and discovery tools",
            Self::Functions => "List, search, and resolve functions",
            Self::Disassembly => "Disassemble code at addresses",
            Self::Decompile => "Decompile functions to pseudocode (requires Hex-Rays)",
            Self::Xrefs => "Cross-reference analysis (xrefs to/from)",
            Self::ControlFlow => "Basic blocks, call graphs, control flow",
            Self::Memory => "Read bytes, strings, and data",
            Self::Search => "Search for bytes, strings, patterns",
            Self::Metadata => "Database info, segments, imports, exports",
            Self::Types => "Types, structs, and stack variable info",
            Self::Editing => "Patching, renaming, and comment editing",
            Self::Debug => "Debugger operations (headless unsupported)",
            Self::Ui => "UI/cursor helpers (headless unsupported)",
            Self::Scripting => "Execute Python scripts via IDAPython",
        }
    }

    pub fn all() -> &'static [ToolCategory] {
        &[
            Self::Core,
            Self::Functions,
            Self::Disassembly,
            Self::Decompile,
            Self::Xrefs,
            Self::ControlFlow,
            Self::Memory,
            Self::Search,
            Self::Metadata,
            Self::Types,
            Self::Editing,
            Self::Debug,
            Self::Ui,
            Self::Scripting,
        ]
    }
}

impl FromStr for ToolCategory {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let normalized = input.trim().to_lowercase().replace(['-', ' '], "_");
        match normalized.as_str() {
            "core" => Ok(Self::Core),
            "functions" | "function" => Ok(Self::Functions),
            "disassembly" | "disasm" => Ok(Self::Disassembly),
            "decompile" | "decompiler" => Ok(Self::Decompile),
            "xrefs" | "xref" | "references" => Ok(Self::Xrefs),
            "control_flow" | "controlflow" | "cfg" => Ok(Self::ControlFlow),
            "memory" | "data" => Ok(Self::Memory),
            "search" => Ok(Self::Search),
            "metadata" | "meta" | "info" => Ok(Self::Metadata),
            "types" | "type" | "structs" => Ok(Self::Types),
            "editing" | "edit" => Ok(Self::Editing),
            "debug" | "debugger" => Ok(Self::Debug),
            "ui" => Ok(Self::Ui),
            "scripting" | "script" | "eval" => Ok(Self::Scripting),
            _ => Err(()),
        }
    }
}

/// Metadata for a single tool
#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: &'static str,
    pub category: ToolCategory,
    /// Short description (1 line, <100 chars) - used in tool_catalog results
    pub short_desc: &'static str,
    /// Full description with usage details - used in tool_help
    pub full_desc: &'static str,
    /// Example invocation (JSON)
    pub example: &'static str,
    /// Whether this tool is in the default (core) set
    pub default: bool,
    /// Keywords for semantic search
    pub keywords: &'static [&'static str],
    /// Alternative names for this tool
    pub aliases: &'static [&'static str],
}

// =============================================================================
// TOOL RENAME MAPPING — old_name → new_primary_name (single source of truth)
// Task 3 applies these renames. Task 4 updates dispatch. Task 5 updates server.
// =============================================================================
//
// === Core (mostly unchanged) ===
// analysis_status     → get_analysis_status     (alias: analysis_status)
// idb_meta            → get_database_info       (alias: idb_meta)
// task_status         → get_task_status          (alias: task_status)
// open_idb, open_dsc, open_sbpf, close_idb, dsc_add_dylib, load_debug_info,
// tool_catalog, tool_help — UNCHANGED
//
// === Functions ===
// list_functions      → UNCHANGED
// list_funcs          → REMOVED as separate entry (alias under list_functions)
// resolve_function    → get_function_by_name     (alias: resolve_function)
// function_at         → get_function_at_address   (alias: function_at)
// lookup_funcs        → batch_lookup_functions    (alias: lookup_funcs)
// analyze_funcs       → run_auto_analysis         (alias: analyze_funcs)
//
// === Disassembly ===
// disasm              → disassemble              (alias: disasm)
// disasm_by_name      → disassemble_function      (alias: disasm_by_name)
// disasm_function_at  → disassemble_function_at   (alias: disasm_function_at)
//
// === Decompile ===
// decompile           → decompile_function        (alias: decompile)
// pseudocode_at       → get_pseudocode_at         (alias: pseudocode_at)
// decompile_structured → UNCHANGED
// batch_decompile     → UNCHANGED
// diff_functions      → diff_pseudocode           (alias: diff_functions)
// search_pseudocode   → UNCHANGED
//
// === Xrefs ===
// xrefs_to            → get_xrefs_to             (alias: xrefs_to)
// xrefs_from          → get_xrefs_from           (alias: xrefs_from)
// xrefs_to_string     → get_xrefs_to_string      (alias: xrefs_to_string)
// xref_matrix         → build_xref_matrix         (alias: xref_matrix)
// xrefs_to_field      → get_xrefs_to_struct_field (alias: xrefs_to_field)
//
// === Control Flow ===
// basic_blocks        → get_basic_blocks          (alias: basic_blocks)
// callers             → get_callers               (alias: callers)
// callees             → get_callees               (alias: callees)
// callgraph           → build_callgraph           (alias: callgraph)
// find_paths          → find_control_flow_paths   (alias: find_paths)
//
// === Memory ===
// get_bytes           → read_bytes                (alias: get_bytes)
// get_string          → read_string               (alias: get_string)
// get_u8              → read_byte                 (alias: get_u8)
// get_u16             → read_word                 (alias: get_u16)
// get_u32             → read_dword                (alias: get_u32)
// get_u64             → read_qword               (alias: get_u64)
// get_global_value    → read_global_variable      (alias: get_global_value)
// int_convert         → convert_number            (alias: int_convert)
// table_scan          → scan_memory_table         (alias: table_scan)
//
// === Search ===
// find_bytes          → search_bytes              (alias: find_bytes)
// search              → search_text               (alias: search)
// strings + find_string + analyze_strings → list_strings
//   (aliases: strings, find_string, analyze_strings — 3 merged into 1)
// find_insns          → search_instructions       (alias: find_insns)
// find_insn_operands  → search_instruction_operands (alias: find_insn_operands)
//
// === Metadata ===
// segments            → list_segments             (alias: segments)
// addr_info           → get_address_info          (alias: addr_info)
// imports             → list_imports              (alias: imports)
// exports             → list_exports              (alias: exports)
// export_funcs        → export_functions          (alias: export_funcs)
// entrypoints         → list_entry_points         (alias: entrypoints)
// list_globals        → UNCHANGED
//
// === Types / Structs ===
// local_types         → list_local_types          (alias: local_types)
// declare_type        → declare_c_type            (alias: declare_type)
// apply_types         → apply_type                (alias: apply_types)
// infer_types         → infer_type                (alias: infer_types)
// stack_frame         → get_stack_frame           (alias: stack_frame)
// declare_stack       → create_stack_variable      (alias: declare_stack)
// delete_stack        → delete_stack_variable      (alias: delete_stack)
// structs             → list_structs              (alias: structs)
// struct_info         → get_struct_info           (alias: struct_info)
// read_struct         → read_struct_at_address     (alias: read_struct)
// search_structs      → UNCHANGED
//
// === Editing ===
// rename              → rename_symbol              (alias: rename)
// rename_lvar         → rename_local_variable      (alias: rename_lvar)
// set_lvar_type       → set_local_variable_type    (alias: set_lvar_type)
// set_comments        → set_comment                (alias: set_comments)
// set_decompiler_comment → UNCHANGED
// patch               → patch_bytes                (alias: patch)
// patch_asm           → patch_assembly             (alias: patch_asm)
//
// === Scripting ===
// run_script          → UNCHANGED
//
// Summary: 49 renames, 20 unchanged, 3 merged into list_strings
// Net count: 69 - 1 (list_funcs removed) - 2 (strings merged) = 66 + 7 new = 73 total
// =============================================================================

/// Static registry of all tools
pub static TOOL_REGISTRY: &[ToolInfo] = &[
    // === CORE (always available) ===
    ToolInfo {
        name: "open_idb",
        category: ToolCategory::Core,
        short_desc: "Open an IDA database or raw binary",
        full_desc: "Open an IDA Pro database file or a raw binary for analysis. \
                    Supports .i64 (64-bit) and .idb (32-bit) databases, as well as raw binaries \
                    like Mach-O/ELF/PE. Raw binaries are auto-analyzed and saved as .i64 alongside the input. \
                    If opening a raw binary with no existing .i64 and a sibling .dSYM is present, \
                    its DWARF debug info is loaded automatically. \
                    Set load_debug_info=true to force loading external debug info after open \
                    (optionally specify debug_info_path). \
                    The database must be opened before using any other analysis tools. \
                    Call close_idb when finished to release database locks; in multi-client servers, coordinate before closing. \
                    In HTTP/SSE mode, open_idb returns a close_token that must be provided to close_idb. \
                    Returns metadata about the binary: file type, processor, bitness, function count.",
        example: r#"{"path": "/path/to/binary", "load_debug_info": true}"#,
        default: true,
        keywords: &["open", "load", "database", "binary", "idb", "i64", "macho", "elf", "pe"],
        aliases: &[],
    },
    ToolInfo {
        name: "open_dsc",
        category: ToolCategory::Core,
        short_desc: "Open a dyld_shared_cache and load one module; use dsc_add_dylib/dsc_add_region for more",
        full_desc: "Open an Apple dyld_shared_cache file and extract a single dylib for analysis. \
                    Handles DSC-specific loader selection and dscu plugin orchestration automatically. \
                    After opening, runs ObjC type and block analysis on the loaded module. \
                    Use this instead of open_idb when working with dyld_shared_cache files. \
                    Optionally load additional frameworks to resolve cross-module references. \
                    To load more code modules after the initial open, call dsc_add_dylib. \
                    To load additional data/GOT/stub regions by address, call dsc_add_region.",
        example: r#"{"path": "/path/to/dyld_shared_cache_arm64e", "arch": "arm64e", "module": "/usr/lib/libobjc.A.dylib", "frameworks": ["/System/Library/Frameworks/Foundation.framework/Foundation"]}"#,
        default: false,
        keywords: &[
            "open", "dsc", "dyld", "shared", "cache", "dylib", "module", "region", "apple",
            "macos", "ios",
        ],
        aliases: &[],
    },
    ToolInfo {
        name: "open_sbpf",
        category: ToolCategory::Core,
        short_desc: "Open a Solana sBPF program (.so) for analysis",
        full_desc: "AOT-compile a Solana sBPF .so to a host-native shared library via sbpf2host, \
                    then open it in IDA Pro with full Hex-Rays decompilation support. \
                    IDA has no native Hex-Rays decompiler for sBPF; this conversion step is required \
                    for decompile/pseudocode/callgraph tools to work on Solana program code. \
                    Debug symbols (.dSYM) produced by sbpf2host are loaded automatically. \
                    Requires sbpf2host (cargo install sbpf2host) or SBPF2HOST env var. \
                    Returns the same db_handle and close_token as open_idb.",
        example: r#"{"path": "~/programs/675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8.so"}"#,
        default: false,
        keywords: &["open", "solana", "sbpf", "bpf", "program", "so", "sbpf2host", "aot", "compile"],
        aliases: &[],
    },
    ToolInfo {
        name: "dsc_add_dylib",
        category: ToolCategory::Core,
        short_desc: "Load an additional dylib into an open DSC database (light analysis only)",
        full_desc: "Incrementally load a single dylib into a database previously opened via open_dsc. \
                    Uses the dscu plugin to add the module, then runs ObjC type analysis. \
                    Skips full auto-analysis to keep the operation fast. \
                    Call once per module; then check analysis_status. \
                    If auto_is_ok is false, run analyze_funcs before relying on xrefs/decompile. \
                    Requires: database opened via open_dsc.",
        example: r#"{"module": "/System/Library/Frameworks/Foundation.framework/Foundation", "timeout_secs": 300}"#,
        default: false,
        keywords: &["dsc", "dyld", "dylib", "module", "load", "add", "framework", "cache"],
        aliases: &[],
    },
    ToolInfo {
        name: "dsc_add_region",
        category: ToolCategory::Core,
        short_desc: "Load a DSC memory region by address (data/GOT/stubs)",
        full_desc: "Incrementally load a specific region from the currently open DSC database by address. \
                    Accepts exactly one address per call. \
                    Uses the dscu plugin region mode for on-demand data/GOT/stub loading. \
                    This does not force full auto-analysis; check analysis_status and run analyze_funcs \
                    when deeper cross-reference/decompile fidelity is required after loading. \
                    Requires: database opened via open_dsc.",
        example: r#"{"address": "0x180116000", "timeout_secs": 300}"#,
        default: false,
        keywords: &[
            "dsc",
            "dyld",
            "region",
            "memory",
            "address",
            "got",
            "stubs",
            "data",
            "load",
        ],
        aliases: &[],
    },
    ToolInfo {
        name: "load_debug_info",
        category: ToolCategory::Core,
        short_desc: "Load external debug info (e.g., dSYM/DWARF)",
        full_desc: "Load external debug info (e.g., DWARF from a dSYM) into the current database. \
                    If path is omitted, attempts to locate a sibling .dSYM for the currently-open database. \
                    Returns whether the load succeeded.",
        example: r#"{"path": "/path/to/binary.dSYM/Contents/Resources/DWARF/binary"}"#,
        default: false,
        keywords: &["debug", "dwarf", "dsym", "symbols", "load"],
        aliases: &[],
    },
    ToolInfo {
        name: "get_analysis_status",
        category: ToolCategory::Core,
        short_desc: "Report auto-analysis status",
        full_desc: "Report auto-analysis status (auto_is_ok, auto_state) so clients can \
                    determine whether analysis-dependent tools like xrefs or decompile are fully ready.",
        example: r#"{}"#,
        default: true,
        keywords: &["analysis", "autoanalysis", "status", "xrefs", "decompile"],
        aliases: &["analysis_status"],
    },
    ToolInfo {
        name: "close_idb",
        category: ToolCategory::Core,
        short_desc: "Close the current database (release locks)",
        full_desc: "Close the currently open IDA database, releasing resources. \
                    Call this when done with analysis or before opening a different database. \
                    In multi-client servers, coordinate before closing to avoid interrupting others. \
                    In HTTP/SSE mode, provide the close_token returned by open_idb.",
        example: r#"{"close_token": "token-from-open-idb"}"#,
        default: true,
        keywords: &["close", "unload", "database"],
        aliases: &[],
    },
    ToolInfo {
        name: "tool_catalog",
        category: ToolCategory::Core,
        short_desc: "Discover available tools by query or category",
        full_desc: "Search for relevant tools based on what you're trying to accomplish. \
                    Returns tool names with short descriptions and relevance reasons. \
                    Use this to find the right tool before calling tool_help for full details.",
        example: r#"{"query": "find all callers of a function"}"#,
        default: true,
        keywords: &["discover", "find", "search", "tools", "help", "catalog"],
        aliases: &[],
    },
    ToolInfo {
        name: "tool_help",
        category: ToolCategory::Core,
        short_desc: "Get full documentation for a tool",
        full_desc: "Returns complete documentation for a specific tool including: \
                    full description, parameter schema, and example invocation. \
                    Use tool_catalog first to find the tool name.",
        example: r#"{"name": "list_functions"}"#,
        default: true,
        keywords: &["help", "docs", "documentation", "schema", "usage"],
        aliases: &[],
    },
    ToolInfo {
        name: "get_task_status",
        category: ToolCategory::Core,
        short_desc: "Check status of a background task (e.g. DSC loading)",
        full_desc: "Check the status of a background task started by open_dsc. \
                    Returns 'running' (with progress message), 'completed' (with db_info — \
                    database is already open and ready for analysis), or 'failed' (with error). \
                    Use the task_id returned by open_dsc when a new .i64 must be created.",
        example: r#"{"task_id": "dsc-abc123"}"#,
        default: true,
        keywords: &["task", "status", "poll", "background", "dsc", "progress"],
        aliases: &["task_status"],
    },
    ToolInfo {
        name: "get_database_info",
        category: ToolCategory::Core,
        short_desc: "Get database metadata and summary",
        full_desc: "Returns metadata about the currently open database: \
                    file type, processor architecture, bitness, entry points, \
                    segment count, function count, and other summary info.",
        example: r#"{}"#,
        default: true,
        keywords: &["info", "metadata", "summary", "database", "binary"],
        aliases: &["idb_meta"],
    },

    // === FUNCTIONS ===
    ToolInfo {
        name: "list_functions",
        category: ToolCategory::Functions,
        short_desc: "List functions with pagination and filtering",
        full_desc: "List all functions in the database with optional name filtering. \
                    Supports pagination via offset/limit. Returns function address, name, and size. \
                    Use filter parameter to search by substring in function name.",
        example: r#"{"offset": 0, "limit": 100, "filter": "init"}"#,
        default: false,
        keywords: &["functions", "list", "enumerate", "find", "filter", "subroutines"],
        aliases: &["list_funcs"],
    },
    ToolInfo {
        name: "get_function_by_name",
        category: ToolCategory::Functions,
        short_desc: "Find function address by name",
        full_desc: "Resolve a function name to its address. Supports exact names and demangled names. \
                    Returns the function's address, full name, and size if found.",
        example: r#"{"name": "main"}"#,
        default: false,
        keywords: &["resolve", "find", "lookup", "function", "name", "address"],
        aliases: &["resolve_function"],
    },
    ToolInfo {
        name: "get_function_prototype",
        category: ToolCategory::Functions,
        short_desc: "Get the type/prototype declaration of a function",
        full_desc: "Retrieve the type declaration (prototype string) for a function. \
                    Uses IDA's type system to extract the C prototype. \
                    Returns: address, prototype string, type kind.",
        example: r#"{"address": "0x100000f00"}"#,
        default: false,
        keywords: &["prototype", "type", "function", "declaration", "signature"],
        aliases: &[],
    },
    ToolInfo {
        name: "get_function_at_address",
        category: ToolCategory::Functions,
        short_desc: "Find the function containing an address",
        full_desc: "Return the function that contains the given address, including start/end and size. \
                    Useful for mapping PC/LR to a function.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["function", "address", "pc", "lr", "containing"],
        aliases: &["function_at"],
    },
    ToolInfo {
        name: "batch_lookup_functions",
        category: ToolCategory::Functions,
        short_desc: "Batch lookup multiple functions by name",
        full_desc: "Look up multiple function names at once. Returns address and size for each found function. \
                    More efficient than multiple get_function_by_name calls.",
        example: r#"{"names": ["main", "printf", "malloc"]}"#,
        default: false,
        keywords: &["lookup", "batch", "multiple", "functions", "names"],
        aliases: &["lookup_funcs"],
    },
    ToolInfo {
        name: "run_auto_analysis",
        category: ToolCategory::Functions,
        short_desc: "Run auto-analysis and wait for completion",
        full_desc: "Run IDA auto-analysis and wait for completion. \
                    Returns whether analysis completed and current function count.",
        example: r#"{"timeout_secs": 120}"#,
        default: false,
        keywords: &["analyze", "functions", "analysis", "auto"],
        aliases: &["analyze_funcs"],
    },

    // === DISASSEMBLY ===
    ToolInfo {
        name: "disassemble",
        category: ToolCategory::Disassembly,
        short_desc: "Disassemble instructions at an address",
        full_desc: "Disassemble machine code starting at the given address. \
                    Returns assembly instructions with addresses and opcodes. \
                    Specify count to control how many instructions to disassemble.",
        example: r#"{"address": "0x1000", "count": 20}"#,
        default: false,
        keywords: &["disassemble", "disasm", "assembly", "instructions", "code"],
        aliases: &["disasm"],
    },
    ToolInfo {
        name: "disassemble_function",
        category: ToolCategory::Disassembly,
        short_desc: "Disassemble a function by name",
        full_desc: "Disassemble a function given its name. Resolves the name to an address \
                    and disassembles the specified number of instructions.",
        example: r#"{"name": "main", "count": 50}"#,
        default: false,
        keywords: &["disassemble", "function", "name", "assembly"],
        aliases: &["disasm_by_name"],
    },
    ToolInfo {
        name: "disassemble_function_at",
        category: ToolCategory::Disassembly,
        short_desc: "Disassemble the function containing an address",
        full_desc: "Disassemble the function that contains the provided address. \
                    Useful when you only have a PC/LR.",
        example: r#"{"address": "0x1000", "count": 200}"#,
        default: false,
        keywords: &["disassemble", "function", "address", "pc", "lr"],
        aliases: &["disasm_function_at"],
    },

    // === DECOMPILE ===
    ToolInfo {
        name: "decompile_function",
        category: ToolCategory::Decompile,
        short_desc: "Decompile function to C pseudocode",
        full_desc: "Decompile a function using Hex-Rays decompiler (if available). \
                    Returns C-like pseudocode. Accepts address or function name.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["decompile", "pseudocode", "c", "source", "hex-rays"],
        aliases: &["decompile"],
    },
    ToolInfo {
        name: "get_pseudocode_at",
        category: ToolCategory::Decompile,
        short_desc: "Get pseudocode for specific address/range",
        full_desc: "Get decompiled pseudocode for a specific address or address range (e.g., a basic block). \
                    Unlike decompile_function which returns the full function, this returns only statements \
                    corresponding to the given address(es).",
        example: r#"{"address": "0x1000", "end_address": "0x1020"}"#,
        default: false,
        keywords: &["pseudocode", "decompile", "block", "range", "statement"],
        aliases: &["pseudocode_at"],
    },
    ToolInfo {
        name: "decompile_structured",
        category: ToolCategory::Decompile,
        short_desc: "Decompile function to structured AST (ctree JSON)",
        full_desc: "Decompile a function and return the Hex-Rays ctree as structured JSON. \
                    Each node has an 'op' field (if/while/call/asg/add/var/num/...) with \
                    recursive children. Includes local variables with types and function signature. \
                    Useful for programmatic analysis rather than reading pseudocode text.",
        example: r#"{"address": "0x1000", "max_depth": 20, "include_types": true}"#,
        default: false,
        keywords: &[
            "decompile",
            "structured",
            "ast",
            "ctree",
            "json",
            "hex-rays",
            "tree",
        ],
        aliases: &[],
    },
    ToolInfo {
        name: "batch_decompile",
        category: ToolCategory::Decompile,
        short_desc: "Decompile multiple functions at once",
        full_desc: "Decompile multiple functions in a single call. Accepts an array of addresses \
                    (hex strings or numbers). Returns pseudocode for each address, with success/error \
                    status per entry. Useful for bulk analysis without repeated round-trips.",
        example: r#"{"addresses": ["0x1000", "0x2000", "0x3000"]}"#,
        default: false,
        keywords: &["decompile", "batch", "multiple", "bulk", "pseudocode"],
        aliases: &[],
    },
    ToolInfo {
        name: "search_pseudocode",
        category: ToolCategory::Search,
        short_desc: "Search decompiled pseudocode for a text pattern",
        full_desc: "Iterate over all functions, decompile each, and return those whose pseudocode \
                    contains the given pattern (case-sensitive substring match). No regex crate used. \
                    Returns matching function addresses, names, and full pseudocode. \
                    Use limit to cap results and timeout_secs to bound execution time.",
        example: r#"{"pattern": "malloc", "limit": 10}"#,
        default: false,
        keywords: &["search", "pseudocode", "decompile", "pattern", "find", "grep"],
        aliases: &[],
    },
    ToolInfo {
        name: "scan_memory_table",
        category: ToolCategory::Memory,
        short_desc: "Scan a memory table by reading entries at stride intervals",
        full_desc: "Read memory at a base address, stepping by stride bytes for count entries. \
                    Useful for scanning vtables, function pointer tables, or any regular-stride \
                    data structure. Returns hex bytes for each entry. Default stride is 8 bytes \
                    (pointer size on 64-bit), max count is 256.",
        example: r#"{"base_address": "0x1000", "stride": 8, "count": 16}"#,
        default: false,
        keywords: &["table", "scan", "memory", "vtable", "pointer", "stride", "bytes"],
        aliases: &["table_scan"],
    },
    ToolInfo {
        name: "diff_pseudocode",
        category: ToolCategory::Decompile,
        short_desc: "Diff two functions' decompiled pseudocode line by line",
        full_desc: "Decompile two functions and produce a line-by-line diff of their pseudocode. \
                    Lines prefixed with ' ' are identical, '-' only in function1, '+' only in function2. \
                    Returns similarity_ratio (0.0-1.0), full pseudocode for both, and diff_lines array. \
                    No external diff crate used - pure std comparison.",
        example: r#"{"addr1": "0x1000", "addr2": "0x2000"}"#,
        default: false,
        keywords: &["diff", "compare", "functions", "decompile", "pseudocode", "similarity"],
        aliases: &["diff_functions"],
    },

    // === XREFS ===
    ToolInfo {
        name: "get_xrefs_to",
        category: ToolCategory::Xrefs,
        short_desc: "Find all references TO an address",
        full_desc: "Find all cross-references pointing to the given address. \
                    Shows what code/data references this location. \
                    Useful for finding callers, data usage, etc.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["xrefs", "references", "to", "callers", "usage"],
        aliases: &["xrefs_to"],
    },
    ToolInfo {
        name: "get_xrefs_from",
        category: ToolCategory::Xrefs,
        short_desc: "Find all references FROM an address",
        full_desc: "Find all cross-references originating from the given address. \
                    Shows what this instruction/data references. \
                    Useful for finding callees, data accesses, etc.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["xrefs", "references", "from", "callees", "targets"],
        aliases: &["xrefs_from"],
    },
    ToolInfo {
        name: "get_xrefs_to_string",
        category: ToolCategory::Xrefs,
        short_desc: "Find xrefs to strings matching a query",
        full_desc: "Find strings that match a query and return xrefs to each match. \
                    Useful for 'xref to cstring' workflows.",
        example: r#"{"query": "value=%d", "limit": 10}"#,
        default: false,
        keywords: &["xrefs", "strings", "cstring", "references", "usage"],
        aliases: &["xrefs_to_string"],
    },
    ToolInfo {
        name: "build_xref_matrix",
        category: ToolCategory::Xrefs,
        short_desc: "Build xref matrix between addresses",
        full_desc: "Build a cross-reference matrix showing relationships between multiple addresses. \
                    Returns a boolean matrix indicating which addresses reference which others.",
        example: r#"{"addresses": ["0x1000", "0x2000", "0x3000"]}"#,
        default: false,
        keywords: &["xrefs", "matrix", "relationships", "graph"],
        aliases: &["xref_matrix"],
    },

    // === CONTROL FLOW ===
    ToolInfo {
        name: "get_basic_blocks",
        category: ToolCategory::ControlFlow,
        short_desc: "Get basic blocks of a function",
        full_desc: "Get the control flow graph basic blocks for a function. \
                    Returns block addresses, sizes, and successor relationships.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["basic", "blocks", "cfg", "control", "flow", "graph"],
        aliases: &["basic_blocks"],
    },
    ToolInfo {
        name: "get_callers",
        category: ToolCategory::ControlFlow,
        short_desc: "Find all callers of a function",
        full_desc: "Find all functions that call the specified function. \
                    Returns caller addresses and names.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["callers", "called", "by", "references", "xrefs"],
        aliases: &["callers"],
    },
    ToolInfo {
        name: "get_callees",
        category: ToolCategory::ControlFlow,
        short_desc: "Find all functions called by a function",
        full_desc: "Find all functions that are called by the specified function. \
                    Returns callee addresses and names.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["callees", "calls", "targets", "functions"],
        aliases: &["callees"],
    },
    ToolInfo {
        name: "build_callgraph",
        category: ToolCategory::ControlFlow,
        short_desc: "Build call graph from a function",
        full_desc: "Build a call graph starting from a function, exploring callers/callees \
                    up to the specified depth. Returns nodes and edges.",
        example: r#"{"roots": "0x1000", "max_depth": 2, "max_nodes": 256}"#,
        default: false,
        keywords: &["callgraph", "call", "graph", "depth", "tree"],
        aliases: &["callgraph"],
    },
    ToolInfo {
        name: "find_control_flow_paths",
        category: ToolCategory::ControlFlow,
        short_desc: "Find control-flow paths between two addresses",
        full_desc: "Find control-flow paths between two addresses within the same function. \
                    Returns all paths up to max_depth. Both addresses must be in the same function.",
        example: r#"{"start": "0x1000", "end": "0x2000", "max_depth": 5}"#,
        default: false,
        keywords: &["paths", "route", "flow", "between", "reach"],
        aliases: &["find_paths"],
    },

    // === MEMORY ===
    ToolInfo {
        name: "read_bytes",
        category: ToolCategory::Memory,
        short_desc: "Read raw bytes from an address",
        full_desc: "Read raw bytes from the database at the specified address. \
                    Returns bytes as hex string. Useful for examining data. \
                    You can also supply a symbol/function name with an optional offset.",
        example: r#"{"name": "interesting_function", "offset": 0, "size": 32}"#,
        default: false,
        keywords: &["bytes", "read", "memory", "data", "raw", "hex"],
        aliases: &["get_bytes"],
    },
    ToolInfo {
        name: "read_string",
        category: ToolCategory::Memory,
        short_desc: "Read string at an address",
        full_desc: "Read a null-terminated string at the specified address. \
                    Supports C strings and other string types recognized by IDA.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["string", "read", "text", "ascii", "data"],
        aliases: &["get_string"],
    },
    ToolInfo {
        name: "read_byte",
        category: ToolCategory::Memory,
        short_desc: "Read 8-bit value",
        full_desc: "Read an unsigned 8-bit value (byte) at the specified address.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["byte", "u8", "read", "value"],
        aliases: &["get_u8"],
    },
    ToolInfo {
        name: "read_word",
        category: ToolCategory::Memory,
        short_desc: "Read 16-bit value",
        full_desc: "Read an unsigned 16-bit value (word) at the specified address.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["word", "u16", "read", "value"],
        aliases: &["get_u16"],
    },
    ToolInfo {
        name: "read_dword",
        category: ToolCategory::Memory,
        short_desc: "Read 32-bit value",
        full_desc: "Read an unsigned 32-bit value (dword) at the specified address.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["dword", "u32", "read", "value"],
        aliases: &["get_u32"],
    },
    ToolInfo {
        name: "read_qword",
        category: ToolCategory::Memory,
        short_desc: "Read 64-bit value",
        full_desc: "Read an unsigned 64-bit value (qword) at the specified address.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["qword", "u64", "read", "value"],
        aliases: &["get_u64"],
    },
    ToolInfo {
        name: "read_global_variable",
        category: ToolCategory::Memory,
        short_desc: "Read global value by name or address",
        full_desc: "Read a global value by name or address. Returns value and raw bytes.",
        example: r#"{"query": "g_flag"}"#,
        default: false,
        keywords: &["global", "value", "read", "symbol", "data"],
        aliases: &["get_global_value"],
    },
    ToolInfo {
        name: "convert_number",
        category: ToolCategory::Memory,
        short_desc: "Convert integers between bases",
        full_desc: "Convert integers between decimal/hex/binary and show ASCII bytes when possible.",
        example: r#"{"inputs": ["0x41424344", 1234]}"#,
        default: false,
        keywords: &["int", "convert", "hex", "decimal", "ascii"],
        aliases: &["int_convert"],
    },

    // === SEARCH ===
    ToolInfo {
        name: "search_bytes",
        category: ToolCategory::Search,
        short_desc: "Search for byte pattern",
        full_desc: "Search for a byte pattern in the database. Supports wildcards. \
                    Returns all matching addresses up to the limit.",
        example: r#"{"pattern": "48 89 5C 24", "limit": 100}"#,
        default: false,
        keywords: &["find", "search", "bytes", "pattern", "hex"],
        aliases: &["find_bytes"],
    },
    ToolInfo {
        name: "search_text",
        category: ToolCategory::Search,
        short_desc: "Search for text or immediate values",
        full_desc: "General search tool. Searches for text strings or immediate values \
                    in instructions. Use search_bytes for byte-pattern searches.",
        example: r#"{"targets": "password", "kind": "text"}"#,
        default: false,
        keywords: &["search", "find", "text", "string", "immediate"],
        aliases: &["search"],
    },
    ToolInfo {
        name: "list_strings",
        category: ToolCategory::Search,
        short_desc: "List all strings in the database",
        full_desc: "List strings found in the database with pagination and optional \
                    substring filter (filter/query). Returns address and content.",
        example: r#"{"offset": 0, "limit": 100, "filter": "http"}"#,
        default: false,
        keywords: &["strings", "list", "text", "data"],
        aliases: &["strings", "find_string", "analyze_strings"],
    },
    ToolInfo {
        name: "search_instructions",
        category: ToolCategory::Search,
        short_desc: "Find instruction sequences by mnemonic",
        full_desc: "Search for instruction mnemonic patterns. If patterns is an array, matches \
                    contiguous sequences. Each pattern matches the mnemonic substring unless it \
                    contains whitespace or commas (then full line match).",
        example: r#"{"patterns": ["mov", "bl"], "limit": 5}"#,
        default: false,
        keywords: &["find", "instructions", "sequence", "pattern"],
        aliases: &["find_insns"],
    },
    ToolInfo {
        name: "search_instruction_operands",
        category: ToolCategory::Search,
        short_desc: "Find instructions by operand substring",
        full_desc: "Search for instructions whose operand text matches any provided substring. \
                    Returns address, mnemonic, operands, and disasm line.",
        example: r#"{"patterns": ["sp", "0x10"], "limit": 5}"#,
        default: false,
        keywords: &["find", "operands", "instructions", "pattern"],
        aliases: &["find_insn_operands"],
    },

    // === METADATA ===
    ToolInfo {
        name: "list_segments",
        category: ToolCategory::Metadata,
        short_desc: "List all segments",
        full_desc: "List all segments in the database with their addresses, sizes, \
                    names, and permissions (read/write/execute).",
        example: r#"{}"#,
        default: false,
        keywords: &["segments", "sections", "memory", "layout"],
        aliases: &["segments"],
    },
    ToolInfo {
        name: "get_address_info",
        category: ToolCategory::Metadata,
        short_desc: "Resolve address to segment/function/symbol",
        full_desc: "Return address context including segment info, containing function, \
                    and nearest named symbol.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["address", "segment", "function", "symbol", "context"],
        aliases: &["addr_info"],
    },
    ToolInfo {
        name: "list_imports",
        category: ToolCategory::Metadata,
        short_desc: "List imported functions",
        full_desc: "List all imported external symbols with their addresses and names.",
        example: r#"{"offset": 0, "limit": 100}"#,
        default: false,
        keywords: &["imports", "external", "libraries", "api"],
        aliases: &["imports"],
    },
    ToolInfo {
        name: "list_exports",
        category: ToolCategory::Metadata,
        short_desc: "List exported functions",
        full_desc: "List all exported functions/symbols with their addresses and names.",
        example: r#"{"offset": 0, "limit": 100}"#,
        default: false,
        keywords: &["exports", "symbols", "public", "api"],
        aliases: &["exports"],
    },
    ToolInfo {
        name: "export_functions",
        category: ToolCategory::Metadata,
        short_desc: "Export functions (JSON)",
        full_desc: "Export functions in JSON format. If addrs is provided, only export those functions.",
        example: r#"{"addrs": ["0x1000", "0x2000"], "format": "json"}"#,
        default: false,
        keywords: &["export", "functions", "json", "dump"],
        aliases: &["export_funcs"],
    },
    ToolInfo {
        name: "list_entry_points",
        category: ToolCategory::Metadata,
        short_desc: "List entry points",
        full_desc: "List all entry points in the binary (main, DllMain, etc.).",
        example: r#"{}"#,
        default: false,
        keywords: &["entry", "start", "main", "entrypoint"],
        aliases: &["entrypoints"],
    },
    ToolInfo {
        name: "list_globals",
        category: ToolCategory::Metadata,
        short_desc: "List global variables",
        full_desc: "List global variables and data items with their addresses, names, and types.",
        example: r#"{"offset": 0, "limit": 100}"#,
        default: false,
        keywords: &["globals", "variables", "data", "symbols"],
        aliases: &[],
    },

    // === TYPES / STRUCTS ===
    ToolInfo {
        name: "list_local_types",
        category: ToolCategory::Types,
        short_desc: "List local types",
        full_desc: "List local types (typedefs, enums, structs, etc.) with pagination and optional filter.",
        example: r#"{"query": "struct", "limit": 50}"#,
        default: false,
        keywords: &["types", "local", "typedef"],
        aliases: &["local_types"],
    },
    ToolInfo {
        name: "get_xrefs_to_struct_field",
        category: ToolCategory::Xrefs,
        short_desc: "Xrefs to a struct field",
        full_desc: "Get cross-references to a struct field by struct name/ordinal and member name/index.",
        example: r#"{"name": "Outer", "member_name": "inner", "limit": 25}"#,
        default: false,
        keywords: &["xrefs", "struct", "field", "member"],
        aliases: &["xrefs_to_field"],
    },
    ToolInfo {
        name: "declare_c_type",
        category: ToolCategory::Types,
        short_desc: "Declare a type in the local type library",
        full_desc: "Parse a C declaration and store it in the local type library (optionally replacing existing).",
        example: r#"{"decl": "typedef int mcp_int_t;", "replace": true}"#,
        default: false,
        keywords: &["type", "declare", "typedef"],
        aliases: &["declare_type"],
    },
    ToolInfo {
        name: "apply_type",
        category: ToolCategory::Types,
        short_desc: "Apply a type to an address or stack variable",
        full_desc: "Apply a named type or C declaration to an address/symbol. \
                    For stack vars, provide stack_offset or stack_name plus decl.",
        example: r#"{"name": "interesting_function", "stack_offset": -16, "decl": "int mcp_local;"}"#,
        default: false,
        keywords: &["types", "apply", "annotations"],
        aliases: &["apply_types"],
    },
    ToolInfo {
        name: "infer_type",
        category: ToolCategory::Types,
        short_desc: "Infer/guess type at an address",
        full_desc: "Guess a type for an address or symbol using IDA's heuristics.",
        example: r#"{"name": "interesting_function"}"#,
        default: false,
        keywords: &["types", "infer", "analysis"],
        aliases: &["infer_types"],
    },
    ToolInfo {
        name: "get_stack_frame",
        category: ToolCategory::Types,
        short_desc: "Get stack frame info",
        full_desc: "Get stack frame layout for the function at an address, including \
                    args/locals ranges and per-member type info.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["stack", "frame", "locals"],
        aliases: &["stack_frame"],
    },
    ToolInfo {
        name: "create_stack_variable",
        category: ToolCategory::Types,
        short_desc: "Declare a stack variable",
        full_desc: "Define a stack variable in a function frame using a C declaration. \
                    Provide function address/name and stack offset (negative for locals).",
        example: r#"{"name": "interesting_function", "offset": -16, "var_name": "mcp_local", "decl": "int mcp_local;"}"#,
        default: false,
        keywords: &["stack", "declare", "variable"],
        aliases: &["declare_stack"],
    },
    ToolInfo {
        name: "delete_stack_variable",
        category: ToolCategory::Types,
        short_desc: "Delete a stack variable",
        full_desc: "Delete a stack variable by name or offset in a function frame.",
        example: r#"{"name": "interesting_function", "offset": -16}"#,
        default: false,
        keywords: &["stack", "delete", "variable"],
        aliases: &["delete_stack"],
    },
    ToolInfo {
        name: "list_enums",
        category: ToolCategory::Types,
        short_desc: "List all enum types in the database",
        full_desc: "List all enum type definitions in the IDA local types database. \
                    Returns each enum name and C declaration. \
                    Supports filtering by name substring and pagination.",
        example: r#"{"filter": "Error", "limit": 20}"#,
        default: false,
        keywords: &["enum", "types", "local", "list", "names"],
        aliases: &[],
    },
    ToolInfo {
        name: "create_enum",
        category: ToolCategory::Types,
        short_desc: "Create an enum type from a C declaration",
        full_desc: "Create a new enum type in the IDA local types database from a C declaration string. \
                    Example: \"enum ErrorCode { OK = 0, ERR_INVALID = 1, ERR_OVERFLOW = 2 };\". \
                    Use list_enums to verify. Use declare_c_type for structs.",
        example: r#"{"decl": "enum SwapResult { SWAP_OK = 0, SWAP_ERR_SLIPPAGE = 1, SWAP_ERR_FUNDS = 2 };"}"#,
        default: false,
        keywords: &["enum", "create", "type", "declare", "define"],
        aliases: &[],
    },
    ToolInfo {
        name: "list_structs",
        category: ToolCategory::Types,
        short_desc: "List structs with pagination",
        full_desc: "List structs (UDTs) in the database with optional name filtering.",
        example: r#"{"limit": 50, "filter": "objc"}"#,
        default: false,
        keywords: &["structs", "types", "list"],
        aliases: &["structs"],
    },
    ToolInfo {
        name: "get_struct_info",
        category: ToolCategory::Types,
        short_desc: "Get struct info by name or ordinal",
        full_desc: "Get struct details including member layout and sizes.",
        example: r#"{"name": "MyStruct"}"#,
        default: false,
        keywords: &["struct", "info", "types"],
        aliases: &["struct_info"],
    },
    ToolInfo {
        name: "read_struct_at_address",
        category: ToolCategory::Types,
        short_desc: "Read a struct instance at an address",
        full_desc: "Read raw bytes for each struct member at a given address.",
        example: r#"{"address": "0x1000", "name": "MyStruct"}"#,
        default: false,
        keywords: &["struct", "read", "values"],
        aliases: &["read_struct"],
    },
    ToolInfo {
        name: "search_structs",
        category: ToolCategory::Types,
        short_desc: "Search structs by name",
        full_desc: "Search for structs by name with optional filter and pagination. \
                    Returns the same structure list output as structs.",
        example: r#"{"query": "my_struct", "limit": 20}"#,
        default: false,
        keywords: &["struct", "search", "types"],
        aliases: &[],
    },

    // === EDITING / PATCHING ===
    ToolInfo {
        name: "set_comment",
        category: ToolCategory::Editing,
        short_desc: "Set comments at an address",
        full_desc: "Set a non-repeatable or repeatable comment at an address. \
                    Empty string clears the comment. You can also supply a symbol/function name \
                    with an optional offset.",
        example: r#"{"name": "interesting_function", "comment": "note", "repeatable": false}"#,
        default: false,
        keywords: &["comments", "set", "annotate"],
        aliases: &["set_comments"],
    },
    ToolInfo {
        name: "set_function_comment",
        category: ToolCategory::Editing,
        short_desc: "Set a function-level comment (visible at function entry)",
        full_desc: "Set a comment at the function entry point using IDA's function comment API. \
                    This differs from set_comment (per-address) and set_decompiler_comment (per-decompiler-line). \
                    Function comments are shown in function listings and navigation views.",
        example: r#"{"name": "process_swap", "comment": "Handles swap instruction routing"}"#,
        default: false,
        keywords: &["comment", "function", "annotate", "note"],
        aliases: &[],
    },
    ToolInfo {
        name: "patch_assembly",
        category: ToolCategory::Editing,
        short_desc: "Patch instructions with assembly text",
        full_desc: "Assemble a single instruction line at the target address and patch the bytes. \
                    Requires a processor module with assembler support; may fail on some targets. \
                    You can supply an address or a symbol name with an optional offset.",
        example: r#"{"name": "interesting_function", "offset": 0, "line": "nop"}"#,
        default: false,
        keywords: &["patch", "asm", "edit", "modify"],
        aliases: &["patch_asm"],
    },
    ToolInfo {
        name: "patch_bytes",
        category: ToolCategory::Editing,
        short_desc: "Patch bytes at an address",
        full_desc: "Patch bytes in the database at the given address. \
                    You can also supply a symbol/function name with an optional offset.",
        example: r#"{"name": "interesting_function", "offset": 0, "bytes": "1f 20 03 d5"}"#,
        default: false,
        keywords: &["patch", "bytes", "edit", "modify"],
        aliases: &["patch"],
    },
    ToolInfo {
        name: "rename_symbol",
        category: ToolCategory::Editing,
        short_desc: "Rename symbols",
        full_desc: "Rename a symbol at an address. Optional flags map to IDA set_name flags. \
                    You can also supply the current name instead of an address.",
        example: r#"{"current_name": "interesting_function", "name": "interesting_function_renamed", "flags": 0}"#,
        default: false,
        keywords: &["rename", "symbol", "edit"],
        aliases: &["rename"],
    },
    ToolInfo {
        name: "batch_rename",
        category: ToolCategory::Editing,
        short_desc: "Rename multiple symbols at once",
        full_desc: "Rename multiple symbols in one call. Each entry specifies an address or current name \
                    plus the new name. Results are returned per-entry (success/error). \
                    Useful for leaf-first renaming workflows to reduce round-trips.",
        example: r#"{"renames": [{"address": "0x1000", "new_name": "process_swap"}, {"current_name": "sub_2000", "new_name": "validate_amount"}]}"#,
        default: false,
        keywords: &["rename", "batch", "bulk", "symbol", "multiple"],
        aliases: &[],
    },
    ToolInfo {
        name: "set_function_prototype",
        category: ToolCategory::Editing,
        short_desc: "Apply a C prototype declaration to a function",
        full_desc: "Apply a C function prototype string to a function in the IDA database. \
                    The prototype is parsed and applied using IDA's type system. \
                    Example prototype: \"int __fastcall foo(void *ctx, int len)\"",
        example: r#"{"address": "0x100000f00", "prototype": "int __fastcall process_swap(void *ctx, int amount)"}"#,
        default: false,
        keywords: &[
            "prototype",
            "type",
            "function",
            "set",
            "declaration",
            "signature",
            "apply",
        ],
        aliases: &[],
    },
    ToolInfo {
        name: "rename_local_variable",
        category: ToolCategory::Editing,
        short_desc: "Rename a local variable in decompiled pseudocode",
        full_desc: "Rename a local variable in the Hex-Rays decompiled pseudocode. \
                    Requires Hex-Rays decompiler. The change is persisted to the IDB.",
        example: r#"{"func_address": "0x100000f00", "lvar_name": "v1", "new_name": "buffer_size"}"#,
        default: false,
        keywords: &["rename", "lvar", "local", "variable", "decompiler", "pseudocode"],
        aliases: &["rename_lvar"],
    },
    ToolInfo {
        name: "set_local_variable_type",
        category: ToolCategory::Editing,
        short_desc: "Set the type of a local variable in decompiled pseudocode",
        full_desc: "Change the type of a local variable in the Hex-Rays decompiled pseudocode. \
                    Accepts C type declaration strings (e.g. \"int *\", \"DWORD\"). \
                    Requires Hex-Rays decompiler.",
        example: r#"{"func_address": "0x100000f00", "lvar_name": "v1", "type_str": "char *"}"#,
        default: false,
        keywords: &["type", "lvar", "local", "variable", "decompiler", "pseudocode", "retype"],
        aliases: &["set_lvar_type"],
    },
    ToolInfo {
        name: "rename_stack_variable",
        category: ToolCategory::Editing,
        short_desc: "Rename a stack frame variable in a function",
        full_desc: "Rename a local variable in a function stack frame. \
                    Locates the variable by its current name and renames it. \
                    Requires a valid function address or name.",
        example: r#"{"func_address": "0x100000f00", "name": "var_4", "new_name": "buffer_size"}"#,
        default: false,
        keywords: &["rename", "stack", "variable", "frame", "local"],
        aliases: &[],
    },
    ToolInfo {
        name: "set_stack_variable_type",
        category: ToolCategory::Editing,
        short_desc: "Set the type of a stack frame variable",
        full_desc: "Set the type of a local variable in a function stack frame. \
                    Accepts C type declaration strings (e.g. \"char *\", \"DWORD\", \"void *\"). \
                    Different from set_local_variable_type which works on Hex-Rays variables.",
        example: r#"{"func_address": "0x100000f00", "name": "buffer_size", "type_decl": "int"}"#,
        default: false,
        keywords: &["type", "stack", "variable", "frame", "local", "retype"],
        aliases: &[],
    },
    ToolInfo {
        name: "set_decompiler_comment",
        category: ToolCategory::Editing,
        short_desc: "Set a comment in decompiled pseudocode",
        full_desc: "Attach a comment to a specific address in the Hex-Rays decompiled pseudocode. \
                    Use itp=69 (ITP_SEMI) for end-of-line comments, itp=74 (ITP_BLOCK1) for block comments. \
                    Empty comment string clears an existing comment. Requires Hex-Rays decompiler.",
        example: r#"{"func_address": "0x100000f00", "address": "0x100000f10", "comment": "check buffer size"}"#,
        default: false,
        keywords: &["comment", "decompiler", "pseudocode", "annotate", "hex-rays"],
        aliases: &[],
    },

    // === SCRIPTING ===
    ToolInfo {
        name: "run_script",
        category: ToolCategory::Scripting,
        short_desc: "Execute Python code via IDAPython",
        full_desc: "Execute a Python script via IDAPython in the currently open database. \
                    Provide either 'code' (inline Python) or 'file' (path to a .py file). \
                    Has full access to all ida_* modules (ida_funcs, ida_bytes, ida_segment, etc.), \
                    idc, and idautils. stdout and stderr are captured and returned. \
                    Use this for custom analysis that goes beyond the built-in tools. \
                    Requires that the IDAPython plugin is loaded (available by default in IDA Pro). \
                    API reference: https://python.docs.hex-rays.com",
        example: r#"{"code": "import idautils\nfor f in idautils.Functions():\n    print(hex(f))"}"#,
        default: false,
        keywords: &["script", "python", "execute", "eval", "idapython", "run", "code", "file"],
        aliases: &[],
    },
];

/// Get tools in the default (core) set
pub fn default_tools() -> impl Iterator<Item = &'static ToolInfo> {
    TOOL_REGISTRY.iter().filter(|t| t.default)
}

/// Get all tools
pub fn all_tools() -> impl Iterator<Item = &'static ToolInfo> {
    TOOL_REGISTRY.iter()
}

/// Get tool by name or alias
pub fn get_tool_by_alias(name: &str) -> Option<&'static ToolInfo> {
    TOOL_REGISTRY
        .iter()
        .find(|t| t.name == name || t.aliases.contains(&name))
}

/// Get tool by name (uses alias lookup internally)
pub fn get_tool(name: &str) -> Option<&'static ToolInfo> {
    get_tool_by_alias(name)
}

/// Resolve alias to primary tool name (returns original if not found)
pub fn primary_name_for(name: &str) -> &str {
    match get_tool_by_alias(name) {
        Some(tool) => tool.name,
        None => name,
    }
}

/// Get tools by category
pub fn tools_by_category(category: ToolCategory) -> impl Iterator<Item = &'static ToolInfo> {
    TOOL_REGISTRY.iter().filter(move |t| t.category == category)
}

/// Search tools by query (simple keyword matching)
pub fn search_tools(query: &str, limit: usize) -> Vec<(&'static ToolInfo, Vec<&'static str>)> {
    let query_lower = query.to_lowercase();
    let query_words: Vec<&str> = query_lower.split_whitespace().collect();

    let mut results: Vec<(&'static ToolInfo, Vec<&'static str>, usize)> = Vec::new();

    for tool in TOOL_REGISTRY.iter() {
        let mut matched_keywords = Vec::new();
        let mut score = 0usize;

        // Check tool name
        let name_lower = tool.name.to_lowercase();
        for word in &query_words {
            if name_lower.contains(word) {
                score += 10;
                matched_keywords.push("name match");
            }
        }

        // Check short description
        let desc_lower = tool.short_desc.to_lowercase();
        for word in &query_words {
            if desc_lower.contains(word) {
                score += 5;
            }
        }

        // Check keywords
        for keyword in tool.keywords {
            let kw_lower = keyword.to_lowercase();
            for word in &query_words {
                if kw_lower.contains(word) || word.contains(&kw_lower) {
                    score += 3;
                    if !matched_keywords.contains(keyword) {
                        matched_keywords.push(keyword);
                    }
                }
            }
        }

        // Check aliases
        for alias in tool.aliases {
            let alias_lower = alias.to_lowercase();
            for word in &query_words {
                if alias_lower.contains(word) {
                    score += 8;
                    if !matched_keywords.contains(alias) {
                        matched_keywords.push(alias);
                    }
                }
            }
        }

        // Check category
        let cat_str = tool.category.as_str().to_lowercase();
        for word in &query_words {
            if cat_str.contains(word) {
                score += 2;
                matched_keywords.push(tool.category.as_str());
            }
        }

        if score > 0 {
            results.push((tool, matched_keywords, score));
        }
    }

    // Sort by score descending
    results.sort_by(|a, b| b.2.cmp(&a.2));

    // Return top results
    results
        .into_iter()
        .take(limit)
        .map(|(tool, keywords, _)| (tool, keywords))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tool_registry::*;

    #[test]
    fn test_default_tools() {
        let defaults: Vec<_> = default_tools().collect();
        assert!(defaults.iter().any(|t| t.name == "open_idb"));
        assert!(defaults.iter().any(|t| t.name == "tool_catalog"));
        assert!(defaults.iter().any(|t| t.name == "tool_help"));
        assert!(defaults.iter().any(|t| t.name == "get_database_info"));
    }

    #[test]
    fn test_search_tools() {
        let results = search_tools("find callers function", 5);
        assert!(!results.is_empty());
        // Should find "get_callers" tool
        assert!(results.iter().any(|(t, _)| t.name == "get_callers"));
    }

    #[test]
    fn test_get_tool() {
        assert!(get_tool("disasm").is_some());
        assert!(get_tool("nonexistent").is_none());
    }
}
