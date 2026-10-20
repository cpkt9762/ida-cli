//! Headless IDA CLI and MCP Server
//!
//! This library provides an MCP (Model Context Protocol) server for headless
//! IDA Pro access. It allows LLM agents to open IDA databases, list functions,
//! get disassembly, and decompile code.
//!
//! Database execution runs through the public Nexus Python client.

use std::path::PathBuf;

pub mod attach;
pub mod blocking;
pub mod cli;
pub mod dsc;
pub mod error;
pub mod federation;
pub mod ida;
pub mod idb_store;
/// Explicit, reversible offline maintenance of legacy flat cache groups.
pub mod legacy_cache;
pub mod preprocess;
pub mod process_spawn;
pub mod router;
pub mod rpc_dispatch;
pub mod sbpf;
pub mod server;
pub mod tool_registry;

pub use error::ToolError;
pub use ida::nexus;
pub use ida::{
    AddressInfo, BasicBlockInfo, BytesResult, DbInfo, ExportInfo, FunctionInfo, FunctionListResult,
    FunctionRangeInfo, ImportInfo, SegmentInfo, StringInfo, StringListResult, StringXrefInfo,
    StringXrefsResult, SymbolInfo, WorkerDispatch, XRefInfo,
};
pub use server::IdaMcpServer;
pub use tool_registry::{ToolCategory, ToolInfo, TOOL_REGISTRY};

/// Expand `~/` prefix to the user's home directory.
pub fn expand_path(path: &str) -> PathBuf {
    path.strip_prefix("~/")
        .and_then(|stripped| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(stripped)))
        .unwrap_or_else(|| PathBuf::from(path))
}
