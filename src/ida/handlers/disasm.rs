//! Disassembly and decompilation handlers.

use crate::disasm::generate_disasm_line;
use crate::error::ToolError;
use crate::ida::pseudocode_lines;
use crate::ida::types::DecompiledLines;
use idalib::decompiler::CFunction;
use idalib::{Address, IDB};
use serde_json::{json, Value};
use std::collections::HashSet;

pub fn handle_disasm_by_name(
    idb: &Option<IDB>,
    name: &str,
    count: usize,
) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name() {
            if func_name == name || func_name.contains(name) {
                let addr = func.start_address();
                return handle_disasm(idb, addr, count);
            }
        }
    }

    Err(ToolError::FunctionNameNotFound(name.to_string()))
}

pub fn handle_disasm(idb: &Option<IDB>, addr: u64, count: usize) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut lines = Vec::with_capacity(count);
    let mut current_addr: Address = addr;

    for _ in 0..count {
        // Get disassembly line
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            // No more valid instructions
            break;
        }

        // Get instruction at current address to find next
        if let Some(insn) = db.insn_at(current_addr) {
            current_addr += insn.len() as u64;
        } else {
            // Move to next head
            if let Some(next) = db.next_head(current_addr) {
                if next <= current_addr {
                    break; // Prevent infinite loop
                }
                current_addr = next;
            } else {
                break;
            }
        }
    }

    if lines.is_empty() {
        return Err(ToolError::AddressOutOfRange(addr));
    }

    Ok(lines.join("\n"))
}

pub fn handle_disasm_function_at(
    idb: &Option<IDB>,
    addr: u64,
    count: usize,
) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;
    let start = func.start_address();
    let end = func.end_address();

    let mut lines = Vec::new();
    let mut current_addr: Address = start;

    while current_addr < end && lines.len() < count {
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            break;
        }

        if let Some(insn) = db.insn_at(current_addr) {
            current_addr += insn.len() as u64;
        } else if let Some(next) = db.next_head(current_addr) {
            if next <= current_addr {
                break;
            }
            current_addr = next;
        } else {
            break;
        }
    }

    if lines.is_empty() {
        return Err(ToolError::AddressOutOfRange(addr));
    }

    Ok(lines.join("\n"))
}

pub fn handle_decompile(idb: &Option<IDB>, addr: u64) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let cfunc = decompile_at(db, addr)?;

    // Get the pseudocode as string
    Ok(cfunc.pseudocode())
}

/// Decompile the function containing `addr` and pair every pseudocode line
/// with the addresses Hex-Rays anchored to it.
///
/// `code` is the same text `handle_decompile` returns; `lines` are its lines.
pub fn handle_decompile_lines(idb: &Option<IDB>, addr: u64) -> Result<DecompiledLines, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let cfunc = decompile_at(db, addr)?;

    let code = cfunc.pseudocode();
    let plain = cfunc
        .pseudocode_plain_lines()
        .map_err(|e| ToolError::IdaError(e.to_string()))?;
    let tagged = cfunc
        .pseudocode_tagged_lines()
        .map_err(|e| ToolError::IdaError(e.to_string()))?;
    let lines =
        pseudocode_lines::build_lines(plain, &tagged, |index| cfunc.treeitem_address(index))?;
    Ok(DecompiledLines { code, lines })
}

fn decompile_at(db: &IDB, addr: u64) -> Result<CFunction<'_>, ToolError> {
    // Check if decompiler is available
    if !db.decompiler_available() {
        return Err(ToolError::DecompilerUnavailable);
    }

    // Find the function at this address
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    // Decompile function
    db.decompile(&func)
        .map_err(|e| ToolError::IdaError(e.to_string()))
}

/// Search decompiled pseudocode of all functions for a text pattern.
/// Runs entirely on the main thread — no cross-thread overhead per function.
pub fn handle_search_pseudocode(
    idb: &Option<IDB>,
    pattern: &str,
    limit: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    if !db.decompiler_available() {
        return Err(ToolError::DecompilerUnavailable);
    }

    let mut matches = Vec::new();
    let mut total_searched = 0usize;
    let mut errors = 0usize;

    for (_id, func) in db.functions() {
        total_searched += 1;
        let addr = func.start_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));

        match db.decompile(&func) {
            Ok(cfunc) => {
                let pseudocode = cfunc.pseudocode();
                if pseudocode.contains(pattern) {
                    matches.push(json!({
                        "address": format!("{:#x}", addr),
                        "name": name,
                        "pseudocode": pseudocode,
                    }));
                    if matches.len() >= limit {
                        break;
                    }
                }
            }
            Err(_) => {
                errors += 1;
            }
        }
    }

    Ok(json!({
        "pattern": pattern,
        "matches": matches,
        "total_searched": total_searched,
        "decompile_errors": errors,
    }))
}

/// Get decompiled pseudocode statements at a specific address or address range.
pub fn handle_pseudocode_at(
    idb: &Option<IDB>,
    addr: u64,
    end_addr: Option<u64>,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    // Check if decompiler is available
    if !db.decompiler_available() {
        return Err(ToolError::DecompilerUnavailable);
    }

    // Find the function at this address
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    let func_start = func.start_address();
    let func_end = func.end_address();
    let func_name = func
        .name()
        .unwrap_or_else(|| format!("sub_{:x}", func_start));

    // Decompile function
    let cfunc = db
        .decompile(&func)
        .map_err(|e| ToolError::IdaError(e.to_string()))?;

    let eamap_ready = cfunc.has_eamap();

    let mut statements = Vec::new();
    let mut seen_eas = HashSet::new();

    if let Some(end) = end_addr {
        // Range query - collect unique statements that cover any address in [addr, end)
        let mut cur = addr;
        while cur < end {
            if let Some(stmts) = cfunc.statements_at(cur) {
                for stmt in stmts {
                    let stmt_ea = stmt.address();
                    if seen_eas.insert(stmt_ea) {
                        let text = stmt.to_string();
                        let bounds = stmt.bounds();
                        statements.push(json!({
                            "address": format!("{:#x}", stmt_ea),
                            "text": text.trim(),
                            "opcode": stmt.opcode(),
                            "bounds": bounds.map(|b| json!({
                                "start": format!("{:#x}", b.start),
                                "end": format!("{:#x}", b.end),
                            })),
                        }));
                    }
                }
            }
            cur += 1;
        }
    } else {
        // Single address query
        if let Some(stmts) = cfunc.statements_at(addr) {
            for stmt in stmts {
                let stmt_ea = stmt.address();
                if seen_eas.insert(stmt_ea) {
                    let text = stmt.to_string();
                    let bounds = stmt.bounds();
                    statements.push(json!({
                        "address": format!("{:#x}", stmt_ea),
                        "text": text.trim(),
                        "opcode": stmt.opcode(),
                        "bounds": bounds.map(|b| json!({
                            "start": format!("{:#x}", b.start),
                            "end": format!("{:#x}", b.end),
                        })),
                    }));
                }
            }
        }
    }

    Ok(json!({
        "function": {
            "address": format!("{:#x}", func_start),
            "name": func_name,
            "start": format!("{:#x}", func_start),
            "end": format!("{:#x}", func_end),
        },
        "query_address": format!("{:#x}", addr),
        "query_end_address": end_addr.map(|a| format!("{:#x}", a)),
        "eamap_ready": eamap_ready,
        "statements": statements,
        "count": statements.len(),
    }))
}

const DECOMPILE_STRUCTURED_PY: &str = include_str!("../../../scripts/decompile_structured.py");

pub fn decompile_structured_script(
    addr: u64,
    max_depth: u32,
    include_types: bool,
    include_addresses: bool,
) -> String {
    format!(
        "EA = {addr:#x}\nMAX_DEPTH = {max_depth}\nINCLUDE_TYPES = {include_types}\nINCLUDE_ADDRESSES = {include_addresses}\n{body}",
        addr = addr,
        max_depth = max_depth,
        include_types = if include_types { "True" } else { "False" },
        include_addresses = if include_addresses { "True" } else { "False" },
        body = DECOMPILE_STRUCTURED_PY,
    )
}
