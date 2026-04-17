# CLI Tool Quick Reference

This page mirrors the actual `ida-cli` binary. Anything not listed here as a
direct subcommand has to be sent through `raw` (single request) or `pipe`
(batch of JSON-RPC lines) using the underlying MCP method name.

## Invocation Shapes

When `ida-cli` is launched without `serve` / `serve-http` / `serve-worker` /
`probe-runtime`, it runs in client mode: it locates the local socket (auto
starting a background HTTP/stdio server if none is live) and sends a single
JSON-RPC request.

Global flags (valid on every client subcommand):

- `--path <file>` target binary or `.i64` / `.idb` database
- `--tenant <id>` optional tenant id for fair-sharing quotas
- `--json` force JSON output
- `--compact` single-line compact JSON output
- `--timeout <secs>` per-request timeout, default 120
- `--socket <path>` override the Unix socket location

## Server Subcommands

These are the only arguments that trigger server mode instead of client mode:

```bash
ida-cli serve                           # stdio MCP transport (router mode)
ida-cli serve-http --bind 127.0.0.1:8765
ida-cli serve-worker                    # internal, spawned by the router
ida-cli probe-runtime                   # internal, prints a backend probe JSON
```

## Direct Client Subcommands

```bash
ida-cli --path <file> list-functions [--filter NAME] [--limit 100] [--offset 0]
ida-cli --path <file> decompile --addr 0x1000
ida-cli --path <file> disasm --addr 0x1000 [--count 20]
ida-cli --path <file> disasm --name main [--count 20]
ida-cli --path <file> xrefs-to --addr 0x1000
ida-cli --path <file> list-strings [--query ERROR] [--limit 100]
ida-cli --path <file> list-segments
```

## Service / Queue Subcommands

```bash
ida-cli --path <file> prewarm [--keep-warm] [--queue] [--priority 0]
ida-cli prewarm-many samples.txt [--jobs 4] [--keep-warm] [--queue]

ida-cli --path <file> enqueue <method> [--priority 0] [--dedupe-key KEY] \
        [--federate] [--params '{"limit":50}']
ida-cli task-status <task_id>
ida-cli list-tasks
ida-cli cancel-task <task_id>

ida-cli federation-list
ida-cli federation-register <name> <url> [--weight 1]
ida-cli federation-unregister <name>
ida-cli federation-heartbeat <name> <url> [--weight 1] \
        [--capability CAP ...] [--tenant-allow T ...] [--node-id ID]

ida-cli --path <file> close
ida-cli status
ida-cli shutdown
```

## Everything Else Goes Through `raw` or `pipe`

The direct subcommands cover only the most common reads. For renaming,
commenting, type work, xrefs-from, basic-blocks, call graphs, batch
decompilation, script execution, and so on, dispatch the MCP method name
directly.

```bash
# single request
ida-cli --path <file> raw '{"method":"get_function_by_name","params":{"name":"main"}}'
ida-cli --path <file> raw '{"method":"get_xrefs_from","params":{"address":"0x1000"}}'
ida-cli --path <file> raw '{"method":"rename_symbol","params":{"address":"0x1000","new_name":"parse_header"}}'
ida-cli --path <file> raw '{"method":"set_function_prototype","params":{"address":"0x1000","prototype":"int64_t __fastcall parse_header(Config *cfg)"}}'
ida-cli --path <file> raw '{"method":"batch_decompile","params":{"addresses":["0x1000","0x2000"]}}'
ida-cli --path <file> raw '{"method":"run_script","params":{"code":"import idautils; print(len(list(idautils.Functions())))"}}'

# batched stream over stdin
ida-cli --json --path <file> pipe <<'EOF'
{"method":"get_analysis_status"}
{"method":"list_functions","params":{"limit":5}}
{"method":"get_xrefs_to","params":{"address":"0x1000"}}
EOF
```

Useful MCP method names (non-exhaustive, verified against
`src/rpc_dispatch.rs`):

- Functions: `list_functions`, `get_function_by_name`, `get_function_at_address`,
  `get_function_prototype`, `batch_lookup_functions`, `export_functions`,
  `run_auto_analysis`
- Disassembly: `disassemble`, `disassemble_function`, `disassemble_function_at`
- Decompilation: `decompile_function`, `get_pseudocode_at`, `batch_decompile`,
  `decompile_structured`, `diff_pseudocode`
- Xrefs / CFG: `get_xrefs_to`, `get_xrefs_from`, `get_xrefs_to_string`,
  `get_xrefs_to_struct_field`, `build_xref_matrix`, `get_basic_blocks`,
  `get_callees`, `get_callers`, `build_callgraph`, `find_control_flow_paths`
- Memory: `read_byte`, `read_word`, `read_dword`, `read_qword`, `read_bytes`,
  `read_string`, `read_global_variable`, `scan_memory_table`, `convert_number`
- Search: `search_text`, `search_bytes`, `search_pseudocode`,
  `search_instructions`, `search_instruction_operands`
- Metadata: `get_database_info`, `get_analysis_status`, `list_segments`,
  `list_strings`, `list_imports`, `list_exports`, `list_entry_points`,
  `list_globals`, `get_address_info`
- Types / structs: `list_local_types`, `list_enums`, `list_structs`,
  `get_struct_info`, `search_structs`, `declare_c_type`, `apply_type`,
  `infer_type`, `create_enum`, `create_stack_variable`,
  `delete_stack_variable`, `rename_stack_variable`, `set_stack_variable_type`,
  `get_stack_frame`, `read_struct_at_address`
- Editing: `rename_symbol`, `batch_rename`, `rename_local_variable`,
  `set_local_variable_type`, `set_comment`, `set_decompiler_comment`,
  `set_function_comment`, `set_function_prototype`, `patch_bytes`,
  `patch_assembly`
- Scripting: `run_script`
- Discovery: `tool_catalog`, `tool_help`

## Output Modes

```bash
ida-cli --json    --path <file> list-functions --limit 5   # pretty JSON
ida-cli --compact --path <file> list-functions --limit 5   # single-line JSON
```

Default output is a human-readable renderer; use `--json` whenever you need to
pipe the response into another tool.

## File Types

- `.i64` / `.idb` — reopens the existing IDA database.
- Raw PE / ELF / Mach-O — analysed on first open; `.i64` is cached alongside.

## Decompilation Policy

- Try decompilation once.
- If it fails explicitly, or if `decompile_function` stalls for more than
  10 seconds, treat the function as currently non-decompilable and drop to
  disassembly until the blockers are understood or removed.

## Notes

- Little-endian byte order matters for `search_bytes`.
- Prefer concrete subcommands over `raw` when both work.
- The MCP layer also exposes `tool_catalog(query=...)` and `tool_help(name=...)`;
  use them with `raw` to explore parameters interactively before wiring a
  script.
