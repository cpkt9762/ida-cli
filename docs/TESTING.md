# Testing

## Run tests

```bash
just test         # Stdio JSONL integration test
just test-http    # HTTP / SSE integration test
just test-script  # IDAPython script execution test
just test-dsc /path/to/dyld_shared_cache_arm64e  # DSC loading test
just cargo-test   # Unit tests (no IDA required)
just test-list-idbs  # list_idbs against a real, isolated daemon
just test-decompile-line-addresses  # decompile_function line_addresses, same setup
```

All integration tests require IDA Pro with a valid license. Run
`cargo build --bin ida-cli` first; the test harness then spawns the built
binary as a worker subprocess.

## What's Tested

**Stdio test** (`just test`)

- MCP protocol handshake
- Tool discovery (`tool_catalog`, `tool_help`)
- Database operations (`open_idb`, `close_idb`, `get_database_info`,
  `get_analysis_status`)
- Analysis tools (`list_functions`, `get_function_by_name`,
  `disassemble_function`, `search_instructions`,
  `search_instruction_operands`)
- Editing tools (`set_comment`, `rename_symbol`, `patch_bytes`,
  `patch_assembly`)
- Types / stack tools (`declare_c_type`, `apply_type`, `infer_type`,
  `get_stack_frame`, `create_stack_variable`, `delete_stack_variable`)
- Metadata tools (`list_segments`, `list_strings`, `list_imports`,
  `list_exports`, `list_structs`, `get_xrefs_to_struct_field`,
  `search_structs`)

**HTTP test** (`just test-http`)

- Streamable HTTP transport with SSE
- `tools/list` returns the full tool list
- Database operations work over HTTP (`open_idb`, `list_functions`,
  `close_idb` with `close_token`)

**list_idbs test** (`just test-list-idbs`, `tests/list_idbs_e2e.rs`)

- Starts a temporary `serve-http` daemon under an isolated `IDA_CLI_HOME`
  (never `~/.ida`) and stops it with `shutdown` through that home
- Two MCP sessions over the daemon's Unix socket each open one database;
  `list_idbs` (MCP and `ida-cli list-idbs`) lists both with distinct client
  ids, paths and worker pids, never a close token
- Closing one database removes only its entry; a shared database stays listed
  until its last reference is released
- Needs `IDA_TEST=1`, an IDA runtime and a C compiler; `IDA_CLI_E2E_BIN`
  tests another build (for example the release binary) and
  `LIST_IDBS_E2E_OUT` writes the transcript of every answer

**decompile line_addresses test** (`just test-decompile-line-addresses`,
`tests/decompile_line_addresses_e2e.rs`)

- Starts a temporary `serve-http` daemon under an isolated `IDA_CLI_HOME`,
  opens a small compiled fixture over MCP and decompiles one function with
  and without `line_addresses`, over MCP and over `ida-cli decompile`
- Checks that the default answer is still only `{code}`, that `lines` has one
  entry per pseudocode line with the same text as `code`, that addresses are
  ascending, unique and inside the function, and that every address on a line
  is one the decompiler maps to a statement (`get_pseudocode_at`)
- Needs `IDA_TEST=1`, an IDA runtime with Hex-Rays and a C compiler;
  `IDA_CLI_E2E_BIN` tests another build and `DECOMPILE_LINES_E2E_OUT` writes
  the answers

**Script test** (`just test-script`)

- Opens a binary and runs inline Python via `run_script`
- Verifies stdout / stderr capture
- Verifies Python error reporting (division by zero)
- Verifies file-based script execution (`.py` file path)

**DSC test** (`just test-dsc <path>`)

- Requires a real `dyld_shared_cache_arm64e` file
- Tests both sync (pre-existing `.i64`) and async (background `idat`) paths
- Polls `get_task_status` until completion
- Verifies the database is usable after loading (`list_functions`)

**Unit tests** (`just cargo-test`)

- `src/dsc.rs` — file type strings, `idat` args, script generation, Python
  string escaping
- `src/server/task.rs` — task registry lifecycle, deduplication,
  cancellation, ISO timestamps
- `shared/ida_install.rs` — install-path normalisation and version parsing

## Test Fixture

Tests use `test/fixtures/mini.c`, a minimal C program compiled into a
Mach-O binary. The integration tests open the raw binary via `open_idb`;
IDA auto-analyses it and writes an `.i64` alongside.
