# MCP Tool Quick Reference

The IDA MCP server exposes dozens of tools. This page lists the most commonly used argument shapes. For anything not listed here, use `tool_catalog` and `tool_help`.

## Database

```text
open_idb(path: "<file>")
  -> restore a `.i64` session or open a raw native binary
  -> optional: load_debug_info: true
  -> returns db_handle + close_token

open_sbpf(path: "<program_id>.so")
  -> Solana sBPF-specific path: sbpf-interpreter LLVM AOT + open + source map
  -> requires a working sbpf-interpreter
  -> returns db_handle + close_token

close_idb(close_token: "<token>")
  -> save annotations and close the session
```

## Decompilation

```text
decompile_function(address: "0x1000")
  -> returns C-like pseudocode

decompile_structured(address: "0x1000", max_depth: 20, include_types: true)
  -> returns a JSON AST (ctree-style)

batch_decompile(addresses: ["0x1000", "0x2000", "0x3000"])
  -> reduces round trips for multiple functions

get_pseudocode_at(address: "0x1000", end_address: "0x1020")
  -> focus on a smaller pseudocode range

diff_pseudocode(addr1: "0x1000", addr2: "0x2000")
  -> line-by-line pseudocode diff + similarity ratio
```

## Disassembly

```text
disassemble(address: "0x1000", count: 20)
disassemble_function(name: "func_name", count: 50)
disassemble_function_at(address: "0x1000", count: 200)
```

## Call Graph and Control Flow

```text
build_callgraph(roots: ["<addr>"], max_depth: 3, max_nodes: 256)
get_callees(address: "<addr>")
get_callers(address: "<addr>")
find_control_flow_paths(start: "0x1000", end: "0x2000", max_depth: 5)
get_basic_blocks(address: "0x1000")
```

## Cross-References

```text
get_xrefs_to(address: "<addr>")
get_xrefs_from(address: "<addr>")
get_xrefs_to_string(query: "swap", limit: 10)
get_xrefs_to_struct_field(name: "MyStruct", member_name: "field", limit: 25)
```

## Functions and Symbols

```text
list_functions(filter: "main", offset: 0, limit: 50)
get_function_by_name(name: "target_func")
get_function_at_address(address: "0x1000")
get_function_prototype(address: "0x1000")
batch_lookup_functions(names: ["main", "printf", "malloc"])
```

## Annotations (Persisted into `.i64`)

```text
rename_symbol(address: "<addr>", name: "new_name")
rename_symbol(current_name: "sub_1511C", name: "decrypt_payload")

batch_rename(renames: [{"address": "0x1000", "name": "new_name"}, ...])

rename_local_variable(func_address: "<addr>", lvar_name: "v1", new_name: "buffer")
set_local_variable_type(func_address: "<addr>", lvar_name: "v1", type_str: "uint64_t")

set_function_prototype(address: "0x1000", prototype: "int64_t __fastcall func(Config *cfg)")
set_function_comment(address: "0x1000", comment: "main swap handler", repeatable: false)

rename_stack_variable(func_address: "0x1000", var_name: "v1", new_name: "amount_in")
set_stack_variable_type(func_address: "0x1000", var_name: "amount_in", type_str: "uint64_t")

declare_c_type(decl: "struct Config { int magic; char key[32]; };", replace: true)
apply_type(name: "func_name", decl: "int64_t __fastcall process(Config *cfg, int len)")
apply_type(name: "func_name", stack_offset: -16, decl: "int local_var;")

set_comment(address: "0x1000", comment: "XOR key", repeatable: false)
set_decompiler_comment(func_address: "0x1000", address: "0x1010", comment: "decrypt loop")
```

## Search

```text
search_bytes(pattern: "6E 00 00 00", limit: 100)   # remember little-endian byte order
search_text(targets: "0x0F00000000", kind: "imm")
search_text(targets: "password", kind: "text")
search_pseudocode(pattern: "malloc", limit: 10)
search_instructions(patterns: ["MUL", "UDIV"], limit: 5)
search_instruction_operands(patterns: ["#0x6E"], limit: 5)
list_strings(query: "error", limit: 20)
list_strings(filter: "http", offset: 0, limit: 100)
```

## Memory Reads

```text
read_bytes(address: "0x1000", size: 32)
read_byte/read_word/read_dword/read_qword(address: "0x1000")
read_string(address: "0x1000")
read_global_variable(query: "g_flag")
scan_memory_table(base_address: "0x1000", stride: 8, count: 16)
convert_number(inputs: ["0x989680", 1234])
```

## Metadata

```text
list_segments()
list_imports()
list_exports()
list_entry_points()
get_address_info(address: "0x1000")
get_analysis_status()
get_database_info()
```

## Types and Structs

```text
list_structs(filter: "config", limit: 50)
get_struct_info(name: "Config")
read_struct_at_address(address: "0x1000", name: "Config")
search_structs(query: "state", limit: 20)
list_local_types(query: "struct", limit: 50)
infer_type(name: "func_name")
get_stack_frame(address: "0x1000")
create_stack_variable(name: "func", offset: -16, var_name: "local", decl: "int local;")
list_enums(filter: "Error", offset: 0, limit: 50)
create_enum(decl: "enum SwapError { InvalidAmount = 0, SlippageExceeded = 1 };")
```

## Editing and Patching

```text
patch_bytes(address: "0x1000", bytes: "90 90 90 90")
patch_assembly(address: "0x1000", line: "nop")
```

## Scripting

```text
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f))")
run_script(file: "/path/to/script.py")
run_script(code: "...", timeout_secs: 300)
```

## Dynamic Debugging

All debug tools accept an optional `db_handle` for multi-database routing.

### Debugger Loading and Process Management

```text
dbg_load_debugger(debugger: "mac", is_remote: true)
  -> debugger: "mac" / "linux" / "win32"

dbg_start_process(path: "/path/to/binary", args: "", timeout: 30)
  -> starts the process and attaches the debugger

dbg_attach_process(pid: 12345, timeout: 15)
  -> attach to an already running process

dbg_detach_process(timeout: 10)
  -> detach and leave the process running

dbg_exit_process(timeout: 10)
  -> terminate the process and clean up the debug server
```

### Breakpoints

```text
dbg_add_breakpoint(address: "0x1000")
dbg_del_breakpoint(address: "0x1000")
dbg_list_breakpoints()
```

### Execution Control

```text
dbg_continue(timeout: 10)
dbg_step_into(timeout: 10)
dbg_step_over(timeout: 10)
dbg_step_out(timeout: 10)
dbg_run_to(address: "0x1000", timeout: 10)
```

### Registers, Memory, and Threads

```text
dbg_get_registers()
dbg_read_memory(address: "0x1000", size: 64)
dbg_write_memory(address: "0x1000", data: "00 01 02 03")
dbg_list_memory()
dbg_list_threads()
dbg_select_thread(thread_id: 123)
dbg_get_state()
dbg_wait_for_event(timeout: 10)
```

### Rebased Addresses During Debugging

When ASLR is active:

- name-based operations are usually stable
- address-based debug operations should use rebased runtime addresses
- breakpoints can still be set on IDB addresses when the backend handles rebasing

## Dynamic Discovery

If you are not sure which tool to use:

```text
tool_catalog(query: "xref")
tool_help(name: "get_xrefs_to")
```

Rule: do not guess parameters when `tool_catalog` and `tool_help` can tell you exactly what the tool expects.
