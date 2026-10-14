# Tools

> Auto-generated from `src/tool_registry.rs`. Do not edit by hand.
> Regenerate with: `cargo run --bin gen_tools_doc -- docs/TOOLS.md`.

## Discovery Workflow

- `tools/list` returns the full tool set (currently 107 tools)
- `tool_catalog(query=...)` searches all tools by intent
- `tool_help(name=...)` returns full documentation and schema
- Call `close_idb` when done to release locks; in multi-client servers coordinate before closing (HTTP/SSE requires close_token from open_idb)

Note: `open_idb` accepts .i64/.idb or raw binaries (Mach-O/ELF/PE). Raw binaries are
auto-analyzed and saved as a .i64 alongside the input. If a sibling .dSYM
exists and no .i64 is present, its DWARF debug info is loaded automatically.

## Core (`core`)

Database open/close and discovery tools

| Tool | Description |
|------|-------------|
| `close_idb` | Close the current database (release locks) |
| `dsc_add_dylib` | Load an additional dylib into an open DSC database (light analysis only) |
| `dsc_add_region` | Load a DSC memory region by address (data/GOT/stubs) |
| `get_analysis_status` | Report auto-analysis status |
| `get_database_info` | Get database metadata and summary |
| `get_task_status` | Check status of a background task (e.g. DSC loading) |
| `list_idbs` | List open databases and the clients holding them |
| `load_debug_info` | Load external debug info (e.g., dSYM/DWARF) |
| `open_dsc` | Open a dyld_shared_cache and load one module; use dsc_add_dylib/dsc_add_region for more |
| `open_idb` | Open an IDA database or raw binary |
| `tool_catalog` | Discover available tools by query or category |
| `tool_help` | Get full documentation for a tool |

## Functions (`functions`)

List, search, and resolve functions

| Tool | Description |
|------|-------------|
| `batch_lookup_functions` | Batch lookup multiple functions by name |
| `get_function_at_address` | Find the function containing an address |
| `get_function_by_name` | Find function address by name |
| `get_function_prototype` | Get the type/prototype declaration of a function |
| `list_functions` | List functions with pagination and filtering |
| `run_auto_analysis` | Run auto-analysis and wait for completion |

## Disassembly (`disassembly`)

Disassemble code at addresses

| Tool | Description |
|------|-------------|
| `disassemble` | Disassemble instructions at an address |
| `disassemble_function` | Disassemble a function by name |
| `disassemble_function_at` | Disassemble the function containing an address |

## Decompile (`decompile`)

Decompile functions to pseudocode (requires Hex-Rays)

| Tool | Description |
|------|-------------|
| `batch_decompile` | Decompile multiple functions at once |
| `decompile_function` | Decompile function to C pseudocode |
| `decompile_structured` | Decompile function to structured AST (ctree JSON) |
| `diff_pseudocode` | Diff two functions' decompiled pseudocode line by line |
| `get_pseudocode_at` | Get pseudocode for specific address/range |

## Xrefs (`xrefs`)

Cross-reference analysis (xrefs to/from)

| Tool | Description |
|------|-------------|
| `build_xref_matrix` | Build xref matrix between addresses |
| `get_xrefs_from` | Find all references FROM an address |
| `get_xrefs_to` | Find all references TO an address |
| `get_xrefs_to_string` | Find xrefs to strings matching a query |
| `get_xrefs_to_struct_field` | Xrefs to a struct field |

## Control Flow (`control_flow`)

Basic blocks, call graphs, control flow

| Tool | Description |
|------|-------------|
| `build_callgraph` | Build call graph from a function |
| `find_control_flow_paths` | Find control-flow paths between two addresses |
| `get_basic_blocks` | Get basic blocks of a function |
| `get_callees` | Find all functions called by a function |
| `get_callers` | Find all callers of a function |

## Memory (`memory`)

Read bytes, strings, and data

| Tool | Description |
|------|-------------|
| `convert_number` | Convert integers between bases |
| `read_byte` | Read 8-bit value |
| `read_bytes` | Read raw bytes from an address |
| `read_dword` | Read 32-bit value |
| `read_global_variable` | Read global value by name or address |
| `read_qword` | Read 64-bit value |
| `read_string` | Read string at an address |
| `read_word` | Read 16-bit value |
| `scan_memory_table` | Scan a memory table by reading entries at stride intervals |

## Search (`search`)

Search for bytes, strings, patterns

| Tool | Description |
|------|-------------|
| `list_strings` | List all strings in the database |
| `search_bytes` | Search for byte pattern |
| `search_instruction_operands` | Find instructions by operand substring |
| `search_instructions` | Find instruction sequences by mnemonic |
| `search_pseudocode` | Search decompiled pseudocode for a text pattern |
| `search_text` | Search for text or immediate values |

## Metadata (`metadata`)

Database info, segments, imports, exports

| Tool | Description |
|------|-------------|
| `export_functions` | Export functions (JSON) |
| `get_address_info` | Resolve address to segment/function/symbol |
| `list_entry_points` | List entry points |
| `list_exports` | List exported functions |
| `list_globals` | List global variables |
| `list_imports` | List imported functions |
| `list_segments` | List all segments |

## Types (`types`)

Types, structs, and stack variable info

| Tool | Description |
|------|-------------|
| `apply_type` | Apply a type to an address or stack variable |
| `create_enum` | Create an enum type from a C declaration |
| `create_stack_variable` | Declare a stack variable |
| `declare_c_type` | Declare a type in the local type library |
| `delete_stack_variable` | Delete a stack variable |
| `get_stack_frame` | Get stack frame info |
| `get_struct_info` | Get struct info by name or ordinal |
| `infer_type` | Infer/guess type at an address |
| `list_enums` | List all enum types in the database |
| `list_local_types` | List local types |
| `list_structs` | List structs with pagination |
| `read_struct_at_address` | Read a struct instance at an address |
| `search_structs` | Search structs by name |

## Editing (`editing`)

Patching, renaming, and comment editing

| Tool | Description |
|------|-------------|
| `batch_rename` | Rename multiple symbols at once |
| `patch_assembly` | Patch instructions with assembly text |
| `patch_bytes` | Patch bytes at an address |
| `rename_local_variable` | Rename a local variable in decompiled pseudocode |
| `rename_stack_variable` | Rename a stack frame variable in a function |
| `rename_symbol` | Rename symbols |
| `set_comment` | Set comments at an address |
| `set_decompiler_comment` | Set a comment in decompiled pseudocode |
| `set_function_comment` | Set a function-level comment (visible at function entry) |
| `set_function_prototype` | Apply a C prototype declaration to a function |
| `set_local_variable_type` | Set the type of a local variable in decompiled pseudocode |
| `set_stack_variable_type` | Set the type of a stack frame variable |

## Debug (`debug`)

Debugger operations (headless unsupported)

| Tool | Description |
|------|-------------|
| `dbg_add_breakpoint` | Set a breakpoint at an address |
| `dbg_attach_process` | Attach the debugger to a running process by PID |
| `dbg_continue` | Continue execution until the next debug event |
| `dbg_del_breakpoint` | Delete a breakpoint at an address |
| `dbg_detach_process` | Detach the debugger without killing the process |
| `dbg_enable_breakpoint` | Enable or disable a breakpoint |
| `dbg_exit_process` | Terminate the debugged process |
| `dbg_get_memory_info` | List memory regions of the debugged process |
| `dbg_get_registers` | Read register values from the suspended process |
| `dbg_get_state` | Get current debugger and process state |
| `dbg_list_breakpoints` | List all breakpoints in the database |
| `dbg_list_threads` | List all threads in the debugged process |
| `dbg_load_debugger` | Load a debugger module for the current binary |
| `dbg_read_memory` | Read bytes from the debugged process memory |
| `dbg_run_to` | Run to a specific address |
| `dbg_select_thread` | Select a thread as the current debugging context |
| `dbg_set_register` | Set a CPU register value in the suspended process |
| `dbg_start_process` | Start the target process under the debugger |
| `dbg_step_into` | Single-step into the next instruction (follows calls) |
| `dbg_step_over` | Single-step over the next instruction (skips calls) |
| `dbg_step_until_ret` | Step until the current function returns |
| `dbg_wait_event` | Wait for the next debug event |
| `dbg_write_memory` | Write bytes to the debugged process memory |

## Scripting (`scripting`)

Execute Python scripts via IDAPython

| Tool | Description |
|------|-------------|
| `run_script` | Execute Python code via IDAPython |

## Notes

- Many tools accept a single value or array (e.g., `"0x1000"` or `["0x1000", "0x2000"]`)
- String inputs may be comma-separated: `"0x1000, 0x2000"`
- Addresses accept hex (`0x1000`) or decimal (`4096`)
- Raw binaries are auto-analyzed on first open; `.i64` is saved alongside the input
