# N6 完整能力盘点与部分对照（BLOCKED）

续派输入 `5e9931ec9ba5f9871d40549df4f6237b6226ebcd`。当前注册表 106 工具（23 个 `dbg_*`）、native 73 / idat 34 项声明完整覆盖；70 个普通方法已接线。生成与覆盖断言：外部 `n6/update_inventory.py`、`n6/capability-inventory-resume.json`。

本表不是 N6 验收完成证明。`E04-METHOD-PASS` 仅表示列出的 raw 方法用例严格通过，未证明所有参数、工具包装、错误/取消和持久化；`HISTORICAL-PASS` 仍仅为旧 N4/N5 证据；`WIRED-UNVERIFIED` 为已接线待验；`LOCAL-UNVERIFIED` 为本地/生命周期待验；`FAIL-TID` 是当前严格值差异；`N7` 为后续范围。永久明确不支持为 0 项，不以未验代替放弃裁定。

N7 另涵盖 open_idb 的 GUI/sBPF 专用输入及缓存 GC/重建协调，不因为这些没有独立注册工具就遗漏边界。所有证据 n6/... 相对于 `/tmp/ida-nexus-run-20261015.98rmfb`。

| 工具 | worker 方法/声明 | aliases | 当前状态 | 原因与证据 |
|---|---|---|---|---|
| `open_idb` | `open (native=Y, idat=Y)` | — | LOCAL-UNVERIFIED | 本地工具/生命周期接线；本轮未做独立全量验证。 证据：`src/server/mod.rs` |
| `open_dsc` | `open_dsc (native=-, idat=-)` | — | N7 | DSC 专用输入和增量流程属于 N7；当前接纳拒绝。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `dsc_add_dylib` | `dsc_add_dylib (native=-, idat=-)` | — | N7 | DSC 专用输入和增量流程属于 N7；当前接纳拒绝。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `dsc_add_region` | `dsc_add_region (native=-, idat=-)` | — | N7 | DSC 专用输入和增量流程属于 N7；当前接纳拒绝。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `load_debug_info` | `load_debug_info (native=Y, idat=-)` | — | WIRED-UNVERIFIED | N6 已编写 owner 接线，未完成逐方法对照和错误/取消验证。 证据：`nexus_bridge/; src/router/nexus_tools.rs` |
| `get_analysis_status` | `get_analysis_status (native=Y, idat=Y)` | `analysis_status` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `close_idb` | `close (native=Y, idat=Y)` | — | LOCAL-UNVERIFIED | 本地工具/生命周期接线；本轮未做独立全量验证。 证据：`src/server/mod.rs` |
| `tool_catalog` | `tool_catalog (native=-, idat=-)` | — | LOCAL-UNVERIFIED | 本地工具/生命周期接线；本轮未做独立全量验证。 证据：`src/server/mod.rs` |
| `tool_help` | `tool_help (native=-, idat=-)` | — | LOCAL-UNVERIFIED | 本地工具/生命周期接线；本轮未做独立全量验证。 证据：`src/server/mod.rs` |
| `get_task_status` | `get_task_status (native=-, idat=-)` | `task_status` | LOCAL-UNVERIFIED | 本地工具/生命周期接线；本轮未做独立全量验证。 证据：`src/server/mod.rs` |
| `get_database_info` | `get_database_info (native=Y, idat=Y)` | `idb_meta` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `list_functions` | `list_functions (native=Y, idat=Y)` | `list_funcs` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_function_by_name` | `get_function_by_name (native=Y, idat=Y)` | `resolve_function` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_function_prototype` | `get_function_prototype (native=Y, idat=-)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 2 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_function_at_address` | `get_function_at_address (native=Y, idat=Y)` | `function_at` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `batch_lookup_functions` | `batch_lookup_functions (native=Y, idat=-)` | `lookup_funcs` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `run_auto_analysis` | `run_auto_analysis (native=Y, idat=-)` | `analyze_funcs` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/c3/n5-comparison.json` |
| `disassemble` | `disassemble (native=Y, idat=Y)` | `disasm` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `disassemble_function` | `disassemble_function (native=Y, idat=Y)` | `disasm_by_name` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `disassemble_function_at` | `disassemble_function_at (native=Y, idat=Y)` | `disasm_function_at` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `decompile_function` | `decompile_function (native=Y, idat=Y)` | `decompile` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_pseudocode_at` | `get_pseudocode_at (native=Y, idat=Y)` | `pseudocode_at` | E04-METHOD-PASS | 本轮 raw 方法严格对照 2 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `decompile_structured` | `decompile_structured (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `batch_decompile` | `batch_decompile (native=Y, idat=Y)` | — | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/c3/n5-comparison.json` |
| `search_pseudocode` | `search_pseudocode (native=Y, idat=Y)` | — | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/c3/n5-comparison.json` |
| `scan_memory_table` | `scan_memory_table (native=Y, idat=-)` | `table_scan` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `diff_pseudocode` | `diff_pseudocode (native=Y, idat=Y)` | `diff_functions` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_xrefs_to` | `get_xrefs_to (native=Y, idat=Y)` | `xrefs_to` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_xrefs_from` | `get_xrefs_from (native=Y, idat=Y)` | `xrefs_from` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_xrefs_to_string` | `get_xrefs_to_string (native=Y, idat=Y)` | `xrefs_to_string` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `build_xref_matrix` | `build_xref_matrix (native=Y, idat=-)` | `xref_matrix` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_basic_blocks` | `get_basic_blocks (native=Y, idat=-)` | `basic_blocks` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_callers` | `get_callers (native=Y, idat=Y)` | `callers` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_callees` | `get_callees (native=Y, idat=Y)` | `callees` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `build_callgraph` | `build_callgraph (native=Y, idat=-)` | `callgraph` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `find_control_flow_paths` | `find_control_flow_paths (native=Y, idat=-)` | `find_paths` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `read_bytes` | `read_bytes (native=Y, idat=Y)` | `get_bytes` | E04-METHOD-PASS | 本轮 raw 方法严格对照 2 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `read_string` | `read_string (native=Y, idat=Y)` | `get_string` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `read_byte` | `read_int (native=Y, idat=Y)` | `get_u8` | E04-METHOD-PASS | 共享 read_int 方法已对照 size=4；本工具宽度包装待真实验证。 证据：`n6/impl3/type-comparison.json` |
| `read_word` | `read_int (native=Y, idat=Y)` | `get_u16` | E04-METHOD-PASS | 共享 read_int 方法已对照 size=4；本工具宽度包装待真实验证。 证据：`n6/impl3/type-comparison.json` |
| `read_dword` | `read_int (native=Y, idat=Y)` | `get_u32` | E04-METHOD-PASS | 共享 read_int 方法已对照 size=4；本工具宽度包装待真实验证。 证据：`n6/impl3/type-comparison.json` |
| `read_qword` | `read_int (native=Y, idat=Y)` | `get_u64` | E04-METHOD-PASS | 共享 read_int 方法已对照 size=4；本工具宽度包装待真实验证。 证据：`n6/impl3/type-comparison.json` |
| `read_global_variable` | `read_global_variable (native=Y, idat=-)` | `get_global_value` | WIRED-UNVERIFIED | N6 已编写 owner 接线，未完成逐方法对照和错误/取消验证。 证据：`nexus_bridge/; src/router/nexus_tools.rs` |
| `convert_number` | `convert_number (native=-, idat=-)` | `int_convert` | LOCAL-UNVERIFIED | 本地工具/生命周期接线；本轮未做独立全量验证。 证据：`src/server/mod.rs` |
| `search_bytes` | `search_bytes (native=Y, idat=Y)` | `find_bytes` | E04-METHOD-PASS | 本轮 raw 方法严格对照 2 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `search_text` | `search_text (native=Y, idat=Y)` | `search` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_strings` | `list_strings (native=Y, idat=Y)` | `strings`, `find_string`, `analyze_strings` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `search_instructions` | `search_instructions (native=Y, idat=-)` | `find_insns` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `search_instruction_operands` | `search_instruction_operands (native=Y, idat=-)` | `find_insn_operands` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_segments` | `list_segments (native=Y, idat=Y)` | `segments` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_address_info` | `get_address_info (native=Y, idat=Y)` | `addr_info` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_imports` | `list_imports (native=Y, idat=Y)` | `imports` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_exports` | `list_exports (native=Y, idat=Y)` | `exports` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `export_functions` | `export_functions (native=Y, idat=-)` | `export_funcs` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_entry_points` | `list_entry_points (native=Y, idat=Y)` | `entrypoints` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_globals` | `list_globals (native=Y, idat=Y)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_local_types` | `list_local_types (native=Y, idat=-)` | `local_types` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_xrefs_to_struct_field` | `get_xrefs_to_struct_field (native=Y, idat=-)` | `xrefs_to_field` | FAIL-TID | 成员实际 tid 值偏移 1，其他字段相同；顺序例外不适用，需编排者裁定。 证据：`n6/impl3/type-comparison.json` |
| `declare_c_type` | `declare_c_type (native=Y, idat=-)` | `declare_type` | E04-METHOD-PASS | 本轮 raw 方法严格对照 3 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `apply_type` | `apply_type (native=Y, idat=-)` | `apply_types` | E04-METHOD-PASS | 本轮 raw 方法严格对照 2 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `infer_type` | `infer_type (native=Y, idat=-)` | `infer_types` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_stack_frame` | `get_stack_frame (native=Y, idat=-)` | `stack_frame` | E04-METHOD-PASS | 本轮 raw 方法严格对照 4 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `create_stack_variable` | `create_stack_variable (native=Y, idat=-)` | `declare_stack` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `delete_stack_variable` | `delete_stack_variable (native=Y, idat=-)` | `delete_stack` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_enums` | `list_enums (native=Y, idat=-)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `create_enum` | `create_enum (native=Y, idat=-)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `list_structs` | `list_structs (native=Y, idat=-)` | `structs` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `get_struct_info` | `get_struct_info (native=Y, idat=-)` | `struct_info` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `read_struct_at_address` | `read_struct_at_address (native=Y, idat=-)` | `read_struct` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `search_structs` | `search_structs (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `set_comment` | `set_comment (native=Y, idat=-)` | `set_comments` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `set_function_comment` | `set_function_comment (native=Y, idat=-)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `patch_assembly` | `patch_assembly (native=Y, idat=-)` | `patch_asm` | WIRED-UNVERIFIED | N6 已编写 owner 接线，未完成逐方法对照和错误/取消验证。 证据：`nexus_bridge/; src/router/nexus_tools.rs` |
| `patch_bytes` | `patch_bytes (native=Y, idat=-)` | `patch` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `rename_symbol` | `rename_symbol (native=Y, idat=-)` | `rename` | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `batch_rename` | `batch_rename (native=Y, idat=-)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `set_function_prototype` | `set_function_prototype (native=Y, idat=-)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `rename_local_variable` | `rename_local_variable (native=Y, idat=-)` | `rename_lvar` | WIRED-UNVERIFIED | N6 已编写 owner 接线，未完成逐方法对照和错误/取消验证。 证据：`nexus_bridge/; src/router/nexus_tools.rs` |
| `set_local_variable_type` | `set_local_variable_type (native=Y, idat=-)` | `set_lvar_type` | WIRED-UNVERIFIED | N6 已编写 owner 接线，未完成逐方法对照和错误/取消验证。 证据：`nexus_bridge/; src/router/nexus_tools.rs` |
| `rename_stack_variable` | `rename_stack_variable (native=Y, idat=-)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `set_stack_variable_type` | `set_stack_variable_type (native=Y, idat=-)` | — | E04-METHOD-PASS | 本轮 raw 方法严格对照 1 项通过；MCP 工具/alias 和完整验收待补。 证据：`n6/impl3/type-comparison.json` |
| `set_decompiler_comment` | `set_decompiler_comment (native=Y, idat=-)` | — | WIRED-UNVERIFIED | N6 已编写 owner 接线，未完成逐方法对照和错误/取消验证。 证据：`nexus_bridge/; src/router/nexus_tools.rs` |
| `run_script` | `run_script (native=Y, idat=Y)` | — | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `dbg_load_debugger` | `dbg_load_debugger (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_start_process` | `dbg_start_process (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_attach_process` | `dbg_attach_process (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_detach_process` | `dbg_detach_process (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_exit_process` | `dbg_exit_process (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_get_state` | `dbg_get_state (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_add_breakpoint` | `dbg_add_breakpoint (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_del_breakpoint` | `dbg_del_breakpoint (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_enable_breakpoint` | `dbg_enable_breakpoint (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_list_breakpoints` | `dbg_list_breakpoints (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_continue` | `dbg_continue (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_step_into` | `dbg_step_into (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_step_over` | `dbg_step_over (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_step_until_ret` | `dbg_step_until_ret (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_run_to` | `dbg_run_to (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_get_registers` | `dbg_get_registers (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_set_register` | `dbg_set_register (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_read_memory` | `dbg_read_memory (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_write_memory` | `dbg_write_memory (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_get_memory_info` | `dbg_get_memory_info (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_list_threads` | `dbg_list_threads (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_select_thread` | `dbg_select_thread (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |
| `dbg_wait_event` | `dbg_wait_event (native=-, idat=-)` | — | WIRED-UNVERIFIED | ToolMux 已接既有 run_script 包装；未真实验证，不宣称工具迁移完成或永久不支持。 证据：`src/router/nexus_tools.rs::Tools::require_tool; src/server/mod.rs::ToolMux::call` |

## 非工具名称的 worker 方法

| 方法 | native / idat | 状态及证据 |
|---|---|---|
| `close` | Y / Y | 生命周期/本地控制；本轮未独立复验。 |
| `open` | Y / Y | 生命周期/本地控制；本轮未独立复验。 |
| `read_int` | Y / Y | 本轮 raw 方法对照通过，见 n6/impl3/type-comparison.json；工具包装待验。 |
| `search_imm` | Y / - | 本轮 raw 方法对照通过，见 n6/impl3/type-comparison.json；工具包装待验。 |
| `shutdown` | Y / Y | 生命周期/本地控制；本轮未独立复验。 |

## 比较例外与需用户裁定

已批准例外仅 `build_callgraph / result.nodes / address`，证据 `n6/dev/preflight-result.json`（同库 8 次两种顺序）；节点内容与类型、edges 仍严格，Nexus nodes 按数值地址稳定输出。

当前阻塞是 `get_xrefs_to_struct_field.result.tid` 的真实值差异（N0 ...116，Nexus ...117），并非顺序。两个节点快照证明 Nexus 多出 `$ debugger application` 后共有类型/成员节点整体偏移 1，见 `n6/tid-diagnosis.json`。未新增 tid 比较例外，未改服务端或伪造 ID。需编排者裁定是否接受带逻辑身份核验的运行时 ID 对照规则，或指定公开 API 消除差异的方案。

明确不支持工具的“需用户裁定”清单为空；如果未来选择放弃任一工具，N9 后会失效，必须另列影响和替代方案。尚未验证的工具均不能直接按永久不支持处理。

固定 N0 decompile_function 只有 code，无 line_addresses；get_pseudocode_at 的地址、opcode、bounds、eamap_ready 两项本轮严格对照通过。独立 ctree 与 dbg_* 的完整契约尚待验证。
