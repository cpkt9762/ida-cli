# N6 能力盘点（阻塞预检，未完成迁移）

输入 `9d71e70fa7e3903f702a158c2aa9229b4367e909`。从 `src/tool_registry.rs::TOOL_REGISTRY`、`src/ida/capabilities.rs` 和当前 Nexus 接纳列表逐项生成；106 个工具、73 个 native 方法、34 个 idat 方法，包含全部 23 个 `dbg_*`。机器清单与覆盖断言见外部 `n6/capability-inventory.json`。

这是一份完整的输入能力盘点，**不是 N6 验收完成的能力对照表**。本轮遇到基线调用图顺序与已接受严格比较规则的冲突后按委托要求停止；未把尚未实现的能力标成永久不支持，也未把历史测试算成本轮 PASS。最终每项仍须补本轮执行、对照及持久化证据。

状态：`HISTORICAL-PASS` 为 N4/N5 已迁移且历史对照通过；`HISTORICAL-LIFECYCLE` 为数据库生命周期历史通过；`N7` 为明确后续阶段范围；`LOCAL-UNVERIFIED` 为无需 IDA 的本地能力；`N6-BLOCKED` 为本轮未迁移且当前明确拒绝。不存在本轮新裁定的“永久不支持”。

`native`/`idat` 列仅表示 capabilities.rs 的方法数组声明。其 native 工具过滤器另直接接受全部工具，不能据此推导所有工具都有同名 worker 方法。`read_byte/word/dword/qword` 映射 `read_int`，open/close 工具映射内部方法。证据 `n5-fix2/...`、`n6/...` 均相对于编排者指定的外部证据根；历史证据未在本轮重新运行。

| 工具 | worker 方法/声明 | aliases | 当前状态 | 原因与证据 |
|---|---|---|---|---|
| `open_idb` | `open (native=Y, idat=Y)` | — | HISTORICAL-LIFECYCLE | N3/N4 生命周期接入；原始二进制和已有 IDB 历史已验；sBPF/GUI 属 N7；本轮未复验。 证据：`n5-fix2/l2/lifecycle-result.json; n5-fix2/k2/contract-result.json` |
| `open_dsc` | `open_dsc (native=-, idat=-)` | — | N7 | DSC 专用输入和增量流程属于 N7；当前接纳拒绝。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `dsc_add_dylib` | `dsc_add_dylib (native=-, idat=-)` | — | N7 | DSC 专用输入和增量流程属于 N7；当前接纳拒绝。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `dsc_add_region` | `dsc_add_region (native=-, idat=-)` | — | N7 | DSC 专用输入和增量流程属于 N7；当前接纳拒绝。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `load_debug_info` | `load_debug_info (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_analysis_status` | `get_analysis_status (native=Y, idat=Y)` | `analysis_status` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `close_idb` | `close (native=Y, idat=Y)` | — | HISTORICAL-LIFECYCLE | N3/N4 生命周期接入；原始二进制和已有 IDB 历史已验；sBPF/GUI 属 N7；本轮未复验。 证据：`n5-fix2/l2/lifecycle-result.json; n5-fix2/k2/contract-result.json` |
| `tool_catalog` | `tool_catalog (native=-, idat=-)` | — | LOCAL-UNVERIFIED | 本地目录/帮助；ToolMux 显式豁免数据库能力检查；本轮未复验。 证据：`src/server/mod.rs::ToolMux::call/tool_catalog/tool_help` |
| `tool_help` | `tool_help (native=-, idat=-)` | — | LOCAL-UNVERIFIED | 本地目录/帮助；ToolMux 显式豁免数据库能力检查；本轮未复验。 证据：`src/server/mod.rs::ToolMux::call/tool_catalog/tool_help` |
| `get_task_status` | `get_task_status (native=-, idat=-)` | `task_status` | N6-BLOCKED | handler 为本地操作，但 ToolMux 未豁免，当前同样被能力检查拒绝；需 N6 接线并验证。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_database_info` | `get_database_info (native=Y, idat=Y)` | `idb_meta` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `list_functions` | `list_functions (native=Y, idat=Y)` | `list_funcs` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_function_by_name` | `get_function_by_name (native=Y, idat=Y)` | `resolve_function` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_function_prototype` | `get_function_prototype (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_function_at_address` | `get_function_at_address (native=Y, idat=Y)` | `function_at` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `batch_lookup_functions` | `batch_lookup_functions (native=Y, idat=-)` | `lookup_funcs` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `run_auto_analysis` | `run_auto_analysis (native=Y, idat=-)` | `analyze_funcs` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/c3/n5-comparison.json` |
| `disassemble` | `disassemble (native=Y, idat=Y)` | `disasm` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `disassemble_function` | `disassemble_function (native=Y, idat=Y)` | `disasm_by_name` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `disassemble_function_at` | `disassemble_function_at (native=Y, idat=Y)` | `disasm_function_at` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `decompile_function` | `decompile_function (native=Y, idat=Y)` | `decompile` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_pseudocode_at` | `get_pseudocode_at (native=Y, idat=Y)` | `pseudocode_at` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `decompile_structured` | `decompile_structured (native=-, idat=-)` | — | N6-BLOCKED | 既有工具生成脚本后路由 run_script，但外层 ToolMux 拒绝；需 N6 迁移/验证。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `batch_decompile` | `batch_decompile (native=Y, idat=Y)` | — | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/c3/n5-comparison.json` |
| `search_pseudocode` | `search_pseudocode (native=Y, idat=Y)` | — | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/c3/n5-comparison.json` |
| `scan_memory_table` | `scan_memory_table (native=Y, idat=-)` | `table_scan` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `diff_pseudocode` | `diff_pseudocode (native=Y, idat=Y)` | `diff_functions` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_xrefs_to` | `get_xrefs_to (native=Y, idat=Y)` | `xrefs_to` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_xrefs_from` | `get_xrefs_from (native=Y, idat=Y)` | `xrefs_from` | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `get_xrefs_to_string` | `get_xrefs_to_string (native=Y, idat=Y)` | `xrefs_to_string` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `build_xref_matrix` | `build_xref_matrix (native=Y, idat=-)` | `xref_matrix` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_basic_blocks` | `get_basic_blocks (native=Y, idat=-)` | `basic_blocks` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_callers` | `get_callers (native=Y, idat=Y)` | `callers` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_callees` | `get_callees (native=Y, idat=Y)` | `callees` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `build_callgraph` | `build_callgraph (native=Y, idat=-)` | `callgraph` | N6-BLOCKED | 当前未迁移；N0 的 nodes 随机顺序已真实复现，现有严格 E04 判定不稳定；需裁定精确比较例外。 证据：`n6/dev/preflight-result.json; src/ida/handlers/controlflow.rs::handle_callgraph` |
| `find_control_flow_paths` | `find_control_flow_paths (native=Y, idat=-)` | `find_paths` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `read_bytes` | `read_bytes (native=Y, idat=Y)` | `get_bytes` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `read_string` | `read_string (native=Y, idat=Y)` | `get_string` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `read_byte` | `read_int (native=Y, idat=Y)` | `get_u8` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `read_word` | `read_int (native=Y, idat=Y)` | `get_u16` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `read_dword` | `read_int (native=Y, idat=Y)` | `get_u32` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `read_qword` | `read_int (native=Y, idat=Y)` | `get_u64` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `read_global_variable` | `read_global_variable (native=Y, idat=-)` | `get_global_value` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `convert_number` | `convert_number (native=-, idat=-)` | `int_convert` | N6-BLOCKED | handler 为本地操作，但 ToolMux 未豁免，当前同样被能力检查拒绝；需 N6 接线并验证。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `search_bytes` | `search_bytes (native=Y, idat=Y)` | `find_bytes` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `search_text` | `search_text (native=Y, idat=Y)` | `search` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_strings` | `list_strings (native=Y, idat=Y)` | `strings`, `find_string`, `analyze_strings` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `search_instructions` | `search_instructions (native=Y, idat=-)` | `find_insns` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `search_instruction_operands` | `search_instruction_operands (native=Y, idat=-)` | `find_insn_operands` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_segments` | `list_segments (native=Y, idat=Y)` | `segments` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_address_info` | `get_address_info (native=Y, idat=Y)` | `addr_info` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_imports` | `list_imports (native=Y, idat=Y)` | `imports` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_exports` | `list_exports (native=Y, idat=Y)` | `exports` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `export_functions` | `export_functions (native=Y, idat=-)` | `export_funcs` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_entry_points` | `list_entry_points (native=Y, idat=Y)` | `entrypoints` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_globals` | `list_globals (native=Y, idat=Y)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_local_types` | `list_local_types (native=Y, idat=-)` | `local_types` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_xrefs_to_struct_field` | `get_xrefs_to_struct_field (native=Y, idat=-)` | `xrefs_to_field` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `declare_c_type` | `declare_c_type (native=Y, idat=-)` | `declare_type` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `apply_type` | `apply_type (native=Y, idat=-)` | `apply_types` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `infer_type` | `infer_type (native=Y, idat=-)` | `infer_types` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_stack_frame` | `get_stack_frame (native=Y, idat=-)` | `stack_frame` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `create_stack_variable` | `create_stack_variable (native=Y, idat=-)` | `declare_stack` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `delete_stack_variable` | `delete_stack_variable (native=Y, idat=-)` | `delete_stack` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_enums` | `list_enums (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `create_enum` | `create_enum (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `list_structs` | `list_structs (native=Y, idat=-)` | `structs` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `get_struct_info` | `get_struct_info (native=Y, idat=-)` | `struct_info` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `read_struct_at_address` | `read_struct_at_address (native=Y, idat=-)` | `read_struct` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `search_structs` | `search_structs (native=-, idat=-)` | — | N6-BLOCKED | 既有工具生成脚本后路由 run_script，但外层 ToolMux 拒绝；需 N6 迁移/验证。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `set_comment` | `set_comment (native=Y, idat=-)` | `set_comments` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `set_function_comment` | `set_function_comment (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `patch_assembly` | `patch_assembly (native=Y, idat=-)` | `patch_asm` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `patch_bytes` | `patch_bytes (native=Y, idat=-)` | `patch` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `rename_symbol` | `rename_symbol (native=Y, idat=-)` | `rename` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `batch_rename` | `batch_rename (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `set_function_prototype` | `set_function_prototype (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `rename_local_variable` | `rename_local_variable (native=Y, idat=-)` | `rename_lvar` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `set_local_variable_type` | `set_local_variable_type (native=Y, idat=-)` | `set_lvar_type` | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `rename_stack_variable` | `rename_stack_variable (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `set_stack_variable_type` | `set_stack_variable_type (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `set_decompiler_comment` | `set_decompiler_comment (native=Y, idat=-)` | — | N6-BLOCKED | N6 未实施；当前在 Tools::require/ToolMux 接纳阶段拒绝；不是永久删除裁定。 证据：`src/router/nexus_tools.rs::Tools::require; src/server/mod.rs::ToolMux::call` |
| `run_script` | `run_script (native=Y, idat=Y)` | — | HISTORICAL-PASS | N4/N5 已接入并有历史对照；本轮未复验。 证据：`n5-fix2/k2/comparison.json` |
| `dbg_load_debugger` | `dbg_load_debugger (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_start_process` | `dbg_start_process (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_attach_process` | `dbg_attach_process (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_detach_process` | `dbg_detach_process (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_exit_process` | `dbg_exit_process (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_get_state` | `dbg_get_state (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_add_breakpoint` | `dbg_add_breakpoint (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_del_breakpoint` | `dbg_del_breakpoint (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_enable_breakpoint` | `dbg_enable_breakpoint (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_list_breakpoints` | `dbg_list_breakpoints (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_continue` | `dbg_continue (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_step_into` | `dbg_step_into (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_step_over` | `dbg_step_over (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_step_until_ret` | `dbg_step_until_ret (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_run_to` | `dbg_run_to (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_get_registers` | `dbg_get_registers (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_set_register` | `dbg_set_register (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_read_memory` | `dbg_read_memory (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_write_memory` | `dbg_write_memory (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_get_memory_info` | `dbg_get_memory_info (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_list_threads` | `dbg_list_threads (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_select_thread` | `dbg_select_thread (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |
| `dbg_wait_event` | `dbg_wait_event (native=-, idat=-)` | — | N6-BLOCKED | 既有 run_debug_script 可路由 run_script，但外层 ToolMux 拒绝此工具；未验证远端调试器、进程/事件/子进程清理；不能宣称公开 API 技术上不支持。 证据：`src/server/mod.rs::run_debug_script; src/ida/handlers/debug/; src/server/mod.rs::ToolMux::call` |

## 非工具名称的 worker 方法

以下补足能力文件中的 5 个内部方法名。其余能力声明已在上表的同名/映射行覆盖，IDAT 的 34 项全部是 native 73 项的子集。

| 方法 | native / idat | 当前状态及证据 |
|---|---|---|
| `close` | Y / Y | 生命周期特设路径；见 close_idb，历史通过，本轮未复验。 |
| `open` | Y / Y | 生命周期特设路径；见 open_idb，历史通过，本轮未复验。 |
| `read_int` | Y / Y | read_byte/word/dword/qword 共享 worker 能力；N6 未迁移，当前拒绝。 |
| `search_imm` | Y / - | 未注册为独立工具，但属于 native 声明；N6 未迁移，当前拒绝。 |
| `shutdown` | Y / Y | router 本地控制路径；并非 Execute 工具；本轮未复验。 |

## 需编排者裁定与后续证明

`build_callgraph.nodes` 的顺序在固定 N0 产物中本身不稳定；同一真实库连续 8 次调用有 2 次与第一次的节点顺序不同，节点内容和 edges 不变。现有严格比较器逐位置比较数组，仅允许校验 SHA256 后规范化输入路径。建议只对此数组按唯一的 address 建索引后使用原严格比较器比较完整节点，拒绝重复节点，保持 edges 及其他数组原序；这是尚未获批的比较例外，不在本轮实现。详细证据与原始响应见外部 `n6/report.md`、`n6/dev/preflight-result.json`。

没有据此改变旧路径、工具输出或 Nexus 能力声明。N9 前若 N6-BLOCKED 行仍未迁移，删除旧路径后这些工具/方法将不能执行；不能通过 run_script 的存在将各工具自动视为已迁移。对于 dbg_* 尤其需要真实 debugger 会话、动态字段对照规则、期限/取消、进程与 socket 清理证据；本轮没有证明它们不可能经公开 API 实现，因此不作永久放弃裁定。

基线 `decompile_function` 的实测输出只有 `code`；输入源码也无 `line_addresses` 或独立 xref 树工具。这里仅记录本样本/输入版本的事实，不能据此排除 N6 对其他高级结果和结构化 ctree 的完整契约核对。
