# N6 完整能力对照

覆盖 `src/tool_registry.rs` 全部 106 工具（含 23 个 `dbg_*`）、全部 aliases，以及 `src/ida/capabilities.rs` 的 native 73 / idat 34 项。103 工具已迁移并完成所述用例对照，3 工具属于 N7，永久明确不支持为 0。生成器与集合相等断言：外部 `n6/finalize_inventory.py`、`n6/capability-inventory-final.json`；Rust 全注册表/能力检查为 `n6_every_registered_tool_and_old_capability_has_an_explicit_path`。

证据 `n6/...` 相对于 `/tmp/ida-nexus-run-20261015.98rmfb`。迁移/对照 PASS 不表示所有参数、架构、许可证和调试器权限组合都经过验证；debugger 的覆盖边界逐项列出。N6 是否验收由编排者决定。

| 工具 | worker 方法（native / idat） | aliases | 状态 | 兼容说明与证据 |
|---|---|---|---|---|
| `open_idb` | `open` (Y / Y) | — | 已迁移并通过对照 | 普通输入及已有 IDB 的打开/释放契约；GUI、sBPF、GC/重建的组合流程留 N7。 `n6/r6-life/lifecycle-result.json; n6/r6-contract/contract-result.json` |
| `open_dsc` | `open_dsc` (- / -) | — | N7 | DSC 专用准备/扩展流程留待 N7；Nexus 能力检查明确拒绝，无 native fallback。 `n6/r13-n6/n6-capability-refusals.json` |
| `dsc_add_dylib` | `dsc_add_dylib` (- / -) | — | N7 | DSC 专用准备/扩展流程留待 N7；Nexus 能力检查明确拒绝，无 native fallback。 `n6/r13-n6/n6-capability-refusals.json` |
| `dsc_add_region` | `dsc_add_region` (- / -) | — | N7 | DSC 专用准备/扩展流程留待 N7；Nexus 能力检查明确拒绝，无 native fallback。 `n6/r13-n6/n6-capability-refusals.json` |
| `load_debug_info` | `load_debug_info` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_analysis_status` | `get_analysis_status` (Y / Y) | `analysis_status` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 两边显式设置相同已完成 analysis 状态；保留原始状态输出。 `n6/r13-n6/n6-tool-comparison.json` |
| `close_idb` | `close` (Y / Y) | — | 已迁移并通过对照 | 普通输入及已有 IDB 的打开/释放契约；GUI、sBPF、GC/重建的组合流程留 N7。 `n6/r6-life/lifecycle-result.json; n6/r6-contract/contract-result.json` |
| `tool_catalog` | `tool_catalog` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `tool_help` | `tool_help` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_task_status` | `get_task_status` (- / -) | `task_status` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_database_info` | `get_database_info` (Y / Y) | `idb_meta` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_functions` | `list_functions` (Y / Y) | `list_funcs` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_function_by_name` | `get_function_by_name` (Y / Y) | `resolve_function` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_function_prototype` | `get_function_prototype` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_function_at_address` | `get_function_at_address` (Y / Y) | `function_at` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `batch_lookup_functions` | `batch_lookup_functions` (Y / -) | `lookup_funcs` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `run_auto_analysis` | `run_auto_analysis` (Y / -) | `analyze_funcs` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `disassemble` | `disassemble` (Y / Y) | `disasm` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `disassemble_function` | `disassemble_function` (Y / Y) | `disasm_by_name` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `disassemble_function_at` | `disassemble_function_at` (Y / Y) | `disasm_function_at` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `decompile_function` | `decompile_function` (Y / Y) | `decompile` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_pseudocode_at` | `get_pseudocode_at` (Y / Y) | `pseudocode_at` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `decompile_structured` | `decompile_structured` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 既有公共 IDAPython 适配脚本经 Nexus Execute。 `n6/r13-n6/n6-tool-comparison.json` |
| `batch_decompile` | `batch_decompile` (Y / Y) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `search_pseudocode` | `search_pseudocode` (Y / Y) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `scan_memory_table` | `scan_memory_table` (Y / -) | `table_scan` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `diff_pseudocode` | `diff_pseudocode` (Y / Y) | `diff_functions` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_xrefs_to` | `get_xrefs_to` (Y / Y) | `xrefs_to` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_xrefs_from` | `get_xrefs_from` (Y / Y) | `xrefs_from` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_xrefs_to_string` | `get_xrefs_to_string` (Y / Y) | `xrefs_to_string` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `build_xref_matrix` | `build_xref_matrix` (Y / -) | `xref_matrix` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_basic_blocks` | `get_basic_blocks` (Y / -) | `basic_blocks` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_callers` | `get_callers` (Y / Y) | `callers` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_callees` | `get_callees` (Y / Y) | `callees` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `build_callgraph` | `build_callgraph` (Y / -) | `callgraph` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `find_control_flow_paths` | `find_control_flow_paths` (Y / -) | `find_paths` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `read_bytes` | `read_bytes` (Y / Y) | `get_bytes` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `read_string` | `read_string` (Y / Y) | `get_string` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `read_byte` | `read_int` (Y / Y) | `get_u8` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `read_word` | `read_int` (Y / Y) | `get_u16` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `read_dword` | `read_int` (Y / Y) | `get_u32` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `read_qword` | `read_int` (Y / Y) | `get_u64` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `read_global_variable` | `read_global_variable` (Y / -) | `get_global_value` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `convert_number` | `convert_number` (- / -) | `int_convert` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `search_bytes` | `search_bytes` (Y / Y) | `find_bytes` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `search_text` | `search_text` (Y / Y) | `search` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_strings` | `list_strings` (Y / Y) | `strings`, `find_string`, `analyze_strings` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 4 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `search_instructions` | `search_instructions` (Y / -) | `find_insns` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `search_instruction_operands` | `search_instruction_operands` (Y / -) | `find_insn_operands` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_segments` | `list_segments` (Y / Y) | `segments` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_address_info` | `get_address_info` (Y / Y) | `addr_info` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_imports` | `list_imports` (Y / Y) | `imports` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_exports` | `list_exports` (Y / Y) | `exports` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `export_functions` | `export_functions` (Y / -) | `export_funcs` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_entry_points` | `list_entry_points` (Y / Y) | `entrypoints` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_globals` | `list_globals` (Y / Y) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_local_types` | `list_local_types` (Y / -) | `local_types` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_xrefs_to_struct_field` | `get_xrefs_to_struct_field` (Y / -) | `xrefs_to_field` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `declare_c_type` | `declare_c_type` (Y / -) | `declare_type` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `apply_type` | `apply_type` (Y / -) | `apply_types` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `infer_type` | `infer_type` (Y / -) | `infer_types` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_stack_frame` | `get_stack_frame` (Y / -) | `stack_frame` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `create_stack_variable` | `create_stack_variable` (Y / -) | `declare_stack` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `delete_stack_variable` | `delete_stack_variable` (Y / -) | `delete_stack` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_enums` | `list_enums` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `create_enum` | `create_enum` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `list_structs` | `list_structs` (Y / -) | `structs` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `get_struct_info` | `get_struct_info` (Y / -) | `struct_info` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `read_struct_at_address` | `read_struct_at_address` (Y / -) | `read_struct` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `search_structs` | `search_structs` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 既有公共 IDAPython 适配脚本经 Nexus Execute。 `n6/r13-n6/n6-tool-comparison.json` |
| `set_comment` | `set_comment` (Y / -) | `set_comments` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `set_function_comment` | `set_function_comment` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `patch_assembly` | `patch_assembly` (Y / -) | `patch_asm` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 ARM64 基线失败文本精确匹配；x86 成功 patch/readback 另两项 PASS。 `n6/r13-n6/n6-tool-comparison.json; n6/r13-n6/n6-x86-comparison.json` |
| `patch_bytes` | `patch_bytes` (Y / -) | `patch` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `rename_symbol` | `rename_symbol` (Y / -) | `rename` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `batch_rename` | `batch_rename` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `set_function_prototype` | `set_function_prototype` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `rename_local_variable` | `rename_local_variable` (Y / -) | `rename_lvar` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `set_local_variable_type` | `set_local_variable_type` (Y / -) | `set_lvar_type` | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 2 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `rename_stack_variable` | `rename_stack_variable` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `set_stack_variable_type` | `set_stack_variable_type` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `set_decompiler_comment` | `set_decompiler_comment` (Y / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `run_script` | `run_script` (Y / Y) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_load_debugger` | `dbg_load_debugger` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_start_process` | `dbg_start_process` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_attach_process` | `dbg_attach_process` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_detach_process` | `dbg_detach_process` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_exit_process` | `dbg_exit_process` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_get_state` | `dbg_get_state` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_add_breakpoint` | `dbg_add_breakpoint` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_del_breakpoint` | `dbg_del_breakpoint` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_enable_breakpoint` | `dbg_enable_breakpoint` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_list_breakpoints` | `dbg_list_breakpoints` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_continue` | `dbg_continue` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_step_into` | `dbg_step_into` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_step_over` | `dbg_step_over` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_step_until_ret` | `dbg_step_until_ret` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_run_to` | `dbg_run_to` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_get_registers` | `dbg_get_registers` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_set_register` | `dbg_set_register` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_read_memory` | `dbg_read_memory` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_write_memory` | `dbg_write_memory` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_get_memory_info` | `dbg_get_memory_info` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_list_threads` | `dbg_list_threads` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_select_thread` | `dbg_select_thread` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |
| `dbg_wait_event` | `dbg_wait_event` (- / -) | — | 已迁移并通过对照 | MCP 工具及全部 aliases 严格对照 1 项 PASS。 真实 IDA 空闲调试器/断点/失败契约；活动 debuggee 成功路径未覆盖。 `n6/r13-n6/n6-tool-comparison.json` |

## 全部能力声明

下表逐项列出 native 73 项；idat 的全部 34 项均为其子集，以 Y 标出并经集合断言。70 个普通方法对应 Nexus METHODS；open/close/shutdown 对应生命周期控制，不作为 IDAPython 工具 Execute。

| 方法 | native | idat | 状态与当前证据 |
|---|---|---|---|
| `open` | Y | Y | 已迁移；n6/r6-life/lifecycle-result.json；n6/r6-contract/contract-result.json |
| `close` | Y | Y | 已迁移；n6/r6-life/lifecycle-result.json；n6/r6-contract/contract-result.json |
| `shutdown` | Y | Y | 已迁移；n6/r6-life/lifecycle-result.json；n6/r6-contract/contract-result.json |
| `load_debug_info` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_analysis_status` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `list_functions` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `get_function_by_name` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_function_prototype` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_function_at_address` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `batch_lookup_functions` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `export_functions` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `disassemble` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `disassemble_function` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `disassemble_function_at` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `decompile_function` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_pseudocode_at` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `list_segments` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `list_strings` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_xrefs_to_string` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `list_local_types` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `declare_c_type` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `apply_type` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `infer_type` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `set_function_prototype` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `rename_stack_variable` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `set_stack_variable_type` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `list_enums` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `create_enum` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_address_info` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `create_stack_variable` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `delete_stack_variable` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_stack_frame` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `list_structs` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_struct_info` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `read_struct_at_address` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_xrefs_to` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `get_xrefs_from` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `get_xrefs_to_struct_field` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `list_imports` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `list_exports` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `list_entry_points` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `read_bytes` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `read_int` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `read_string` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `read_global_variable` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `set_comment` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `set_function_comment` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `rename_symbol` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `batch_rename` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `rename_local_variable` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `set_local_variable_type` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `set_decompiler_comment` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `patch_bytes` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `patch_assembly` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_basic_blocks` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_callees` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_callers` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `build_callgraph` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `find_control_flow_paths` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `build_xref_matrix` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `get_database_info` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `list_globals` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `run_auto_analysis` | Y | - | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `search_bytes` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `search_text` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `search_imm` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `search_instructions` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `search_instruction_operands` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `run_script` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `batch_decompile` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `search_pseudocode` | Y | Y | 已迁移并通过工具/别名对照；n6/r13-n6/n6-tool-comparison.json；n6/r6-contract/comparison.json |
| `scan_memory_table` | Y | - | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |
| `diff_pseudocode` | Y | Y | 已迁移并通过严格方法对照；n6/r13-n6/n6-comparison.json |

## 比较规则与差异清单

1. `build_callgraph.result.nodes`：唯一身份键 `address`；N0 同库相同输入连续 8 次出现两种顺序，证据 `n6/dev/preflight-result.json`。仅此字段按键配对，数量、全部值和类型、edges 及未登记字段严格比较。Nexus 按数值地址稳定输出。

2. `get_xrefs_to_struct_field.result.tid`：SDK 分配的成员 TID（此前 `$ debugger application` 多一次 netnode 分配造成偏移，证据 `n6/tid-diagnosis.json`）。第二次续派采用第一步：预建 IDB 经公开 auto_wait 完成分析并校验输入元数据，显式 `save_database` 后关闭，再逐字节复制；ARM64、x86 与工具矩阵分别记录三份一致 SHA256。第一步消除磁盘分配历史，但不能保证会话内后续分配相同：r6 全部数值严格相等；r7 的同字段再次偏移，按已批准第二步身份规则通过，证据 n6/r7-n6/n6-comparison.json。最终运行的实际数值与后备使用记录见下述 n6-comparison.json 的 allocated_id_exception 和 allocated_id_witnesses，不把端口或地址当分配 ID。证据 `n6/r13-n6/n6-prebuilt-idb.json`、`n6/r13-n6/n6-tools-prebuilt-idb.json`、`n6/r13-n6/n6-x86-prebuilt-idb.json`、`n6/r13-n6/n6-comparison.json`。

后备比较器只登记上述 tid 字段，要求合法非 BADADDR、全成员 ID 唯一、同会话重复稳定、把 tid 作为公开 get_udm_by_tid 输入成功，实体名称/类型/成员/偏移/大小完整严格一致。真实运行同时保存了这些 witness，后备比较器有 9 项单元测试中的正反例；地址、偏移、大小、端口均不规范化。

3. 已有 IDB 默认打开后，`get_analysis_status.auto_enabled` 在 native 为 true、Nexus 为 false；明确配置来源是 `src/router/nexus_bridge/cache.rs:138–141` 的 `auto_analysis=false`，不是仅因某个瞬间分析未完成。工具矩阵通过公开 inf_set_auto_enabled/enable_auto/auto_wait 显式启用两边分析并设置相同已完成状态之后才严格对照；不能据此宣称默认打开状态相同。未修改产品状态或删除字段。

4. dbg_attach_process 的错误含实际监听端口；测试在相同 OS 选择端口顺序运行两侧 server，保留完整错误字符串严格比较，无端口例外。MCP 写工具保留 N0 既有的重复 IDA error 前缀，raw 结构不变。

固定 N0 decompile_function 结果只有 code，没有 line_addresses；ctree 的 include_types/include_addresses 和 get_pseudocode_at 的地址、opcode、bounds、eamap_ready 均进入对照。没有删除现有扩展字段。

## N7 边界与需用户裁定

N7 的 3 个 DSC 注册工具当前明确拒绝；open_idb 的 GUI/sBPF、专用输入流程，以及缓存 GC/重建也留 N7。旧自动 GC 暂停、开发选择入口 IDA_CLI_NEXUS_DEV 必须在 N9 删除。N9 会删除旧后端，永久不支持的工具届时失效；本轮永久不支持工具为 0，因此该类“需用户裁定”清单为空。

23 个 dbg_* 均经 Nexus 的 run_script 适配并完成逐项严格对照；本机只验证空闲状态、断点和失败契约，没有把活动 debuggee 的启动、attach、单步或寄存器/内存成功路径标成已验证。活动 debuggee 的成功启动、停止事件、attach、单步、寄存器/内存修改与清理，必须在 N8 全量验收前补齐；本轮不实现，不代表永久弃用工具。
