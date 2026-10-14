use crate::ida::runtime::WorkerBackendKind;

const NATIVE_LINKED_METHODS: &[&str] = &[
    "open",
    "close",
    "shutdown",
    "load_debug_info",
    "get_analysis_status",
    "list_functions",
    "get_function_by_name",
    "get_function_prototype",
    "get_function_at_address",
    "batch_lookup_functions",
    "export_functions",
    "disassemble",
    "disassemble_function",
    "disassemble_function_at",
    "decompile_function",
    "get_pseudocode_at",
    "list_segments",
    "list_strings",
    "get_xrefs_to_string",
    "list_local_types",
    "declare_c_type",
    "apply_type",
    "infer_type",
    "set_function_prototype",
    "rename_stack_variable",
    "set_stack_variable_type",
    "list_enums",
    "create_enum",
    "get_address_info",
    "create_stack_variable",
    "delete_stack_variable",
    "get_stack_frame",
    "list_structs",
    "get_struct_info",
    "read_struct_at_address",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_xrefs_to_struct_field",
    "list_imports",
    "list_exports",
    "list_entry_points",
    "read_bytes",
    "read_int",
    "read_string",
    "read_global_variable",
    "set_comment",
    "set_function_comment",
    "rename_symbol",
    "batch_rename",
    "rename_local_variable",
    "set_local_variable_type",
    "set_decompiler_comment",
    "patch_bytes",
    "patch_assembly",
    "get_basic_blocks",
    "get_callees",
    "get_callers",
    "build_callgraph",
    "find_control_flow_paths",
    "build_xref_matrix",
    "get_database_info",
    "list_globals",
    "run_auto_analysis",
    "search_bytes",
    "search_text",
    "search_imm",
    "search_instructions",
    "search_instruction_operands",
    "run_script",
    "batch_decompile",
    "search_pseudocode",
    "scan_memory_table",
    "diff_pseudocode",
];

const IDAT_COMPAT_METHODS: &[&str] = &[
    "open",
    "close",
    "shutdown",
    "get_analysis_status",
    "get_database_info",
    "list_functions",
    "get_function_by_name",
    "get_function_at_address",
    "get_address_info",
    "disassemble",
    "disassemble_function",
    "disassemble_function_at",
    "decompile_function",
    "get_pseudocode_at",
    "batch_decompile",
    "search_pseudocode",
    "diff_pseudocode",
    "list_segments",
    "list_strings",
    "list_imports",
    "list_exports",
    "list_entry_points",
    "list_globals",
    "read_bytes",
    "read_string",
    "read_int",
    "search_text",
    "search_bytes",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_xrefs_to_string",
    "get_callers",
    "get_callees",
    "run_script",
];

pub fn supported_methods_for(backend: WorkerBackendKind) -> &'static [&'static str] {
    match backend {
        WorkerBackendKind::IdatCompat => IDAT_COMPAT_METHODS,
        WorkerBackendKind::NativeLinked => NATIVE_LINKED_METHODS,
    }
}

pub fn supported_tools_for(backend: WorkerBackendKind) -> Vec<String> {
    crate::tool_registry::all_tools()
        .filter(|tool| tool_supported_by_backend(tool.name, backend))
        .map(|tool| tool.name.to_string())
        .collect()
}

fn tool_supported_by_backend(name: &str, backend: WorkerBackendKind) -> bool {
    if matches!(backend, WorkerBackendKind::NativeLinked) {
        return true;
    }
    let worker_method = match name {
        "open_idb" => "open",
        "close_idb" => "close",
        "read_byte" | "read_word" | "read_dword" | "read_qword" => "read_int",
        "tool_catalog" | "tool_help" | "get_task_status" | "convert_number" | "list_idbs" => {
            return true
        }
        other => other,
    };
    IDAT_COMPAT_METHODS.contains(&worker_method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_linked_capabilities_are_not_empty() {
        assert!(supported_methods_for(WorkerBackendKind::NativeLinked).len() > 50);
        assert!(supported_tools_for(WorkerBackendKind::NativeLinked).len() > 50);
    }

    #[test]
    fn list_idbs_is_a_daemon_tool_every_backend_supports() {
        for backend in [
            WorkerBackendKind::NativeLinked,
            WorkerBackendKind::IdatCompat,
        ] {
            let tools = supported_tools_for(backend);
            assert!(tools.iter().any(|tool| tool == "list_idbs"), "{backend}");
        }
    }

    #[test]
    fn idat_compat_tools_are_filtered_to_supported_methods() {
        let tools = supported_tools_for(WorkerBackendKind::IdatCompat);
        assert!(tools.iter().any(|tool| tool == "open_idb"));
        assert!(tools.iter().any(|tool| tool == "decompile_function"));
        assert!(!tools.iter().any(|tool| tool == "patch_bytes"));
    }
}
