"""N6 single IDA edits and memory reads. No lifecycle or backend fallback."""

EDIT_METHODS = ("set_comment", "set_function_comment", "rename_symbol", "patch_bytes",
                "patch_assembly", "rename_local_variable", "set_local_variable_type",
                "set_decompiler_comment", "read_bytes", "read_int", "read_string")
WRITE_METHODS = ("set_comment", "set_function_comment", "rename_symbol", "batch_rename",
                 "patch_bytes", "patch_assembly", "rename_local_variable", "set_local_variable_type",
                 "set_decompiler_comment", "declare_c_type", "apply_type", "set_function_prototype",
                 "create_stack_variable", "delete_stack_variable", "rename_stack_variable",
                 "set_stack_variable_type", "create_enum", "run_auto_analysis", "load_debug_info", "run_script")


def rename_entry(entry, parse_address):
    """One N0 batch item; successful previous entries are never rolled back."""
    import ida_funcs
    import ida_name
    import idautils
    ea = parse_address(entry.get("address"))
    name = entry.get("current_name")
    if ea is None and name is not None:
        for index in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(index)
            symbol = ida_funcs.get_func_name(func.start_ea) if func else None
            if symbol and (name == symbol or name in symbol):
                ea = func.start_ea
                break
        if ea is None:
            ea = next((a for a, symbol in idautils.Names() if name == symbol or name in symbol), None)
    new_name = entry["new_name"]
    if ea is None:
        return {"address": "", "current_name": name, "new_name": new_name, "success": False,
                "error": f"Function not found: {name}" if name is not None else "Invalid parameters: expected address or name"}
    ok = ida_name.set_name(ea, new_name, 0)
    result = {"address": hex(ea), "new_name": new_name, "success": bool(ok)}
    if not ok:
        result["error"] = f"failed to set name at {ea:#x}"
    return result


def invoke_edit(method, params, resolve, parse_address):
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_ida
    import ida_idp
    import ida_name
    import ida_idaapi
    import ida_segment

    if method in ("rename_local_variable", "set_local_variable_type", "set_decompiler_comment"):
        ea = parse_address(params["func_address"]) or 0
        if not ida_hexrays.init_hexrays_plugin():
            raise ValueError("Decompiler not available")
        func = ida_funcs.get_func(ea)
        cfunc = ida_hexrays.decompile(func, flags=ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_NO_CACHE) if func else None
        if method == "rename_local_variable":
            saved = ida_hexrays.lvar_saved_info_t()
            ok = cfunc is not None and ida_hexrays.locate_lvar(saved.ll, ea, params["lvar_name"])
            if ok:
                saved.name = params["new_name"]
                ok = ida_hexrays.modify_user_lvar_info(ea, ida_hexrays.MLI_NAME, saved)
            value = {"func_address": hex(ea), "lvar_name": params["lvar_name"], "new_name": params["new_name"]}
        elif method == "set_local_variable_type":
            tif, name = parse_type(params["type_str"], True)
            saved = ida_hexrays.lvar_saved_info_t()
            ok = name is not None and cfunc is not None and ida_hexrays.locate_lvar(saved.ll, ea, params["lvar_name"])
            if ok:
                saved.type = tif
                ok = ida_hexrays.modify_user_lvar_info(ea, ida_hexrays.MLI_TYPE, saved)
            value = {"func_address": hex(ea), "lvar_name": params["lvar_name"], "type_str": params["type_str"]}
        else:
            ok = cfunc is not None
            itp = params.get("itp")
            itp = 69 if itp is None else itp
            target = parse_address(params["address"]) or 0
            if ok:
                location = ida_hexrays.treeloc_t()
                location.ea, location.itp = target, itp
                cfunc.set_user_cmt(location, params["comment"] or None)
                cfunc.save_user_cmts()
            value = {"func_address": hex(ea), "address": hex(target), "itp": itp, "comment": params["comment"]}
        if not ok:
            action = {"rename_local_variable": "rename local variable", "set_local_variable_type": "set lvar type",
                      "set_decompiler_comment": "set decompiler comment"}[method]
            target = target if method == "set_decompiler_comment" else ea
            raise ValueError(f"IDA error: failed to {action} at {target:#x}")
        return value
    if method == "read_int":
        ea = parse_address(params.get("address"))
        if ea is None:
            ea = parse_address(params.get("addr")) or 0
        size = params.get("size", 4)
        if type(size) is not int or not 0 <= size < 2**64:
            size = 4
        readers = {1: ida_bytes.get_byte, 2: ida_bytes.get_word, 4: ida_bytes.get_dword, 8: ida_bytes.get_qword}
        if size not in readers:
            raise ValueError(f"IDA error: unsupported integer size: {size}")
        value = readers[size](ea)
        return {"address": hex(ea), "size": size, "value": value, "hex": hex(value)}
    if method == "read_string":
        ea = parse_address(params.get("address")) or 0
    else:
        name = params.get("current_name") if method == "rename_symbol" else params.get("target_name", params.get("name"))
        ea = resolve(params.get("address"), name, params.get("offset") or 0)
    if method in ("read_bytes", "read_string"):
        count = params.get("size" if method == "read_bytes" else "max_len")
        count = (16 if method == "read_bytes" else 1024) if count is None else count
        raw = ida_bytes.get_bytes(ea, min(count, 0x10000)) or b""
        if method == "read_string":
            raw = raw.split(b"\0", 1)[0]
            return {"address": hex(ea), "string": raw.decode("utf-8", "replace"), "length": len(raw), "bytes": raw.hex()}
        return {"address": hex(ea), "bytes": raw.hex(), "length": len(raw)}
    if method in ("set_comment", "set_function_comment"):
        repeatable = params.get("repeatable") or False
        comment = params["comment"]
        if method == "set_comment":
            ok = ida_bytes.set_cmt(ea, comment, repeatable)
        else:
            func = ida_funcs.get_func(ea)
            if func is None:
                raise ValueError(f"IDA error: no function found at address {ea:#x}")
            ok = ida_funcs.set_func_cmt(func, comment, repeatable)
        if not ok:
            raise ValueError(f"IDA error: failed to set comment at {ea:#x}")
        return {"address": hex(ea), "comment": comment, "repeatable": repeatable}
    if method == "rename_symbol":
        flags = params.get("flags") or 0
        if not ida_name.set_name(ea, params["name"], flags):
            raise ValueError(f"IDA error: failed to set name at {ea:#x}")
        return {"address": hex(ea), "name": params["name"], "flags": flags}
    if method == "patch_assembly":
        ida_idp.set_target_assembler(ida_ida.inf_get_asmtype())
        segment = ida_segment.getseg(ea)
        cs = segment.sel if segment else ida_idaapi.BADADDR
        use32 = segment.bitness == 1 if segment else ida_ida.inf_is_32bit_exactly()
        assembled = None
        for selector, bits in ((cs, use32), (ida_idaapi.BADADDR, use32),
                               (cs, not use32), (ida_idaapi.BADADDR, not use32)):
            assembled = ida_idp.AssembleLine(ea, selector, ea, bits, params["line"])
            if assembled:
                break
        if not isinstance(assembled, bytes) or not assembled:
            raise ValueError(f"IDA error: failed to assemble line at {ea:#x}")
        raw = assembled
    else:
        raw = bytes(params["bytes"])
    ida_bytes.patch_bytes(ea, raw)
    value = {"address": hex(ea), "length": len(raw)}
    if method == "patch_assembly":
        value.update(line=params["line"], bytes=raw.hex(" "))
    return value
