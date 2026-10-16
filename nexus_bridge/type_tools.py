"""N6 type/frame operations, executed on the leased owner's IDA thread."""

TYPE_METHODS = ("list_local_types", "declare_c_type", "apply_type", "infer_type",
                "set_function_prototype", "get_function_prototype", "get_stack_frame",
                "create_stack_variable", "delete_stack_variable", "rename_stack_variable",
                "set_stack_variable_type", "list_enums", "create_enum")


def type_kind(tif):
    for predicate, kind in (("is_struct", "struct"), ("is_union", "union"),
                            ("is_enum", "enum"), ("is_func", "function"),
                            ("is_ptr", "pointer"), ("is_array", "array"),
                            ("is_typedef", "typedef")):
        if getattr(tif, predicate)():
            return kind
    return "other"


def parse_type(decl, relaxed=False):
    import ida_typeinf as ti
    tif = ti.tinfo_t()
    flags = ti.PT_TYP | ti.PT_SIL | ti.PT_SEMICOLON
    if relaxed:
        flags |= ti.PT_RELAXED
    name = ti.parse_decl(tif, None, decl, flags)
    return tif, name


def local_types():
    import ida_typeinf as ti
    for ordinal in range(1, ti.get_ordinal_limit(None)):
        tif = ti.tinfo_t()
        if not tif.get_numbered_type(None, ordinal, ti.BTF_TYPEDEF, True):
            continue
        name = ti.get_numbered_type_name(None, ordinal)
        if name:
            yield ordinal, name, tif


def frame_data(ea):
    import ida_funcs
    import ida_frame
    import ida_typeinf as ti
    pfn, tif, udt = ida_funcs.get_func(ea), ti.tinfo_t(), ti.udt_type_data_t()
    if pfn is None or not ida_frame.get_func_frame(tif, pfn) or not tif.get_udt_details(udt, ti.GTD_CALC_LAYOUT):
        raise ValueError(f"Function not found at address {ea:#x}")
    return pfn, tif, udt


def frame_member(pfn, udt, name, offset):
    import ida_frame
    if name:
        for i, member in enumerate(udt):
            if member.name == name:
                return i
    if offset is not None:
        off = ida_frame.calc_frame_offset(pfn, offset)
        if off == -1 or off == 2**64-1:
            off = offset
        for i, member in enumerate(udt):
            if member.offset // 8 == off:
                return i
    return None


def stack_edit(method, ea, params):
    import ida_funcs
    import ida_frame
    import ida_typeinf as ti
    name, offset = params.get("var_name") or params.get("stack_name") or "", params.get("offset") or 0
    if method == "apply_type":
        offset = params.get("stack_offset") or 0
    result = {"function": hex(ea), "name": name, "offset": offset,
              "code": ti.TERR_BAD_TYPE, "status": "error"}
    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        result["code"] = ti.TERR_BAD_ARG
        return result
    if method == "create_stack_variable":
        tif, parsed = parse_type(params["decl"], params.get("relaxed", False))
        if parsed is not None and ida_frame.define_stkvar(pfn, name or None, offset, tif):
            result.update(code=ti.TERR_OK, status="ok", name=name or ida_frame.build_stkvar_name(pfn, offset) or "")
        return result
    frame, udt = ti.tinfo_t(), ti.udt_type_data_t()
    if not ida_frame.get_func_frame(frame, pfn) or not frame.get_udt_details(udt, ti.GTD_CALC_LAYOUT):
        result["code"] = ti.TERR_BAD_ARG if method == "delete_stack_variable" else ti.TERR_BAD_TYPE
        return result
    use_offset = params.get("stack_offset") if method == "apply_type" else params.get("offset")
    index = frame_member(pfn, udt, name, use_offset)
    if index is None:
        result["code"] = ti.TERR_NOT_FOUND
        return result
    if method == "delete_stack_variable":
        result["code"] = frame.del_udm(index, 0)
    else:
        tif, parsed = parse_type(params["decl"], params.get("relaxed", False))
        if parsed is not None:
            result["code"] = frame.set_udm_type(index, tif, ti.ETF_NO_ARRAY if params.get("strict") else 0)
    if result["code"] == ti.TERR_OK:
        result.update(status="ok", name=udt[index].name)
    return result


def invoke_type(method, params, resolve):
    import ida_funcs
    import ida_frame
    import ida_range
    import ida_typeinf as ti

    if method in ("list_local_types", "list_enums"):
        items = []
        pattern = (params.get("filter") or "").lower()
        for ordinal, name, tif in local_types():
            if pattern not in name.lower() or (method == "list_enums" and not tif.is_enum()):
                continue
            item = {"ordinal": ordinal, "name": name, "decl": tif.dstr()}
            if method == "list_local_types":
                item["kind"] = type_kind(tif)
            items.append(item)
        offset, limit = params.get("offset") or 0, params.get("limit")
        limit = 100 if limit is None else limit
        page = items[offset:offset + limit]
        value = {"types" if method == "list_local_types" else "enums": page, "total": len(items)}
        if method == "list_enums" or offset + len(page) < len(items):
            value["next_offset"] = offset + len(page) if offset + len(page) < len(items) else None
        return value
    if method in ("declare_c_type", "create_enum"):
        relaxed = method == "create_enum" or params.get("relaxed", False)
        if params.get("multi"):
            flags = ti.HTI_HIGH | (ti.HTI_RELAXED if relaxed else 0)
            return {"errors": ti.parse_decls(None, params["decl"], None, flags)}
        tif, name = parse_type(params["decl"], relaxed)
        value = {"code": ti.TERR_BAD_TYPE, "name": "", "decl": "", "kind": ""}
        if name is not None:
            if name:
                flags = ti.NTF_COPY | (ti.NTF_REPLACE if params.get("replace") else 0)
                value.update(code=tif.set_named_type(None, name, flags), name=name,
                             decl=tif.dstr(), kind=type_kind(tif))
            else:
                value["code"] = ti.TERR_BAD_NAME
        if method == "create_enum":
            if value["code"] < 0:
                raise ValueError(f"IDA error: Failed to create enum (code {value['code']}): {params['decl']}")
        else:
            value["replaced"] = params.get("replace") or False
        return value
    if method in ("rename_stack_variable", "set_stack_variable_type"):
        ea = resolve(params.get("func_address"), params.get("func_name"))
        if method == "set_stack_variable_type":
            edited = stack_edit("apply_type", ea, {"stack_name": params["name"], "decl": params["type_decl"], "relaxed": True})
            if edited["code"] < 0:
                raise ValueError(f"IDA error: Failed to set type for '{params['name']}': code {edited['code']}")
            return {"func_address": hex(ea), "variable": edited["name"], "type": params["type_decl"]}
        pfn, _, udt = frame_data(ea)
        index = frame_member(pfn, udt, params["name"], None)
        if index is None:
            if method == "rename_stack_variable":
                raise ValueError(f"IDA error: Stack variable '{params['name']}' not found in function at {ea:#x}")
            raise ValueError(f"IDA error: Failed to set type for '{params['name']}': code {ti.TERR_NOT_FOUND}")
        member = udt[index]
        if method == "rename_stack_variable":
            offset = member.offset // 8 - pfn.frsize
            edited = stack_edit("create_stack_variable", ea, {"var_name": params["new_name"],
                "offset": offset, "decl": member.type.dstr() or "int", "relaxed": True})
            if edited["code"] < 0:
                raise ValueError(f"IDA error: Failed to rename stack variable: code {edited['code']}")
            return {"func_address": hex(ea), "old_name": params["name"], "new_name": edited["name"], "offset": offset}
    ea = resolve(params.get("address"), params.get("target_name", params.get("name")),
                 params.get("offset") or 0 if method not in ("create_stack_variable", "delete_stack_variable") else 0)
    if method == "get_stack_frame":
        pfn, _, udt = frame_data(ea)
        parts = {}
        for name, part in (("args", ida_frame.FPC_ARGS), ("retaddr", ida_frame.FPC_RETADDR),
                           ("savregs", ida_frame.FPC_SAVREGS), ("locals", ida_frame.FPC_LVARS)):
            bounds = ida_range.range_t()
            ida_frame.get_frame_part(bounds, pfn, part)
            parts[name] = (bounds.start_ea, bounds.end_ea)
        members = []
        for member in udt:
            off = member.offset // 8
            part = next((name for name, (a, b) in parts.items()
                         if (a <= off < b if a <= b else b <= off < a)), "unknown")
            members.append({"name": member.name, "type_name": member.type.dstr(),
                "offset_bits": member.offset, "size_bits": member.size, "offset": off,
                "size": (member.size + 7)//8, "is_bitfield": member.is_bitfield(), "part": part})
        value = {"address": hex(ea), "frame_size": ida_frame.get_frame_size(pfn),
            "ret_size": ida_frame.get_frame_retsize(pfn), "frsize": pfn.frsize,
            "frregs": pfn.frregs, "argsize": pfn.argsize, "fpd": pfn.fpd,
            "member_count": len(udt), "members": members}
        value.update({name + "_range": {"start": hex(a), "end": hex(b)} for name, (a, b) in parts.items()})
        return value
    if method in ("create_stack_variable", "delete_stack_variable"):
        if method == "delete_stack_variable" and params.get("offset") is None and params.get("var_name") is None:
            raise ValueError("Invalid parameters: delete_stack requires offset or name")
        return stack_edit(method, ea, params)
    if method == "apply_type":
        if params.get("stack_offset") is not None or params.get("stack_name") is not None:
            if params.get("decl") is None:
                raise ValueError("Invalid parameters: apply_types for stack var requires decl")
            return stack_edit(method, ea, params)
        if params.get("decl") is not None:
            tif, name = parse_type(params["decl"], params.get("relaxed", False))
            flags = ti.TINFO_DEFINITE | (ti.TINFO_DELAYFUNC if params.get("delay") else 0) | (ti.TINFO_STRICT if params.get("strict") else 0)
            ok = name is not None and ti.apply_tinfo(ea, tif, flags)
            source = "decl"
        elif params.get("type_name") is not None:
            ok, source = ti.apply_named_type(ea, params["type_name"]), "named"
        else:
            raise ValueError("Invalid parameters: apply_types requires decl or type_name")
        return {"address": hex(ea), "applied": bool(ok), "source": source}
    if method == "set_function_prototype":
        tif, name = parse_type(params["prototype"], True)
        if name is None or not ti.apply_tinfo(ea, tif, ti.TINFO_DEFINITE):
            raise ValueError(f"IDA error: Failed to apply prototype '{params['prototype']}' at {ea:#x}")
        return {"address": hex(ea), "prototype": params["prototype"], "applied": True}
    if method in ("infer_type", "get_function_prototype"):
        tif = ti.tinfo_t()
        code = ti.guess_tinfo(tif, ea)
        if method == "get_function_prototype":
            if code == 0:
                raise ValueError(f"IDA error: No type information at {ea:#x}")
            return {"address": hex(ea), "prototype": tif.dstr(), "kind": type_kind(tif)}
        return {"address": hex(ea), "code": code, "decl": tif.dstr(), "kind": type_kind(tif),
                "status": {0: "failed", 1: "trivial", 2: "ok"}.get(code, "unknown")}
    raise ValueError(f"unimplemented type method: {method}")
