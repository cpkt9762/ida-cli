"""N6 control flow and database queries using public IDAPython."""
ANALYSIS_METHODS = ("get_basic_blocks", "get_callers", "get_callees", "build_callgraph",
                    "find_control_flow_paths", "build_xref_matrix", "list_segments",
                    "list_imports", "list_exports", "list_entry_points")


def function_info(func):
    import ida_funcs
    return {"address": hex(func.start_ea), "name": ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}",
            "size": func.end_ea - func.start_ea}


def call_relations(ea, callers=False):
    import ida_bytes
    import ida_funcs
    import ida_idaapi
    import idautils
    func = ida_funcs.get_func(ea)
    if not func:
        raise ValueError(f"Function not found at address {ea:#x}")
    result, seen = [], set()
    if callers:
        refs = idautils.XrefsTo(func.start_ea, 0)
    else:
        def outgoing():
            cursor = func.start_ea
            while cursor < func.end_ea:
                yield from idautils.XrefsFrom(cursor, 0)
                following = ida_bytes.next_head(cursor, ida_idaapi.BADADDR)
                if following == ida_idaapi.BADADDR or following <= cursor:
                    break
                cursor = following
        refs = outgoing()
    for ref in refs:
        if ref.type not in (16, 17):
            continue
        target = ida_funcs.get_func(ref.frm if callers else ref.to)
        if target and target.start_ea not in seen:
            seen.add(target.start_ea)
            result.append(function_info(target))
    return result


def segment_info(seg):
    import ida_segment
    kinds = ("NORM", "XTRN", "CODE", "DATA", "IMP", "GRP", "NULL", "UNDF", "BSS", "ABSSYM", "COMM", "IMEM")
    return {"name": ida_segment.get_segm_name(seg), "start": hex(seg.start_ea), "end": hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea, "permissions": ''.join(c if seg.perm & flag else '-'
                for flag, c in ((4, 'r'), (2, 'w'), (1, 'x'))),
            "type": kinds[seg.type], "bitness": seg.bitness}


def invoke_analysis(method, params, parse_address):
    import ida_funcs
    import ida_gdl
    import ida_idaapi
    import ida_name
    import ida_segment
    import idautils
    if method == "list_segments":
        return [segment_info(ida_segment.getseg(ea)) for ea in idautils.Segments()]
    if method == "list_entry_points":
        return [hex(entry[2]) for entry in idautils.Entries()]
    if method in ("list_imports", "list_exports"):
        items = []
        for ea, name in idautils.Names():
            seg = ida_segment.getseg(ea)
            if method == "list_imports" and (seg is None or seg.type not in (ida_segment.SEG_XTRN, ida_segment.SEG_IMP)):
                continue
            item = {"address": hex(ea), "name": name}
            item["ordinal" if method == "list_imports" else "is_public"] = len(items) if method == "list_imports" else ida_name.is_public_name(ea)
            items.append(item)
        offset, limit = params.get("offset") or 0, params.get("limit")
        return items[offset:offset + (100 if limit is None else limit)]
    if method == "build_xref_matrix":
        addrs = [ea for ea in (parse_address(v) for v in params.get("addrs", [])) if ea is not None]
        refs = {ea: {r.to for r in idautils.XrefsFrom(ea, 0)} for ea in addrs}
        return {"addrs": [hex(ea) for ea in addrs], "matrix": [[b in refs[a] for b in addrs] for a in addrs]}
    if method == "build_callgraph":
        from collections import deque
        roots = params["roots"]
        ea = parse_address(roots[0] if isinstance(roots, list) and roots else roots) or 0
        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"Function not found at address {ea:#x}")
        nodes, edges = {func.start_ea: function_info(func)}, []
        queue = deque([(func.start_ea, 0)])
        depth, maximum = params.get("max_depth"), params.get("max_nodes")
        depth, maximum = max(1, 5 if depth is None else depth), max(1, 100 if maximum is None else maximum)
        while queue:
            current, level = queue.popleft()
            if level >= depth:
                continue
            if len(nodes) >= maximum:
                break
            for callee in call_relations(current):
                target = int(callee["address"], 16)
                edges.append({"from": hex(current), "to": hex(target)})
                if target not in nodes and len(nodes) < maximum:
                    nodes[target] = callee
                    queue.append((target, level+1))
        return {"nodes": [nodes[ea] for ea in sorted(nodes)], "edges": edges}
    ea = parse_address(params.get("start") if method == "find_control_flow_paths" else params.get("address")) or 0
    if method in ("get_callers", "get_callees"):
        return call_relations(ea, method == "get_callers")
    func = ida_funcs.get_func(ea)
    if not func:
        raise ValueError(f"Function not found at address {ea:#x}")
    cfg = list(ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS))
    if method == "get_basic_blocks":
        kinds = ("normal", "indjump", "ret", "cndret", "noret", "enoret", "extern", "error")
        return [{"start": hex(block.start_ea), "end": hex(block.end_ea), "size": block.end_ea - block.start_ea,
                 "block_type": kinds[block.type] if block.type != 5 else "unknown",
                 "successors": [hex(b.start_ea) for b in block.succs()],
                 "predecessors": [hex(b.start_ea) for b in block.preds()]} for block in cfg]
    end = parse_address(params["end"]) or 0
    if not func.contains(end):
        raise ValueError("Not supported: find_paths only supports addresses within the same function")
    start_block = next((b for b in cfg if b.start_ea <= ea < b.end_ea), None)
    end_block = next((b for b in cfg if b.start_ea <= end < b.end_ea), None)
    if start_block is None or end_block is None:
        raise ValueError(f"Address {ea if start_block is None else end:#x} is outside valid range")
    maximum, depth = params.get("max_paths"), params.get("max_depth")
    maximum, depth = max(1, 10 if maximum is None else maximum), max(1, 10 if depth is None else depth)
    paths, stack = [], [(start_block, [])]
    while stack and len(paths) < maximum:
        block, path = stack.pop()
        if len(path) > depth:
            continue
        path = path + [hex(block.start_ea)]
        if block.id == end_block.id:
            paths.append(path)
        else:
            stack.extend((b, path) for b in reversed(list(block.succs())) if hex(b.start_ea) not in path)
    return {"paths": paths, "count": len(paths)}
