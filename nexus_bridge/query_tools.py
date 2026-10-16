"""N6 ordinary data queries; all results contain plain JSON values."""
QUERY_METHODS = ("batch_lookup_functions", "export_functions", "list_globals", "read_global_variable",
                 "list_strings", "get_xrefs_to_string", "get_address_info", "scan_memory_table",
                 "diff_pseudocode", "get_pseudocode_at", "load_debug_info")


def handler_address(raw, parse_address):
    """Legacy handler grammar additionally accepts 0b/0o (RPC grammar does not)."""
    if not isinstance(raw, str):
        return None
    return parse_address(raw, handler=True)


def invoke_query(method, params, resolve, parse_address, invoke):
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_idaapi
    import ida_lines
    import ida_name
    import ida_segment
    import idautils

    if method == "load_debug_info":
        from pathlib import Path
        import ida_kernwin
        import ida_loader
        path = params.get("path")
        if path is None:
            base = Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
            if base.suffix.lower() in ('.i64','.idb'):
                base = base.with_suffix('')
            candidate = Path(str(base)+'.dSYM')/'Contents/Resources/DWARF'/base.name
            if not candidate.exists():
                raise ValueError("Invalid database path: No sibling .dSYM found")
            path = str(candidate)
        if not Path(path).exists():
            raise ValueError("Invalid database path: File not found: "+path)
        return {"path":path,"loaded":ida_kernwin.load_dbg_dbginfo(path,None,ida_idaapi.BADADDR,params.get("verbose") or False)}

    if method == "export_functions":
        return invoke("list_functions", {"offset": params.get("offset") or 0, "limit": params.get("limit") if params.get("limit") is not None else 100})["value"]
    if method == "batch_lookup_functions":
        funcs = [function_info(ida_funcs.getn_func(i)) for i in range(ida_funcs.get_func_qty())]
        results = []
        for query in params["queries"]:
            ea = handler_address(query, parse_address)
            func = ida_funcs.get_func(ea) if ea is not None else None
            item = function_info(func) if func else (next((f for f in funcs if query == f["name"] or query in f["name"]), None) if ea is None else None)
            results.append({"query": query, "result": item} if item else {"query": query, "error": "Function not found"})
        return {"results": results}
    if method == "list_globals":
        pattern = (params.get("query") or "").lower()
        items = [{"address": hex(ea), "name": name, "is_public": ida_name.is_public_name(ea), "is_weak": ida_name.is_weak_name(ea)}
                 for ea, name in idautils.Names() if pattern in name.lower() and ida_funcs.get_func(ea) is None]
        offset, limit = params.get("offset") or 0, params.get("limit")
        page = items[offset:offset+(100 if limit is None else limit)]
        return {"globals": page, "total": len(items), "next_offset": offset+len(page) if offset+len(page)<len(items) else None}
    if method == "read_global_variable":
        query = params["query"]
        ea = handler_address(query, parse_address)
        if ea is None:
            ea = next((ea for ea, name in idautils.Names() if name == query), None)
        if ea is None:
            raise ValueError(f"Function not found: {query}")
        raw = ida_bytes.get_bytes(ea, 8) or b""
        value = int.from_bytes(raw, 'little')
        return {"address": hex(ea), "value": value, "hex": hex(value), "bytes": raw.hex()}
    if method in ("list_strings", "get_xrefs_to_string"):
        query = params.get("query", params.get("filter"))
        query = query if isinstance(query, str) else None
        insensitive = params.get("case_insensitive", True)
        insensitive = insensitive if type(insensitive) is bool else True
        exact = params.get("exact") is True
        items = []
        strings = idautils.Strings()
        for item in strings:
            content = (ida_bytes.get_bytes(item.ea, item.length) or b'').decode('utf-8', errors='replace')
            hay, needle = (content.lower(), query.lower()) if query is not None and insensitive else (content, query)
            if query is not None and not (hay == needle if exact else needle in hay):
                continue
            entry = {"address": hex(item.ea), "content": content, "length": len(content.encode('utf-8'))}
            if method == "get_xrefs_to_string":
                maximum = max(1, min(1024, params.get("max_xrefs") if params.get("max_xrefs") is not None else 10))
                refs = [hex(ref.frm) for ref in idautils.XrefsTo(item.ea, 0)][:maximum]
                entry.update(xrefs=refs, xref_count=len(refs))
            items.append(entry)
        offset, limit = params.get("offset") or 0, params.get("limit")
        page = items[offset:offset+(100 if limit is None else limit)]
        result = {"strings": page, "total": len(items)}
        if offset+len(page)<len(items):
            result["next_offset"] = offset+len(page)
        return result
    if method == "get_address_info":
        ea = resolve(params.get("address"), params.get("target_name"), params.get("offset") or 0)
        seg, func = ida_segment.getseg(ea), ida_funcs.get_func(ea)
        names = list(idautils.Names())
        # SDK get_nlist_idx returns the closest preceding name.
        index = ida_name.get_nlist_idx(ea)
        symbol = None
        if 0 <= index < len(names):
            address, name = names[index]
            delta = max(-2**63, min(2**63-1, ea-address))
            symbol = {"name": name, "address": hex(address), "delta": delta, "exact": delta==0,
                      "is_public": ida_name.is_public_name(address), "is_weak": ida_name.is_weak_name(address)}
        function = dict(function_info(func), start=hex(func.start_ea), end=hex(func.end_ea)) if func else None
        return {"address": hex(ea), "segment": segment_info(seg) if seg else None, "function": function, "symbol": symbol}
    if method == "scan_memory_table":
        ea = parse_address(params["base_address"])
        if ea is None:
            raise ValueError("Invalid parameters: base_address is required")
        stride = max(1, 8 if params.get("stride") is None else params["stride"])
        count = min(256, 16 if params.get("count") is None else params["count"])
        entries = [{"index": i, "address": hex(ea+i*stride), "bytes": (ida_bytes.get_bytes(ea+i*stride, min(stride,0x10000)) or b"").hex()} for i in range(count)]
        return {"base_address": hex(ea), "stride": stride, "count": len(entries), "entries": entries}
    if method == "diff_pseudocode":
        codes = []
        for key in ("addr1", "addr2"):
            ea = parse_address(params[key])
            if ea is None:
                raise ValueError(f"Invalid parameters: {key} is required")
            answer = invoke("decompile_function", {"address": ea, "_multiple": True})
            if not answer["ok"]:
                raise ValueError(answer["error"])
            codes.append(answer["value"]["code"])
        a, b = (code.splitlines() for code in codes)
        diff, same, different = [], 0, 0
        for i in range(max(len(a),len(b))):
            if i < len(a) and i < len(b) and a[i]==b[i]:
                same+=1; diff.append('  '+a[i])
            else:
                different+=1
                if i<len(a): diff.append('- '+a[i])
                if i<len(b): diff.append('+ '+b[i])
        import math
        similarity = math.floor((same/(same+different) if same+different else 1)*100+0.5)/100
        return {"function1": codes[0], "function2": codes[1], "similarity_ratio": similarity, "diff_lines": diff}
    if method == "get_pseudocode_at":
        ea = parse_address(params["address"]) or 0
        end = parse_address(params.get("end_address"))
        if not ida_hexrays.init_hexrays_plugin():
            raise ValueError("Decompiler not available")
        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"Function not found at address {ea:#x}")
        failure = ida_hexrays.hexrays_failure_t()
        cf = ida_hexrays.decompile(func, failure, ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_NO_CACHE)
        if cf is None:
            raise ValueError('IDA error: '+failure.desc())
        # The N0 contract samples CFS_BOUNDS before materializing either map.
        eamap_ready = bool(cf.statebits & ida_hexrays.CFS_BOUNDS)
        eamap, bounds = cf.get_eamap(), cf.get_boundaries()
        statements, seen = [], set()
        for cursor in range(ea, ea+1 if end is None else end):
            mapped = ida_hexrays.eamap_find(eamap, cursor)
            for stmt in ida_hexrays.eamap_second(mapped) if mapped != ida_hexrays.eamap_end(eamap) else []:
                if stmt.ea in seen:
                    continue
                seen.add(stmt.ea)
                iterator = ida_hexrays.boundaries_find(bounds, stmt)
                ranges = ida_hexrays.boundaries_second(iterator) if iterator != ida_hexrays.boundaries_end(bounds) else None
                first = ranges.getrange(0) if ranges is not None and not ranges.empty() else None
                statements.append({"address": hex(stmt.ea), "text": ida_lines.tag_remove(stmt.print1(cf)).strip(),
                    "opcode": stmt.op, "bounds": {"start": hex(first.start_ea), "end": hex(first.end_ea)} if first else None})
        return {"function": {"address": hex(func.start_ea), "name": ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}",
                "start": hex(func.start_ea), "end": hex(func.end_ea)}, "query_address": hex(ea), "query_end_address": hex(end) if end is not None else None,
                "eamap_ready": eamap_ready, "statements": statements, "count": len(statements)}
    raise ValueError(f"unimplemented query method: {method}")
