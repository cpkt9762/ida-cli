"""N6 local UDT inspection, including public type-member xrefs."""
STRUCT_METHODS = ("list_structs", "get_struct_info", "read_struct_at_address", "get_xrefs_to_struct_field")


def struct_types():
    import ida_typeinf as ti
    for ordinal, name, tif in local_types():
        if not (tif.is_struct() or tif.is_union()):
            continue
        udt = ti.udt_type_data_t()
        if tif.get_udt_details(udt, ti.GTD_CALC_LAYOUT):
            yield {"ordinal": ordinal, "name": name, "size": udt.total_size,
                   "is_union": udt.is_union, "member_count": len(udt)}, tif, udt


def invoke_struct(method, params, parse_address, xrefs):
    import ida_bytes
    import ida_idaapi
    import ida_xref
    import idautils
    if method == "list_structs":
        pattern = (params.get("filter") or "").lower()
        items = [item[0] for item in struct_types() if pattern in item[0]["name"].lower()]
        offset, limit = params.get("offset") or 0, params.get("limit")
        page = items[offset:offset + (100 if limit is None else limit)]
        result = {"structs": page, "total": len(items)}
        if offset + len(page) < len(items):
            result["next_offset"] = offset + len(page)
        return result
    ordinal, name = params.get("ordinal"), params.get("name")
    found = None
    if ordinal is not None:
        found = next((item for item in struct_types() if item[0]["ordinal"] == ordinal), None)
        if found is None:
            raise ValueError(f"Invalid parameters: unknown struct ordinal: {ordinal}")
    elif name is not None:
        query = name.strip()
        strip = lambda text: text.removeprefix("struct ").removeprefix("union ")
        found = next((item for item in struct_types() if item[0]["name"] == query or strip(item[0]["name"]) in (query, strip(query))), None)
        if found is None:
            fuzzy = [item for item in struct_types() if query.lower() in item[0]["name"].lower()]
            if len(fuzzy) == 1:
                found = fuzzy[0]
        if found is None:
            raise ValueError(f"Invalid parameters: unknown struct name: {name}")
    else:
        label = {"get_struct_info": "struct_info requires ordinal or name", "read_struct_at_address": "read_struct requires ordinal or name",
                 "get_xrefs_to_struct_field": "xrefs_to_field requires struct ordinal or name"}[method]
        raise ValueError("Invalid parameters: " + label)
    info, tif, udt = found
    if method == "get_xrefs_to_struct_field":
        index, member_name = params.get("member_index"), params.get("member_name")
        if index is None:
            if member_name is None:
                raise ValueError("Invalid parameters: xrefs_to_field requires member index or name")
            index = next((i for i, m in enumerate(udt) if m.name == member_name), None)
            if index is None:
                raise ValueError(f"Invalid parameters: unknown struct member name: {member_name} in {info['name']}")
        if index >= len(udt):
            raise ValueError(f"Invalid parameters: member index out of range: {index} (member_count={len(udt)})")
        tid, member = tif.get_udm_tid(index), udt[index]
        if tid == ida_idaapi.BADADDR:
            raise ValueError("Invalid parameters: struct member has no TID")
        limit = params.get("limit")
        limit = 100 if limit is None else limit
        refs = list(idautils.XrefsTo(tid, ida_xref.XREF_TID))
        return {"struct_ordinal": info["ordinal"], "struct_name": info["name"], "member_index": index,
                "member_name": member.name, "member_type": member.type.dstr(), "member_offset_bits": member.offset,
                "member_size_bits": member.size, "tid": hex(tid), "xrefs": [xrefs(r) for r in refs[:limit]], "truncated": len(refs) > limit}
    members = []
    ea = parse_address(params.get("address")) or 0
    for member in udt:
        off, size = member.offset // 8, (member.size+7)//8
        item = {"name": member.name, "type_name": member.type.dstr(), "offset_bits": member.offset,
                "size_bits": member.size, "offset": off, "size": size, "is_bitfield": member.is_bitfield()}
        if method == "read_struct_at_address":
            item["bytes"] = (ida_bytes.get_bytes(min(2**64-1, ea + off), min(0x10000, size)) or b"").hex() if size else ""
        members.append(item)
    result = dict(info, members=members)
    if method == "read_struct_at_address":
        result.pop("member_count")
        result.pop("is_union")
        result["address"] = hex(ea)
    return result
