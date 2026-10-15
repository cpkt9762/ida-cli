"""N4 business code, evaluated only inside an already leased Nexus database.

Public IDAPython APIs preserve the native-linked N0 JSON contract. No database
opening, process creation, or legacy execution belongs in this module.
"""

METHODS = ("get_database_info", "get_analysis_status", "list_functions",
           "get_function_by_name", "get_function_at_address", "get_xrefs_to",
           "get_xrefs_from", "disassemble", "disassemble_function",
           "disassemble_function_at", "decompile_function", "run_script")


def processor_name():
    """Read the public IDA 9.5 SDK processor_t prefix, absent from IDAPython.

    SDK idp.hpp declares get_ph(), psnames/plnames and get_proc_index().
    Validate the ABI and selected short name before reading the long name.
    This executes inside IDA; it does not inspect Nexus internals.
    """
    import ctypes
    import ida_ida
    import ida_idp
    import ida_kernwin

    if ida_kernwin.get_kernel_version() != "9.5":
        raise RuntimeError("processor long-name SDK adapter requires IDA 9.5")

    class Prefix(ctypes.Structure):
        _fields_ = [("version", ctypes.c_int32), ("id", ctypes.c_int32),
                    ("flag", ctypes.c_uint32), ("flag2", ctypes.c_uint32),
                    ("cnbits", ctypes.c_int32), ("dnbits", ctypes.c_int32),
                    ("psnames", ctypes.POINTER(ctypes.c_char_p)),
                    ("plnames", ctypes.POINTER(ctypes.c_char_p))]

    get_ph = ctypes.CDLL(None).get_ph
    get_ph.argtypes = []
    get_ph.restype = ctypes.POINTER(Prefix)
    pointer = get_ph()
    if not pointer:
        raise RuntimeError("public SDK get_ph returned null")
    ph = pointer.contents
    expected = (900, ida_idp.ph_get_id(), ida_idp.ph_get_flag(),
                ida_idp.ph_get_cnbits(), ida_idp.ph_get_dnbits())
    actual = (ph.version, ph.id, ph.flag, ph.cnbits, ph.dnbits)
    if ctypes.sizeof(ctypes.c_void_p) != 8 or actual != expected:
        raise RuntimeError("public SDK processor_t ABI validation failed")
    index = ida_idp.get_ph().get_proc_index()
    if not 0 <= index < 256 or not ph.psnames or not ph.plnames:
        raise RuntimeError("public SDK processor name index/pointers invalid")
    # Walk to the selected subtype without crossing either null terminator.
    for position in range(index + 1):
        short, long = ph.psnames[position], ph.plnames[position]
        if not short or not long:
            raise RuntimeError("public SDK processor name array ended early")
    if short.decode("utf-8").lstrip("-") != ida_ida.inf_get_procname():
        raise RuntimeError("public SDK processor subtype does not match database")
    return long.decode("utf-8")


def invoke(method, params):
    import ida_auto
    import ida_funcs
    import ida_ida
    import ida_idaapi
    import ida_idp
    import ida_loader
    import ida_nalt
    import idautils
    import idc

    def failure(message):
        return {"ok": False, "error": message}

    def status():
        state = ida_auto.get_auto_state()
        states = {0: "NONE", 10: "UNK", 20: "CODE", 25: "WEAK", 30: "PROC",
                  35: "TAIL", 38: "FCHUNK", 40: "USED", 45: "USD2", 50: "TYPE",
                  60: "LIBF", 70: "LBF2", 80: "LBF3", 90: "CHLB", 200: "FINAL"}
        enabled = ida_ida.inf_is_auto_enabled()
        ready = ida_auto.auto_is_ok()
        return {"auto_enabled": enabled, "auto_is_ok": ready,
                "auto_state": "AU_" + states.get(state, "UNKNOWN"),
                "auto_state_id": state, "analysis_running": enabled and not ready}

    def functions():
        for index in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(index)
            if func:
                yield func, {"address": hex(func.start_ea),
                             "name": ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}",
                             "size": func.end_ea - func.start_ea}

    def named(name):
        return next(((func, info) for func, info in functions()
                     if name == info["name"] or name in info["name"]), (None, None))

    def address():
        value = params.get("address", params.get("addr"))
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**64:
            return value
        if isinstance(value, str):
            value = value.strip()
            try:
                result = int(value[2:], 16) if value.startswith(("0x", "0X")) else int(value, 10)
                if 0 <= result < 2**64:
                    return result
            except ValueError:
                pass
        return None

    def target():
        ea = address()
        if ea is not None:
            return min(2**64 - 1, ea + unsigned("offset", 0))
        name = params.get("target_name", params.get("name"))
        if isinstance(name, str):
            func, _ = named(name)
            if func:
                return min(2**64 - 1, func.start_ea + unsigned("offset", 0))
            for entry, symbol in idautils.Names():
                if name == symbol or name in symbol:
                    return min(2**64 - 1, entry + unsigned("offset", 0))
        return None

    def unsigned(key, default):
        value = params.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**64 else default

    def disasm(ea, count, end=None):
        import ida_bytes
        import ida_lines
        import ida_ua
        lines = []
        while len(lines) < count and (end is None or ea < end):
            text = idc.generate_disasm_line(ea, 0)
            if not text:
                break
            lines.append(f"{ea:#x}:\t{ida_lines.tag_remove(text)}")
            insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(insn, ea)
            following = ea + size if size else ida_bytes.next_head(ea, ida_idaapi.BADADDR)
            if following == ida_idaapi.BADADDR or following <= ea:
                break
            ea = following
        return "\n".join(lines)

    if method in ("disassemble", "decompile_function") and isinstance(params.get("address"), list):
        results = []
        for ea in params["address"]:
            item = invoke(method, dict(params, address=ea, _multiple=True))
            entry = {"address": hex(ea)}
            entry.update(item["value"] if item["ok"] else {"error": item["error"]})
            results.append(entry)
        return {"ok": True, "value": {"results": results}}
    if method == "get_analysis_status":
        value = status()
    elif method == "get_database_info":
        file_types = ("OldEXE", "OldCOM", "BIN", "DRV", "WIN", "HEX", "MEX", "LX",
                      "LE", "NLM", "COFF", "PE", "OMF", "SREC", "ZIP", "OMFLIB", "AR",
                      "LOADER", "ELF", "W32RUN", "AOUT", "PRC", "EXE", "COM", "AIXAR",
                      "MACHO", "PSXOBJ", "MD1IMG")
        file_type = ida_ida.inf_get_filetype()
        processor = processor_name()
        base = ida_ida.inf_get_baseaddr()
        main = ida_ida.inf_get_main()
        md5 = ida_nalt.retrieve_input_file_md5()
        sha256 = ida_nalt.retrieve_input_file_sha256()
        value = {"file_type": file_types[file_type],
                 "processor": processor, "bits": 64 if ida_ida.inf_is_64bit() else
                 (32 if ida_ida.inf_is_32bit_exactly() else 16),
                 "function_count": ida_funcs.get_func_qty(),
                 "input_file_path": ida_nalt.get_input_file_path(),
                 "input_file_size": ida_nalt.retrieve_input_file_size(),
                 "md5": md5.hex() if md5 else "", "sha256": sha256.hex() if sha256 else "",
                 "base_address": hex(base) if base != ida_idaapi.BADADDR else None,
                 "min_address": hex(ida_ida.inf_get_min_ea()), "max_address": hex(ida_ida.inf_get_max_ea()),
                 "main_address": hex(main) if main != ida_idaapi.BADADDR else None}
    elif method == "list_functions":
        pattern = params.get("filter")
        items = [info for _, info in functions()
                 if not isinstance(pattern, str) or pattern.lower() in info["name"].lower()]
        offset, limit = unsigned("offset", 0), unsigned("limit", 100)
        page = items[offset:offset + limit]
        following = offset + len(page)
        value = {"functions": page, "total": len(items)}
        if following < len(items):
            value["next_offset"] = following
    elif method in ("get_function_by_name", "disassemble_function"):
        name = params.get("name")
        if not isinstance(name, str):
            return failure("Invalid parameters: missing name")
        func, info = named(name)
        if not func:
            return failure(f"Function not found: {name}")
        if method == "get_function_by_name":
            value = info
        else:
            text = disasm(func.start_ea, unsigned("count", 10))
            if not text:
                return failure(f"Address {func.start_ea:#x} is outside valid range")
            value = {"disasm": text}
    elif method in ("get_function_at_address", "disassemble_function_at"):
        ea = target()
        if ea is None:
            name = params.get("target_name", params.get("name"))
            return failure(f"Function not found: {name}" if isinstance(name, str) else "Invalid parameters: expected address or name")
        func = ida_funcs.get_func(ea)
        if not func:
            return failure(f"Function not found at address {ea:#x}")
        if method == "get_function_at_address":
            value = {"address": hex(func.start_ea), "name": ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}",
                     "start": hex(func.start_ea), "end": hex(func.end_ea),
                     "size": func.end_ea - func.start_ea}
        else:
            text = disasm(func.start_ea, unsigned("count", 200), func.end_ea)
            if not text:
                return failure(f"Address {ea:#x} is outside valid range")
            value = {"disasm": text}
    elif method in ("get_xrefs_to", "get_xrefs_from"):
        ea = address() or 0
        code_types = {0: "Unknown", 16: "FarCall", 17: "NearCall", 18: "FarJump",
                      19: "NearJump", 20: "Obsolete", 21: "Flow"}
        data_types = {0: "Unknown", 1: "Offset", 2: "Write", 3: "Read", 4: "Text",
                      5: "Informational", 6: "EnumMember"}
        refs = idautils.XrefsTo(ea, 0) if method == "get_xrefs_to" else idautils.XrefsFrom(ea, 0)
        value = [{"from": hex(ref.frm), "to": hex(ref.to), "is_code": bool(ref.iscode),
                  "type": ("Code(" + code_types[ref.type & 31] + ")") if ref.iscode else
                  ("Data(" + data_types[ref.type & 31] + ")")} for ref in refs]
    elif method in ("disassemble", "decompile_function"):
        ea = address()
        if ea is None:
            return failure("Invalid address format: missing address")
        if method == "disassemble":
            text = disasm(ea, unsigned("count", 10))
            if not text:
                return failure(f"Address {ea:#x} is outside valid range")
            value = {"disasm": text}
        else:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                return failure("Decompiler not available")
            func = ida_funcs.get_func(ea)
            if not func:
                return failure(f"Function not found at address {ea:#x}")
            code = str(ida_hexrays.decompile(func))
            signature = next((line for line in code.splitlines() if line.strip()
                              and not line.strip().startswith(("//", "/*")) and "(" in line), "")
            if not params.get("_multiple") and any(name in signature for name in ("sub_", "nullsub_", "j_sub_")):
                code = (chr(0x1F4A1) + " If you understand this function's purpose, "
                        "immediately call rename_symbol to rename it before proceeding.\n\n" + code)
            value = {"code": code}
    elif method == "run_script":
        import __main__
        import contextlib
        import io
        import traceback
        stdout, stderr = io.StringIO(), io.StringIO()
        success, message = True, None
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                # Native N0's extlang wrapper executes user code on line 11.
                # Keep that frame for uncaught SystemExit/KeyboardInterrupt;
                # Nexus's internal cancellation BaseException must propagate.
                __main__.__dict__["_mcp_code_input"] = params.get("code") or ""
                exec("\n" * 10 + "exec(_mcp_code_input)", __main__.__dict__)
            except Exception as exc:
                message = str(exc)
                success = not bool(message)  # N0 treats an empty error string as success.
            except (SystemExit, KeyboardInterrupt) as exc:
                success = False
                message = "failed to execute wrapper: " + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__.tb_next))
                stdout, stderr = io.StringIO(), io.StringIO()
            finally:
                __main__.__dict__.pop("_mcp_code_input", None)

        def truncate(text):
            # Match native N0's C-string/UTF-8 boundary and 1 MiB per stream cap.
            raw = text.split("\0", 1)[0].encode("utf-8")
            return raw[:1024 * 1024].decode("utf-8", "ignore") + "\n... [truncated at 1MB]" if len(raw) > 1024 * 1024 else raw.decode("utf-8")

        out, err = truncate(stdout.getvalue()), truncate(stderr.getvalue())
        value = {"success": success, "stdout": out, "stderr": err}
        summary = message.strip() if message and message.strip() else next((line.strip() for line in reversed(err.splitlines()) if line.strip()), None)
        if message:
            value["error"] = truncate(message)
        elif not success and summary:
            value["error"] = summary
        if summary:
            value["error_summary"] = summary
        details = ((summary or "") + "\n" + err).lower()
        for kind, needles in (("SyntaxError", ("syntaxerror", "invalid syntax")),
                              ("NameError", ("nameerror",)), ("AttributeError", ("attributeerror",)),
                              ("ImportError", ("importerror", "modulenotfounderror")),
                              ("TypeError", ("typeerror",)), ("ValueError", ("valueerror",))):
            if any(needle in details for needle in needles):
                value["error_kind"] = kind
                break
    else:
        raise ValueError(f"Nexus method {method} is not implemented in N4")
    return {"ok": True, "value": value}
