//! IDAPython script generators for register, memory, thread, and event inspection.

/// Generate a script to read register values from the debugged process.
pub fn generate_get_registers_script(register_names: Option<&[String]>) -> String {
    let filter_code = match register_names {
        Some(names) if !names.is_empty() => {
            let names_py: Vec<String> = names.iter().map(|n| format!("\"{}\"", n)).collect();
            format!("names = [{}]", names_py.join(", "))
        }
        _ => r#"import ida_idp
_raw = list(ida_idp.ph_get_regnames())
names = []
_seen = set()
for _n in _raw:
    rv = ida_idd.regval_t()
    if ida_dbg.get_reg_val(_n, rv) and _n not in _seen:
        names.append(_n)
        _seen.add(_n)"#
            .to_string(),
    };
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot read registers: state={{state}}, need DSTATE_SUSP(-1)")
else:
    regs = {{}}
    {filter_code}
    for name in names:
        rv = ida_idd.regval_t()
        if ida_dbg.get_reg_val(name, rv):
            regs[name] = safe_hex(rv.ival)
    ip = safe_hex(ida_dbg.get_ip_val())
    sp = safe_hex(ida_dbg.get_sp_val())
    make_result(True, {{"registers": regs, "ip": ip, "sp": sp}})
"#,
        filter_code = filter_code,
    );
    super::build_script(&body)
}

/// Generate a script to set a register value in the debugged process.
pub fn generate_set_register_script(register_name: &str, value: u64) -> String {
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot set register: state={{state}}, need DSTATE_SUSP(-1)")
else:
    rv = ida_idd.regval_t()
    rv.ival = {value}
    ok = ida_dbg.set_reg_val("{register_name}", rv)
    make_result(ok, {{"register": "{register_name}", "value": safe_hex({value}), "set_ok": ok}})
"#,
        register_name = register_name,
        value = value,
    );
    super::build_script(&body)
}

/// Generate a script to read bytes from debugged process memory.
pub fn generate_read_memory_script(address: u64, size: u64) -> String {
    let clamped = size.min(4096);
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot read memory: state={{state}}, need DSTATE_SUSP(-1)")
else:
    import idc as _idc
    size = min({clamped}, 4096)
    data = _idc.read_dbg_memory({address}, size)
    if data is not None and len(data) > 0:
        hex_str = data.hex()
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        make_result(True, {{
            "address": safe_hex({address}),
            "size": len(data),
            "hex": hex_str,
            "ascii": ascii_str,
        }})
    else:
        make_result(False, error=f"Failed to read {{size}} bytes at {{safe_hex({address})}}")
"#,
        clamped = clamped,
        address = address,
    );
    super::build_script(&body)
}

/// Generate a script to write bytes to debugged process memory.
pub fn generate_write_memory_script(address: u64, data_hex: &str) -> String {
    let clean_hex = data_hex.replace(' ', "");
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot write memory: state={{state}}, need DSTATE_SUSP(-1)")
else:
    import idc as _idc
    data_bytes = bytes.fromhex("{clean_hex}")
    ok = _idc.write_dbg_memory({address}, data_bytes)
    make_result(bool(ok), {{"address": safe_hex({address}), "bytes_written": len(data_bytes) if ok else 0, "ok": bool(ok)}})
"#,
        clean_hex = clean_hex,
        address = address,
    );
    super::build_script(&body)
}

/// Generate a script to enumerate memory regions of the debugged process.
pub fn generate_get_memory_info_script() -> String {
    let body = r#"
import idaapi
ranges = idaapi.meminfo_vec_t()
n = ida_dbg.get_dbg_memory_info(ranges)
if n < 0:
    make_result(False, error=f"get_dbg_memory_info failed (code={n}). This debug server may not support memory region enumeration.")
else:
    regions = []
    for i in range(n):
        r = ranges[i]
        regions.append({
            "start": safe_hex(r.start_ea),
            "end": safe_hex(r.end_ea),
            "name": str(r.name) if r.name else "",
            "sclass": str(r.sclass) if hasattr(r, "sclass") else "",
            "perm": int(r.perm) if hasattr(r, "perm") else 0,
        })
    make_result(True, {"regions": regions, "count": len(regions)})
"#;
    super::build_script(body)
}

/// Generate a script to list all threads in the debugged process.
pub fn generate_list_threads_script() -> String {
    let body = r#"
threads = []
for i in range(ida_dbg.get_thread_qty()):
    tid = ida_dbg.getn_thread(i)
    name = ""
    try:
        name = ida_dbg.getn_thread_name(i) or ""
    except Exception:
        pass
    threads.append({"id": tid, "name": name, "index": i})
current = ida_dbg.get_current_thread()
make_result(True, {"threads": threads, "current_thread": current, "count": len(threads)})
"#;
    super::build_script(body)
}

/// Generate a script to select a thread as the current debugging context.
pub fn generate_select_thread_script(thread_id: u64) -> String {
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot select thread: state={{state}}, need DSTATE_SUSP(-1)")
else:
    ok = ida_dbg.select_thread({thread_id})
    make_result(ok, {{"thread_id": {thread_id}, "selected": ok}})
"#,
        thread_id = thread_id,
    );
    super::build_script(&body)
}

/// Generate a script to wait for the next debug event.
pub fn generate_wait_event_script(timeout: u64, flags: u32) -> String {
    let body = format!(
        r#"
combined_flags = {flags} | WFNE_SILENT
code = ida_dbg.wait_for_next_event(combined_flags, {timeout})
evt = ida_dbg.get_debug_event()
state = ida_dbg.get_process_state()
make_result(True, {{
    "event_code": code,
    "state": state,
    "event_id": evt.eid() if evt else None,
    "ip": safe_hex(ida_dbg.get_ip_val()) if state == -1 else None,
}})
"#,
        flags = flags,
        timeout = timeout,
    );
    super::build_script(&body)
}
