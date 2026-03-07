//! IDAPython script generators for breakpoint management.

/// Generate a script to add a breakpoint at the given address.
pub fn generate_add_breakpoint_script(
    address: u64,
    size: u64,
    bpt_type: &str,
    condition: Option<&str>,
) -> String {
    let condition_block = match condition {
        Some(cond) => format!(
            r#"
if ok:
    bpt = ida_dbg.bpt_t()
    if ida_dbg.get_bpt({address}, bpt):
        bpt.condition = "{cond}"
        ida_dbg.update_bpt(bpt)
"#,
            address = address,
            cond = cond.replace('"', "\\\""),
        ),
        None => String::new(),
    };
    let body = format!(
        r#"
bpt_types = {{"soft": 4, "exec": 8, "write": 1, "read": 2, "rdwr": 3, "default": 12}}
btype = bpt_types.get("{bpt_type}", 12)
ok = ida_dbg.add_bpt({address}, {size}, btype)
{condition_block}
make_result(ok, {{"address": safe_hex({address}), "added": ok, "type": btype}})
"#,
        bpt_type = bpt_type,
        address = address,
        size = size,
        condition_block = condition_block,
    );
    super::build_script(&body)
}

/// Generate a script to delete a breakpoint at the given address.
pub fn generate_del_breakpoint_script(address: u64) -> String {
    let body = format!(
        r#"
ok = ida_dbg.del_bpt({address})
make_result(ok, {{"address": safe_hex({address}), "deleted": ok}})
"#,
        address = address,
    );
    super::build_script(&body)
}

/// Generate a script to enable or disable a breakpoint.
pub fn generate_enable_breakpoint_script(address: u64, enable: bool) -> String {
    let enable_py = if enable { "True" } else { "False" };
    let body = format!(
        r#"
ok = ida_dbg.enable_bpt({address}, {enable_py})
make_result(ok, {{"address": safe_hex({address}), "enabled": {enable_py}, "ok": ok}})
"#,
        address = address,
        enable_py = enable_py,
    );
    super::build_script(&body)
}

/// Generate a script to list all breakpoints in the database.
pub fn generate_list_breakpoints_script() -> String {
    let body = r#"
bpts = []
for i in range(ida_dbg.get_bpt_qty()):
    bpt = ida_dbg.bpt_t()
    if ida_dbg.getn_bpt(i, bpt):
        bpts.append({
            "address": safe_hex(bpt.ea),
            "type": bpt.type,
            "size": bpt.size,
            "enabled": bool(bpt.flags & 0x008),
            "condition": str(bpt.condition) if bpt.condition else None,
        })
make_result(True, {"breakpoints": bpts, "count": len(bpts)})
"#;
    super::build_script(body)
}
