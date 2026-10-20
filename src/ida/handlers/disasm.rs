const DECOMPILE_STRUCTURED_PY: &str = include_str!("../../../scripts/decompile_structured.py");
pub fn decompile_structured_script(
    addr: u64,
    max_depth: u32,
    include_types: bool,
    include_addresses: bool,
) -> String {
    format!(
        "EA = {addr:#x}\nMAX_DEPTH = {max_depth}\nINCLUDE_TYPES = {include_types}\nINCLUDE_ADDRESSES = {include_addresses}\n{body}",
        addr = addr,
        max_depth = max_depth,
        include_types = if include_types { "True" } else { "False" },
        include_addresses = if include_addresses { "True" } else { "False" },
        body = DECOMPILE_STRUCTURED_PY,
    )
}
