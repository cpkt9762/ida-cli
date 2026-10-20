//! Pure IDAPython script and parameter helpers; no native IDA linkage.
pub mod debug;
pub mod disasm;
use crate::error::ToolError;
pub(crate) fn parse_address_str(s: &str) -> Result<u64, ToolError> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| ToolError::InvalidAddress(s.to_string()))
    } else if s.starts_with("0b") || s.starts_with("0B") {
        u64::from_str_radix(&s[2..], 2).map_err(|_| ToolError::InvalidAddress(s.to_string()))
    } else if s.starts_with("0o") || s.starts_with("0O") {
        u64::from_str_radix(&s[2..], 8).map_err(|_| ToolError::InvalidAddress(s.to_string()))
    } else {
        s.parse::<u64>()
            .map_err(|_| ToolError::InvalidAddress(s.to_string()))
    }
}
