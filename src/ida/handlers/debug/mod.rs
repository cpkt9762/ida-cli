use crate::error::ToolError;
use serde_json::Value;

pub const HEADLESS_PREAMBLE: &str = r#"
import json, ida_dbg, ida_idd, idaapi

DSTATE_SUSP = -1
DSTATE_NOTASK = 0
DSTATE_RUN = 1

WFNE_ANY = 1
WFNE_SUSP = 2
WFNE_SILENT = 4
WFNE_CONT = 8
WFNE_NOWAIT = 16
WFNE_USEC = 32

def safe_hex(v):
    if v is None:
        return None
    try:
        if v == 0xFFFFFFFFFFFFFFFF:
            return None
        return hex(v)
    except Exception:
        return None

def make_result(success, data=None, error=None):
    r = {"success": success, "error": error, "data": data}
    print(json.dumps(r))
"#;

pub fn parse_debug_output(result: &Value) -> Result<Value, ToolError> {
    let stdout = result
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(last_line) = stdout.lines().rev().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }) else {
        return Err(ToolError::IdaError(
            "Debug script produced no JSON output".to_string(),
        ));
    };

    let parsed: Value = serde_json::from_str(last_line)
        .map_err(|_| ToolError::IdaError("Debug script produced no JSON output".to_string()))?;

    if parsed.get("success").and_then(Value::as_bool) != Some(true) {
        let error_msg = parsed
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| parsed.get("error").map(|v| v.to_string()))
            .unwrap_or_else(|| "Debug script failed".to_string());
        return Err(ToolError::IdaError(error_msg));
    }

    Ok(parsed)
}

pub fn build_script(body: &str) -> String {
    format!("{}\n{}", HEADLESS_PREAMBLE, body)
}

/// Auto-detect the platform-appropriate IDA remote debug server binary.
///
/// Scans every detected IDA installation (honoring `IDADIR`, then newest
/// version first) for the platform's debug server under `dbgsrv/`. This
/// avoids hardcoding version-specific paths, so a freshly installed IDA
/// release is picked up automatically.
///
/// Returns the absolute path to `mac_server_arm` (macOS ARM64),
/// `mac_server` (macOS x86_64), `linux_server64` (Linux), or `None` if
/// no debug server is found. The caller passes this to script generators
/// so the generated Python can spawn the server on demand.
pub fn find_debug_server_path() -> Option<String> {
    let server_name = debug_server_binary_name()?;

    for install_dir in crate::ida::install::candidate_install_dirs() {
        let candidate = install_dir.join("dbgsrv").join(server_name);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }

    None
}

/// The debug server executable name for the current target platform, or
/// `None` on platforms where the remote debug server is unsupported.
fn debug_server_binary_name() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        if cfg!(target_arch = "aarch64") {
            Some("mac_server_arm")
        } else {
            Some("mac_server")
        }
    }

    #[cfg(target_os = "linux")]
    {
        Some("linux_server64")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

pub mod breakpoint;
pub mod execution;
pub mod inspect;
pub mod process;
