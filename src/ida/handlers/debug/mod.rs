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
/// Returns the absolute path to `mac_server_arm` (macOS ARM64),
/// `mac_server` (macOS x86_64), `linux_server64` (Linux), or `None` if
/// no debug server is found.  The caller passes this to script generators
/// so the generated Python can spawn the server on demand.
pub fn find_debug_server_path() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let candidates: &[&str] = if cfg!(target_arch = "aarch64") {
            &[
                "/Applications/IDA Professional 9.3.app/Contents/MacOS/dbgsrv/mac_server_arm",
                "/Applications/IDA Professional 9.2.app/Contents/MacOS/dbgsrv/mac_server_arm",
                "/Applications/IDA Home 9.3.app/Contents/MacOS/dbgsrv/mac_server_arm",
                "/Applications/IDA Essential 9.3.app/Contents/MacOS/dbgsrv/mac_server_arm",
            ]
        } else {
            &[
                "/Applications/IDA Professional 9.3.app/Contents/MacOS/dbgsrv/mac_server",
                "/Applications/IDA Professional 9.2.app/Contents/MacOS/dbgsrv/mac_server",
                "/Applications/IDA Home 9.3.app/Contents/MacOS/dbgsrv/mac_server",
                "/Applications/IDA Essential 9.3.app/Contents/MacOS/dbgsrv/mac_server",
            ]
        };
        for p in candidates {
            if std::path::Path::new(p).exists() {
                return Some(p.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    {
        let bases = ["/opt/idapro-9.3", "/opt/idapro-9.2"];
        for base in &bases {
            let p = format!("{}/dbgsrv/linux_server64", base);
            if std::path::Path::new(&p).exists() {
                return Some(p);
            }
        }
        None
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
