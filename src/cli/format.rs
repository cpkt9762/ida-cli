use serde_json::Value;

const MAX_HUMAN_LINES: usize = 200;

pub enum OutputMode {
    Human,
    Json,
    Compact,
}

pub fn format_response(mode: &OutputMode, method: &str, value: &Value) -> String {
    match mode {
        OutputMode::Json => {
            serde_json::to_string_pretty(value).unwrap_or_else(|_| format!("{value}"))
        }
        OutputMode::Compact => serde_json::to_string(value).unwrap_or_else(|_| format!("{value}")),
        OutputMode::Human => format_human(method, value),
    }
}

fn format_human(method: &str, value: &Value) -> String {
    if let Some(cached) = value.get("cached").and_then(|v| v.as_bool()) {
        if cached {
            if let Some(summary) = value.get("summary").and_then(|v| v.as_str()) {
                return summary.to_string();
            }
        }
    }

    match method {
        "list_functions" | "list_funcs" => format_function_list(value),
        "list_strings" | "strings" => format_string_list(value),
        "list_segments" | "segments" => format_segment_list(value),
        "status" => format_status(value),
        _ => {
            let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| format!("{value}"));
            truncate_output(&pretty)
        }
    }
}

fn format_function_list(v: &Value) -> String {
    let total = v.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    let funcs = match v.get("functions").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            return serde_json::to_string_pretty(v).unwrap_or_else(|_| format!("{v}"));
        }
    };

    let mut lines = Vec::with_capacity(funcs.len() + 1);
    lines.push(format!("Functions ({} of {}):", funcs.len(), total));
    for f in funcs {
        let addr = f.get("address").and_then(|v| v.as_str()).unwrap_or("?");
        let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let size = f.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        lines.push(format!("  {addr}  {name}  (size: {size})"));
    }
    truncate_output(&lines.join("\n"))
}

fn format_string_list(v: &Value) -> String {
    let total = v.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    let strings = match v.get("strings").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            return serde_json::to_string_pretty(v).unwrap_or_else(|_| format!("{v}"));
        }
    };

    let mut lines = Vec::with_capacity(strings.len() + 1);
    lines.push(format!("Strings ({} of {}):", strings.len(), total));
    for s in strings {
        let addr = s.get("address").and_then(|v| v.as_str()).unwrap_or("?");
        let val = s
            .get("content")
            .or_else(|| s.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        lines.push(format!("  {addr}  {:?}", val));
    }
    truncate_output(&lines.join("\n"))
}

fn format_segment_list(v: &Value) -> String {
    let segments = match v
        .as_array()
        .or_else(|| v.get("segments").and_then(|v| v.as_array()))
    {
        Some(a) => a,
        None => {
            return serde_json::to_string_pretty(v).unwrap_or_else(|_| format!("{v}"));
        }
    };

    let mut lines = Vec::with_capacity(segments.len() + 1);
    lines.push(format!("Segments ({}):", segments.len()));
    for s in segments {
        let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let start = s
            .get("start")
            .or_else(|| s.get("start_address"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let end = s
            .get("end")
            .or_else(|| s.get("end_address"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let perms = s.get("permissions").and_then(|v| v.as_str()).unwrap_or("");
        lines.push(format!("  {name}  {start}-{end}  {perms}"));
    }
    truncate_output(&lines.join("\n"))
}

fn format_status(v: &Value) -> String {
    let count = v.get("worker_count").and_then(|v| v.as_u64()).unwrap_or(0);
    let max_workers = v.get("max_workers").and_then(|v| v.as_u64());
    let max_workers_per_tenant = v.get("max_workers_per_tenant").and_then(|v| v.as_u64());
    let max_pending = v.get("max_pending_per_worker").and_then(|v| v.as_u64());
    let max_pending_per_tenant = v.get("max_pending_per_tenant").and_then(|v| v.as_u64());
    let max_spawns = v.get("max_concurrent_spawns").and_then(|v| v.as_u64());
    let active = v
        .get("active_handle")
        .and_then(|v| v.as_str())
        .unwrap_or("-");

    let mut lines = vec![format!("worker_count: {count}")];
    if let Some(max_workers) = max_workers {
        lines.push(format!("max_workers: {max_workers}"));
    }
    if let Some(max_workers_per_tenant) = max_workers_per_tenant {
        lines.push(format!("max_workers_per_tenant: {max_workers_per_tenant}"));
    }
    if let Some(max_pending) = max_pending {
        lines.push(format!("max_pending_per_worker: {max_pending}"));
    }
    if let Some(max_pending_per_tenant) = max_pending_per_tenant {
        lines.push(format!("max_pending_per_tenant: {max_pending_per_tenant}"));
    }
    if let Some(retention) = v.get("nexus_retention") {
        for kind in ["business", "internal", "total"] {
            if let (Some(used), Some(capacity)) = (
                retention
                    .get(format!("{kind}_used"))
                    .and_then(Value::as_u64),
                retention
                    .get(format!("{kind}_capacity"))
                    .and_then(Value::as_u64),
            ) {
                lines.push(format!("nexus_retention_{kind}: {used}/{capacity}"));
            }
        }
    }
    if let Some(max_spawns) = max_spawns {
        lines.push(format!("max_concurrent_spawns: {max_spawns}"));
    }
    lines.push(format!("active_handle: {active}"));

    if let Some(metadata) = v.get("metadata") {
        let version = metadata
            .get("version")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let rpc_socket = metadata
            .get("rpc_socket_path")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let mcp_socket = metadata
            .get("mcp_socket_path")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let http_address = metadata
            .get("http_address")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        lines.push(format!("daemon_version: {version}"));
        for field in ["ida_version", "installed_ida_version"] {
            let value = metadata
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            lines.push(format!("{field}: {value}"));
        }
        lines.push(format!("rpc_socket: {rpc_socket}"));
        lines.push(format!("mcp_socket: {mcp_socket}"));
        lines.push(format!("http_address: {http_address}"));
        if let Some(methods) = metadata
            .get("supported_methods")
            .and_then(|value| value.as_array())
        {
            lines.push(format!("supported_methods: {}", methods.len()));
        }
        if let Some(tools) = metadata
            .get("supported_tools")
            .and_then(|value| value.as_array())
        {
            lines.push(format!("supported_tools: {}", tools.len()));
        }
    }

    if let Some(runtime) = v.get("runtime_probe") {
        let backend = runtime
            .get("backend")
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        let supported = runtime
            .get("supported")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        lines.push(format!(
            "runtime_backend: {backend} (supported={supported})"
        ));
    }

    if let Some(cache) = v.get("idb_cache") {
        let files = cache
            .get("file_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let bytes = cache
            .get("total_size_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        lines.push(format!("idb_cache: {files} files, {bytes} bytes"));
    }
    if let Some(cache) = v.get("response_cache") {
        let files = cache
            .get("file_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let bytes = cache
            .get("total_size_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        lines.push(format!("response_cache: {files} files, {bytes} bytes"));
    }

    if let Some(workers) = v.get("workers").and_then(|v| v.as_array()) {
        if workers.is_empty() {
            lines.push("workers: []".to_string());
        } else {
            lines.push("workers:".to_string());
            for worker in workers {
                let handle = worker.get("handle").and_then(|v| v.as_str()).unwrap_or("?");
                let backend = worker
                    .get("backend")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let tenant = worker
                    .get("tenant_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let pending = worker
                    .get("pending_requests")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let refs = worker
                    .get("ref_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let idle = worker
                    .get("idle_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let path = worker
                    .get("open_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                lines.push(format!(
                    "  {handle} backend={backend} tenant={tenant} pending={pending} refs={refs} idle={idle}s path={path}"
                ));
            }
        }
    }

    lines.join("\n")
}

fn truncate_output(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= MAX_HUMAN_LINES {
        return s.to_string();
    }
    let mut out = lines[..MAX_HUMAN_LINES].join("\n");
    out.push_str(&format!(
        "\n... {} more lines, use --json for full output",
        lines.len() - MAX_HUMAN_LINES
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::{format_response, OutputMode};
    use serde_json::json;

    #[test]
    fn rv81_human_status_shows_retention_usage_and_limits() {
        let response = json!({"nexus_retention":{
            "business_used":513,"business_capacity":262144,
            "internal_used":4,"internal_capacity":12582912,
            "total_used":517,"total_capacity":16777216}});
        let text = format_response(&OutputMode::Human, "status", &response);
        assert!(text.contains("nexus_retention_business: 513/262144"));
        assert!(text.contains("nexus_retention_internal: 4/12582912"));
        assert!(text.contains("nexus_retention_total: 517/16777216"));
    }

    #[test]
    fn human_strings_show_backend_content() {
        for field in ["content", "value"] {
            let response = json!({"total": 1, "strings": [
                {"address": "0x1838", field: "usage: printf 雪\n"}
            ]});
            assert_eq!(
                format_response(&OutputMode::Human, "list_strings", &response),
                "Strings (1 of 1):\n  0x1838  \"usage: printf 雪\\n\""
            );
        }
    }

    #[test]
    fn human_segments_show_backend_address_ranges() {
        for (start, end) in [("start", "end"), ("start_address", "end_address")] {
            let segment =
                json!({"name": "__text", start: "0x1000", end: "0x2000", "permissions": "r-x"});
            for response in [json!([segment]), json!({"segments": [segment]})] {
                assert_eq!(
                    format_response(&OutputMode::Human, "list_segments", &response),
                    "Segments (1):\n  __text  0x1000-0x2000  r-x"
                );
            }
        }
    }
}
