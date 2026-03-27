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
        let val = s.get("value").and_then(|v| v.as_str()).unwrap_or("?");
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
            .get("start_address")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let end = s.get("end_address").and_then(|v| v.as_str()).unwrap_or("?");
        let perms = s.get("permissions").and_then(|v| v.as_str()).unwrap_or("");
        lines.push(format!("  {name}  {start}-{end}  {perms}"));
    }
    truncate_output(&lines.join("\n"))
}

fn format_status(v: &Value) -> String {
    let count = v.get("worker_count").and_then(|v| v.as_u64()).unwrap_or(0);
    let workers = v
        .get("workers")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    format!("worker_count: {count}\nworkers: [{workers}]")
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
