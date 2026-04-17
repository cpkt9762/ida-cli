use serde_json::Value;
use std::path::Path;

const DEFAULT_MAX_INLINE_BYTES: usize = 512;
const CACHE_DIR: &str = "/tmp/ida-cli-out";

pub fn guard_response_size(method: &str, result: Value) -> Value {
    let max_bytes = std::env::var("IDA_MCP_MAX_INLINE_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_INLINE_BYTES);

    let json_str = serde_json::to_string(&result).unwrap_or_default();
    let size = json_str.len();

    if size <= max_bytes {
        return result;
    }

    let _ = std::fs::create_dir_all(CACHE_DIR);

    let hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        json_str.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    };
    let filename = format!("{}-{}.json", method, hash);
    let file_path = Path::new(CACHE_DIR).join(&filename);

    if let Err(e) = std::fs::write(&file_path, &json_str) {
        tracing::warn!("Failed to cache response to {:?}: {}", file_path, e);
        return result;
    }

    let item_count = count_items(&result);
    let summary = format!(
        "Response too large for inline display ({:.1}KB{}). \
         Full output saved to: {}\n\
         Use `cat {}` or Read tool to access the data.",
        size as f64 / 1024.0,
        if let Some(n) = item_count {
            format!(", {} items", n)
        } else {
            String::new()
        },
        file_path.display(),
        file_path.display(),
    );

    serde_json::json!({
        "cached": true,
        "file": file_path.to_string_lossy(),
        "size_bytes": size,
        "item_count": item_count,
        "summary": summary,
    })
}

fn count_items(v: &Value) -> Option<usize> {
    if let Some(obj) = v.as_object() {
        for key in [
            "strings",
            "functions",
            "exports",
            "imports",
            "segments",
            "xrefs",
            "results",
            "items",
            "callgraph",
        ] {
            if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                return Some(arr.len());
            }
        }
    }
    if let Some(arr) = v.as_array() {
        return Some(arr.len());
    }
    None
}
