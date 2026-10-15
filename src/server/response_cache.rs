use serde_json::Value;
use std::time::SystemTime;

const DEFAULT_MAX_INLINE_BYTES: usize = 512;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ResponseCacheStats {
    pub dir: String,
    pub file_count: usize,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ResponseCacheEvictionStats {
    pub evicted_files: usize,
    pub evicted_bytes: u64,
    pub remaining_bytes: u64,
}

pub async fn guard_response_size(
    method: &str,
    result: Value,
) -> Result<Value, crate::error::ToolError> {
    Ok(cache_or_inline(method, result).await)
}

// Cache failure must never turn an already successful database operation into
// an RPC failure. Retain the value outside the job, including failed thread spawn.
pub(crate) async fn cache_or_inline(method: &str, result: Value) -> Value {
    cache_with(method, result, crate::blocking::response).await
}

type CacheJob = Box<dyn FnOnce() -> Result<Option<Value>, crate::error::ToolError> + Send>;
async fn cache_with<F>(method: &str, result: Value, launch: impl FnOnce(CacheJob) -> F) -> Value
where
    F: std::future::Future<
        Output = Result<Result<Option<Value>, crate::error::ToolError>, crate::error::ToolError>,
    >,
{
    cache_shared(
        method,
        std::sync::Arc::new(std::sync::Mutex::new(result)),
        launch,
    )
    .await
}

async fn cache_shared<F>(
    method: &str,
    original: std::sync::Arc<std::sync::Mutex<Value>>,
    launch: impl FnOnce(CacheJob) -> F,
) -> Value
where
    F: std::future::Future<
        Output = Result<Result<Option<Value>, crate::error::ToolError>, crate::error::ToolError>,
    >,
{
    let method = method.to_string();
    let borrowed = original.clone();
    let cached = launch(Box::new(move || {
        let mut value = borrowed.lock().unwrap_or_else(|e| e.into_inner());
        let cached = guard_response_size_sync(&method, &value)?;
        if cached.is_some() {
            let original = std::mem::take(&mut *value);
            drop(value);
            drop(original); // Destroy large arrays/objects on this bounded worker.
        }
        Ok(cached)
    }))
    .await;
    match cached {
        Ok(Ok(Some(summary))) => summary,
        other => {
            if let Ok(Err(error)) | Err(error) = other {
                tracing::warn!(%error, "response cache unavailable; returning complete inline result");
            }
            // The job has returned (or was dropped on spawn failure); no I/O
            // holds this lock now. No clone/encoding of a large Value here.
            std::mem::take(&mut *original.lock().unwrap_or_else(|e| e.into_inner()))
        }
    }
}

fn guard_response_size_sync(
    method: &str,
    result: &Value,
) -> Result<Option<Value>, crate::error::ToolError> {
    let max_bytes = std::env::var("IDA_MCP_MAX_INLINE_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_INLINE_BYTES);

    let json_str = serde_json::to_string(&result)
        .map_err(|e| crate::error::ToolError::IdaError(format!("response encoding: {e}")))?;
    let size = json_str.len();

    if size <= max_bytes {
        return Ok(None);
    }

    let cache_dir = crate::idb_store::response_cache_dir();
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| crate::error::ToolError::IdaError(format!("response cache directory: {e}")))?;

    let hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        json_str.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    };
    let safe_method: String = method
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(128)
        .collect();
    let filename = format!("{}-{}.json", safe_method, hash);
    let file_path = cache_dir.join(&filename);

    std::fs::write(&file_path, &json_str).map_err(|e| {
        crate::error::ToolError::IdaError(format!(
            "response cache write {}: {e}",
            file_path.display()
        ))
    })?;

    let item_count = count_items(result);
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

    Ok(Some(serde_json::json!({
        "cached": true,
        "file": file_path.to_string_lossy(),
        "size_bytes": size,
        "item_count": item_count,
        "summary": summary,
    })))
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

pub fn try_stats() -> std::io::Result<ResponseCacheStats> {
    let path = crate::idb_store::response_cache_dir();
    let mut file_count = 0;
    let mut total_size_bytes = 0u64;
    let entries = match std::fs::read_dir(&path) {
        Ok(entries) => Some(entries),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if let Some(entries) = entries {
        for entry in entries {
            let meta = entry?.metadata()?;
            if meta.is_file() {
                file_count += 1;
                total_size_bytes = total_size_bytes.saturating_add(meta.len());
            }
        }
    }
    Ok(ResponseCacheStats {
        dir: path.display().to_string(),
        file_count,
        total_size_bytes,
    })
}

pub fn stats() -> ResponseCacheStats {
    let path = crate::idb_store::response_cache_dir();
    let mut file_count = 0usize;
    let mut total_size_bytes = 0u64;

    if let Ok(entries) = std::fs::read_dir(&path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    file_count += 1;
                    total_size_bytes = total_size_bytes.saturating_add(meta.len());
                }
            }
        }
    }

    ResponseCacheStats {
        dir: path.display().to_string(),
        file_count,
        total_size_bytes,
    }
}

pub fn prune_to_limit(max_bytes: u64) -> ResponseCacheEvictionStats {
    let path = crate::idb_store::response_cache_dir();
    let mut files = Vec::new();
    let mut total_size = 0u64;

    if let Ok(entries) = std::fs::read_dir(&path) {
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            total_size = total_size.saturating_add(meta.len());
            files.push((entry.path(), meta.len(), mtime));
        }
    }

    if total_size <= max_bytes {
        return ResponseCacheEvictionStats {
            evicted_files: 0,
            evicted_bytes: 0,
            remaining_bytes: total_size,
        };
    }

    files.sort_by_key(|(_, _, mtime)| *mtime);
    let mut evicted_files = 0usize;
    let mut evicted_bytes = 0u64;

    for (path, size, _) in files {
        if total_size <= max_bytes {
            break;
        }
        let _ = std::fs::remove_file(path);
        total_size = total_size.saturating_sub(size);
        evicted_files += 1;
        evicted_bytes = evicted_bytes.saturating_add(size);
    }

    ResponseCacheEvictionStats {
        evicted_files,
        evicted_bytes,
        remaining_bytes: total_size,
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn cache_worker_launch_failure_preserves_original_success_without_cloning() {
        let value = serde_json::json!({"stdout":"输出".repeat(1000), "result":{"saved":true}});
        let result = cache_with("run_script", value.clone(), |job| async move {
            drop(job); // std::thread::Builder::spawn failure drops its closure.
            Err(crate::error::ToolError::IdaError(
                "ida-response-encode spawn: injected failure".into(),
            ))
        })
        .await;
        assert_eq!(result, value);
    }
}

#[cfg(test)]
mod f4_regressions {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn cached_success_consumes_original_in_background_job() {
        let original = std::sync::Arc::new(std::sync::Mutex::new(
            serde_json::json!({"stdout":"large Unicode 输出".repeat(1000),"result":[1,2,3]}),
        ));
        let observed = original.clone();
        let caller = std::thread::current().id();
        let result = cache_shared("f4-drop", original.clone(), |job| async move {
            crate::blocking::response(move || {
                assert_ne!(std::thread::current().id(), caller);
                let result = job();
                assert!(observed.lock().unwrap().is_null(), "successful job must take and destroy the large original on this background thread");
                result
            }).await
        }).await;
        assert_eq!(result["cached"], true);
        assert!(original.lock().unwrap().is_null());
    }
}
