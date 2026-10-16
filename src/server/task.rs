//! Lightweight in-process task registry for background operations.
//!
//! Serves two consumers:
//! - The custom `task_status` MCP tool (universal fallback for all clients)
//! - The native MCP Tasks protocol (SEP-1686) via `ServerHandler` methods

use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::task::JoinHandle;

pub const TERMINAL_TASK_CAP: usize = 256;
/// `ttl` value exposed via MCP task metadata.
/// `0` communicates there is no minimum retention guarantee.
pub const TASK_RETENTION_TTL_MS: u64 = 0;

/// N2 can project Nexus operations without using TaskRegistry::cancel's legacy
/// JoinHandle abort semantics. Queue/cancel-pending retain the old running value;
/// richer state and stop confirmation are additive metadata.
pub fn nexus_task_state_json(
    snapshot: &crate::ida::nexus::OperationSnapshot,
    created_at: &str,
    updated_at: &str,
) -> Result<Value, crate::ida::nexus::NexusError> {
    let task_id = snapshot.identity.task_id.as_ref().ok_or_else(|| {
        crate::ida::nexus::NexusError::new(
            crate::ida::nexus::NexusErrorCode::InvalidIdentity,
            "operation has no background task id",
        )
    })?;
    Ok(serde_json::json!({
        "task_id": task_id.as_str(),
        "status": snapshot.status.legacy_status(),
        "message": snapshot.error.as_ref().map(ToString::to_string).unwrap_or_else(|| format!("{:?}", snapshot.status)),
        "created_at": created_at,
        "updated_at": updated_at,
        "meta": {"nexus": snapshot},
        "result": snapshot.result,
    }))
}

/// Task status in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Snapshot of a background task's state (cloneable, no handles).
#[derive(Debug, Clone)]
pub struct TaskState {
    pub id: String,
    pub status: TaskStatus,
    pub message: String,
    pub meta: Option<Value>,
    pub result: Option<Value>,
    pub created_at: Instant,
    pub updated_at: Instant,
    /// ISO-8601 creation timestamp for the MCP protocol.
    pub created_at_iso: String,
    /// ISO-8601 timestamp for the most recent state/message update.
    pub updated_at_iso: String,
    /// Deduplication key (e.g. the output .i64 path).
    pub key: Option<String>,
}

/// Internal entry that owns the abort handle.
struct TaskEntry {
    state: TaskState,
    handle: Option<JoinHandle<()>>,
    cancellation: Option<crate::preprocess::PreparationCancellation>,
}

/// Thread-safe registry of background tasks.
#[derive(Clone)]
pub struct TaskRegistry {
    inner: Arc<Mutex<HashMap<String, TaskEntry>>>,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl TaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn create_internal(
        &self,
        prefix: &str,
        key: Option<&str>,
        message: &str,
        meta: Option<Value>,
    ) -> Result<String, String> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(key) = key {
            if let Some(existing_id) = entries
                .values()
                .find(|entry| {
                    entry.state.status == TaskStatus::Running
                        && entry.state.key.as_deref() == Some(key)
                })
                .map(|entry| entry.state.id.clone())
            {
                return Err(existing_id);
            }
        }

        let id = next_task_id(prefix);
        let (now, created) = now_with_iso();
        let state = TaskState {
            id: id.clone(),
            status: TaskStatus::Running,
            message: message.to_string(),
            meta,
            result: None,
            created_at: now,
            updated_at: now,
            created_at_iso: created.clone(),
            updated_at_iso: created,
            key: key.map(ToOwned::to_owned),
        };
        entries.insert(
            id.clone(),
            TaskEntry {
                state,
                handle: None,
                cancellation: None,
            },
        );
        prune_terminal_tasks(&mut entries);
        Ok(id)
    }

    /// Create a task with a deduplication key. If a running task with
    /// the same key already exists, returns `Err(existing_task_id)`.
    pub fn create_keyed(&self, key: &str, message: &str) -> Result<String, String> {
        self.create_internal("dsc", Some(key), message, None)
    }

    /// Create a generic running task without deduplication.
    pub fn create(&self, prefix: &str, message: &str) -> String {
        self.create_internal(prefix, None, message, None)
            .expect("unkeyed task creation must succeed")
    }

    /// Create a generic running task with an optional deduplication key.
    pub fn create_with_key(
        &self,
        prefix: &str,
        key: Option<&str>,
        message: &str,
    ) -> Result<String, String> {
        self.create_internal(prefix, key, message, None)
    }

    pub fn create_with_meta(
        &self,
        prefix: &str,
        key: Option<&str>,
        message: &str,
        meta: Value,
    ) -> Result<String, String> {
        self.create_internal(prefix, key, message, Some(meta))
    }

    /// Store the `JoinHandle` for a task so it can be cancelled.
    pub fn set_handle(&self, id: &str, handle: JoinHandle<()>) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.handle = Some(handle);
        }
    }

    pub fn set_cancellation(
        &self,
        id: &str,
        cancellation: crate::preprocess::PreparationCancellation,
    ) {
        if let Some(entry) = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(id)
        {
            entry.cancellation = Some(cancellation);
        }
    }
    /// Only the offline supervisor calls this after cleanup has returned evidence.
    pub fn cancellation_confirmed(&self, id: &str) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.status = TaskStatus::Cancelled;
            entry.state.message = "Cancelled after owned process cleanup".into();
            entry.state.meta = Some(serde_json::json!({"execution_stopped":true}));
            entry.handle = None;
            refresh_updated(&mut entry.state);
        }
        prune_terminal_tasks(&mut entries);
    }

    /// Get a cloneable snapshot of a task's current state.
    pub fn get(&self, id: &str) -> Option<TaskState> {
        let entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        entries.get(id).map(|e| e.state.clone())
    }

    /// List all tasks (snapshots only).
    pub fn list_all(&self) -> Vec<TaskState> {
        let entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        entries.values().map(|e| e.state.clone()).collect()
    }

    /// Update the progress message on a running task.
    pub fn update_message(&self, id: &str, message: &str) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.message = message.to_string();
            refresh_updated(&mut entry.state);
        }
    }

    pub fn merge_meta(&self, id: &str, meta_patch: Value) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            match (&mut entry.state.meta, meta_patch) {
                (Some(Value::Object(existing)), Value::Object(patch)) => {
                    for (k, v) in patch {
                        existing.insert(k, v);
                    }
                }
                (_, patch) => entry.state.meta = Some(patch),
            }
            refresh_updated(&mut entry.state);
        }
    }

    /// Mark a task as completed with a JSON result.
    pub fn complete(&self, id: &str, result: Value) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.status = TaskStatus::Completed;
            entry.state.message = "Completed".to_string();
            entry.state.result = Some(result);
            refresh_updated(&mut entry.state);
            entry.handle = None;
        }
        prune_terminal_tasks(&mut entries);
    }

    /// Mark a task as failed with an error message.
    pub fn fail(&self, id: &str, error: &str) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.status = TaskStatus::Failed;
            entry.state.message = error.to_string();
            refresh_updated(&mut entry.state);
            entry.handle = None;
        }
        prune_terminal_tasks(&mut entries);
    }

    /// Cancel a running task. Returns `true` if the task was running
    /// and has been aborted.
    pub fn cancel(&self, id: &str) -> bool {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            if entry.state.status == TaskStatus::Running {
                if let Some(token) = &entry.cancellation {
                    if token.is_cancelled() {
                        return false;
                    }
                    if !token.cancel() {
                        return false;
                    }
                    entry.state.message =
                        "Cancellation requested; waiting for cleanup evidence".into();
                    entry.state.meta = Some(
                        serde_json::json!({"cancel_requested":true,"execution_stopped":false}),
                    );
                    refresh_updated(&mut entry.state);
                    return true;
                }
                if let Some(handle) = entry.handle.take() {
                    handle.abort();
                }
                entry.state.status = TaskStatus::Cancelled;
                entry.state.message = "Cancelled by client".to_string();
                refresh_updated(&mut entry.state);
                prune_terminal_tasks(&mut entries);
                return true;
            }
        }
        false
    }

    /// Create a completed task with a precomputed result payload.
    ///
    /// Used for inline task-mode calls that complete immediately but still
    /// need to be retrievable via tasks/get and tasks/result.
    pub fn create_completed(&self, message: &str, result: Value) -> String {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = next_task_id("task");
        let (now, created) = now_with_iso();
        let state = TaskState {
            id: id.clone(),
            status: TaskStatus::Completed,
            message: message.to_string(),
            meta: None,
            result: Some(result),
            created_at: now,
            updated_at: now,
            created_at_iso: created.clone(),
            updated_at_iso: created,
            key: None,
        };
        entries.insert(
            id.clone(),
            TaskEntry {
                state,
                handle: None,
                cancellation: None,
            },
        );
        prune_terminal_tasks(&mut entries);
        id
    }
}

/// Generate a unique task ID using an atomic counter and prefix.
fn next_task_id(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

fn now_with_iso() -> (Instant, String) {
    (Instant::now(), iso_now())
}

fn refresh_updated(state: &mut TaskState) {
    let (updated_at, updated_at_iso) = now_with_iso();
    state.updated_at = updated_at;
    state.updated_at_iso = updated_at_iso;
}

fn prune_terminal_tasks(entries: &mut HashMap<String, TaskEntry>) {
    let terminal_ids: Vec<_> = entries
        .iter()
        .filter_map(|(id, entry)| {
            (entry.state.status != TaskStatus::Running)
                .then_some((id.clone(), entry.state.updated_at))
        })
        .collect();

    if terminal_ids.len() <= TERMINAL_TASK_CAP {
        return;
    }

    let mut ordered = terminal_ids;
    ordered.sort_by_key(|(_, updated_at)| *updated_at);
    let remove_count = ordered.len() - TERMINAL_TASK_CAP;

    for (id, _) in ordered.into_iter().take(remove_count) {
        entries.remove(&id);
    }
}

/// ISO-8601 timestamp for the current time (UTC).
pub fn iso_now() -> String {
    iso_from_system_time(std::time::SystemTime::now())
}

/// Format `time` as `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds).
pub fn iso_from_system_time(time: std::time::SystemTime) -> String {
    let duration = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Manual UTC formatting to avoid adding chrono dependency.
    // Good enough for task timestamps.
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since epoch to Y-M-D (simplified leap year handling)
    let (year, month, day) = epoch_days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's date library
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use crate::server::task::{TaskRegistry, TaskStatus};
    use serde_json::json;

    #[test]
    fn create_and_get() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("test-key", "Starting")
            .expect("should succeed");
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Running);
        assert_eq!(state.message, "Starting");
        assert!(state.result.is_none());
        assert!(!state.created_at_iso.is_empty());
    }

    #[test]
    fn update_message() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("k1", "Phase 1")
            .expect("should succeed");
        registry.update_message(&id, "Phase 2");
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.message, "Phase 2");
    }

    #[test]
    fn complete_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("k2", "Working")
            .expect("should succeed");
        let result = json!({"db": "opened"});
        registry.complete(&id, result.clone());
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Completed);
        assert_eq!(state.result, Some(result));
    }

    #[test]
    fn fail_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("k3", "Working")
            .expect("should succeed");
        registry.fail(&id, "idat exited with code 4");
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Failed);
        assert_eq!(state.message, "idat exited with code 4");
    }

    #[test]
    fn get_nonexistent() {
        let registry = TaskRegistry::new();
        assert!(registry.get("dsc-nope").is_none());
    }

    #[test]
    fn keyed_dedup_prevents_duplicate() {
        let registry = TaskRegistry::new();
        let id1 = registry
            .create_keyed("/path/to/dsc.i64", "First")
            .expect("first should succeed");
        let dup = registry.create_keyed("/path/to/dsc.i64", "Second");
        assert_eq!(dup, Err(id1.clone()));

        // After completing, a new task with the same key can be created.
        registry.complete(&id1, json!({}));
        let id2 = registry
            .create_keyed("/path/to/dsc.i64", "Third")
            .expect("should succeed after first completed");
        assert_ne!(id1, id2);
    }

    #[test]
    fn cancel_running_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("k4", "Working")
            .expect("should succeed");
        assert!(registry.cancel(&id));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Cancelled);

        // Cancelling again returns false.
        assert!(!registry.cancel(&id));
    }

    #[test]
    fn list_all_tasks() {
        let registry = TaskRegistry::new();
        let _ = registry.create_keyed("a", "Task A");
        let _ = registry.create_keyed("b", "Task B");
        assert_eq!(registry.list_all().len(), 2);
    }

    #[test]
    fn iso_timestamp_format() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("ts", "Timestamp test")
            .expect("should succeed");
        let state = registry.get(&id).expect("task should exist");
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert!(
            state.created_at_iso.len() == 20,
            "unexpected ISO length: {}",
            state.created_at_iso
        );
        assert!(state.created_at_iso.ends_with('Z'));
    }

    #[test]
    fn create_and_merge_meta() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_with_meta("job", None, "Queued", json!({"tenant_id": "team-a"}))
            .expect("should succeed");
        registry.merge_meta(&id, json!({"path": "/tmp/sample.bin", "remote": false}));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(
            state.meta,
            Some(json!({
                "tenant_id": "team-a",
                "path": "/tmp/sample.bin",
                "remote": false,
            }))
        );
    }

    #[test]
    fn iso_from_system_time_formats_known_instants() {
        use std::time::{Duration, UNIX_EPOCH};
        assert_eq!(
            super::iso_from_system_time(UNIX_EPOCH),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            super::iso_from_system_time(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            "2023-11-14T22:13:20Z"
        );
    }
}
