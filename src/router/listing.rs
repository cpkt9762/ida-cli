//! Types behind `list_idbs`: who opened which database, and what is listed.
//!
//! The router keeps one worker per open database. This module holds the
//! per-worker open record, the opaque client identity attached to every
//! reference, and the serializable listing built from them. Close tokens are
//! credentials: nothing in here stores or serializes one.

use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// How a client reached the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// An MCP session (stdio, Streamable HTTP, or the MCP Unix socket).
    Mcp,
    /// A tenant-scoped RPC caller: the CLI socket, `/enqueuez`, prewarm.
    Rpc,
}

impl ClientKind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Rpc => "rpc",
        }
    }
}

/// Opaque, non-reversible identity of a database client.
///
/// This is an identifier for display and for telling clients apart, never a
/// credential: it is not accepted anywhere as proof of ownership.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ClientIdentity {
    pub client_id: String,
    pub kind: ClientKind,
}

static NEXT_MCP_SESSION: AtomicU64 = AtomicU64::new(0);

impl ClientIdentity {
    /// A fresh identity for one MCP session. Every call yields a new id.
    pub fn mcp_session() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let sequence = NEXT_MCP_SESSION.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        Self {
            client_id: opaque_id(
                ClientKind::Mcp,
                &[
                    &nanos.to_le_bytes(),
                    &pid.to_le_bytes(),
                    &sequence.to_le_bytes(),
                ],
            ),
            kind: ClientKind::Mcp,
        }
    }

    /// The identity shared by every RPC caller using one tenant id. A missing
    /// or blank tenant means the `default` tenant, as everywhere in the router.
    pub fn rpc_tenant(tenant_id: Option<&str>) -> Self {
        let tenant_id = super::RouterState::normalize_tenant(tenant_id);
        Self {
            client_id: opaque_id(ClientKind::Rpc, &[tenant_id.as_bytes()]),
            kind: ClientKind::Rpc,
        }
    }
}

/// `<kind>-<16 hex>` from a domain-separated blake3 hash of `parts`.
fn opaque_id(kind: ClientKind, parts: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ida-cli/client-id/v1\0");
    hasher.update(kind.prefix().as_bytes());
    hasher.update(&[0]);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let hex = hasher.finalize().to_hex();
    format!("{}-{}", kind.prefix(), &hex.as_str()[..16])
}

/// Lifecycle of the database inside one worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DbState {
    /// An `open` request was issued and not yet confirmed. The worker may
    /// already hold the database files.
    Opening,
    /// The worker confirmed the database is open.
    Open,
    /// The last `open` failed; the worker holds no database.
    Failed,
}

/// What happened to an `open` request, as seen by the router.
#[derive(Debug, Clone)]
pub enum OpenOutcome {
    /// The worker answered; `idb_path` is the database path it reported.
    Opened { idb_path: Option<PathBuf> },
    /// The worker answered with an error or exited.
    Failed,
    /// The router stopped waiting; the worker may still finish opening.
    TimedOut,
}

/// The router's record of the database held by one worker.
#[derive(Debug, Clone)]
pub struct DbRecord {
    pub state: DbState,
    pub idb_path: Option<PathBuf>,
    pub opened_at: Option<SystemTime>,
}

impl DbRecord {
    /// A worker that was just spawned and is about to open its database.
    pub fn new() -> Self {
        Self {
            state: DbState::Opening,
            idb_path: None,
            opened_at: None,
        }
    }

    /// An `open` request is about to be sent. A database that is already open
    /// stays open: a repeated `open` of the same path is answered from the
    /// existing session.
    pub fn begin_open(&mut self) {
        if self.state != DbState::Open {
            self.state = DbState::Opening;
        }
    }

    /// Fold in the result of an `open` request.
    pub fn finish_open(&mut self, outcome: OpenOutcome, now: SystemTime) {
        match outcome {
            OpenOutcome::Opened { idb_path } => {
                if self.state != DbState::Open {
                    self.state = DbState::Open;
                    self.opened_at = Some(now);
                }
                if idb_path.is_some() {
                    self.idb_path = idb_path;
                }
            }
            OpenOutcome::Failed => {
                if self.state != DbState::Open {
                    self.state = DbState::Failed;
                }
            }
            OpenOutcome::TimedOut => {}
        }
    }

    /// Whether `list_idbs` reports this worker: it holds, or is acquiring, a
    /// database.
    pub fn is_listed(&self) -> bool {
        matches!(self.state, DbState::Opening | DbState::Open)
    }
}

impl Default for DbRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// The worker process behind a listed database.
#[derive(Debug, Clone, Serialize)]
pub struct ListedWorker {
    pub pid: Option<u32>,
    pub backend: String,
}

/// A client currently holding references to a listed database.
#[derive(Debug, Clone, Serialize)]
pub struct ListedHolder {
    #[serde(flatten)]
    pub client: ClientIdentity,
    pub refs: usize,
    pub is_caller: bool,
}

/// One open database. Never carries a close token.
#[derive(Debug, Clone, Serialize)]
pub struct ListedIdb {
    pub db_handle: String,
    pub state: DbState,
    /// The path the database was opened from (a binary or an .i64).
    pub input_path: Option<String>,
    /// The database file the worker reported; null while still opening.
    pub idb_path: Option<String>,
    pub opened_by: ClientIdentity,
    pub opened_by_caller: bool,
    /// UTC time the open was confirmed; null while still opening.
    pub opened_at: Option<String>,
    pub open_secs: Option<u64>,
    pub idle_secs: u64,
    pub worker: ListedWorker,
    /// Whether this is the daemon's active database.
    pub active: bool,
    pub ref_count: usize,
    pub holders: Vec<ListedHolder>,
}

/// The `list_idbs` result.
#[derive(Debug, Clone, Serialize)]
pub struct IdbListing {
    pub count: usize,
    pub idbs: Vec<ListedIdb>,
}

impl IdbListing {
    pub fn new(idbs: Vec<ListedIdb>) -> Self {
        Self {
            count: idbs.len(),
            idbs,
        }
    }

    pub fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn mcp_sessions_get_distinct_opaque_ids() {
        let first = ClientIdentity::mcp_session();
        let second = ClientIdentity::mcp_session();
        assert_ne!(first.client_id, second.client_id);
        assert_eq!(first.kind, ClientKind::Mcp);
        assert!(first.client_id.starts_with("mcp-"));
        assert_eq!(first.client_id.len(), "mcp-".len() + 16);
    }

    #[test]
    fn rpc_identity_is_stable_per_tenant_and_hides_it() {
        let a = ClientIdentity::rpc_tenant(Some("acme-secret-tenant"));
        let b = ClientIdentity::rpc_tenant(Some("acme-secret-tenant"));
        let other = ClientIdentity::rpc_tenant(Some("default"));
        assert_eq!(a, b);
        assert_ne!(a.client_id, other.client_id);
        assert!(a.client_id.starts_with("rpc-"));
        assert!(!a.client_id.contains("acme"));
    }

    #[test]
    fn blank_or_missing_tenant_is_the_default_tenant() {
        let default = ClientIdentity::rpc_tenant(Some("default"));
        assert_eq!(ClientIdentity::rpc_tenant(None), default);
        assert_eq!(ClientIdentity::rpc_tenant(Some("  ")), default);
        assert_eq!(ClientIdentity::rpc_tenant(Some(" default ")), default);
    }

    #[test]
    fn mcp_and_rpc_ids_never_collide_across_kinds() {
        let rpc = opaque_id(ClientKind::Rpc, &[b"x"]);
        let mcp = opaque_id(ClientKind::Mcp, &[b"x"]);
        assert_ne!(rpc, mcp);
    }

    #[test]
    fn new_record_is_listed_as_opening() {
        let record = DbRecord::new();
        assert_eq!(record.state, DbState::Opening);
        assert!(record.is_listed());
        assert!(record.idb_path.is_none());
        assert!(record.opened_at.is_none());
    }

    #[test]
    fn successful_open_records_path_and_time() {
        let mut record = DbRecord::new();
        record.begin_open();
        record.finish_open(
            OpenOutcome::Opened {
                idb_path: Some(PathBuf::from("/db/a.i64")),
            },
            at(100),
        );
        assert_eq!(record.state, DbState::Open);
        assert_eq!(record.idb_path, Some(PathBuf::from("/db/a.i64")));
        assert_eq!(record.opened_at, Some(at(100)));
    }

    #[test]
    fn repeated_open_keeps_first_open_time() {
        let mut record = DbRecord::new();
        record.finish_open(
            OpenOutcome::Opened {
                idb_path: Some(PathBuf::from("/db/a.i64")),
            },
            at(100),
        );
        record.begin_open();
        assert_eq!(record.state, DbState::Open);
        record.finish_open(
            OpenOutcome::Opened {
                idb_path: Some(PathBuf::from("/db/a.i64")),
            },
            at(500),
        );
        assert_eq!(record.opened_at, Some(at(100)));
    }

    #[test]
    fn failed_open_is_not_listed_but_failed_reopen_keeps_open_db() {
        let mut record = DbRecord::new();
        record.finish_open(OpenOutcome::Failed, at(1));
        assert_eq!(record.state, DbState::Failed);
        assert!(!record.is_listed());

        let mut open = DbRecord::new();
        open.finish_open(OpenOutcome::Opened { idb_path: None }, at(1));
        open.begin_open();
        open.finish_open(OpenOutcome::Failed, at(2));
        assert_eq!(open.state, DbState::Open);
        assert!(open.is_listed());
    }

    #[test]
    fn timed_out_open_stays_opening() {
        let mut record = DbRecord::new();
        record.begin_open();
        record.finish_open(OpenOutcome::TimedOut, at(1));
        assert_eq!(record.state, DbState::Opening);
        assert!(record.is_listed());
    }

    #[test]
    fn failed_worker_can_recover_on_a_later_open() {
        let mut record = DbRecord::new();
        record.finish_open(OpenOutcome::Failed, at(1));
        record.begin_open();
        assert_eq!(record.state, DbState::Opening);
        record.finish_open(OpenOutcome::Opened { idb_path: None }, at(9));
        assert_eq!(record.state, DbState::Open);
        assert_eq!(record.opened_at, Some(at(9)));
    }

    #[test]
    fn empty_listing_serializes_to_zero_count_and_empty_array() {
        let value = IdbListing::new(Vec::new()).to_json().expect("serialize");
        assert_eq!(value["count"], 0);
        assert_eq!(value["idbs"], serde_json::json!([]));
    }
}
