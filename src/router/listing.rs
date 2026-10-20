//! Types behind `list_idbs`: who opened which database, and what is listed.
//!
//! Nexus leases carry opaque client identities; listings group them by database.
//! Close tokens are credentials and are never serialized here.

use serde::Serialize;
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
    fn empty_listing_serializes_to_zero_count_and_empty_array() {
        let value = IdbListing::new(Vec::new()).to_json().expect("serialize");
        assert_eq!(value["count"], 0);
        assert_eq!(value["idbs"], serde_json::json!([]));
    }
}
