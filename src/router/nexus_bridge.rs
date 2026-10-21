//! Persistent public Python client adapter. Neither lane shares a physical stream.
pub mod cache;
pub mod cache_lock;
mod custody_wire;
mod file_jobs;
pub mod generations;
mod helper;
pub(crate) mod installation;
mod owned_files;
pub mod protocol;
mod receiver;
pub mod recovery_guard;
#[cfg(feature = "nexus-test-support")]
mod test_barriers;
#[cfg(feature = "nexus-test-support")]
mod test_process_ledger;
pub(crate) mod verification;

fn spawn_child(command: &mut tokio::process::Command) -> anyhow::Result<tokio::process::Child> {
    #[cfg(feature = "nexus-test-support")]
    {
        test_process_ledger::spawn(command)
    }
    #[cfg(not(feature = "nexus-test-support"))]
    {
        Ok(crate::process_spawn::with_spawn_fence(|| command.spawn())?)
    }
}

#[cfg(feature = "nexus-test-support")]
pub fn test_spawn_child(
    command: &mut tokio::process::Command,
) -> anyhow::Result<tokio::process::Child> {
    spawn_child(command)
}

#[cfg(feature = "nexus-test-support")]
pub async fn test_output_child(
    child: tokio::process::Child,
) -> std::io::Result<std::process::Output> {
    output_child(child).await
}

#[cfg(feature = "nexus-test-support")]
pub(crate) fn test_spawn_std_child(
    command: &mut std::process::Command,
) -> anyhow::Result<std::process::Child> {
    test_process_ledger::spawn_std(command)
}

fn python_ledger(command: &mut tokio::process::Command) {
    #[cfg(feature = "nexus-test-support")]
    if std::env::var_os("R2_LEDGER").is_some() {
        command.arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r2_process_ledger.py"),
        );
    }
    #[cfg(not(feature = "nexus-test-support"))]
    let _ = command;
}
use super::nexus_transport::{Delivery, NexusEndpoint, NexusWireFrame};
use crate::nexus::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{unix::OwnedWriteHalf, UnixListener, UnixStream};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{broadcast, Mutex as AsyncMutex};

type Writer = Arc<AsyncMutex<OwnedWriteHalf>>;

fn record_child_exit(pid: Option<u32>, status: &std::process::ExitStatus, method: &str) {
    #[cfg(feature = "nexus-test-support")]
    test_process_ledger::terminal(pid, status, method);
    #[cfg(not(feature = "nexus-test-support"))]
    let _ = (pid, status, method);
}

#[cfg(feature = "nexus-test-support")]
pub fn test_record_child_exit(pid: u32, status: &std::process::ExitStatus, method: &str) {
    record_child_exit(Some(pid), status, method);
}

pub(crate) async fn kill_child(child: &mut Child) -> std::io::Result<()> {
    #[cfg(feature = "nexus-test-support")]
    let pid = child.id();
    child.kill().await?;
    // Tokio kill() already waits. Capture its cached, actual status with the
    // PID saved before reaping; Child::id() becomes None after that point.
    #[cfg(feature = "nexus-test-support")]
    match child.try_wait() {
        Ok(Some(status)) => record_child_exit(pid, &status, "Child.kill.await.cached_status"),
        other => tracing::error!(
            ?pid,
            ?other,
            "test ledger could not collect killed child's status"
        ),
    }
    Ok(())
}

fn try_wait_child(child: &mut Child) -> std::io::Result<Option<std::process::ExitStatus>> {
    let pid = child.id();
    let status = child.try_wait()?;
    if let Some(status) = &status {
        record_child_exit(pid, status, "Child.try_wait");
    }
    Ok(status)
}

async fn wait_child(child: &mut Child) -> std::io::Result<std::process::ExitStatus> {
    let pid = child.id();
    let status = child.wait().await?;
    record_child_exit(pid, &status, "Child.wait");
    Ok(status)
}

async fn output_child(child: Child) -> std::io::Result<std::process::Output> {
    let pid = child.id();
    let output = child.wait_with_output().await?;
    record_child_exit(pid, &output.status, "Child.wait_with_output");
    Ok(output)
}
#[derive(Clone)]
pub struct BridgeConfig {
    pub python: PathBuf,
    pub script: PathBuf,
    /// New private directory; must not already exist. Short enough for Unix sockets.
    pub directory: PathBuf,
    pub environment: BTreeMap<String, String>,
}
struct Pending {
    attempt: DeliveryAttempt,
    granted: bool,
    uncertain: bool,
    stopped: bool,
    open_disconnected: Option<SessionLease>,
}
struct State {
    endpoint: NexusEndpoint,
    helper: Option<Arc<helper::Helper>>,
    bridge_observer: Option<String>,
    bridge_exit: Mutex<Option<Value>>,
    launch_settle: Mutex<LaunchSettle>,
    observer_stop: tokio_util::sync::CancellationToken,
    observation_faults: Mutex<HashMap<String, String>>,
    custody_resources: Mutex<HashMap<LeaseId, custody_wire::Resource>>,
    custody_replies: Mutex<HashMap<String, (Value, Value)>>,
    startups: Mutex<HashMap<String, Value>>,
    custody_retirements: Mutex<HashMap<String, Value>>,
    closed_history: Mutex<std::collections::VecDeque<Value>>,
    proof_handoffs: Mutex<HashSet<String>>,
    retired_open_resources: Mutex<HashSet<OperationId>>,
    callbacks: Mutex<()>,
    pending: Mutex<HashMap<u64, Pending>>,
    leases: Mutex<HashMap<LeaseId, SessionLease>>,
    release_errors: Mutex<HashMap<LeaseId, (SessionLease, String)>>,
    release_facts: Mutex<HashMap<LeaseId, (SessionLease, Value)>>,
    owner_proofs: Mutex<HashMap<LeaseId, (SessionLease, Value)>>,
    startup_proofs: Mutex<HashMap<String, Value>>,
    rejected_acquisitions: Mutex<HashSet<SessionLease>>,
    events: broadcast::Sender<Value>,
    open_replies: Mutex<HashMap<OperationId, tokio::sync::oneshot::Sender<Value>>>,
    open_reply_capacity: usize,
    cache_root: PathBuf,
    failed: std::sync::atomic::AtomicBool,
    stop: tokio_util::sync::CancellationToken,
}
fn take_closed_history(
    history: &mut std::collections::VecDeque<Value>,
    keep: usize,
    ready: impl Fn(&Value) -> bool,
) -> Vec<Value> {
    let closed: Vec<_> = history
        .iter()
        .enumerate()
        .filter(|(_, item)| ready(item))
        .map(|(index, _)| index)
        .collect();
    let remove = closed.len().saturating_sub(keep);
    let mut discarded = Vec::new();
    for index in closed.into_iter().take(remove).rev() {
        if let Some(old) = history.remove(index) {
            discarded.push(old);
        }
    }
    discarded.reverse();
    discarded
}

impl State {
    fn observations_empty(&self) -> bool {
        self.tracked_observations_empty() && self.helper_observations_empty()
    }
    /// What the helper still holds after the exact bridge process is gone while
    /// this router tracks no resource, startup or retirement. Such watches and
    /// parent reservations were signed by the dead bridge before Rust learned of
    /// them, so nothing in this process can advance them; they stay durable in
    /// `helper-state.json` for the helper's orphan expiry and later recovery.
    /// `None` while any tracked responsibility, file job or a live bridge exists,
    /// or while the helper cannot be observed.
    fn untracked_helper_obligations(&self) -> Option<Value> {
        let helper = self.helper.as_ref()?;
        let exited = self
            .bridge_exit
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_some();
        if !exited
            || !self.failed.load(std::sync::atomic::Ordering::Acquire)
            || !self.tracked_observations_empty()
        {
            return None;
        }
        let status = helper.status_snapshot();
        let snapshot = &status["snapshot"];
        if !snapshot.is_object() || status["file_jobs_pending"] != 0 {
            return None;
        }
        let held = ["used", "parent_count", "live_ref_bytes"]
            .iter()
            .any(|field| snapshot[field] != 0);
        held.then(|| {
            json!({"used":snapshot["used"],"parent_count":snapshot["parent_count"],
                "reserved":snapshot["reserved"],"live_ref_bytes":snapshot["live_ref_bytes"],
                "watches":snapshot["watches"]})
        })
    }
    fn helper_observations_empty(&self) -> bool {
        self.helper.as_ref().is_none_or(|helper| {
            let status = helper.status_snapshot();
            let snapshot = &status["snapshot"];
            snapshot.is_object()
                && ["used", "parent_count", "live_ref_bytes"]
                    .iter()
                    .all(|field| snapshot[field] == 0)
                && status["file_jobs_pending"] == 0
        })
    }
    fn tracked_observations_empty(&self) -> bool {
        let resources_empty = self
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty();
        let startups_empty = self
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty();
        let retirements: Vec<_> = self
            .custody_retirements
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .cloned()
            .collect();
        let exited = self
            .bridge_exit
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_some();
        let retirements_empty = retirements.is_empty()
            || (exited
                && retirements.iter().all(|receipt| {
                    let Ok(acquisition) = decode::<AcquisitionId>(receipt["acquisition"].clone())
                    else {
                        return false;
                    };
                    self.endpoint
                        .transition(|sessions, _| sessions.acquisition_verifies_copy(&acquisition))
                        .is_ok_and(|verification| {
                            !verification || receipt["verification_removed"] == true
                        })
                }));
        resources_empty && startups_empty && retirements_empty
    }
    fn compact_closed_history(&self) {
        self.endpoint
            .transition(|sessions, _| sessions.compact_closed_diagnostics(128));
        let discarded = {
            let mut history = self
                .closed_history
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            take_closed_history(&mut history, 128, |old| {
                let Ok(acquisition) = decode::<AcquisitionId>(old["acquisition"].clone()) else {
                    return false;
                };
                self.endpoint
                    .transition(|sessions, _| {
                        sessions
                            .acquisition_sdk_finished(&acquisition)
                            .and_then(|finished| {
                                Ok(finished && sessions.acquisition_closed(&acquisition)?)
                            })
                    })
                    .unwrap_or(false)
            })
        };
        for old in discarded {
            let Ok(lease) = decode::<Option<SessionLease>>(old["lease"].clone()) else {
                continue;
            };
            let watch = old["watch"].as_str().unwrap_or_default().to_owned();

            if let Some(lease) = lease {
                self.owner_proofs
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&lease.lease_id);
                self.release_facts
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&lease.lease_id);
                self.release_errors
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&lease.lease_id);
                self.leases
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&lease.lease_id);
                self.rejected_acquisitions
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&lease);
            }
            self.proof_handoffs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&watch);
            self.startup_proofs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&watch);
            self.observation_faults
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&watch);
        }
    }
    /// Known save refusal is independent of sideband persistence and physical
    /// release. Call only after the exact observation/terminal is authorized.
    fn remember_save_guard_error(
        &self,
        lease: &SessionLease,
        value: &Value,
    ) -> Result<(), NexusError> {
        let Some(message) = value.as_str().filter(|message| !message.is_empty()) else {
            return Ok(());
        };
        let mut errors = self
            .release_errors
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = errors
            .entry(lease.lease_id.clone())
            .or_insert_with(|| (lease.clone(), String::new()));
        if entry.0 != *lease {
            return Err(invalid("save diagnostic lease mismatch"));
        }
        if !entry.1.contains(message) {
            if !entry.1.is_empty() {
                entry.1.push_str("; ");
            }
            entry.1.push_str(message);
        }
        Ok(())
    }

    fn open_reply(
        &self,
        id: &OperationId,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<Value>> {
        let mut replies = self.open_replies.lock().unwrap_or_else(|e| e.into_inner());
        anyhow::ensure!(
            !self.failed.load(std::sync::atomic::Ordering::Acquire),
            "bridge disconnected"
        );
        anyhow::ensure!(
            replies.len() < self.open_reply_capacity && !replies.contains_key(id),
            "Busy: open reply capacity or duplicate identity"
        );
        let (sender, receiver) = tokio::sync::oneshot::channel();
        replies.insert(id.clone(), sender);
        Ok(receiver)
    }
    fn emit(&self, event: Value) {
        tracing::debug!(event = event["event"].as_str(), attempt = ?event.get("attempt"), lease = ?event.get("lease"), "Nexus bridge lifecycle");
        if event["attempt"]["target"]["kind"] == "open" && event.get("error").is_some() {
            tracing::warn!(
                category = event["error"]["code"].as_str(),
                reason = event["error"]["message"].as_str(),
                operation = event["attempt"]["target"]["identity"]["operation_id"].as_str(),
                diagnostics = ?event.get("diagnostics"),
                "Nexus open failed"
            );
        }
        // Open transfers lease responsibility: diagnostic broadcast may lag,
        // but a registered supervisor must receive its exact terminal outcome.
        if matches!(
            event["event"].as_str(),
            Some("opened" | "failed" | "uncertain" | "not_sent" | "remote_error")
        ) && event["attempt"]["target"]["kind"] == "open"
        {
            if let Some(id) = event["attempt"]["target"]["identity"]["operation_id"].as_str() {
                if let Ok(id) = OperationId::new(id) {
                    if let Some(sender) = self
                        .open_replies
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&id)
                    {
                        let _ = sender.send(event.clone());
                    }
                }
            }
        }
        if event["event"] == "bridge_disconnected" {
            for (_, sender) in self
                .open_replies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .drain()
            {
                let _ = sender.send(event.clone());
            }
        }
        let _ = self.events.send(event); // Diagnostics only; N1 remains authoritative.
    }
    fn fail(&self, reason: &str) {
        if self.failed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        self.stop.cancel();
        let pending = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
        let leases: Vec<_> = self
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        self.endpoint.transition(|sessions, _| {
            for item in pending.values() {
                let error = NexusError::new(NexusErrorCode::Disconnected, reason);
                let result = sessions.delivery_failed(
                    &item.attempt,
                    if item.granted {
                        DispatchFailure::Uncertain(error)
                    } else {
                        DispatchFailure::NotSent(error)
                    },
                );
                if let Err(error) = result {
                    tracing::error!(%error, "bridge failure callback rejected");
                }
            }
            for lease in leases {
                sessions.disconnected(&lease.instance_id, lease.generation);
            }
        });
        self.emit(json!({"event":"bridge_disconnected", "reason":reason}));
    }
}
/// Owned by one RouterState. Dropping it kills only its own bridge, never an owner.
pub struct NexusBridge {
    state: Arc<State>,
    child: Arc<AsyncMutex<Child>>,
    lifetime: AsyncMutex<Option<ChildStdin>>,
    control: Writer,
    directory: PathBuf,
    prepared_python: PathBuf,
    installation: PathBuf,
    owned_files: Mutex<Option<owned_files::OwnedFiles>>,
    probe_cleanup_ready: std::sync::atomic::AtomicBool,
    untracked_settled: std::sync::atomic::AtomicBool,
    pub ida_version: String,
    pub installed_ida_version: Option<String>,
    pub pid: u32,
}
/// How long helper-only obligations must stay unchanged after the bridge process
/// exit before shutdown treats them as untracked (longer than one helper call).
const UNTRACKED_HELPER_SETTLE: Duration = Duration::from_secs(3);
/// Exec margin after the exact bridge was reaped. Nothing can fork a worker for
/// a signed launch any more; a child that was between fork and exec when its
/// parent died finishes exec within milliseconds, so five seconds is a wide
/// margin before the process table is read as evidence of absence.
const LAUNCH_SETTLE_MARGIN: Duration = Duration::from_secs(5);
/// Pacing of the helper's process-table/discovery probes for one launch.
const LAUNCH_SETTLE_PROBE: Duration = Duration::from_secs(1);

/// Router-side clock and pacing for settling a launch whose bridge was reaped
/// before the Spawned fact was signed.
#[derive(Default)]
struct LaunchSettle {
    reaped_at: Option<std::time::Instant>,
    probed: HashMap<String, std::time::Instant>,
    reported: HashMap<String, String>,
}
// F2/P2-b: acquired before bind/spawn, retained across every startup await.
// The drop reaper owns the Child (no PID rediscovery) and waits before unlink,
// so a child cannot recreate l after cleanup. It needs no live Tokio runtime.
struct StartupGuard {
    child: Option<Child>,
    directory: Option<PathBuf>,
}
impl Drop for StartupGuard {
    fn drop(&mut self) {
        let Some(directory) = self.directory.take() else {
            return;
        };
        if let Some(mut child) = self.child.take() {
            if let Err(error) = child.start_kill() {
                tracing::warn!(%error, "bridge startup kill failed");
            }
            std::thread::spawn(move || {
                loop {
                    match try_wait_child(&mut child) {
                        Ok(Some(_)) => break,
                        Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                        Err(error) => {
                            tracing::error!(%error, "bridge startup reap unconfirmed; paths retained");
                            return;
                        }
                    }
                }
                cleanup_startup_sockets(&directory);
            });
        } else {
            cleanup_startup_sockets(&directory);
        }
    }
}
fn cleanup_startup_sockets(directory: &std::path::Path) {
    for name in ["b", "c", "l"] {
        if let Err(error) = remove_owned_socket(&directory.join(name)) {
            tracing::error!(%error, path = %directory.join(name).display(), "bridge startup socket cleanup failed");
        }
    }
}
impl NexusBridge {
    /// The bridge channel failed or was stopped; this router never replaces it.
    pub(crate) fn is_lost(&self) -> bool {
        self.state.failed.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn resource_retirement_pending(&self, lease: &SessionLease) -> bool {
        self.state
            .custody_retirements
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|receipt| {
                receipt["lease"] == json!(lease) && !receipt["resource_retirement"].is_null()
            })
    }
    /// Non-secret current obligations, independent of command subscribers.
    pub fn lifecycle_status(&self) -> Value {
        let state = &self.state;
        let acquisitions = state
            .endpoint
            .transition(|s, _| Ok::<_, NexusError>(s.acquisition_status()))
            .unwrap_or_else(|error| json!({"error":error.details()}));
        let resources: Vec<_> = state.custody_resources.lock().unwrap_or_else(|e|e.into_inner())
            .values().map(|r|json!({"watch":r.watch,"target":r.target,"owner":r.owner,
                "lease":r.lease,"acquisition":r.acquisition,"public_proof_adopted":r.proof.is_some(),
                "producer_closed":r.consumer.is_some(),"bridge_closed":r.bridge_proof_ack,
                "boot_retirement_scope":r.origin_binding["boot_retirement_capability"],
                "boot_retirement_reason":r.origin_binding["unsupported_reason"],
                "permission_scope":r.origin_binding["permission_scope"]})).collect();
        let startups: Vec<_> = state
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|r| {
                json!({"watch":r["watch"],"target":r["target"],"owner":r["owner"],
                "acquisition":r["acquisition"],"launch":r["launch"],
                "public_proof_adopted":r.get("proof").is_some(),
                "boot_retirement_scope":r["origin_binding"]["boot_retirement_capability"],
                "boot_retirement_reason":r["origin_binding"]["unsupported_reason"],
                "permission_scope":r["origin_binding"]["permission_scope"]})
            })
            .collect();
        let blocked = state
            .observation_faults
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let untracked = state.untracked_helper_obligations();
        json!({"ready": !state.failed.load(std::sync::atomic::Ordering::SeqCst) && !state.stop.is_cancelled(), "resources":resources.len(),"startup_and_pre_attach":startups.len(),
            "bridge_dir":self.installation,"prepared_python":self.prepared_python,
            "maintenance_launcher":self.installation.join("maintenance-launch"),
            "resource_details":resources,"startup_details":startups,"blocked":blocked,"acquisitions":acquisitions,
            "retirement_acks":state.custody_retirements.lock().unwrap_or_else(|e|e.into_inner()).len(),
            "helper":state.helper.as_ref().map(|h|h.status_snapshot()),
            "state_root":state.helper.as_ref().map(|h|&h.state_root),
            "live_limit":state.open_reply_capacity,"same_boot_eligibility":false,
            "boot_retirement":"requires_verified_native_creation_and_consumption_scope",
            "untracked_helper_obligations":untracked,
            "next_action":if !blocked.is_empty() {"inspect_observation_failure"}
                else if untracked.is_some() {"shutdown_then_restart_helper_retains_obligations"}
                else {"wait_public_owner_lifetime"}})
    }
    pub(crate) fn owner_release_status(&self, lease: &SessionLease) -> Value {
        let resource = self
            .state
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&lease.lease_id)
            .filter(|r| r.lease == *lease)
            .cloned();
        let mut value = self
            .state
            .release_facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&lease.lease_id)
            .filter(|(exact, _)| exact == lease)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| json!({}));
        if let Some(resource) = resource {
            value["owner"] = resource.owner;
            value["watch"] = json!(resource.watch);
        }
        let proofs = self
            .state
            .owner_proofs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let proof = proofs
            .get(&lease.lease_id)
            .filter(|(exact, _)| exact == lease)
            .map(|(_, proof)| proof.clone())
            .or_else(|| {
                // Only confirmed nonlast leases share this diagnostic owner
                // fact. Their original ACK/result and N1 history stay intact.
                (value["outcome"]["lease_released"] == true
                    && value["outcome"]["ack_kind"] == "nonlast"
                    && value["owner"].is_object())
                .then(|| {
                    proofs
                        .values()
                        .find(|(_, proof)| proof["record"]["owner"] == value["owner"])
                        .map(|(_, proof)| proof.clone())
                })
                .flatten()
            });
        drop(proofs);
        value["owner_released"] =
            json!(proof.is_some() || value["outcome"]["owner_released"] == true);
        value["owner_pending"] = json!(value["owner_released"] != true);
        if let Some(proof) = proof {
            value["evidence_scope"] = json!("public_owner_lifetime");
            value["proof"] = proof;
        }
        if let Ok(Some(evidence)) = self
            .state
            .endpoint
            .transition(|s, _| s.resource_retirement(lease))
        {
            value["resource_retirement"] = evidence;
            value["owner_pending"] = json!(false);
            value["evidence_scope"] = json!("verified_boot_change_resource_retirement");
        }
        value
    }
    pub(crate) fn retains_owner_observation(&self, lease: &SessionLease) -> bool {
        self.state
            .custody_resources
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains_key(&lease.lease_id)
            || self
                .state
                .release_facts
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains_key(&lease.lease_id)
            || self
                .state
                .owner_proofs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains_key(&lease.lease_id)
    }
    pub(crate) fn take_release_error(&self, lease: &SessionLease) -> Option<String> {
        self.state
            .release_errors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&lease.lease_id)
            .and_then(|(exact, message)| (exact == lease).then(|| message.clone()))
    }
    pub(crate) fn cleanup_blocked(&self, lease: &SessionLease, error: NexusError) {
        let mut facts = self
            .state
            .release_facts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (exact, value) = facts
            .entry(lease.lease_id.clone())
            .or_insert_with(|| (lease.clone(), json!({})));
        if exact == lease {
            value["cleanup_state"] = json!("CleanupBlocked");
            if value["cleanup_error"].is_null() {
                value["cleanup_error"] = error.details();
            }
        }
    }
    pub(crate) fn retry_cleanup(&self, lease: &SessionLease) {
        if let Some((exact, facts)) = self
            .state
            .release_facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&lease.lease_id)
        {
            if exact == lease {
                facts["cleanup_state"] = json!("CleanupRetryAccepted");
            }
        }
    }
    pub async fn start(
        router: &super::RouterState,
        mut config: BridgeConfig,
    ) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let startup_cwd = std::env::current_dir()?;
        let ida_home: PathBuf = startup_cwd
            .join(crate::idb_store::ida_home_from(
                config
                    .environment
                    .get("IDA_CLI_HOME")
                    .map(std::ffi::OsStr::new),
                config.environment.get("HOME").map(std::ffi::OsStr::new),
            ))
            .components()
            .collect();
        let home = ida_home
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Nexus home is not UTF-8"))?;
        config
            .environment
            .insert("IDA_CLI_HOME".into(), home.into());
        config.environment.insert(
            "IDA_CLI_NEXUS_PROTOCOL".into(),
            serde_json::to_string(&protocol::Protocol::current())?,
        );
        std::fs::create_dir(&config.directory)?;
        std::fs::set_permissions(&config.directory, std::fs::Permissions::from_mode(0o700))?;
        let mut owned_files = owned_files::OwnedFiles::created(&config.directory)?;
        let installation_path = config.directory.join("installation");
        installation::create(&installation_path)?;
        owned_files.record_installation()?;
        config.environment.insert(
            "IDA_CLI_BRIDGE_INSTALLATION".into(),
            installation_path.to_string_lossy().into_owned(),
        );
        let mut helper = if config
            .script
            .file_name()
            .is_some_and(|name| name == "bridge.py")
        {
            Some(helper::Helper::start(&mut config, &installation_path).await?)
        } else {
            None // Explicit fixture adapters keep their pre-custody wire contract.
        };
        let mut owner = StartupGuard {
            child: None,
            directory: Some(config.directory.clone()),
        };
        let business_path = config.directory.join("b");
        let control_path = config.directory.join("c");
        let business = UnixListener::bind(&business_path)?;
        owned_files.record_socket("b")?;
        let control = UnixListener::bind(&control_path)?;
        owned_files.record_socket("c")?;
        let capacity = router.config.max_pending_per_tenant;
        let log = std::fs::File::create(config.directory.join("stderr.log"))?;
        owned_files.record(std::path::Path::new("stderr.log"), false)?;
        let production = config
            .script
            .file_name()
            .is_some_and(|name| name == "bridge.py");
        let mut process = Command::new(&config.python);
        if production {
            process.arg("-I").arg("-B");
            python_ledger(&mut process);
            process
                .arg(installation_path.join("bootstrap.py"))
                .arg("bridge");
        } else {
            process.arg(&config.script);
        }
        owner.child = Some(spawn_child(
            process
                .current_dir(&startup_cwd)
                .arg(&business_path)
                .arg(&control_path)
                .arg(capacity.to_string())
                .env_clear()
                .envs(&config.environment)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::from(log))
                .kill_on_drop(true),
        )?);
        let child = owner
            .child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("startup child missing"))?;
        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("bridge exited before PID registration"))?;
        let lifetime = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("bridge stdout missing"))?;
        let mut lines = BufReader::new(stdout).lines();
        let startup = async {
            let line = lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("bridge exited without readiness"))?;
            let ready: Value = serde_json::from_str(&line)?;
            if ready["ready"] != true {
                anyhow::bail!("Nexus readiness: {}", ready["error"]);
            }
            if ready["custody_protocol"] == 1 && helper.is_none() {
                let root = ready["paths"]["state_dir"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("helper state path missing"))?;
                config
                    .environment
                    .insert("IDA_NEXUS_STATE_DIR".into(), root.into());
                helper = Some(helper::Helper::start(&mut config, &installation_path).await?);
            }
            protocol::Protocol::validate(ready["protocol"].clone())?;
            anyhow::ensure!(
                ready["paths"]["ida_cli_home"].as_str() == ida_home.to_str(),
                "ProtocolMismatch: bridge home differs from startup home"
            );
            let state_dir = ready["paths"]["state_dir"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("ProtocolMismatch: missing Nexus state root"))?;
            anyhow::ensure!(
                std::path::Path::new(state_dir).is_absolute(),
                "ProtocolMismatch: Nexus state root must be absolute"
            );
            let caps: NexusCapabilities = serde_json::from_value(ready["capabilities"].clone())?;
            anyhow::ensure!(
                caps.runtime.nexus == Some(Version(0, 13, 4))
                    && caps.runtime.domain == Some(Version(0, 5, 1)),
                "ProtocolMismatch: fixed client versions required"
            );
            caps.runtime.validate()?;
            let (b, _) = business.accept().await?;
            let (c, _) = control.accept().await?;
            Ok::<_, anyhow::Error>((
                caps,
                b,
                c,
                ready["observer_incarnation"].as_str().map(str::to_owned),
                ready["installed_ida_version"].as_str().map(str::to_owned),
            ))
        };
        let connected = tokio::time::timeout(Duration::from_secs(15), startup).await;
        let (caps, b, c, bridge_observer, installed_ida_version) = match connected {
            Ok(Ok(value)) => value,
            other => {
                return Err(match other {
                    Ok(Err(error)) => error,
                    _ => anyhow::anyhow!("bridge readiness deadline expired"),
                });
            }
        };
        let ida_version = format!("{}.{}", caps.runtime.ida.0, caps.runtime.ida.1);
        router.install_nexus_capabilities(caps)?;
        let endpoint = router.nexus_endpoint();
        let lanes = endpoint
            .take_lanes()
            .ok_or_else(|| anyhow::anyhow!("Nexus lanes already consumed"))?;
        let (events, _) = broadcast::channel(capacity.max(8));
        let state = Arc::new(State {
            cache_root: ida_home.join("idb"),
            endpoint,
            helper,
            bridge_observer,
            bridge_exit: Mutex::new(None),
            launch_settle: Mutex::new(LaunchSettle::default()),
            observer_stop: tokio_util::sync::CancellationToken::new(),
            observation_faults: Mutex::new(HashMap::new()),
            custody_resources: Mutex::new(HashMap::new()),
            custody_replies: Mutex::new(HashMap::new()),
            startups: Mutex::new(HashMap::new()),
            custody_retirements: Mutex::new(HashMap::new()),
            closed_history: Mutex::new(std::collections::VecDeque::new()),
            proof_handoffs: Mutex::new(HashSet::new()),
            retired_open_resources: Mutex::new(HashSet::new()),
            callbacks: Mutex::new(()),
            pending: Mutex::new(HashMap::new()),
            leases: Mutex::new(HashMap::new()),
            release_errors: Mutex::new(HashMap::new()),
            release_facts: Mutex::new(HashMap::new()),
            owner_proofs: Mutex::new(HashMap::new()),
            startup_proofs: Mutex::new(HashMap::new()),
            rejected_acquisitions: Mutex::new(HashSet::new()),
            events,
            open_replies: Mutex::new(HashMap::new()),
            open_reply_capacity: capacity,
            failed: std::sync::atomic::AtomicBool::new(false),
            stop: tokio_util::sync::CancellationToken::new(),
        });
        let bw = start_channel(b, state.clone(), false);
        let cw = start_channel(c, state.clone(), true);
        if let Some(helper) = &state.helper {
            send(&cw, &json!({"helper_configuration":{"endpoint":helper.endpoint,"incarnation":helper.incarnation,"state_root":helper.state_root}})).await?;
        }
        tokio::spawn(pump(lanes.business, bw, state.clone()));
        tokio::spawn(pump(lanes.control, cw.clone(), state.clone()));
        let child = owner
            .child
            .take()
            .ok_or_else(|| anyhow::anyhow!("startup child missing"))?;
        let child = Arc::new(AsyncMutex::new(child));
        let observed_child = child.clone();
        let observing = Arc::downgrade(&state);
        let proof_writer = cw.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                let Some(state) = observing.upgrade() else {
                    break;
                };
                if state.observer_stop.is_cancelled() {
                    break;
                }
                match try_wait_child(&mut *observed_child.lock().await) {
                    Ok(Some(status)) => {
                        *state.bridge_exit.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some(json!({"pid":pid,"status":status.to_string()}));
                        state
                            .launch_settle
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .reaped_at
                            .get_or_insert_with(std::time::Instant::now);
                    }
                    Ok(None) => {}
                    Err(error) => tracing::warn!(%error, "bridge producer waitpid unavailable"),
                }
                if let Err(error) = custody_wire::proofs(&state, &proof_writer).await {
                    tracing::warn!(%error, "owner observation retained; proof custody not complete");
                }
                // EOF/Drop owns no caller to request finish. Exact waitpid plus
                // empty custody/helper state authorizes only our helper's exit.
                if state.failed.load(std::sync::atomic::Ordering::Acquire)
                    && state
                        .bridge_exit
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .is_some()
                    && state.observations_empty()
                {
                    if let Some(helper) = &state.helper {
                        match helper.finish().await {
                            Ok(()) => {
                                state.observer_stop.cancel();
                                break;
                            }
                            Err(error) => {
                                tracing::warn!(%error, "closed bridge helper retirement pending")
                            }
                        }
                    }
                }
            }
        });
        let ticking = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            while !ticking.failed.load(std::sync::atomic::Ordering::Acquire) {
                interval.tick().await;
                let operations: Vec<_> = ticking
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .filter_map(|p| match &p.attempt.target {
                        DeliveryTarget::Execute { identity } => Some(identity.clone()),
                        _ => None,
                    })
                    .collect();
                let leases: Vec<_> = ticking
                    .leases
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .cloned()
                    .collect();
                ticking.endpoint.transition(|s, t| {
                    for lease in leases {
                        if s.resource_retirement(&lease).is_ok_and(|r|r.is_some()) { continue; }
                        if let Err(error) = s.poll_preparation(&lease, t) {
                            tracing::debug!(%error, "Nexus preparing cancellation pending");
                        }
                        if s.cleanup_exhausted(&lease) && s.status(&lease.client_id,&lease)
                            .is_ok_and(|status| status.phase == SessionPhase::ReleaseRequired) {
                            let mut facts=ticking.release_facts.lock().unwrap_or_else(|e|e.into_inner());
                            let entry=facts.entry(lease.lease_id.clone()).or_insert_with(||(lease.clone(),json!({})));
                            entry.1["cleanup_state"]=json!("CleanupBlocked");
                            entry.1["cleanup_error"]=NexusError::new(NexusErrorCode::Busy,
                                "exact acquisition cleanup RPC capacity exhausted; retained without replay").details();
                        }
                        let blocked = ticking.release_facts.lock().unwrap_or_else(|e|e.into_inner())
                            .get(&lease.lease_id).is_some_and(|(_, facts)| facts["cleanup_state"] == "CleanupBlocked");
                        if !blocked && s.status(&lease.client_id, &lease).is_ok_and(|status| status.phase == SessionPhase::ReleaseRequired) {
                            if let Err(error) = s.release(&lease.client_id, &lease, t) {
                                tracing::debug!(%error, lease_id=lease.lease_id.as_str(), "Nexus retained open lease cleanup pending");
                            }
                        }
                    }
                    for op in operations {
                        if s.operation_progress(&op.lease.client_id, &op)
                            .is_ok_and(|snapshot| snapshot.status.is_terminal() && snapshot.execution_stopped) {
                            continue;
                        }
                        if let Err(error) = s.expire(&op.lease.client_id, &op, t) {
                            tracing::debug!(%error, operation_id=op.operation_id.as_str(), "bridge deadline poll");
                        }
                    }
                });
            }
        });
        owned_files.record_socket("l")?;
        if state.helper.is_some() {
            owned_files.record(std::path::Path::new("helper.log"), false)?;
            owned_files.record_socket("h")?;
        }
        owner.directory = None; // ownership transfers to the live bridge only now.
        Ok(Self {
            state,
            child,
            lifetime: AsyncMutex::new(lifetime),
            control: cw,
            directory: config.directory,
            prepared_python: config.python,
            installation: installation_path.canonicalize()?,
            owned_files: Mutex::new(Some(owned_files)),
            probe_cleanup_ready: std::sync::atomic::AtomicBool::new(false),
            untracked_settled: std::sync::atomic::AtomicBool::new(false),
            ida_version,
            installed_ida_version,
            pid,
        })
    }
    pub fn subscribe(&self) -> broadcast::Receiver<Value> {
        self.state.events.subscribe()
    }
    pub fn open_reply(
        &self,
        id: &OperationId,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<Value>> {
        self.state.open_reply(id)
    }
    pub fn forget_open_reply(&self, id: &OperationId) {
        self.state
            .open_replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }
    #[cfg(test)]
    pub(crate) fn test_reply_count(&self) -> usize {
        self.state.open_replies.lock().unwrap().len()
    }
    pub fn endpoint(&self) -> NexusEndpoint {
        self.state.endpoint.clone()
    }
    /// Consume injected OS-source observations through the production U6 path.
    #[cfg(feature = "nexus-test-support")]
    pub async fn test_boot_resource_projection(&self) -> anyhow::Result<()> {
        custody_wire::test_boot_resource_projection(&self.state, &self.control).await
    }
    #[cfg(feature = "nexus-test-support")]
    pub async fn test_helper_pause(&self) -> anyhow::Result<Value> {
        self.state
            .helper
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("test helper missing"))?
            .inject_pause()
            .await
    }

    #[cfg(feature = "nexus-test-support")]
    pub async fn test_helper_fault(&self, cleanup: bool) -> anyhow::Result<Value> {
        if cleanup {
            self.state.observer_stop.cancel();
        }
        let helper = self
            .state
            .helper
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("test helper missing"))?;
        helper.inject_crash().await
    }
    pub(crate) fn open_resource_obligations(&self, identity: &OpenIdentity) -> (bool, bool) {
        // OpenIdentity contains only typed strings/options. Fail closed if its
        // representation ever acquires a fallible serializer.
        let Ok(encoded) = serde_json::to_value(identity) else {
            return (true, false);
        };
        let live = self
            .state
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|item| item["acquisition"]["parent"] == encoded);
        let retired = self
            .state
            .retired_open_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&identity.operation_id);
        (live, retired)
    }
    #[cfg(feature = "nexus-test-support")]
    pub fn test_detach_observer(&self) {
        self.state.observer_stop.cancel();
    }
    #[cfg(feature = "nexus-test-support")]
    pub async fn test_wait_injected_orphan(&self) -> anyhow::Result<Value> {
        self.state
            .helper
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("helper unavailable"))?
            .wait_injected_orphan()
            .await
    }
    #[cfg(feature = "nexus-test-support")]
    pub async fn test_finished_helper_heartbeat(&self) -> anyhow::Result<Value> {
        self.state
            .helper
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("test helper missing"))?
            .call(json!({"kind":"heartbeat"}))
            .await
    }
    pub async fn status(&self, id: &str) -> anyhow::Result<()> {
        send(&self.control, &json!({"local_status":id})).await
    }
    pub(crate) async fn wait_shutdown_ready(
        &self,
        preparation: &crate::preprocess::Preparation,
    ) -> Result<(), crate::error::ToolError> {
        // Untracked helper obligations must stay unchanged for a full settle
        // window: a retirement this router is still finishing briefly leaves
        // both its tables and the helper in that shape.
        let mut untracked_since: Option<(Value, std::time::Instant)> = None;
        loop {
            if let Some(helper) = &self.state.helper {
                if !helper.is_finished() {
                    tokio::time::timeout_at(
                        preparation.deadline.into(),
                        helper.observe_for_shutdown(),
                    )
                    .await
                    .map_err(|_| {
                        NexusError::new(
                            NexusErrorCode::CancelPending,
                            "shutdown observation deadline expired; bridge retained",
                        )
                    })?
                    .map_err(|error| {
                        NexusError::new(
                            NexusErrorCode::CancelPending,
                            format!(
                                "shutdown helper observation unconfirmed: {error}; bridge retained"
                            ),
                        )
                    })?;
                }
            }
            if self.state.observations_empty() {
                return Ok(());
            }
            match self.state.untracked_helper_obligations() {
                // Settled once; the RPC shutdown and the final process shutdown
                // both pass through here and must not pay the window twice.
                Some(_)
                    if self
                        .untracked_settled
                        .load(std::sync::atomic::Ordering::Acquire) =>
                {
                    return Ok(());
                }
                Some(held) => match &untracked_since {
                    Some((previous, since))
                        if *previous == held && since.elapsed() >= UNTRACKED_HELPER_SETTLE =>
                    {
                        self.untracked_settled
                            .store(true, std::sync::atomic::Ordering::Release);
                        return Ok(());
                    }
                    Some((previous, _)) if *previous == held => {}
                    _ => untracked_since = Some((held, std::time::Instant::now())),
                },
                None => untracked_since = None,
            }
            #[cfg(test)]
            self.state
                .emit(json!({"event":"shutdown_observations_pending"}));
            if preparation.check().is_err() {
                return Err(NexusError::new(NexusErrorCode::CancelPending,
                    format!("shutdown waits for existing custody retirement and helper observations; bridge retained; inspect {}/helper-state.json and lifecycle blocked entries, restore the exact target storage, then retry shutdown with the same coordinator; never replay unknown database operations", self.directory.display())).into());
            }
            tokio::time::sleep_until(
                preparation
                    .deadline
                    .min(std::time::Instant::now() + Duration::from_millis(20))
                    .into(),
            )
            .await;
        }
    }
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.wait_shutdown_ready(&crate::preprocess::Preparation::new(Duration::from_secs(
            15,
        )))
        .await?;
        self.lifetime.lock().await.take();
        let mut child = self.child.lock().await;
        match tokio::time::timeout(Duration::from_secs(12), wait_child(&mut child)).await {
            Ok(status) => {
                status?;
            }
            Err(_) => {
                kill_child(&mut child).await?;
                wait_child(&mut child).await?;
                remove_lifetime_socket(&self.directory)?;
                anyhow::bail!(
                    "bridge cleanup deadline expired; own bridge killed, owner stop unconfirmed"
                );
            }
        }
        let socket_cleanup = self.remove_recorded_socket("l");
        self.state.fail("bridge stopped");
        if let Some(held) = self.state.untracked_helper_obligations() {
            // The helper would refuse finish: it owns obligations that only the
            // dead bridge knew. Keep them durable; its orphan expiry abandons
            // them with a recorded cause, and a later incarnation recovers them.
            // No proof, retirement or replay is fabricated here.
            tracing::warn!(held = %held, directory = %self.directory.display(),
                "bridge process is gone; shutdown leaves untracked helper obligations durable in helper-state.json");
            self.state.observer_stop.cancel();
            socket_cleanup?;
            return Ok(());
        }
        if let Some(helper) = &self.state.helper {
            // Never force-stop an observer with outstanding responsibility.
            helper.finish().await?;
        }
        // Accepted finish proves the helper has no remaining observation
        // responsibility. Stop the local poller only after that acceptance;
        // a refused finish must keep recovery/observation running.
        self.state.observer_stop.cancel();
        self.probe_cleanup_ready
            .store(true, std::sync::atomic::Ordering::Release);
        socket_cleanup?;
        Ok(())
    }

    fn remove_recorded_socket(&self, name: &str) -> anyhow::Result<()> {
        let owned = self
            .owned_files
            .lock()
            .map_err(|_| anyhow::anyhow!("bridge creation records poisoned"))?;
        if let Some(owned) = &*owned {
            owned.remove_socket(name)?;
        }
        Ok(())
    }

    /// Only a readiness probe with no acquisition history may discard its
    /// temporary installation. Ordinary sessions retain all durable evidence.
    pub(crate) async fn cleanup_probe(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.probe_cleanup_ready
                .load(std::sync::atomic::Ordering::Acquire),
            "probe cleanup requires confirmed bridge/helper shutdown"
        );
        anyhow::ensure!(
            self.state
                .endpoint
                .transition(|s, _| s.retention_status())
                .total_used
                == 0,
            "probe cleanup refused: acquisition history retained"
        );
        let mut owned = self
            .owned_files
            .lock()
            .map_err(|_| anyhow::anyhow!("bridge creation records poisoned"))?
            .take()
            .ok_or_else(|| anyhow::anyhow!("probe creation records already consumed"))?;
        if let Some(helper) = &self.state.helper {
            // Finish atomically creates the final registry inode. Its durable
            // creator/incarnation and empty obligations must be verified before
            // that last creation is registered for disposable probe cleanup.
            let created = helper
                .finish_record()?
                .ok_or_else(|| anyhow::anyhow!("probe helper finish not durably confirmed"))?;
            owned.record_validated(std::path::Path::new("helper-state.json"), &created)?;
        }
        owned.cleanup()
    }
    /// Test supervisor may terminate this exact child; no process-name scans.
    pub async fn terminate(&self) -> anyhow::Result<()> {
        let mut child = self.child.lock().await;
        kill_child(&mut child).await?;
        wait_child(&mut child).await?;
        remove_lifetime_socket(&self.directory)?;
        self.state.fail("bridge terminated");
        Ok(())
    }
}
impl Drop for NexusBridge {
    fn drop(&mut self) {
        self.state.fail("bridge owner dropped");
        for name in ["b", "c", "l"] {
            if let Err(error) = self.remove_recorded_socket(name) {
                tracing::warn!(%error, "bridge socket cleanup retained replacement");
            }
        }
    }
}
// R-sock: the child owns l inside this parent's fresh 0700 directory. Also
// remove it after waitpid/SIGKILL, when Python cannot run its finally block.
fn remove_lifetime_socket(directory: &std::path::Path) -> std::io::Result<()> {
    remove_owned_socket(&directory.join("l"))
}
fn remove_owned_socket(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {}
        Ok(_) => return Err(std::io::Error::other("owned socket was replaced")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
async fn send(writer: &Writer, value: &Value) -> anyhow::Result<()> {
    let mut data = serde_json::to_vec(value)?;
    data.push(b'\n');
    writer.lock().await.write_all(&data).await?;
    Ok(())
}
async fn pump(mut lane: tokio::sync::mpsc::Receiver<Delivery>, writer: Writer, state: Arc<State>) {
    loop {
        let delivery = tokio::select! {
            _ = state.stop.cancelled() => break,
            delivery = lane.recv() => match delivery { Some(value) => value, None => break },
        };
        if state.failed.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        #[cfg(test)]
        if std::env::var("N4_F2_OPEN_FAULT").as_deref() == Ok("zero-byte") {
            static FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
            if let DeliveryTarget::Open { identity } = &delivery.attempt.target {
                if FIRST.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    state
                        .endpoint
                        .transition(|s, _| s.cancel_open(&identity.client_id, identity))
                        .unwrap();
                }
            }
        }
        let sequence = delivery.attempt.sequence.get();
        state
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                sequence,
                Pending {
                    attempt: delivery.attempt.clone(),
                    granted: false,
                    uncertain: false,
                    stopped: false,
                    open_disconnected: None,
                },
            );
        let mut stream = writer.lock().await;
        let mut counted = CountingWriter {
            inner: &mut stream,
            bytes: 0,
        };
        let result = tokio::select! {
            _ = state.stop.cancelled() => break,
            result = delivery.write(&mut counted) => result,
        };
        if let Err(error) = result {
            state
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&sequence);
            tracing::warn!(%error, "bridge lane write failed");
            if counted.bytes != 0 || error.code == NexusErrorCode::Disconnected {
                state.fail("bridge lane stream failed");
                break;
            }
            // Proven zero-byte local failure affects this request only.
        }
    }
}
struct CountingWriter<'a> {
    inner: &'a mut OwnedWriteHalf,
    bytes: usize,
}
impl tokio::io::AsyncWrite for CountingWriter<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut *self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(size)) = result {
            self.bytes += size;
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

// One in-flight decoder, queued by the existing control stream reader. No
// try-acquire, no CLI control encoder permit, no increase in lane admission.
async fn decode_control(line: Vec<u8>) -> anyhow::Result<Result<Value, serde_json::Error>> {
    static GATE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));
    let permit = GATE.clone().acquire_owned().await?;
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("nexus-control-decode".into())
        .spawn(move || {
            let _permit = permit;
            let _ = send.send(serde_json::from_slice(&line));
        })?;
    Ok(receive.await?)
}

fn start_channel(stream: UnixStream, state: Arc<State>, control: bool) -> Writer {
    let (read, write) = stream.into_split();
    let writer = Arc::new(AsyncMutex::new(write));
    let responding = writer.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(read);
        loop {
            let next = tokio::select! { _ = state.stop.cancelled() => break, next = receiver::read_line(&mut lines) => next };
            match next {
                Ok(Some(line)) => {
                    let decoded = if control {
                        decode_control(line)
                            .await
                            .map_err(|e| crate::error::ToolError::IdaError(e.to_string()))
                    } else {
                        crate::blocking::request_decode(move || {
                            serde_json::from_slice::<Value>(&line)
                        })
                        .await
                    };
                    let event = match decoded {
                        Ok(Ok(value)) => value,
                        Ok(Err(error)) => {
                            receiver::rejected(
                                &state,
                                None,
                                format!("invalid complete JSON line: {error}"),
                            );
                            continue;
                        }
                        Err(error) => {
                            tracing::error!(%error, "bridge decoder unavailable");
                            break;
                        }
                    };
                    match receiver::receive_event(event, &responding, &state, control).await {
                        Ok(receiver::ReceiveOutcome::Accepted) => {}
                        Ok(
                            receiver::ReceiveOutcome::Dropped(reason)
                            | receiver::ReceiveOutcome::ResourceRetained(reason),
                        ) => {
                            tracing::debug!(%reason, "Nexus isolated event rejection");
                        }
                        Err(error) => {
                            tracing::error!(%error, "bridge physical event write failed");
                            break;
                        }
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(%error, "bridge response read failed");
                    break;
                }
            }
        }
        state.fail("bridge response stream disconnected");
        if let Err(error) = responding.lock().await.shutdown().await {
            tracing::debug!(%error, "bridge half-close");
        }
    });
    writer
}
async fn event_received(
    mut event: Value,
    writer: &Writer,
    state: &Arc<State>,
    control: bool,
) -> anyhow::Result<()> {
    if event["event"] == "owner_backup_proof" {
        anyhow::ensure!(control, "backup proof on wrong lane");
        let watch = event["watch"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("backup watch missing"))?;
        let proof = &event["proof"];
        anyhow::ensure!(
            state.bridge_observer.as_deref() == proof["record"]["helper"].as_str()
                && proof["record"]["watch"] == watch
                && proof["record"]["evidence_type"] == "public_owner_lifetime",
            "backup proof producer mismatch"
        );
        let mut resources = state
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(resource) = resources.values_mut().find(|r| r.watch == watch) {
            anyhow::ensure!(
                proof["record"]["owner"] == resource.owner
                    && proof["record"]["acquisition"]
                        == serde_json::to_value(&resource.acquisition)?,
                "backup proof resource mismatch"
            );
            resource.backup = Some(proof.clone());
        } else {
            drop(resources);
            let mut observations = state.startups.lock().unwrap_or_else(|e| e.into_inner());
            let item = observations
                .get_mut(watch)
                .ok_or_else(|| anyhow::anyhow!("backup proof unknown watch"))?;
            anyhow::ensure!(
                item["owner"] == proof["record"]["owner"]
                    && item["acquisition"] == proof["record"]["acquisition"],
                "backup proof observation mismatch"
            );
            item["backup_proof"] = proof.clone();
        }
        return Ok(());
    }
    if event["event"] == "nonlast_transfer_ack" {
        anyhow::ensure!(control, "nonlast acknowledgement on wrong lane");
        return custody_wire::nonlast_ack(&event, state).await;
    }
    if event["event"] == "owner_proof_ack" {
        anyhow::ensure!(control, "owner proof acknowledgement on wrong lane");
        let watch = event["watch"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("owner proof watch missing"))?;
        let resource = state
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|r| r.watch == watch)
            .cloned();
        let (owner, proof, target, coord) = if let Some(resource) = &resource {
            (
                resource.owner.clone(),
                resource
                    .proof
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("proof ACK before custody"))?,
                resource.target.clone(),
                resource.coord_key.clone(),
            )
        } else {
            let observations = state.startups.lock().unwrap_or_else(|e| e.into_inner());
            let item = observations
                .get(watch)
                .ok_or_else(|| anyhow::anyhow!("proof ACK has no retained observation"))?;
            (
                item["owner"].clone(),
                item["proof"].clone(),
                item["target"].clone(),
                item["coord_key"].clone(),
            )
        };
        anyhow::ensure!(
            owner == event["owner"] && proof["sha256"] == event["sha256"],
            "owner proof ACK binding mismatch"
        );
        let helper = state
            .helper
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("proof ACK helper missing"))?;
        if event["consumer"].is_null() {
            anyhow::ensure!(
                resource.is_none() && event["reason"] == "no_bridge_producer",
                "absent bridge producer is only valid for unleased startup"
            );
            let status = helper.call(json!({"kind":"lookup", "watch":watch})).await?;
            let item = &status["item"];
            anyhow::ensure!(
                status["state_root"] == helper.state_root
                    && item["owner"] == owner
                    && item["acquisition"] == proof["record"]["acquisition"]
                    && item["owner_receipt"]["record"]["kind"] == "StartupOwnerSubscribed"
                    && item["owner_receipt"]["record"]["helper"] == helper.incarnation
                    && item["launch"].is_object(),
                "absent bridge producer startup binding mismatch"
            );
            helper
                .journal(
                    json!({"action":"bridge_absent","target":target,"coord_key":coord,
                "watch":watch,"proof":proof,"incarnation":state.bridge_observer}),
                )
                .await?;
        } else {
            anyhow::ensure!(
                state.bridge_observer.as_deref() == event["consumer"]["record"]["helper"].as_str()
                    && event.get("reason").is_none(),
                "bridge producer ACK binding mismatch"
            );
            let committed = helper
                .journal(
                    json!({"action":"bridge_closed","target":target,"coord_key":coord,
                "watch":watch,"consumer":event["consumer"]}),
                )
                .await;
            if committed.is_err() {
                state
                    .proof_handoffs
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(watch);
            }
            committed?;
        }
        if let Some(resource) = resource {
            if let Some(current) = state
                .custody_resources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&resource.lease.lease_id)
            {
                current.bridge_proof_ack = true;
            }
        } else if let Some(item) = state
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(watch)
        {
            item["bridge_proof_ack"] = json!(true);
        }
        return Ok(());
    }
    if event["event"] == "custody_retired_ack" {
        anyhow::ensure!(control, "retirement acknowledgement on wrong lane");
        let watch = event["receipt"]["watch"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("retirement watch missing"))?;
        let mut pending = state
            .custody_retirements
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(receipt) = pending.get(watch) {
            anyhow::ensure!(
                *receipt == event["receipt"],
                "retirement acknowledgement mismatch"
            );
            let receipt = pending
                .remove(watch)
                .ok_or_else(|| anyhow::anyhow!("retirement disappeared"))?;
            state
                .closed_history
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push_back(receipt.clone());
            state.emit(json!({"event":"custody_settled", "lease":receipt["lease"], "acquisition":receipt["acquisition"], "watch":watch}));
        }
        return Ok(());
    }
    if event["event"] == "custody_receipt" {
        anyhow::ensure!(control, "custody receipt on wrong lane");
        let nonce = event["nonce"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("custody receipt nonce missing"))?;
        let removed = state
            .custody_replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(nonce);
        #[cfg(feature = "nexus-test-support")]
        if let Some((request, _)) = &removed {
            if request["action"] == "file_job_prepare" {
                state.emit(
                    json!({"event":"file_job_reply_consumed","job_nonce":request["job_nonce"],
                    "recovery_id":request["recovery_id"],"nonce":nonce}),
                );
            }
        }
        #[cfg(not(feature = "nexus-test-support"))]
        let _ = removed;
        return Ok(());
    }
    if event["event"] == "released" && event["outcome"]["lease_released"] == true {
        if let Err(error) = custody_wire::detach_fact(&event, state).await {
            event["local_cleanup_error"] = json!(format!(
                "detach ACK parsed; target observation persistence failed: {error}"
            ));
        }
    }
    if event["event"] == "custody_request"
        || (event["event"] == "release_observation" && event.get("nonce").is_some())
    {
        anyhow::ensure!(control, "custody request must use independent control lane");
        let nonce = event["nonce"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or_else(|| anyhow::anyhow!("invalid custody nonce"))?;
        let retained = state
            .custody_replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(nonce)
            .cloned();
        if let Some((original, response)) = retained {
            anyhow::ensure!(original == event, "conflicting custody retransmission");
            if response.is_null() {
                return Ok(()); // One in-flight receiver preparation owns this nonce.
            }
            send(writer, &response).await.map_err(|error| {
                error
                    .downcast::<std::io::Error>()
                    .map(receiver::EventIoError::from)
                    .map(anyhow::Error::from)
                    .unwrap_or_else(|error| error)
            })?;
            return Ok(());
        }
        anyhow::ensure!(
            state
                .custody_replies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len()
                < state.open_reply_capacity + 8,
            "Busy: unacknowledged custody replies full; existing obligations retained"
        );
        if event["action"] == "file_job_prepare" {
            // A receiver may need root SH/startup. Its bounded preparation must
            // not occupy the physical control reader or any N1 short lock.
            state
                .custody_replies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(nonce.into(), (event.clone(), Value::Null));
            let owned_state = state.clone();
            let owned_writer = writer.clone();
            tokio::spawn(async move {
                let result = async {
                    let value = custody_wire::receive(&event, &owned_state).await?;
                    #[cfg(feature = "nexus-test-support")]
                    test_barriers::asynchronous(
                        "file_job_ready_reply",
                        json!({"request":event,"response":value}),
                    )
                    .await?;
                    Ok::<_, anyhow::Error>(value)
                }
                .await;
                let reply = match result {
                    Ok(value) => value,
                    Err(error) => {
                        json!({"custody_reply":event["nonce"],"ok":false,"error":error.to_string()})
                    }
                };
                if let Some(nonce) = event["nonce"].as_str() {
                    owned_state
                        .custody_replies
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(nonce.into(), (event.clone(), reply.clone()));
                }
                if let Err(error) = send(&owned_writer, &reply).await {
                    tracing::error!(%error,"file-job preparation reply delivery failed");
                }
            });
            return Ok(());
        }
        if event["action"] == "no_attach" {
            // The ordinary receiver owns this exact nonce until its terminal;
            // the proof pump may then resume a retained signed closure.
            state
                .custody_replies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(nonce.into(), (event.clone(), Value::Null));
        }
        let result = custody_wire::receive(&event, state).await;
        let reply = match result {
            Ok(value) => value,
            Err(error) => {
                json!({"custody_reply":event["nonce"],"ok":false,"error":error.to_string()})
            }
        };
        state
            .custody_replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(nonce.into(), (event.clone(), reply.clone()));
        send(writer, &reply).await.map_err(|error| {
            error
                .downcast::<std::io::Error>()
                .map(receiver::EventIoError::from)
                .map(anyhow::Error::from)
                .unwrap_or_else(|error| error)
        })?;
        return Ok(());
    }
    if event["event"] == "dispatch_ready" {
        let encoded = event["frame"].take();
        let frame: NexusWireFrame = if control {
            serde_json::from_value(encoded)?
        } else {
            crate::blocking::request_decode(move || serde_json::from_value(encoded)).await??
        };
        let sequence = frame.attempt.sequence.get();
        anyhow::ensure!(
            state
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&sequence)
                .is_some_and(|p| p.attempt == frame.attempt && !p.granted),
            "unknown, mismatched or duplicate dispatch request"
        );
        anyhow::ensure!(
            control
                == matches!(
                    frame.payload,
                    SessionCommand::Cancel { .. }
                        | SessionCommand::Release { .. }
                        | SessionCommand::Shutdown { .. }
                ),
            "dispatch request on wrong lane"
        );
        let mut output = writer.lock().await;
        let attempt = frame.attempt.clone();
        let expires = frame.expires_monotonic_ns;
        // Retain the N2 frame until the Python executor is ready. The final
        // grant carries remaining duration only, never the absolute clock.
        let endpoint = state.endpoint.clone();
        let checking = attempt.clone();
        let resource_state = state.clone();
        let consume = move || {
            frame.consume().and_then(|(command, _)| {
                if matches!(command, SessionCommand::Open { .. })
                    && !resource_state.rejected_acquisitions.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
                    return Err(invalid("unregistered acquired handle retained by bridge; new acquisition blocked for protocol cleanup"));
                }
                endpoint.transition(|s, _| s.send_eligible(&command, &checking))?;
                Ok(command)
            })
        };
        let command = if control {
            consume()
        } else {
            crate::blocking::request_decode(consume).await?
        };
        let mut garbage = None;
        let remaining = expires.saturating_sub(super::nexus_transport::monotonic_ns()?) / 1_000_000;
        let command = if remaining == 0 {
            if let Ok(command) = command {
                garbage = Some(command);
            }
            Err(NexusError::new(
                NexusErrorCode::QueueExpired,
                "expired before dispatch grant",
            ))
        } else {
            command
        };
        let reply = match command {
            Ok(command) => {
                if let Some(pending) = state
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_mut(&sequence)
                {
                    pending.granted = true;
                }
                // Drop the possibly large DTO on a bounded worker. Python retains
                // the original payload; this final grant is constant size.
                garbage = Some(command);
                json!({"grant":true,"sequence":sequence,"remaining_ms":remaining})
            }
            Err(error) => {
                state.endpoint.transition(|s, _| {
                    s.delivery_failed(&attempt, DispatchFailure::NotSent(error))
                })?;
                state
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&sequence);
                json!({"grant":false,"sequence":sequence})
            }
        };
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        output
            .write_all(&bytes)
            .await
            .map_err(receiver::EventIoError)?;
        drop(output);
        if let Some(command) = garbage {
            crate::blocking::response(move || drop(command)).await?;
        }
        return Ok(());
    }
    let owned = state.clone();
    if control {
        apply_event(event, &owned)
    } else {
        crate::blocking::response(move || apply_event(event, &owned)).await?
    }
}
fn apply_event(mut event: Value, state: &State) -> anyhow::Result<()> {
    if event["event"] == "disconnected" {
        let lease: SessionLease = serde_json::from_value(event["lease"].clone())?;
        let _ordered = state.callbacks.lock().unwrap_or_else(|e| e.into_inner());
        let registered = state
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&lease.lease_id)
            .cloned();
        if registered.as_ref() == Some(&lease) {
            state
                .endpoint
                .transition(|s, _| s.lease_disconnected(&lease))?;
        } else {
            anyhow::ensure!(registered.is_none(), "disconnect lease identity mismatch");
            let attempt: DeliveryAttempt = decode(event["attempt"].clone())?;
            let DeliveryTarget::Open { identity } = &attempt.target else {
                return Err(invalid("disconnect open correlation missing").into());
            };
            if identity.client_id != lease.client_id {
                return Err(invalid("disconnect client mismatch").into());
            }
            let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(open) = pending.get_mut(&attempt.sequence.get()) {
                if open.attempt != attempt
                    || open
                        .open_disconnected
                        .as_ref()
                        .is_some_and(|old| old != &lease)
                {
                    return Err(invalid("disconnect open attempt mismatch").into());
                }
                open.open_disconnected = Some(lease);
            }
            // No pending open and no registered lease means cleanup/failure
            // already won. A late callback cannot invalidate sibling sessions.
        }
        state.emit(event);
        return Ok(());
    }
    if event["event"] == "local_status" {
        event["custody_replies_pending"] = json!(state
            .custody_replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len());
        event["n1_acquisitions"] = state
            .endpoint
            .transition(|s, _| Ok::<_, NexusError>(s.acquisition_status()))?;
        let helper_status = state.helper.as_ref().map(|h| h.status_snapshot());
        let resources: Vec<_> = state
            .custody_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|r| {
                json!({"watch":r.watch,"target":r.target,"coord_key":r.coord_key,
                "acquisition":r.acquisition,"lease":r.lease,"owner":r.owner,
                "public_proof_adopted":r.proof.is_some(),"producer_closed":r.consumer.is_some(),
                "bridge_closed":r.bridge_proof_ack})
            })
            .collect();
        let startups: Vec<_> = state
            .startups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|r| {
                json!({"watch":r["watch"],"target":r["target"],"coord_key":r["coord_key"],
                "acquisition":r["acquisition"],"launch":r["launch"],"owner":r["owner"],
                "public_proof_adopted":r.get("proof").is_some()})
            })
            .collect();
        event["custody"] = json!({
            "helper":helper_status,"resource_details":resources,"startup_details":startups,
            "state_root":state.helper.as_ref().map(|h| &h.state_root),
            "helper_endpoint":state.helper.as_ref().map(|h| &h.endpoint),
            "resources":state.custody_resources.lock().unwrap_or_else(|e| e.into_inner()).len(),
            "startup_and_pre_attach":state.startups.lock().unwrap_or_else(|e| e.into_inner()).len(),
            "retirement_acks":state.custody_retirements.lock().unwrap_or_else(|e| e.into_inner()).len(),
            "limit":state.open_reply_capacity,
            "blocked":*state.observation_faults.lock().unwrap_or_else(|e| e.into_inner()),
            "same_boot_eligibility":false,
            "boot_retirement":"requires_verified_native_creation_and_consumption_scope"});
        state.emit(event);
        return Ok(());
    }
    let name = event["event"].as_str().unwrap_or("");
    anyhow::ensure!(
        matches!(
            name,
            "ack"
                | "opened"
                | "completed"
                | "yielded"
                | "stopped"
                | "cancel_ack"
                | "released"
                | "shutdown_completed"
                | "remote_error"
                | "failed"
                | "not_sent"
                | "uncertain"
                | "stop_unconfirmed"
                | "release_unconfirmed"
                | "release_observation"
        ),
        "unknown or unsupported message family"
    );
    // Clone/decode potentially large results and errors before taking N1's lock.
    // Business callbacks already run on the bounded response worker.
    let mut value = event.get("result").cloned().unwrap_or(Value::Null);
    let mut received_error: Option<NexusError> =
        event.get("error").cloned().map(decode).transpose()?;
    let mut take_error = || {
        received_error
            .take()
            .ok_or_else(|| invalid("bridge error missing"))
    };
    let _ordered = state.callbacks.lock().unwrap_or_else(|e| e.into_inner());
    let attempt: DeliveryAttempt = serde_json::from_value(event["attempt"].clone())?;
    let retired = state.endpoint.transition(|s, _| match &attempt.target {
        DeliveryTarget::Release { lease } => s.resource_retirement(lease),
        DeliveryTarget::Execute { identity }
        | DeliveryTarget::Cancel { identity, .. }
        | DeliveryTarget::Shutdown { identity } => s.resource_retirement(&identity.lease),
        DeliveryTarget::Open { .. } => Ok(None),
    })?;
    anyhow::ensure!(retired.is_none(), "late event for retired boot resource");
    let sequence = attempt.sequence.get();
    if let DeliveryTarget::Release { lease } = &attempt.target {
        if matches!(
            name,
            "released" | "uncertain" | "not_sent" | "failed" | "remote_error"
        ) {
            let facts = state
                .release_facts
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            anyhow::ensure!(
                !facts
                    .get(&lease.lease_id)
                    .is_some_and(|(exact, value)| exact == lease
                        && value["attempt"] == json!(attempt)
                        && value["terminal"].is_string()),
                "duplicate release terminal"
            );
        }
    }
    let target_matches = match name {
        "opened" => matches!(attempt.target, DeliveryTarget::Open { .. }),
        "completed" | "yielded" | "stopped" | "stop_unconfirmed" => {
            matches!(attempt.target, DeliveryTarget::Execute { .. })
        }
        "released" | "release_unconfirmed" | "release_observation" => {
            matches!(attempt.target, DeliveryTarget::Release { .. })
        }
        "cancel_ack" => matches!(attempt.target, DeliveryTarget::Cancel { .. }),
        "shutdown_completed" => matches!(attempt.target, DeliveryTarget::Shutdown { .. }),
        _ => true,
    };
    anyhow::ensure!(target_matches, "event family/command target mismatch");
    let (known, superseded) = {
        let pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        (
            pending.get(&sequence).is_some_and(|p| p.attempt == attempt),
            pending
                .values()
                .any(|p| p.attempt.target == attempt.target && p.attempt.sequence.get() > sequence),
        )
    };
    if !known {
        if name == "opened" {
            // Pending is a command table, not acquisition authority. N1 retains
            // exact opening tombstones after failure/cancellation.
            let DeliveryTarget::Open { identity } = &attempt.target else {
                anyhow::bail!("open target mismatch");
            };
            let lease: SessionLease = decode(event["lease"].clone())?;
            let registered = state
                .leases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&lease.lease_id)
                .cloned();
            if registered.as_ref() == Some(&lease) {
                return Err(
                    invalid("duplicate acquired lease; existing responsibility retained").into(),
                );
            }
            state.endpoint.transition(|s, _| {
                s.delivery_status(&identity.client_id, &attempt)?;
                s.open_progress(&identity.client_id, identity)?;
                Ok::<_, NexusError>(())
            })?;
        } else if name == "released" {
            let DeliveryTarget::Release { lease } = &attempt.target else {
                anyhow::bail!("release target mismatch");
            };
            let delivery = state
                .endpoint
                .transition(|s, _| s.delivery_status(&lease.client_id, &attempt))?;
            anyhow::ensure!(
                delivery.state != DeliveryState::Confirmed,
                "duplicate release terminal"
            );
        } else if name == "stopped" {
            state.endpoint.transition(|s, _| {
                let DeliveryTarget::Execute { identity } = &attempt.target else {
                    return Err(invalid("stop target mismatch"));
                };
                // Old slices cannot stop a newer physical delivery.
                s.delivery_status(&identity.lease.client_id, &attempt)?;
                if !s.execution_stopped(identity)? {
                    return Err(invalid("duplicate stop terminal"));
                }
                Ok::<_, NexusError>(())
            })?;
            state.emit(event);
            return Ok(());
        } else {
            let reason = if superseded
                || state
                    .endpoint
                    .transition(|s, _| s.delivery_superseded(&attempt))
            {
                "superseded bridge attempt"
            } else {
                "unknown, mismatched or duplicate bridge attempt"
            };
            return Err(invalid(reason).into());
        }
    }
    let result = state.endpoint.transition(|s, _| -> Result<(), NexusError> {
        match name {
            "ack" => {
                s.delivery_acknowledged(&attempt)?;
            }
            "opened" => {
                let lease: SessionLease = decode(event["lease"].clone())?;
                let caps: NexusCapabilities = decode(event["capabilities"].clone())?;
                let DeliveryTarget::Open { identity } = &attempt.target else {
                    return Err(invalid("open target mismatch"));
                };
                let disconnected = state
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&sequence)
                    .and_then(|p| p.open_disconnected.clone());
                if disconnected.as_ref().is_some_and(|old| old != &lease) {
                    return Err(invalid("opened lease differs from buffered disconnect"));
                }
                match s.opened(identity, lease.clone(), caps)? {
                    OpenDisposition::Ready(_) => {}
                    OpenDisposition::ReleaseRequired { .. } => {
                        // The bridge poll owns retries after proven NotSent. A
                        // full control lane must not discard lease responsibility.
                    }
                }
                state
                    .leases
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(lease.lease_id.clone(), lease.clone());
                if let Some(disconnected) = disconnected.as_ref() {
                    if disconnected != &lease {
                        return Err(invalid("opened lease differs from buffered disconnect"));
                    }
                    s.lease_disconnected(&lease)?;
                }
            }
            "completed" => {
                let DeliveryTarget::Execute { identity } = &attempt.target else {
                    return Err(invalid("execute target mismatch"));
                };
                s.complete(identity, Completion::Success(value.take()))?;
            }
            "yielded" => {
                let DeliveryTarget::Execute { identity } = &attempt.target else {
                    return Err(invalid("yield target mismatch"));
                };
                s.yield_operation(identity, event["checkpoint"].clone())?;
            }
            "stopped" => {
                let DeliveryTarget::Execute { identity } = &attempt.target else {
                    return Err(invalid("stop target mismatch"));
                };
                let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(item) = pending.get_mut(&sequence) {
                    item.stopped = true;
                    if item.uncertain {
                        s.execution_stopped(identity)?;
                    }
                }
            }
            "cancel_ack" => {
                if event["accepted"] == true {
                    s.delivery_acknowledged(&attempt)?;
                } else {
                    s.delivery_failed(
                        &attempt,
                        DispatchFailure::Uncertain(NexusError::new(
                            NexusErrorCode::CancelPending,
                            "public cancellation returned false; no stop confirmation",
                        )),
                    )?;
                }
                if event["outcome"]["execution_stopped"] == true {
                    let DeliveryTarget::Cancel { identity, .. } = &attempt.target else {
                        return Err(invalid("cancel proof target mismatch"));
                    };
                    let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
                    let execution = pending.values_mut().find(|p| {
                        matches!(&p.attempt.target,
                        DeliveryTarget::Execute { identity: original } if original == identity)
                    });
                    if let Some(execution) = execution {
                        execution.stopped = true;
                        if execution.uncertain {
                            s.execution_stopped(identity)?;
                        }
                    } else {
                        s.execution_stopped(identity)?;
                    }
                }
            }
            "released" => {
                if event.get("outcome").is_some() && event["outcome"]["lease_released"] != true {
                    return Err(invalid(
                        "released without a parsed lease ACK or public proof",
                    ));
                }
                if !s.released(&attempt)? {
                    return Err(invalid("duplicate release terminal"));
                }
                if let DeliveryTarget::Release { lease } = &attempt.target {
                    if let Some(message) = event["local_cleanup_error"].as_str() {
                        let mut errors = state
                            .release_errors
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        let entry = errors
                            .entry(lease.lease_id.clone())
                            .or_insert_with(|| (lease.clone(), String::new()));
                        if !entry.1.is_empty() {
                            entry.1.push_str("; ");
                        }
                        entry.1.push_str(message);
                    }
                    // Preserve the SDK's legacy benign stream-close races as
                    // diagnostics in the outcome. They do not constitute a
                    // failed lease detach or a rejected save. Unexpected local
                    // cleanup failures still reach the close caller.
                    let failures: Vec<_> = event["outcome"]["cleanup_failures"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|failure| {
                            !matches!(
                                (failure["phase"].as_str(), failure["type"].as_str()),
                                (Some("stream_shutdown" | "stream_raw"), Some("OSError"))
                                    | (Some("stream_response"), Some("OSError" | "ValueError"))
                            )
                        })
                        .collect();
                    if !failures.is_empty() {
                        let mut errors = state
                            .release_errors
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        let entry = errors
                            .entry(lease.lease_id.clone())
                            .or_insert_with(|| (lease.clone(), String::new()));
                        if !entry.1.is_empty() {
                            entry.1.push_str("; ");
                        }
                        entry.1.push_str(&format!(
                            "ACK parsed; local cleanup failures: {}",
                            json!(failures)
                        ));
                    }
                    state
                        .leases
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&lease.lease_id);
                }
            }
            "shutdown_completed" => {
                s.shutdown_completed(&attempt)?;
            }
            "remote_error" if matches!(&attempt.target, DeliveryTarget::Execute { .. }) => {
                let DeliveryTarget::Execute { identity } = &attempt.target else {
                    return Err(invalid("execute target mismatch"));
                };
                let completion = match event["remote_code"].as_str() {
                    Some("operation_cancelled") => Completion::Cancelled,
                    Some("operation_timeout") => Completion::ExecutionTimedOut,
                    _ => Completion::Failed(take_error()?),
                };
                s.complete(identity, completion)?;
            }
            "release_observation" => {
                if !matches!(attempt.target, DeliveryTarget::Release { .. })
                    || event["schema"] != 1
                    || event["release_protocol"] != 1
                {
                    return Err(invalid("release observation identity/version mismatch"));
                }
            }
            "stop_unconfirmed" | "release_unconfirmed" => {}
            "uncertain" => {
                let accepted =
                    s.delivery_failed(&attempt, DispatchFailure::Uncertain(take_error()?))?;
                if !accepted && matches!(attempt.target, DeliveryTarget::Release { .. }) {
                    return Err(invalid("duplicate release terminal"));
                }
                if let DeliveryTarget::Execute { identity } = &attempt.target {
                    let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(item) = pending.get_mut(&sequence) {
                        item.uncertain = true;
                        if item.stopped {
                            s.execution_stopped(identity)?;
                        }
                    }
                }
            }
            "remote_error" if matches!(&attempt.target, DeliveryTarget::Shutdown { .. }) => {
                s.shutdown_rejected(&attempt)?;
            }
            "failed" | "not_sent" | "remote_error" => {
                let accepted =
                    s.delivery_failed(&attempt, DispatchFailure::NotSent(take_error()?))?;
                if !accepted && matches!(attempt.target, DeliveryTarget::Release { .. }) {
                    return Err(invalid("duplicate release terminal"));
                }
                if let DeliveryTarget::Open { identity } = &attempt.target {
                    s.open_failed(identity)?;
                }
            }
            _ => return Err(invalid("unknown bridge event")),
        }
        // Store the accepted command's raw result before publishing its terminal.
        // Retirement and public proof only project current liveness; they must
        // not have to reconstruct a missing lost-ACK or NotSent outcome later.
        if matches!(
            name,
            "released" | "uncertain" | "not_sent" | "failed" | "remote_error"
        ) {
            if let DeliveryTarget::Release { lease } = &attempt.target {
                state.remember_save_guard_error(lease, &event["save_guard_error"])?;
                let mut facts = state
                    .release_facts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let entry = facts
                    .entry(lease.lease_id.clone())
                    .or_insert_with(|| (lease.clone(), json!({})));
                entry.1["attempt"] = json!(attempt);
                entry.1["terminal"] = json!(name);
                if let Some(outcome) = event.get("outcome") {
                    entry.1["outcome"] = outcome.clone();
                    if outcome["cleanup_blocked"] == true {
                        entry.1["cleanup_state"] = json!("CleanupBlocked");
                    }
                }
                if let Some(error) = event.get("observation_error").filter(|e| !e.is_null()) {
                    entry.1["observation_error"] = error.clone();
                }
                if name == "not_sent" && event["outcome"]["stage"] == "preflight" {
                    entry.1["preflight"] = event["outcome"].clone();
                    if entry.1["original_preflight"].is_null() {
                        entry.1["original_preflight"] = event["outcome"].clone();
                    }
                }
                if let Some(error) = event.get("error") {
                    entry.1["command_error"] = error.clone();
                    if entry.1["original_error"].is_null() {
                        entry.1["original_error"] = error.clone();
                    }
                }
            }
        }
        Ok(())
    });
    result?;
    let waiting_for_outcome_or_proof = state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&sequence)
        .is_some_and(|p| {
            (name == "uncertain" && !p.stopped) || (name == "stopped" && !p.uncertain)
        });
    if !matches!(name, "ack" | "stop_unconfirmed" | "release_observation")
        && !waiting_for_outcome_or_proof
    {
        state
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&sequence);
    }
    state.emit(event);
    Ok(())
}
fn invalid(message: &str) -> NexusError {
    NexusError::new(NexusErrorCode::InvalidTransition, message)
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, NexusError> {
    serde_json::from_value(value).map_err(|error| invalid(&error.to_string()))
}

#[cfg(test)]
#[path = "../../tests/support/n4_bridge.rs"]
mod n4_fix_regressions;

#[cfg(test)]
#[path = "../../tests/support/r5_receiver.rs"]
mod r5_receiver_tests;

#[cfg(test)]
#[path = "../../tests/support/fa_shutdown.rs"]
mod final_shutdown_tests;

#[cfg(all(test, feature = "nexus-test-support"))]
#[path = "../../tests/support/bridge_loss.rs"]
mod bridge_loss_tests;
