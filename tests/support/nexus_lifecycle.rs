use super::support::*;
use ida_mcp::nexus::*;
use serde_json::json;

#[test]
fn cancel_before_open_handle_keeps_tracking_and_releases_late_acquisition() {
    let mut rig = Rig::new();
    let (identity, lease) = rig.begin_open("cancel-opening", "instance", 1, 120);
    assert_eq!(
        rig.sessions
            .cancel_open(&ClientId::new("other-client").unwrap(), &identity)
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidIdentity
    );
    assert_eq!(
        rig.sessions
            .cancel_open(&lease.client_id, &identity)
            .unwrap(),
        OperationStatus::CancelRequested
    );
    assert!(
        rig.backend.controls.is_empty(),
        "no handle exists to acknowledge remote cancellation"
    );
    match rig
        .sessions
        .opened(&identity, lease.clone(), capabilities())
        .unwrap()
    {
        OpenDisposition::ReleaseRequired {
            lease: acquired,
            error,
        } => {
            assert_eq!(acquired, lease);
            assert_eq!(error.code, NexusErrorCode::Cancelled);
        }
        OpenDisposition::Ready(_) => panic!("cancelled opening must not publish a usable handle"),
    }
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
    assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Released
    );
}

#[test]
fn shutdown_rejection_cannot_restore_a_successor_control_request() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let mut begin = |name: &str| {
        rig.sessions
            .shutdown(
                &lease.client_id,
                &lease,
                ShutdownSpec {
                    request: accepted(&rig.clock, name, "shutdown", json!({})),
                    operation_id: OperationId::new(name).unwrap(),
                    save: true,
                },
                &mut rig.backend,
            )
            .unwrap()
    };
    let first = begin("shutdown-first");
    let first_attempt = rig.last_attempt();
    assert!(rig.sessions.shutdown_rejected(&first_attempt).unwrap());
    let second = rig
        .sessions
        .shutdown(
            &lease.client_id,
            &lease,
            ShutdownSpec {
                request: accepted(&rig.clock, "shutdown-second", "shutdown", json!({})),
                operation_id: OperationId::new("shutdown-second").unwrap(),
                save: true,
            },
            &mut rig.backend,
        )
        .unwrap();
    assert!(
        !rig.sessions.shutdown_rejected(&first_attempt).unwrap(),
        "old rejection cannot restore the successor"
    );
    assert_ne!(first, second);
    let status = rig.sessions.status(&lease.client_id, &lease).unwrap();
    assert_eq!(status.phase, SessionPhase::ShutdownRequested);
    assert_eq!(status.pending_shutdown, Some(second));
    assert_eq!(
        rig.sessions
            .release(&lease.client_id, &lease, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::CancelPending
    );
    let (opening, new_lease) = rig.begin_open("while-closing", "instance", 1, 120);
    assert!(matches!(
        rig.sessions
            .opened(&opening, new_lease, capabilities())
            .unwrap(),
        OpenDisposition::ReleaseRequired {
            error: NexusError {
                code: NexusErrorCode::Busy,
                ..
            },
            ..
        }
    ));
}

#[test]
fn unknown_execution_on_a_disconnected_lease_still_blocks_same_owner_shutdown() {
    let mut rig = Rig::new();
    let a = rig.connect("a", "instance", 1);
    let operation = rig.queue(&a, "unknown-before-shutdown", "rename_symbol", 120);
    rig.dispatch(&operation);
    assert!(rig.sessions.disconnected(&a.instance_id, 1));
    let b = rig.connect("b", "instance", 1);
    assert_eq!(
        rig.sessions
            .shutdown(
                &b.client_id,
                &b,
                ShutdownSpec {
                    request: accepted(&rig.clock, "unsafe-shutdown", "shutdown", json!({})),
                    operation_id: OperationId::new("unsafe-shutdown").unwrap(),
                    save: true
                },
                &mut rig.backend
            )
            .unwrap_err()
            .code,
        NexusErrorCode::ExclusiveCloseRequired
    );
    assert!(!rig
        .backend
        .controls
        .iter()
        .any(|c| matches!(c, SessionCommand::Shutdown { .. })));
    assert_eq!(
        rig.snapshot(&operation).status,
        OperationStatus::UnknownOutcome
    );
    assert!(!rig.snapshot(&operation).execution_stopped);
}

#[test]
fn bounded_retention_returns_busy_instead_of_forgetting_terminal_identity() {
    let mut rig = Rig::new();
    rig.sessions = NexusSessions::new(rig.clock.clone(), Ok(capabilities()), 2);
    let lease = rig.connect("a", "instance", 1);
    let old = rig.queue(&lease, "last-slot", "list_functions", 120);
    rig.dispatch(&old);
    rig.sessions
        .complete(&old, Completion::Success(json!({"preserved":true})))
        .unwrap();
    assert_eq!(
        rig.sessions
            .queue(
                &lease.client_id,
                &lease,
                accepted(&rig.clock, "full", "rename_symbol", json!({})),
                OperationId::new("full").unwrap()
            )
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    assert!(!rig.sessions.complete(&old, Completion::Cancelled).unwrap());
    assert_eq!(rig.snapshot(&old).result, Some(json!({"preserved":true})));
    assert_eq!(rig.backend.executed.len(), 1);
}

#[test]
fn stopped_remote_error_keeps_cause_and_never_replays_partial_writes() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "partial-write", "rename_symbol", 120);
    rig.dispatch(&op);
    rig.sessions
        .complete(
            &op,
            Completion::Failed(NexusError::new(
                NexusErrorCode::Busy,
                "script failed after first edit",
            )),
        )
        .unwrap();
    let state = rig.snapshot(&op);
    assert_eq!(state.status, OperationStatus::Failed);
    assert!(state.execution_stopped);
    let error = state.error.unwrap();
    assert_eq!(error.retry_advice(), RetryAdvice::NeverReplay);
    assert_eq!(
        error.cause.unwrap().message,
        "script failed after first edit"
    );
    assert!(rig
        .sessions
        .dispatch(&lease.client_id, &op, &mut rig.backend)
        .is_err());
    assert_eq!(rig.backend.writes, 1);
}

#[test]
fn deadline_completion_and_cancel_confirmation_race_has_one_timeout_result() {
    use std::sync::{Arc, Barrier, Mutex};
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "deadline-race", "rename_symbol", 1);
    rig.dispatch(&op);
    rig.sessions
        .cancel(
            &lease.client_id,
            &op,
            CancelReason::Client,
            &mut rig.backend,
        )
        .unwrap();
    rig.clock.advance(1000);
    let sessions = Arc::new(Mutex::new(rig.sessions));
    let barrier = Arc::new(Barrier::new(4));
    let winners = std::thread::scope(|scope| {
        let start = barrier.clone();
        let registry = sessions.clone();
        let id = op.clone();
        let success = scope.spawn(move || {
            start.wait();
            registry
                .lock()
                .unwrap()
                .complete(&id, Completion::Success(json!({"late":true})))
                .unwrap()
        });
        let start = barrier.clone();
        let registry = sessions.clone();
        let id = op.clone();
        let cancelled = scope.spawn(move || {
            start.wait();
            registry
                .lock()
                .unwrap()
                .complete(&id, Completion::Cancelled)
                .unwrap()
        });
        let start = barrier.clone();
        let registry = sessions.clone();
        let id = op.clone();
        let timeout = scope.spawn(move || {
            start.wait();
            registry
                .lock()
                .unwrap()
                .expire(&id.lease.client_id, &id, &mut RecordingBackend::default())
                .unwrap()
        });
        barrier.wait();
        let result = [success.join().unwrap(), cancelled.join().unwrap()];
        let snapshot = timeout.join().unwrap();
        assert!(matches!(
            snapshot.status,
            OperationStatus::CancelRequested | OperationStatus::TimedOut
        ));
        result
    });
    assert_eq!(winners.into_iter().filter(|winner| *winner).count(), 1);
    let final_state = sessions
        .lock()
        .unwrap()
        .operation_status(&lease.client_id, &op)
        .unwrap();
    assert_eq!(final_state.status, OperationStatus::TimedOut);
    assert!(final_state.execution_stopped);
    assert!(final_state.result.is_none());
    assert_eq!(rig.backend.writes, 1);
}

#[test]
fn open_matching_late_lease_cleanup_and_release_are_separate_from_shutdown() {
    let mut rig = Rig::new();
    let (open, lease) = rig.begin_open("late", "instance", 1, 1);
    let mut forged = open.clone();
    forged.request_id = RequestId::new("wrong-response").unwrap();
    assert_eq!(
        rig.sessions
            .opened(&forged, lease.clone(), capabilities())
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidLease
    );
    rig.clock.advance(1000);
    assert!(matches!(
        rig.sessions
            .opened(&open, lease.clone(), capabilities())
            .unwrap(),
        OpenDisposition::ReleaseRequired { .. }
    ));
    assert!(rig
        .sessions
        .queue(
            &lease.client_id,
            &lease,
            accepted(&rig.clock, "expired-open-use", "rename_symbol", json!({})),
            OperationId::new("expired-open-use").unwrap()
        )
        .is_err());
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::ReleaseRequested
    );
    assert!(
        matches!(rig.backend.controls.last(),Some(SessionCommand::Release { lease:l }) if l==&lease)
    );
    assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Released
    );
    assert!(!rig
        .backend
        .controls
        .iter()
        .any(|c| matches!(c, SessionCommand::Shutdown { .. })));
}

#[test]
fn explicit_shutdown_requires_managed_local_exclusivity_and_remote_check() {
    let mut rig = Rig::new();
    let a = rig.connect("a", "shared", 1);
    let b = rig.connect("b", "shared", 1);
    assert_eq!(
        rig.sessions
            .shutdown(
                &a.client_id,
                &a,
                ShutdownSpec {
                    request: accepted(&rig.clock, "shutdown-a", "shutdown", json!({})),
                    operation_id: OperationId::new("shutdown-a").unwrap(),
                    save: true
                },
                &mut rig.backend
            )
            .unwrap_err()
            .code,
        NexusErrorCode::ExclusiveCloseRequired
    );
    rig.sessions
        .release(&b.client_id, &b, &mut rig.backend)
        .unwrap();
    assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
    let shutdown = rig
        .sessions
        .shutdown(
            &a.client_id,
            &a,
            ShutdownSpec {
                request: accepted(&rig.clock, "shutdown-a", "shutdown", json!({})),
                operation_id: OperationId::new("shutdown-a").unwrap(),
                save: true,
            },
            &mut rig.backend,
        )
        .unwrap();
    assert!(matches!(
        rig.backend.controls.last(),
        Some(SessionCommand::Shutdown {
            require_exclusive: true,
            save: true,
            ..
        })
    ));
    assert_eq!(
        rig.sessions
            .status(&a.client_id, &a)
            .unwrap()
            .pending_shutdown,
        Some(shutdown)
    );
    assert!(rig.sessions.shutdown_rejected(&rig.last_attempt()).unwrap());
    assert_eq!(
        rig.sessions.status(&a.client_id, &a).unwrap().phase,
        SessionPhase::Active
    );
    let (open, mut gui) = rig.begin_open("gui", "gui-instance", 1, 120);
    gui.owner = OwnerKind::Gui;
    assert!(matches!(
        rig.sessions
            .opened(&open, gui.clone(), capabilities())
            .unwrap(),
        OpenDisposition::Ready(_)
    ));
    assert_eq!(
        rig.sessions
            .shutdown(
                &gui.client_id,
                &gui,
                ShutdownSpec {
                    request: accepted(&rig.clock, "shutdown-gui", "shutdown", json!({})),
                    operation_id: OperationId::new("shutdown-gui").unwrap(),
                    save: true
                },
                &mut rig.backend
            )
            .unwrap_err()
            .code,
        NexusErrorCode::ExclusiveCloseRequired
    );
}
