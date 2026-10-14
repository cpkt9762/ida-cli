use super::failures::{cancel, transport_error, unknown_operation, DeferredBackend};
use super::support::*;
use ida_mcp::nexus::*;
use serde_json::json;

#[test]
fn synchronous_and_deferred_execute_failures_share_the_same_transition_and_error() {
    for uncertain in [false, true] {
        let mut snapshots = Vec::new();
        for synchronous in [false, true] {
            let mut rig = Rig::new();
            let lease = rig.connect("parity", "instance", 1);
            let op = rig.queue(&lease, "failure-parity", "rename_symbol", 120);
            let source = transport_error("identical failure");
            let failure = if uncertain {
                DispatchFailure::Uncertain(source)
            } else {
                DispatchFailure::NotSent(source)
            };
            let returned = if synchronous {
                rig.backend.fail_business = Some(failure);
                rig.sessions
                    .dispatch(&lease.client_id, &op, &mut rig.backend)
                    .unwrap_err()
            } else {
                rig.dispatch(&op);
                assert!(rig
                    .sessions
                    .delivery_failed(&rig.last_attempt(), failure)
                    .unwrap());
                rig.sessions
                    .delivery_status(&lease.client_id, &rig.last_attempt())
                    .unwrap()
                    .error
                    .unwrap()
            };
            let snapshot = rig.snapshot(&op);
            assert_eq!(snapshot.error, Some(returned));
            assert_eq!(snapshot.execution_stopped, !uncertain);
            snapshots.push(snapshot);
        }
        assert_eq!(snapshots[0].status, snapshots[1].status);
        assert_eq!(snapshots[0].error, snapshots[1].error);
    }
}

#[test]
fn synchronous_cancel_release_shutdown_failures_share_retryable_and_uncertain_semantics() {
    for uncertain in [false, true] {
        let failure = || {
            if uncertain {
                DispatchFailure::Uncertain(transport_error("control fail"))
            } else {
                DispatchFailure::NotSent(transport_error("control fail"))
            }
        };
        let mut rig = Rig::new();
        let op = unknown_operation(&mut rig);
        let original = rig.snapshot(&op).error;
        rig.backend.fail_control = Some(failure());
        assert!(rig
            .sessions
            .cancel(
                &op.lease.client_id,
                &op,
                CancelReason::Client,
                &mut rig.backend
            )
            .is_err());
        assert_eq!(rig.snapshot(&op).error, original);
        assert!(!rig.snapshot(&op).execution_stopped);
        assert!(!rig.sessions.complete(&op, Completion::Cancelled).unwrap());
        rig.backend.fail_control = Some(failure());
        assert!(rig
            .sessions
            .release(&op.lease.client_id, &op.lease, &mut rig.backend)
            .is_err());
        assert_eq!(
            rig.sessions
                .status(&op.lease.client_id, &op.lease)
                .unwrap()
                .phase,
            if uncertain {
                SessionPhase::ReleaseRequested
            } else {
                SessionPhase::Active
            }
        );
        if uncertain {
            assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
        }
        let lease = rig.connect("shutdown-control", "other-instance", 1);
        rig.backend.fail_control = Some(failure());
        assert!(rig
            .sessions
            .shutdown(
                &lease.client_id,
                &lease,
                ShutdownSpec {
                    request: accepted(&rig.clock, "sync-shutdown", "shutdown", json!({})),
                    operation_id: OperationId::new("sync-shutdown").unwrap(),
                    save: true,
                },
                &mut rig.backend
            )
            .is_err());
        assert_eq!(
            rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
            if uncertain {
                SessionPhase::ShutdownRequested
            } else {
                SessionPhase::Active
            }
        );
    }
}

#[test]
fn explicit_control_retries_do_not_consume_operation_retention_or_revive_old_attempts() {
    let mut rig = Rig::new();
    rig.sessions = NexusSessions::new(rig.clock.clone(), Ok(capabilities()), 2);
    let op = unknown_operation(&mut rig);
    let original = rig.snapshot(&op).error;
    let mut oldest = None;
    for _ in 0..64 {
        let attempt = cancel(&mut rig, &op, CancelReason::Client);
        oldest.get_or_insert(attempt.clone());
        assert!(rig
            .sessions
            .delivery_failed(
                &attempt,
                DispatchFailure::NotSent(transport_error("retry control only"))
            )
            .unwrap());
    }
    let last = cancel(&mut rig, &op, CancelReason::Client);
    assert!(!rig
        .sessions
        .delivery_acknowledged(&oldest.unwrap())
        .unwrap());
    assert!(rig.sessions.delivery_acknowledged(&last).unwrap());
    assert_eq!(rig.snapshot(&op).error, original);
    assert_eq!(rig.backend.writes, 1);
    assert!(!rig.sessions.complete(&op, Completion::Cancelled).unwrap());
    rig.sessions
        .release(&op.lease.client_id, &op.lease, &mut rig.backend)
        .unwrap();
    assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
}

#[test]
fn old_generation_delivery_failures_and_confirmations_cannot_touch_successor_lease() {
    let mut rig = Rig::new();
    let old = rig.connect("old-control", "instance", 1);
    rig.sessions
        .release(&old.client_id, &old, &mut rig.backend)
        .unwrap();
    let attempt = rig.last_attempt();
    let fresh = rig.connect("fresh-control", "instance", 2);
    assert!(!rig
        .sessions
        .delivery_failed(
            &attempt,
            DispatchFailure::NotSent(transport_error("old generation"))
        )
        .unwrap());
    assert!(!rig.sessions.delivery_acknowledged(&attempt).unwrap());
    assert_eq!(
        rig.sessions.released(&attempt).unwrap_err().code,
        NexusErrorCode::StaleGeneration
    );
    assert_eq!(
        rig.sessions.status(&fresh.client_id, &fresh).unwrap().phase,
        SessionPhase::Active
    );
    let op = rig.queue(&fresh, "fresh-execute", "rename_symbol", 120);
    rig.dispatch(&op);
    assert_eq!(rig.backend.writes, 1);
    assert!(!rig
        .sessions
        .delivery_failed(
            &attempt,
            DispatchFailure::Uncertain(transport_error("late"))
        )
        .unwrap());
    assert!(!rig.snapshot(&op).execution_stopped);
}

#[test]
fn not_sent_proof_after_disconnect_retires_unknown_execute_without_rewriting_result() {
    let mut rig = Rig::new();
    let lease = rig.connect("proof-disconnect", "instance", 1);
    let op = rig.queue(&lease, "proof-after-disconnect", "rename_symbol", 120);
    let mut backend = DeferredBackend::default();
    rig.sessions
        .dispatch(&lease.client_id, &op, &mut backend)
        .unwrap();
    assert!(rig.sessions.disconnected(&lease.instance_id, 1));
    let original = rig.snapshot(&op).error;
    assert!(rig
        .sessions
        .delivery_failed(
            backend.attempts.last().unwrap(),
            DispatchFailure::NotSent(transport_error("writer proves no dispatch"))
        )
        .unwrap());
    assert_eq!(rig.snapshot(&op).status, OperationStatus::UnknownOutcome);
    assert_eq!(rig.snapshot(&op).error, original);
    assert!(rig.snapshot(&op).execution_stopped);
    assert_eq!(backend.queued.len(), 1);
}
