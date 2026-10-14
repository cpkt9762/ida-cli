use super::support::*;
use ida_mcp::nexus::*;
use serde_json::json;

#[test]
fn all_command_kinds_require_queued_current_attempt_and_complete_identity() {
    for kind in ["open", "execute", "cancel", "release", "shutdown"] {
        let mut rig = Rig::new();
        let (command, attempt) = if kind == "open" {
            rig.begin_open("pending", "instance", 1, 120);
            (
                rig.backend.business.last().unwrap().clone(),
                rig.last_attempt(),
            )
        } else {
            let lease = rig.connect("active", "instance", 1);
            match kind {
                "execute" | "cancel" => {
                    let op = rig.queue(&lease, "operation", "rename_symbol", 120);
                    rig.dispatch(&op);
                    if kind == "cancel" {
                        rig.sessions
                            .cancel(
                                &lease.client_id,
                                &op,
                                CancelReason::Client,
                                &mut rig.backend,
                            )
                            .unwrap();
                        (
                            rig.backend.controls.last().unwrap().clone(),
                            rig.last_attempt(),
                        )
                    } else {
                        (
                            rig.backend.business.last().unwrap().clone(),
                            rig.last_attempt(),
                        )
                    }
                }
                "release" => {
                    rig.sessions
                        .release(&lease.client_id, &lease, &mut rig.backend)
                        .unwrap();
                    (
                        rig.backend.controls.last().unwrap().clone(),
                        rig.last_attempt(),
                    )
                }
                "shutdown" => {
                    let request = accepted(&rig.clock, "shutdown", "shutdown", json!({}));
                    rig.sessions
                        .shutdown(
                            &lease.client_id,
                            &lease,
                            ShutdownSpec {
                                request,
                                operation_id: OperationId::new("shutdown").unwrap(),
                                save: true,
                            },
                            &mut rig.backend,
                        )
                        .unwrap();
                    (
                        rig.backend.controls.last().unwrap().clone(),
                        rig.last_attempt(),
                    )
                }
                _ => unreachable!(),
            }
        };
        assert!(
            rig.sessions.send_eligible(&command, &attempt).is_ok(),
            "{kind}"
        );
        let mut forged = attempt.clone();
        forged.sequence = std::num::NonZeroU64::new(attempt.sequence.get() + 1).unwrap();
        assert!(
            rig.sessions.send_eligible(&command, &forged).is_err(),
            "{kind}: stale sequence"
        );
        rig.sessions.delivery_acknowledged(&attempt).unwrap();
        assert!(
            rig.sessions.send_eligible(&command, &attempt).is_err(),
            "{kind}: ACK cannot authorize another send"
        );
    }
}

#[test]
fn execute_cancel_owner_replacement_and_unknown_live_stop_gates() {
    let mut rig = Rig::new();
    let lease = rig.connect("old", "instance", 1);
    let op = rig.queue(&lease, "operation", "rename_symbol", 1);
    rig.dispatch(&op);
    let execute = rig.backend.business.last().unwrap().clone();
    let execute_attempt = rig.last_attempt();
    let cause = NexusError::new(NexusErrorCode::Disconnected, "lost response");
    rig.sessions
        .delivery_failed(&execute_attempt, DispatchFailure::Uncertain(cause))
        .unwrap();
    assert!(!rig.snapshot(&op).execution_stopped);
    assert!(rig
        .sessions
        .send_eligible(&execute, &execute_attempt)
        .is_err());
    rig.sessions
        .cancel(
            &lease.client_id,
            &op,
            CancelReason::Client,
            &mut rig.backend,
        )
        .unwrap();
    let old_cancel = rig.backend.controls.last().unwrap().clone();
    let old_attempt = rig.last_attempt();
    assert!(
        rig.sessions
            .send_eligible(&old_cancel, &old_attempt)
            .is_ok(),
        "UnknownOutcome still permits exact stop control"
    );
    rig.clock.advance(1000);
    rig.sessions
        .expire(&lease.client_id, &op, &mut rig.backend)
        .unwrap();
    let current = rig.backend.controls.last().unwrap().clone();
    let current_attempt = rig.last_attempt();
    assert!(
        rig.sessions
            .send_eligible(&old_cancel, &old_attempt)
            .is_err(),
        "deadline escalation supersedes old cancel"
    );
    assert!(rig
        .sessions
        .send_eligible(&current, &current_attempt)
        .is_ok());
    rig.connect("replacement", "instance", 2);
    assert!(
        rig.sessions
            .send_eligible(&current, &current_attempt)
            .is_err(),
        "old owner controls cannot be emitted"
    );
}

#[test]
fn cancelled_or_finished_open_and_control_lifecycles_cannot_emit() {
    let mut rig = Rig::new();
    let (open, lease) = rig.begin_open("pending", "instance", 1, 120);
    let command = rig.backend.business.last().unwrap().clone();
    let attempt = rig.last_attempt();
    rig.sessions.cancel_open(&lease.client_id, &open).unwrap();
    assert!(rig.sessions.send_eligible(&command, &attempt).is_err());
    assert!(matches!(
        rig.sessions
            .opened(&open, lease.clone(), capabilities())
            .unwrap(),
        OpenDisposition::ReleaseRequired { .. }
    ));
    assert!(rig.sessions.send_eligible(&command, &attempt).is_err());
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
    let command = rig.backend.controls.last().unwrap().clone();
    let attempt = rig.last_attempt();
    rig.sessions.released(&attempt).unwrap();
    assert!(rig.sessions.send_eligible(&command, &attempt).is_err());
}

#[test]
fn completed_native_rejects_old_cancel_and_finished_shutdown_cannot_emit() {
    let mut rig = Rig::new();
    let lease = rig.connect("native-stop", "instance", 1);
    let op = rig.queue(&lease, "operation", "rename_symbol", 120);
    rig.dispatch(&op);
    rig.sessions
        .cancel(
            &lease.client_id,
            &op,
            CancelReason::Client,
            &mut rig.backend,
        )
        .unwrap();
    let command = rig.backend.controls.last().unwrap().clone();
    let attempt = rig.last_attempt();
    rig.sessions
        .complete(&op, Completion::Success(json!({"completed":true})))
        .unwrap();
    assert!(rig.sessions.send_eligible(&command, &attempt).is_err());
    rig.sessions
        .shutdown(
            &lease.client_id,
            &lease,
            ShutdownSpec {
                request: accepted(&rig.clock, "finished-shutdown", "shutdown", json!({})),
                operation_id: OperationId::new("finished-shutdown").unwrap(),
                save: true,
            },
            &mut rig.backend,
        )
        .unwrap();
    let command = rig.backend.controls.last().unwrap().clone();
    let attempt = rig.last_attempt();
    assert!(rig.sessions.send_eligible(&command, &attempt).is_ok());
    assert!(rig.sessions.shutdown_rejected(&attempt).unwrap());
    assert!(rig.sessions.send_eligible(&command, &attempt).is_err());
}
