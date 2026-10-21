//! Deterministic N1 contracts, not a Python bridge or real IDA E2E suite.
use std::sync::{Arc, Barrier, Mutex};

use ida_mcp::nexus;
use ida_mcp::nexus::*;
use serde_json::json;

#[path = "support/nexus_contract.rs"]
mod support;
use support::*;

#[test]
fn r2_late_notsent_preserves_public_lifetime_release_and_original_failure() {
    let mut rig = Rig::new();
    let lease = rig.connect("r2-proof", "r2-owner", 1);
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .expect("release attempt");
    let attempt = rig
        .sessions
        .status(&lease.client_id, &lease)
        .expect("snapshot")
        .control_delivery
        .expect("delivery")
        .attempt;
    rig.sessions
        .public_owner_lifetime(&lease)
        .expect("adapter already adopted exact durable proof");
    let error = NexusError::new(
        NexusErrorCode::OperationFailed,
        "fresh protection refused before detach",
    );
    rig.sessions
        .delivery_failed(&attempt, DispatchFailure::NotSent(error.clone()))
        .expect("late genuine NotSent");
    let snapshot = rig
        .sessions
        .status(&lease.client_id, &lease)
        .expect("final snapshot");
    assert_eq!(
        snapshot.phase,
        SessionPhase::Released,
        "public owner proof cannot be undone"
    );
    let delivery = snapshot
        .control_delivery
        .expect("original delivery history");
    assert_eq!(
        delivery.state,
        DeliveryState::NotSent,
        "proof is not a detach ACK"
    );
    assert_eq!(delivery.error, Some(error), "original caller cause remains");
}
#[path = "support/nexus_compatibility.rs"]
mod compatibility;
#[path = "support/nexus_lifecycle.rs"]
mod lifecycle;

#[test]
fn completed_write_continuation_disconnect_never_reports_not_dispatched() {
    for lease_only in [false, true] {
        let mut rig = Rig::new();
        let lease = rig.connect("continued", "owner", 1);
        let write = rig.queue(&lease, "write", "batch_rename", 120);
        rig.dispatch(&write);
        rig.sessions
            .yield_operation(&write, json!({"index":1}))
            .expect("first slice completed");
        if lease_only {
            rig.sessions.lease_disconnected(&lease).expect("lease loss");
        } else {
            assert!(rig
                .sessions
                .disconnected(&lease.instance_id, lease.generation));
        }
        let snapshot = rig.snapshot(&write);
        let error = snapshot.error.expect("continuation failure");
        assert_eq!(error.code, NexusErrorCode::OperationFailed, "{error}");
        assert!(error.message.contains("effects may remain"), "{error}");
        assert!(error.message.contains("do not replay"), "{error}");
        assert_eq!(error.retry_advice(), RetryAdvice::NeverReplay);
        assert_eq!(snapshot.status, OperationStatus::Failed);
        assert!(snapshot.execution_stopped);
        let error = rig
            .sessions
            .dispatch(&lease.client_id, &write, &mut rig.backend)
            .expect_err("disconnected continuation cannot dispatch");
        assert_eq!(error.code, NexusErrorCode::OperationFailed);
        assert!(error.message.contains("effects may remain"));
        assert_eq!(rig.backend.writes, 1);
    }
}

#[test]
fn completed_write_continuation_notsent_preserves_effects_in_return_and_snapshot() {
    let mut rig = Rig::new();
    let lease = rig.connect("continued", "owner", 1);
    let write = rig.queue(&lease, "write", "batch_rename", 120);
    rig.dispatch(&write);
    rig.sessions
        .yield_operation(&write, json!({"index":1}))
        .expect("first slice completed");
    let cause = NexusError::new(NexusErrorCode::Disconnected, "next slice not sent");
    rig.backend.fail_business = Some(DispatchFailure::NotSent(cause.clone()));
    let error = rig
        .sessions
        .dispatch(&lease.client_id, &write, &mut rig.backend)
        .expect_err("continuation could not be sent");
    assert_eq!(error.code, NexusErrorCode::OperationFailed, "{error}");
    assert!(error.message.contains("effects may remain"), "{error}");
    assert!(error.message.contains("do not replay"), "{error}");
    assert_eq!(error.retry_advice(), RetryAdvice::NeverReplay);
    assert_eq!(error.cause.as_deref(), Some(&cause));
    assert_eq!(rig.snapshot(&write).error, Some(error));
    assert_eq!(rig.backend.writes, 1, "only the first slice wrote");
}

#[test]
fn completed_write_continuation_uncertain_keeps_unknown_outcome() {
    let mut rig = Rig::new();
    let lease = rig.connect("continued", "owner", 1);
    let write = rig.queue(&lease, "write", "batch_rename", 120);
    rig.dispatch(&write);
    rig.sessions
        .yield_operation(&write, json!({"index":1}))
        .expect("first slice completed");
    rig.backend.fail_business = Some(DispatchFailure::Uncertain(NexusError::new(
        NexusErrorCode::Disconnected,
        "send outcome unknown",
    )));
    let error = rig
        .sessions
        .dispatch(&lease.client_id, &write, &mut rig.backend)
        .expect_err("next slice outcome unknown");
    assert_eq!(error.code, NexusErrorCode::UnknownOutcome);
    assert_eq!(error.retry_advice(), RetryAdvice::NeverReplay);
    let snapshot = rig.snapshot(&write);
    assert_eq!(snapshot.status, OperationStatus::UnknownOutcome);
    assert!(!snapshot.execution_stopped);
    assert_eq!(snapshot.error, Some(error));
    assert_eq!(
        rig.backend.writes, 2,
        "uncertain slice may already have written"
    );
}

#[test]
fn n6_expired_write_continuation_reports_completed_effects() {
    let mut rig = Rig::new();
    let lease = rig.connect("n6-expire", "n6-expire-owner", 1);
    let write = rig.queue(&lease, "rename", "batch_rename", 1);
    rig.dispatch(&write);
    rig.sessions
        .yield_operation(&write, json!({"index":1}))
        .expect("first write slice completed");
    rig.clock.advance(1001);
    let error = rig
        .sessions
        .dispatch(&lease.client_id, &write, &mut rig.backend)
        .expect_err("expired continuation cannot dispatch");
    assert_eq!(error.code, NexusErrorCode::QueueExpired);
    assert!(error.message.contains("effects may remain"), "{error}");
    assert!(!error.message.contains("before execution"), "{error}");
    let snapshot = rig.snapshot(&write);
    assert_eq!(snapshot.status, OperationStatus::TimedOut);
    assert!(snapshot.execution_stopped);
    assert_eq!(snapshot.error, Some(error));
    assert_eq!(rig.backend.writes, 1, "only the first slice wrote");
}

#[test]
fn n6_write_slices_resume_at_checkpoint_and_cancel_never_replays() {
    let mut rig = Rig::new();
    let lease = rig.connect("n6", "n6-owner", 1);
    let write = rig.queue(&lease, "rename", "batch_rename", 120);
    rig.dispatch(&write);
    rig.sessions
        .yield_operation(&write, json!({"index":1}))
        .expect("completed write slice permits continuation");
    rig.dispatch(&write);
    assert_eq!(rig.backend.writes, 2);
    assert_eq!(rig.backend.executed[1].params["_n5_checkpoint"]["index"], 1);
    rig.sessions
        .cancel(
            &lease.client_id,
            &write,
            CancelReason::Client,
            &mut rig.backend,
        )
        .expect("cancel in-flight slice");
    rig.sessions
        .yield_operation(&write, json!({"index":2}))
        .expect("returned slice confirms execution stopped");
    assert_eq!(rig.snapshot(&write).status, OperationStatus::Cancelled);
    assert!(rig.snapshot(&write).execution_stopped);
    assert!(rig
        .sessions
        .dispatch(&lease.client_id, &write, &mut rig.backend)
        .is_err());
    assert_eq!(
        rig.backend.writes, 2,
        "cancellation never replays already dispatched writes"
    );
}

#[test]
fn n5_yield_rejoins_fifo_without_renewing_identity_or_deadline() {
    let mut rig = Rig::new();
    let lease = rig.connect("n5", "n5-instance", 1);
    let long = rig.queue(&lease, "long", "batch_decompile", 1);
    rig.dispatch(&long);
    let short = rig.queue(&lease, "short", "list_functions", 120);
    rig.sessions
        .yield_operation(&long, json!({"index":1}))
        .unwrap();
    assert_eq!(rig.snapshot(&long).status, OperationStatus::Queued);
    assert!(rig.snapshot(&long).execution_stopped);
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &long, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    rig.dispatch(&short);
    rig.sessions
        .complete(&short, Completion::Success(json!("short")))
        .unwrap();
    rig.dispatch(&long);
    assert_eq!(
        rig.backend.executed.last().unwrap().params["_n5_checkpoint"]["index"],
        1
    );
    rig.sessions
        .yield_operation(&long, json!({"index":2}))
        .unwrap();
    rig.clock.advance(1001);
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &long, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::QueueExpired
    );
    assert_eq!(rig.snapshot(&long).status, OperationStatus::TimedOut);
    assert_eq!(rig.backend.executed.len(), 3);
}

#[test]
fn n5_cancel_at_slice_boundary_confirms_stop_and_does_not_resume() {
    let mut rig = Rig::new();
    let lease = rig.connect("n5", "n5-instance", 1);
    let long = rig.queue(&lease, "cancel-long", "batch_decompile", 120);
    rig.dispatch(&long);
    rig.sessions
        .cancel(
            &lease.client_id,
            &long,
            CancelReason::Client,
            &mut rig.backend,
        )
        .unwrap();
    assert!(!rig.snapshot(&long).execution_stopped);
    rig.sessions
        .yield_operation(&long, json!({"index":1}))
        .unwrap();
    assert_eq!(rig.snapshot(&long).status, OperationStatus::Cancelled);
    assert!(rig.snapshot(&long).execution_stopped);
    assert!(rig
        .sessions
        .dispatch(&lease.client_id, &long, &mut rig.backend)
        .is_err());
    let next = rig.queue(&lease, "next", "list_functions", 120);
    rig.dispatch(&next);
}

#[test]
fn n5_late_slice_preserves_unknown_outcome_and_deadline_boundary_stops() {
    for unknown in [false, true] {
        let mut rig = Rig::new();
        let lease = rig.connect("n5-boundary", "n5-owner", 1);
        let long = rig.queue(&lease, "boundary", "batch_decompile", 1);
        rig.dispatch(&long);
        if unknown {
            rig.sessions
                .delivery_failed(
                    rig.backend.attempts.last().unwrap(),
                    DispatchFailure::Uncertain(NexusError::new(
                        NexusErrorCode::Disconnected,
                        "fixture",
                    )),
                )
                .unwrap();
            assert_eq!(rig.snapshot(&long).status, OperationStatus::UnknownOutcome);
        } else {
            rig.clock.advance(1001);
        }
        rig.sessions
            .yield_operation(&long, json!({"index":1}))
            .unwrap();
        assert_eq!(
            rig.snapshot(&long).status,
            if unknown {
                OperationStatus::UnknownOutcome
            } else {
                OperationStatus::TimedOut
            }
        );
        assert!(rig.snapshot(&long).execution_stopped);
        assert!(rig
            .sessions
            .dispatch(&lease.client_id, &long, &mut rig.backend)
            .is_err());
        assert_eq!(
            rig.backend.executed.len(),
            1,
            "late slice never resumes/replays"
        );
    }
}

#[test]
fn e02_capability_and_readiness_rejections_never_execute_or_fallback() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let error = rig
        .sessions
        .queue(
            &lease.client_id,
            &lease,
            accepted(&rig.clock, "unsupported", "patch_bytes", json!({})),
            OperationId::new("unsupported").unwrap(),
        )
        .unwrap_err();
    assert_eq!(error.code, NexusErrorCode::UnsupportedCapability);
    assert!(rig.backend.executed.is_empty());
    assert_eq!(rig.backend.writes, 0);

    let request = accepted(&rig.clock, "not-ready", "open", json!({}));
    let mut unavailable = NexusSessions::new(
        rig.clock.clone(),
        Err(NexusError::new(
            NexusErrorCode::BridgeUnavailable,
            "not installed",
        )),
        8,
    );
    let before = rig.backend.business.len();
    assert_eq!(
        unavailable
            .open(
                &lease.client_id,
                request,
                OpenSpec {
                    operation_id: OperationId::new("not-ready").unwrap(),
                    path: "/test.i64".into(),
                    options: json!({})
                },
                &mut rig.backend
            )
            .unwrap_err()
            .code,
        NexusErrorCode::BridgeUnavailable
    );
    assert_eq!(rig.backend.business.len(), before);

    let op = rig.queue(&lease, "unconnected", "rename_symbol", 120);
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &op, &mut UnconnectedNexus)
            .unwrap_err()
            .code,
        NexusErrorCode::BridgeUnavailable
    );
    assert_eq!(rig.snapshot(&op).status, OperationStatus::Failed);
    assert!(rig.snapshot(&op).execution_stopped);
    assert_eq!(rig.backend.writes, 0);
}

#[test]
fn e02_runtime_and_missing_dependency_errors_are_diagnostic_before_open() {
    let mut rig = Rig::new();
    let client = ClientId::new("client").unwrap();
    for (field, code) in [
        ("ida", NexusErrorCode::RuntimeUnavailable),
        ("python", NexusErrorCode::RuntimeUnavailable),
        ("missing", NexusErrorCode::DependencyUnavailable),
        ("old", NexusErrorCode::DependencyUnavailable),
    ] {
        let mut caps = capabilities();
        match field {
            "ida" => caps.runtime.ida = Version(9, 3, 0),
            "python" => caps.runtime.python = Version(3, 10, 0),
            "missing" => caps.runtime.nexus = None,
            "old" => caps.runtime.domain = Some(Version(0, 5, 0)),
            _ => unreachable!(),
        }
        let mut sessions = NexusSessions::new(rig.clock.clone(), Ok(caps), 8);
        let error = sessions
            .open(
                &client,
                accepted(&rig.clock, field, "open", json!({})),
                OpenSpec {
                    operation_id: OperationId::new(field).unwrap(),
                    path: "/copy.i64".into(),
                    options: json!({}),
                },
                &mut rig.backend,
            )
            .unwrap_err();
        assert_eq!(error.code, code);
        assert!(!error.message.is_empty());
    }
    assert!(rig.backend.business.is_empty());
}

#[test]
fn e02_capabilities_are_per_lease_and_bad_runtime_handles_require_release() {
    let mut rig = Rig::new();
    let full = rig.connect("full", "instance-a", 1);
    let (open, limited) = rig.begin_open("limited", "instance-b", 1, 120);
    let mut caps = capabilities();
    caps.methods.remove("rename_symbol");
    assert!(matches!(
        rig.sessions.opened(&open, limited.clone(), caps).unwrap(),
        OpenDisposition::Ready(_)
    ));
    let error = rig
        .sessions
        .queue(
            &limited.client_id,
            &limited,
            accepted(&rig.clock, "limited-write", "rename_symbol", json!({})),
            OperationId::new("limited-write").unwrap(),
        )
        .unwrap_err();
    assert_eq!(error.code, NexusErrorCode::UnsupportedCapability);
    let supported = rig.queue(&full, "full-write", "rename_symbol", 120);
    rig.dispatch(&supported);
    assert_eq!(rig.backend.writes, 1);
    let (open, bad_runtime) = rig.begin_open("bad-runtime", "old-ida", 1, 120);
    let mut caps = capabilities();
    caps.runtime.ida = Version(9, 3, 0);
    match rig
        .sessions
        .opened(&open, bad_runtime.clone(), caps)
        .unwrap()
    {
        OpenDisposition::ReleaseRequired { lease, error } => {
            assert_eq!(lease, bad_runtime);
            assert_eq!(error.code, NexusErrorCode::RuntimeUnavailable);
        }
        OpenDisposition::Ready(_) => panic!("unsupported runtime must not become usable"),
    }
    assert!(rig
        .sessions
        .queue(
            &bad_runtime.client_id,
            &bad_runtime,
            accepted(&rig.clock, "bad-use", "rename_symbol", json!({})),
            OperationId::new("bad-use").unwrap()
        )
        .is_err());
    rig.sessions
        .release(&bad_runtime.client_id, &bad_runtime, &mut rig.backend)
        .unwrap();
}

#[test]
fn advertised_lifecycle_method_cannot_bypass_session_ownership_gates() {
    let mut rig = Rig::new();
    let (open, lease) = rig.begin_open("a", "instance", 1, 120);
    let mut caps = capabilities();
    caps.methods.insert("close".into(), MethodEffect::MayWrite);
    assert!(matches!(
        rig.sessions.opened(&open, lease.clone(), caps).unwrap(),
        OpenDisposition::Ready(_)
    ));
    assert_eq!(
        rig.sessions
            .queue(
                &lease.client_id,
                &lease,
                accepted(&rig.clock, "lifecycle-bypass", "close", json!({})),
                OperationId::new("lifecycle-bypass").unwrap()
            )
            .unwrap_err()
            .code,
        NexusErrorCode::UnsupportedCapability
    );
    assert!(rig.backend.executed.is_empty());
    assert!(rig.backend.controls.is_empty());
}

#[test]
fn task_and_request_ids_are_correlated_without_allowing_request_reuse() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "correlation", "list_functions", 120);
    assert_eq!(op.request_id.as_str(), "r-correlation");
    assert_eq!(op.task_id.as_ref().unwrap().as_str(), "t-correlation");
    let reused = accepted(&rig.clock, "correlation", "rename_symbol", json!({}));
    assert_eq!(
        rig.sessions
            .queue(
                &lease.client_id,
                &lease,
                reused,
                OperationId::new("different-op").unwrap()
            )
            .unwrap_err()
            .code,
        NexusErrorCode::DuplicateIdentity
    );
    assert!(rig.backend.executed.is_empty());
}

#[test]
fn uncertain_open_is_not_replayed_and_reconciles_to_its_exact_handle() {
    let mut rig = Rig::new();
    let client = ClientId::new("uncertain-open-client").unwrap();
    let request = accepted(&rig.clock, "uncertain-open", "open", json!({}));
    let identity = OpenIdentity {
        client_id: client.clone(),
        request_id: RequestId::new("r-uncertain-open").unwrap(),
        task_id: Some(TaskId::new("t-uncertain-open").unwrap()),
        operation_id: OperationId::new("uncertain-open").unwrap(),
    };
    rig.backend.fail_business = Some(DispatchFailure::Uncertain(NexusError::new(
        NexusErrorCode::Disconnected,
        "open response lost",
    )));
    let spec = OpenSpec {
        operation_id: identity.operation_id.clone(),
        path: "/copy.i64".into(),
        options: json!({}),
    };
    assert_eq!(
        rig.sessions
            .open(&client, request.clone(), spec.clone(), &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::UnknownOutcome
    );
    assert_eq!(
        rig.sessions
            .open(&client, request, spec, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::DuplicateIdentity
    );
    assert_eq!(rig.backend.business.len(), 1);
    let lease = SessionLease {
        client_id: client,
        lease_id: LeaseId::new("uncertain-open-lease").unwrap(),
        instance_id: InstanceId::new("instance").unwrap(),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    assert!(matches!(
        rig.sessions
            .opened(&identity, lease, capabilities())
            .unwrap(),
        OpenDisposition::ReleaseRequired { .. }
    ));
}

#[test]
fn e14_expired_queued_write_never_reaches_executor_even_after_slot_frees() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let long = rig.queue(&lease, "long", "list_functions", 120);
    rig.dispatch(&long);
    let write = rig.queue(&lease, "expired-write", "rename_symbol", 1);
    assert_eq!(rig.snapshot(&write).status, OperationStatus::Queued);
    rig.clock.advance(1000);
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &write, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::QueueExpired
    );
    assert_eq!(rig.snapshot(&write).status, OperationStatus::TimedOut);
    assert_eq!(rig.backend.writes, 0);
    assert!(rig
        .sessions
        .complete(&long, Completion::Success(json!({})))
        .unwrap());
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &write, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidTransition
    );
    assert_eq!(rig.backend.writes, 0);
    assert_eq!(rig.backend.executed.len(), 1);
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .expect("expired request no longer retains lease");
}

#[test]
fn e14_acceptance_precedes_preparation_and_bridge_queue_consumes_remaining_budget() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let request = accepted(
        &rig.clock,
        "preparation",
        "rename_symbol",
        json!({"timeout_secs":1}),
    );
    rig.clock.advance(900);
    let op = rig
        .sessions
        .queue(
            &lease.client_id,
            &lease,
            request,
            OperationId::new("prepared").unwrap(),
        )
        .unwrap();
    rig.dispatch(&op);
    let command = rig.backend.executed.last().expect("one command");
    assert_eq!(command.remaining_ms.milliseconds(), 100);
    let bridge_deadline = command.remaining_ms.start(rig.clock.now()).unwrap();
    rig.clock.advance(100);
    assert!(bridge_deadline.expired(rig.clock.now()));
    assert_eq!(
        bridge_deadline.remaining(rig.clock.now()).unwrap_err().code,
        NexusErrorCode::DeadlineExpired
    );
    let pending = rig
        .sessions
        .expire(&lease.client_id, &op, &mut rig.backend)
        .unwrap();
    assert_eq!(pending.status, OperationStatus::CancelRequested);
    assert!(!pending.execution_stopped);
    assert!(rig.sessions.complete(&op, Completion::Cancelled).unwrap());
    assert_eq!(rig.snapshot(&op).status, OperationStatus::TimedOut);
}

#[test]
fn e15_cancel_ack_is_not_stop_and_release_and_next_execution_wait() {
    let mut rig = Rig::new();
    let a = rig.connect("a", "instance", 1);
    let b = rig.connect("b", "instance", 1);
    let op = rig.queue(&a, "cancel", "rename_symbol", 120);
    rig.dispatch(&op);
    let pending = rig
        .sessions
        .cancel(&a.client_id, &op, CancelReason::Client, &mut rig.backend)
        .unwrap();
    assert_eq!(pending.status, OperationStatus::CancelRequested);
    assert!(!pending.execution_stopped);
    assert_eq!(
        pending.error.unwrap().retry_advice(),
        RetryAdvice::ObserveOperation
    );
    assert!(
        matches!(rig.backend.controls.last(), Some(SessionCommand::Cancel { identity, .. }) if identity == &op)
    );
    assert_eq!(
        rig.sessions
            .release(&a.client_id, &a, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::CancelPending
    );
    let next = rig.queue(&b, "next", "list_functions", 120);
    assert_eq!(
        rig.sessions
            .dispatch(&b.client_id, &next, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    assert!(rig.sessions.complete(&op, Completion::Cancelled).unwrap());
    assert_eq!(rig.snapshot(&op).status, OperationStatus::Cancelled);
    rig.dispatch(&next);
    rig.sessions
        .release(&a.client_id, &a, &mut rig.backend)
        .unwrap();
    assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
    assert_eq!(
        rig.sessions.status(&b.client_id, &b).unwrap().phase,
        SessionPhase::Active
    );
    assert_eq!(rig.snapshot(&next).status, OperationStatus::Running);
}

#[test]
fn e15_queued_cancel_and_zero_budget_have_no_side_effects() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let queued = rig.queue(&lease, "queued-cancel", "rename_symbol", 120);
    assert_eq!(
        rig.sessions
            .cancel(
                &lease.client_id,
                &queued,
                CancelReason::Client,
                &mut rig.backend
            )
            .unwrap()
            .status,
        OperationStatus::Cancelled
    );
    assert!(rig.backend.controls.is_empty());
    assert!(rig
        .sessions
        .dispatch(&lease.client_id, &queued, &mut rig.backend)
        .is_err());
    let zero = rig.queue(&lease, "zero", "rename_symbol", 0);
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &zero, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::QueueExpired
    );
    assert_eq!(rig.backend.writes, 0);
    assert!(rig.backend.executed.is_empty());
}

#[test]
fn e15_completion_cancel_race_has_exactly_one_terminal_winner() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "race", "rename_symbol", 120);
    rig.dispatch(&op);
    rig.sessions
        .cancel(
            &lease.client_id,
            &op,
            CancelReason::Client,
            &mut rig.backend,
        )
        .unwrap();
    let sessions = Arc::new(Mutex::new(rig.sessions));
    let barrier = Arc::new(Barrier::new(3));
    let wins = std::thread::scope(|scope| {
        let start = barrier.clone();
        let registry = sessions.clone();
        let identity = op.clone();
        let complete = scope.spawn(move || {
            start.wait();
            registry
                .lock()
                .unwrap()
                .complete(&identity, Completion::Success(json!({"winner":"complete"})))
                .unwrap()
        });
        let start = barrier.clone();
        let registry = sessions.clone();
        let identity = op.clone();
        let cancel = scope.spawn(move || {
            start.wait();
            registry
                .lock()
                .unwrap()
                .complete(&identity, Completion::Cancelled)
                .unwrap()
        });
        barrier.wait();
        [
            complete.join().expect("completion thread"),
            cancel.join().expect("cancel thread"),
        ]
    });
    assert_eq!(wins.into_iter().filter(|won| *won).count(), 1);
    let state = sessions
        .lock()
        .unwrap()
        .operation_status(&lease.client_id, &op)
        .unwrap();
    assert!(matches!(
        state.status,
        OperationStatus::Succeeded | OperationStatus::Cancelled
    ));
    assert!(state.execution_stopped);
    assert_eq!(
        state.result.is_some(),
        state.status == OperationStatus::Succeeded
    );
    assert_eq!(rig.backend.writes, 1);
}

#[test]
fn e15_late_response_and_old_cancel_cannot_overwrite_successor() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let old = rig.queue(&lease, "old", "list_functions", 120);
    rig.dispatch(&old);
    assert!(rig
        .sessions
        .complete(&old, Completion::Success(json!({"old":true})))
        .unwrap());
    let next = rig.queue(&lease, "new", "rename_symbol", 120);
    rig.dispatch(&next);
    let controls = rig.backend.controls.len();
    assert!(!rig
        .sessions
        .complete(&old, Completion::ExecutionTimedOut)
        .unwrap());
    rig.sessions
        .cancel(
            &lease.client_id,
            &old,
            CancelReason::Client,
            &mut rig.backend,
        )
        .unwrap();
    assert_eq!(rig.backend.controls.len(), controls);
    assert_eq!(rig.snapshot(&next).status, OperationStatus::Running);
    assert_eq!(rig.snapshot(&old).result, Some(json!({"old":true})));
    let mut forged = old.clone();
    forged.operation_id = next.operation_id.clone();
    assert_eq!(
        rig.sessions
            .complete(&forged, Completion::Cancelled)
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidIdentity
    );
    assert_eq!(rig.snapshot(&next).status, OperationStatus::Running);
    assert!(rig
        .sessions
        .queue(
            &lease.client_id,
            &lease,
            accepted(&rig.clock, "reuse", "rename_symbol", json!({})),
            old.operation_id.clone()
        )
        .is_err());
}

#[test]
fn e15_client_lease_and_owner_generation_isolation() {
    let mut rig = Rig::new();
    let a = rig.connect("a", "instance", 1);
    let b = rig.connect("b", "instance", 1);
    let old = rig.queue(&a, "old-generation", "rename_symbol", 120);
    rig.dispatch(&old);
    assert_eq!(
        rig.sessions
            .cancel(&b.client_id, &old, CancelReason::Client, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidLease
    );
    let mut forged = a.clone();
    forged.lease_id = LeaseId::new("not-a-lease").unwrap();
    assert_eq!(
        rig.sessions
            .release(&a.client_id, &forged, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidLease
    );
    let replacement = rig.connect("replacement", "instance", 2);
    assert_eq!(rig.snapshot(&old).status, OperationStatus::UnknownOutcome);
    let next = rig.queue(&replacement, "new-generation", "rename_symbol", 120);
    rig.dispatch(&next);
    let controls = rig.backend.controls.len();
    assert_eq!(
        rig.sessions
            .cancel(&a.client_id, &old, CancelReason::Client, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::StaleGeneration
    );
    assert!(!rig.sessions.disconnected(&a.instance_id, 1));
    assert!(!rig
        .sessions
        .complete(&old, Completion::Success(json!({"late":true})))
        .unwrap());
    assert_eq!(rig.backend.controls.len(), controls);
    assert_eq!(rig.snapshot(&next).status, OperationStatus::Running);
    assert_eq!(
        rig.sessions
            .release(&a.client_id, &a, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::StaleGeneration
    );
}

#[test]
fn e15_disconnect_after_write_dispatch_is_unknown_and_never_replayed() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "write-disconnect", "rename_symbol", 120);
    rig.dispatch(&op);
    let queued = rig.queue(&lease, "not-dispatched", "rename_symbol", 120);
    assert!(rig.sessions.disconnected(&lease.instance_id, 1));
    let unknown = rig.snapshot(&op);
    assert_eq!(unknown.status, OperationStatus::UnknownOutcome);
    assert!(!unknown.execution_stopped);
    assert_eq!(
        unknown.error.unwrap().retry_advice(),
        RetryAdvice::NeverReplay
    );
    assert_eq!(rig.snapshot(&queued).status, OperationStatus::Failed);
    assert!(rig.snapshot(&queued).execution_stopped);
    assert!(rig
        .sessions
        .dispatch(&lease.client_id, &op, &mut rig.backend)
        .is_err());
    assert_eq!(rig.backend.writes, 1);
    assert_eq!(
        rig.sessions
            .release(&lease.client_id, &lease, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::CancelPending
    );
    assert!(!rig
        .sessions
        .complete(&op, Completion::Success(json!({"late":true})))
        .unwrap());
    assert_eq!(rig.snapshot(&op).status, OperationStatus::UnknownOutcome);
    assert!(rig.snapshot(&op).execution_stopped);
    assert!(rig.snapshot(&op).result.is_none());
    assert_eq!(rig.backend.executed.len(), 1);
}

#[test]
fn uncertain_send_holds_slot_and_preserves_source_while_proven_not_sent_releases() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "uncertain", "rename_symbol", 120);
    rig.backend.fail_business = Some(DispatchFailure::Uncertain(NexusError::new(
        NexusErrorCode::Disconnected,
        "pipe closed after write",
    )));
    let error = rig
        .sessions
        .dispatch(&lease.client_id, &op, &mut rig.backend)
        .unwrap_err();
    assert_eq!(error.code, NexusErrorCode::UnknownOutcome);
    assert_eq!(error.cause.unwrap().message, "pipe closed after write");
    let next = rig.queue(&lease, "after-uncertain", "list_functions", 120);
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &next, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    assert!(!rig
        .sessions
        .complete(&op, Completion::Success(json!({})))
        .unwrap());
    rig.backend.fail_business = Some(DispatchFailure::NotSent(NexusError::new(
        NexusErrorCode::Busy,
        "bounded queue full",
    )));
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &next, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    assert!(rig.snapshot(&next).execution_stopped);
    assert_eq!(rig.snapshot(&next).status, OperationStatus::Failed);
    let final_op = rig.queue(&lease, "after-not-sent", "list_functions", 120);
    rig.dispatch(&final_op);
    assert_eq!(rig.backend.writes, 1);
}

#[test]
fn failed_cancel_delivery_and_execution_timeout_do_not_claim_early_stop() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "cancel-control-error", "rename_symbol", 120);
    rig.dispatch(&op);
    rig.backend.fail_control = Some(DispatchFailure::NotSent(NexusError::new(
        NexusErrorCode::Busy,
        "control queue full",
    )));
    assert_eq!(
        rig.sessions
            .cancel(
                &lease.client_id,
                &op,
                CancelReason::Client,
                &mut rig.backend
            )
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    assert_eq!(rig.snapshot(&op).status, OperationStatus::CancelRequested);
    assert!(!rig.snapshot(&op).execution_stopped);
    assert!(rig
        .sessions
        .complete(&op, Completion::ExecutionTimedOut)
        .unwrap());
    let stopped = rig.snapshot(&op);
    assert_eq!(stopped.status, OperationStatus::TimedOut);
    assert!(stopped.execution_stopped);
    assert_eq!(
        stopped.error.unwrap().code,
        NexusErrorCode::ExecutionTimeout
    );
}

#[test]
fn completion_after_deadline_loses_even_without_timer_delivery() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "late-deadline", "rename_symbol", 1);
    rig.dispatch(&op);
    rig.clock.advance(1000);
    assert!(rig
        .sessions
        .complete(&op, Completion::Success(json!({"changed":true})))
        .unwrap());
    let state = rig.snapshot(&op);
    assert_eq!(state.status, OperationStatus::TimedOut);
    assert!(state.execution_stopped);
    assert_eq!(rig.backend.writes, 1);
    assert_eq!(
        state.error.unwrap().retry_advice(),
        RetryAdvice::NeverReplay
    );
}

#[path = "support/nexus_failures.rs"]
mod failures;

#[path = "support/nexus_delivery_lifecycle.rs"]
mod delivery_lifecycle;
#[path = "support/nexus_delivery_regression.rs"]
mod delivery_regression;

#[path = "support/nexus_send_eligibility.rs"]
mod send_eligibility;

#[test]
fn f1_lease_disconnect_is_scoped_and_keeps_sibling_execution_live() {
    let mut rig = Rig::new();
    let a = rig.connect("a", "owner", 1);
    let b = rig.connect("b", "owner", 1);
    let op = rig.queue(&b, "sibling-running", "rename_symbol", 120);
    rig.sessions
        .dispatch(&b.client_id, &op, &mut rig.backend)
        .unwrap();
    assert!(rig.sessions.lease_disconnected(&a).unwrap());
    assert!(!rig.sessions.lease_disconnected(&a).unwrap());
    assert_eq!(
        rig.sessions.status(&a.client_id, &a).unwrap().phase,
        SessionPhase::Disconnected
    );
    assert_eq!(
        rig.sessions.status(&b.client_id, &b).unwrap().phase,
        SessionPhase::Active
    );
    assert_eq!(rig.snapshot(&op).status, OperationStatus::Running);
    assert!(!rig.snapshot(&op).execution_stopped);
    rig.sessions
        .complete(&op, Completion::Success(json!("sibling result")))
        .unwrap();
    assert_eq!(rig.snapshot(&op).status, OperationStatus::Succeeded);
    let mut forged = a.clone();
    forged.client_id = b.client_id.clone();
    assert!(rig.sessions.lease_disconnected(&forged).is_err());
}

#[test]
fn f1_stop_proof_is_independent_of_business_outcome_and_preserves_unknown_cause() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "owner", 1);
    let op = rig.queue(&lease, "unknown-stop", "rename_symbol", 120);
    assert!(
        rig.sessions.execution_stopped(&op).is_err(),
        "queued work cannot receive a stop proof"
    );
    rig.sessions
        .dispatch(&lease.client_id, &op, &mut rig.backend)
        .unwrap();
    assert!(
        rig.sessions.execution_stopped(&op).is_err(),
        "running work still needs its business outcome"
    );
    let attempt = rig.backend.attempts.last().unwrap().clone();
    rig.sessions
        .delivery_failed(
            &attempt,
            DispatchFailure::Uncertain(NexusError::new(
                NexusErrorCode::Disconnected,
                "lost response",
            )),
        )
        .unwrap();
    let before = rig.snapshot(&op);
    assert_eq!(before.status, OperationStatus::UnknownOutcome);
    assert!(!before.execution_stopped);
    assert!(rig.sessions.execution_stopped(&op).unwrap());
    assert!(!rig.sessions.execution_stopped(&op).unwrap());
    let after = rig.snapshot(&op);
    assert_eq!(after.status, before.status);
    assert_eq!(after.error, before.error);
    assert_eq!(after.result, None);
    assert!(after.execution_stopped);
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
}

// Baseline adapter: before N4-F1, reading a result was only possible by
// operation_status(), which clones it. Inherent move API takes precedence.
#[allow(dead_code)]
trait BaselineResultRead {
    fn take_operation_result(
        &mut self,
        client: &ClientId,
        identity: &OperationIdentity,
    ) -> Result<Option<serde_json::Value>, NexusError>;
}
impl<C: Clock> BaselineResultRead for NexusSessions<C> {
    fn take_operation_result(
        &mut self,
        client: &ClientId,
        identity: &OperationIdentity,
    ) -> Result<Option<serde_json::Value>, NexusError> {
        Ok(self.operation_status(client, identity)?.result)
    }
}
#[test]
fn n4_fix_large_result_is_moved_without_copying_its_allocation() {
    let mut rig = Rig::new();
    let lease = rig.connect("move", "owner", 1);
    let op = rig.queue(&lease, "large", "list_functions", 120);
    rig.dispatch(&op);
    let text = "payload".repeat(1024 * 1024);
    let allocation = text.as_ptr();
    rig.sessions
        .complete(&op, Completion::Success(serde_json::Value::String(text)))
        .unwrap();
    let progress = rig
        .sessions
        .operation_progress(&lease.client_id, &op)
        .unwrap();
    assert_eq!(progress.status, OperationStatus::Succeeded);
    assert!(
        progress.result.is_none(),
        "metadata poll cannot contain a business result"
    );
    let moved = rig
        .sessions
        .take_operation_result(&lease.client_id, &op)
        .unwrap()
        .unwrap();
    assert_eq!(
        moved.as_str().unwrap().as_ptr(),
        allocation,
        "lock-held result extraction must move the original allocation"
    );
    assert!(
        rig.sessions
            .operation_status(&lease.client_id, &op)
            .unwrap()
            .result
            .is_none(),
        "result is consumed exactly once"
    );
}

#[test]
fn abandoned_open_retains_late_lease_and_preserves_not_sent_release_ownership() {
    for late in [false, true] {
        let mut rig = Rig::new();
        let (open, lease) = rig.begin_open("abandoned", "owner", 1, 120);
        if !late {
            assert!(matches!(
                rig.sessions
                    .opened(&open, lease.clone(), capabilities())
                    .unwrap(),
                OpenDisposition::Ready(_)
            ));
        }
        rig.sessions.abandon_open(&lease.client_id, &open).unwrap();
        if late {
            assert!(matches!(
                rig.sessions
                    .opened(&open, lease.clone(), capabilities())
                    .unwrap(),
                OpenDisposition::ReleaseRequired { .. }
            ));
        }
        assert_eq!(
            rig.sessions
                .open_progress(&lease.client_id, &open)
                .unwrap()
                .0,
            Some(lease.clone())
        );
        assert_eq!(
            rig.sessions
                .open_progress(&ClientId::new("intruder").unwrap(), &open)
                .unwrap_err()
                .code,
            NexusErrorCode::InvalidIdentity
        );
        assert_eq!(
            rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
            SessionPhase::ReleaseRequired
        );
        rig.sessions
            .release(&lease.client_id, &lease, &mut rig.backend)
            .unwrap();
        let attempt = rig.backend.attempts.last().unwrap().clone();
        rig.sessions
            .delivery_failed(
                &attempt,
                DispatchFailure::NotSent(NexusError::new(NexusErrorCode::Busy, "fixture full")),
            )
            .unwrap();
        assert_eq!(
            rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
            SessionPhase::ReleaseRequired
        );
        rig.sessions
            .release(&lease.client_id, &lease, &mut rig.backend)
            .unwrap();
        rig.sessions
            .released(rig.backend.attempts.last().unwrap())
            .unwrap();
        rig.sessions.abandon_open(&lease.client_id, &open).unwrap();
        assert_eq!(
            rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
            SessionPhase::Released
        );
    }
}

#[test]
fn n5_f2_superseded_attempt_is_exact_and_available_at_dispatch() {
    let mut rig = Rig::new();
    let lease = rig.connect("gap-client", "gap-owner", 1);
    let op = rig.queue(&lease, "gap", "batch_decompile", 120);
    rig.dispatch(&op);
    let old = rig.backend.attempts.last().unwrap().clone();
    assert!(!rig.sessions.delivery_superseded(&old));
    rig.sessions
        .yield_operation(&op, json!({"index":1}))
        .unwrap();
    assert!(!rig.sessions.delivery_superseded(&old));
    rig.dispatch(&op);
    let new = rig.backend.attempts.last().unwrap().clone();
    assert!(rig.sessions.delivery_superseded(&old));
    assert!(!rig.sessions.delivery_superseded(&new));
    let mut forged = old.clone();
    if let DeliveryTarget::Execute { identity } = &mut forged.target {
        identity.lease.client_id = ClientId::new("other-client").unwrap();
    }
    assert!(!rig.sessions.delivery_superseded(&forged));
    forged = old.clone();
    forged.sequence = std::num::NonZeroU64::new(new.sequence.get() + 1).unwrap();
    assert!(!rig.sessions.delivery_superseded(&forged));
    rig.sessions
        .complete(&op, Completion::Success(json!("second")))
        .unwrap();
    assert!(rig.sessions.delivery_superseded(&old));
}

#[test]
fn r3a_public_lifetime_before_detach_terminal_preserves_exact_ack() {
    let mut rig = Rig::new();
    let lease = rig.connect("r3a-proof-first", "r3a-proof-first-owner", 1);
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .expect("issue one release");
    let delivery = rig
        .sessions
        .status(&lease.client_id, &lease)
        .expect("release status")
        .control_delivery
        .expect("retained release delivery");
    rig.sessions
        .public_owner_lifetime(&lease)
        .expect("exact public lifetime proof");
    let after_proof = rig
        .sessions
        .status(&lease.client_id, &lease)
        .expect("proof status");
    assert_eq!(after_proof.phase, SessionPhase::Released);
    assert_eq!(
        after_proof
            .control_delivery
            .expect("proof does not synthesize ACK")
            .state,
        delivery.state
    );
    assert!(rig
        .sessions
        .released(&delivery.attempt)
        .expect("late exact ACK retained"));
    assert_eq!(
        rig.sessions
            .status(&lease.client_id, &lease)
            .expect("final status")
            .control_delivery
            .expect("original delivery retained")
            .state,
        DeliveryState::Confirmed
    );
    assert!(!rig
        .sessions
        .released(&delivery.attempt)
        .expect("duplicate terminal is idempotent"));
}

#[test]
fn r3a_cancel_before_custody_never_grants_preparation() {
    let mut rig = Rig::new();
    let (parent, lease) = rig.begin_open("r3a-cancel", "owner-r3a", 1, 120);
    rig.sessions
        .cancel_open(&lease.client_id, &parent)
        .expect("cancel pending parent");
    let acquisition = AcquisitionId {
        parent,
        purpose: AcquisitionPurpose::Final,
        ordinal: 1,
    };
    let decision = rig
        .sessions
        .acquired(&acquisition, lease.clone(), true)
        .expect("retain late handle");
    assert_eq!(decision.disposition, CustodyDisposition::CleanupOnly);
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::ReleaseRequired
    );
    assert_eq!(
        rig.sessions
            .acquired(&acquisition, lease.clone(), true)
            .unwrap(),
        decision
    );
    let identity = OperationIdentity {
        task_id: None,
        request_id: RequestId::new("r3a-rpc").unwrap(),
        operation_id: OperationId::new("r3a-rpc").unwrap(),
        lease: lease.clone(),
    };
    assert!(rig
        .sessions
        .internal_grant(
            &acquisition,
            identity,
            InternalPurpose::Runtime,
            decision.grant_epoch
        )
        .is_err());
    assert_eq!(
        rig.backend.business.len(),
        1,
        "only outer open was enqueued"
    );
}

#[test]
fn r3a_preparing_denies_user_execute_and_cancel_revokes_epoch() {
    let mut rig = Rig::new();
    let (parent, lease) = rig.begin_open("r3a-epoch", "owner-r3a", 1, 120);
    let acquisition = AcquisitionId {
        parent: parent.clone(),
        purpose: AcquisitionPurpose::Final,
        ordinal: 1,
    };
    let decision = rig
        .sessions
        .acquired(&acquisition, lease.clone(), true)
        .unwrap();
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Preparing
    );
    let request = accepted(&rig.clock, "r3a-user", "list_functions", json!({}));
    assert!(rig
        .sessions
        .queue(
            &lease.client_id,
            &lease,
            request,
            OperationId::new("r3a-user").unwrap()
        )
        .is_err());
    let identity = OperationIdentity {
        task_id: None,
        request_id: RequestId::new("r3a-running").unwrap(),
        operation_id: OperationId::new("r3a-running").unwrap(),
        lease: lease.clone(),
    };
    let (attempt, _) = rig
        .sessions
        .internal_grant(
            &acquisition,
            identity.clone(),
            InternalPurpose::Runtime,
            decision.grant_epoch,
        )
        .unwrap();
    rig.sessions.cancel_open(&lease.client_id, &parent).unwrap();
    let revoked = rig.sessions.custody_decision(&lease).unwrap();
    assert_eq!(revoked.disposition, CustodyDisposition::CleanupOnly);
    assert!(revoked.grant_epoch > decision.grant_epoch);
    rig.sessions
        .delivery_failed(
            &attempt,
            DispatchFailure::Uncertain(NexusError::new(NexusErrorCode::Disconnected, "RPC EOF")),
        )
        .unwrap();
    let stopped = rig
        .sessions
        .operation_status(&lease.client_id, &identity)
        .unwrap();
    assert_eq!(stopped.status, OperationStatus::UnknownOutcome);
    assert!(!stopped.execution_stopped);
    assert!(
        rig.sessions
            .release(&lease.client_id, &lease, &mut rig.backend)
            .is_err(),
        "EOF does not stop RPC"
    );
    rig.sessions
        .complete(&identity, Completion::Success(json!("9.5")))
        .unwrap();
    let late = rig
        .sessions
        .operation_status(&lease.client_id, &identity)
        .unwrap();
    assert_eq!(late.status, OperationStatus::UnknownOutcome);
    assert!(late.execution_stopped);
    assert!(
        rig.sessions
            .prepared(&acquisition, &lease, capabilities(), false)
            .is_err(),
        "late result cannot revive parent"
    );
}

#[test]
fn r3a_custody_does_not_complete_open_and_ready_requires_exact_rpc_facts() {
    let mut rig = Rig::new();
    let (parent, lease) = rig.begin_open("r3a-ready", "r3a-owner", 1, 120);
    let outer = rig
        .backend
        .attempts
        .last()
        .expect("outer open attempt")
        .clone();
    let acquisition = AcquisitionId {
        parent: parent.clone(),
        purpose: AcquisitionPurpose::Final,
        ordinal: 1,
    };
    let decision = rig
        .sessions
        .acquired(&acquisition, lease.clone(), true)
        .expect("early custody");
    assert_ne!(
        rig.sessions
            .delivery_status(&lease.client_id, &outer)
            .unwrap()
            .state,
        DeliveryState::Confirmed,
        "physical custody cannot finish the caller's open"
    );
    assert!(
        rig.sessions
            .prepared(&acquisition, &lease, capabilities(), false)
            .is_err(),
        "no prepared RPC facts"
    );
    for (ordinal, purpose) in [
        InternalPurpose::Guard,
        InternalPurpose::Runtime,
        InternalPurpose::Root,
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("r3a-prep-{ordinal}");
        let identity = OperationIdentity {
            task_id: None,
            request_id: RequestId::new(&name).unwrap(),
            operation_id: OperationId::new(&name).unwrap(),
            lease: lease.clone(),
        };
        rig.sessions
            .internal_grant(
                &acquisition,
                identity.clone(),
                purpose,
                decision.grant_epoch,
            )
            .expect("exact internal grant");
        assert!(
            rig.sessions
                .internal_grant(
                    &acquisition,
                    identity.clone(),
                    purpose,
                    decision.grant_epoch
                )
                .is_err(),
            "replayed request cannot start the public RPC twice"
        );
        assert!(
            rig.sessions
                .prepared(&acquisition, &lease, capabilities(), false)
                .is_err(),
            "running RPC has no stopped evidence"
        );
        rig.sessions
            .complete(&identity, Completion::Success(json!({"ok":true})))
            .expect("real RPC return");
    }
    let mut forged = acquisition.clone();
    forged.parent.request_id = RequestId::new("forged-prepared").unwrap();
    assert!(rig
        .sessions
        .prepared(&forged, &lease, capabilities(), false)
        .is_err());
    assert!(
        rig.sessions
            .prepared(&acquisition, &lease, capabilities(), true)
            .is_err(),
        "bridge cannot replace parent requirements"
    );
    rig.sessions
        .prepared(&acquisition, &lease, capabilities(), false)
        .expect("all required operations succeeded and stopped");
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Active
    );
    assert_eq!(
        rig.sessions
            .delivery_status(&lease.client_id, &outer)
            .unwrap()
            .state,
        DeliveryState::Confirmed
    );
    assert!(
        rig.sessions.cancel_open(&lease.client_id, &parent).is_err(),
        "Active uses session lifecycle"
    );
}

#[test]
fn rv81_completed_business_operations_outlive_the_pending_default() {
    let config = ida_mcp::router::RouterConfig::from_env();
    assert_eq!(config.max_pending_per_tenant, 512);
    assert_eq!(config.nexus_retention_capacity, 262144);
    let mut rig = Rig::new();
    rig.sessions = NexusSessions::with_limits(
        rig.clock.clone(),
        Ok(capabilities()),
        config.max_pending_per_tenant,
        config.nexus_retention_capacity,
    );
    let lease = rig.connect("rv81", "rv81-owner", 1);
    let mut first = None;
    for index in 0..513 {
        let operation = rig.queue(&lease, &format!("rv81-{index}"), "list_functions", 120);
        rig.dispatch(&operation);
        rig.sessions
            .complete(&operation, Completion::Success(json!({"index":index})))
            .expect("complete actual business operation");
        rig.sessions
            .take_operation_result(&lease.client_id, &operation)
            .expect("consume result without forgetting terminal identity");
        first.get_or_insert(operation);
        let usage = rig.sessions.retention_status();
        assert_eq!(
            usage.business_used,
            index + 2,
            "open plus completed operations"
        );
        assert_eq!(usage.total_used, index + 2);
        assert_eq!(usage.business_capacity, 262144);
        assert_eq!(usage.internal_capacity, 12582912);
        assert_eq!(usage.total_capacity, 16777216);
    }
    let first = first.expect("first completed operation");
    assert_eq!(rig.snapshot(&first).status, OperationStatus::Succeeded);
    let duplicate = rig
        .sessions
        .queue(
            &lease.client_id,
            &lease,
            accepted(&rig.clock, "rv81-0", "list_functions", json!({})),
            first.operation_id,
        )
        .expect_err("terminal ID must remain reserved for this coordinator lifetime");
    assert_eq!(duplicate.code, NexusErrorCode::DuplicateIdentity);
    assert_eq!(rig.backend.executed.len(), 513);
}

#[test]
fn rv81_small_retention_is_independent_of_physical_admission() {
    let mut rig = Rig::new();
    rig.sessions = NexusSessions::with_limits(rig.clock.clone(), Ok(capabilities()), 1, 3);
    let lease = rig.connect("rv81-small", "rv81-small-owner", 1);
    for index in 0..2 {
        let operation = rig.queue(&lease, &format!("small-{index}"), "list_functions", 120);
        rig.dispatch(&operation);
        rig.sessions
            .complete(&operation, Completion::Success(json!(index)))
            .expect("complete before testing cumulative retention");
    }
    let error = rig
        .sessions
        .queue(
            &lease.client_id,
            &lease,
            accepted(&rig.clock, "overflow", "list_functions", json!({})),
            OperationId::new("overflow").unwrap(),
        )
        .expect_err("retention full at 3, no pending work");
    assert_eq!(error.code, NexusErrorCode::Busy);
    for text in [
        "business contract",
        "3/3",
        "coordinator lifetime",
        "restart the daemon/bridge",
        "IDA_CLI_NEXUS_RETENTION_CAPACITY",
        "do not replay",
    ] {
        assert!(error.message.contains(text), "missing {text}: {error}");
    }
    assert_eq!(
        rig.sessions.retention_status().total_used,
        3,
        "refusal retains every ID"
    );
}

#[test]
fn runtime_support_is_exactly_ida_94_and_95() {
    let mut caps = capabilities();
    for version in [Version(9, 4, 0), Version(9, 5, 0)] {
        caps.runtime.ida = version;
        caps.runtime
            .validate()
            .expect("explicitly supported runtime");
    }
    for version in [Version(9, 3, 0), Version(9, 6, 0), Version(10, 0, 0)] {
        caps.runtime.ida = version;
        assert_eq!(
            caps.runtime
                .validate()
                .expect_err("unknown runtime must fail")
                .code,
            NexusErrorCode::RuntimeUnavailable
        );
    }
}
