//! Deterministic N1 contracts, not a Python bridge or real IDA E2E suite.
use std::sync::{Arc, Barrier, Mutex};

use ida_mcp::nexus::*;
use serde_json::json;

#[path = "support/nexus_contract.rs"]
mod support;
use support::*;
#[path = "support/nexus_compatibility.rs"]
mod compatibility;
#[path = "support/nexus_lifecycle.rs"]
mod lifecycle;

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
