use ida_mcp::nexus::*;
use serde_json::json;

use super::support::*;

pub(super) fn unknown_operation(rig: &mut Rig) -> OperationIdentity {
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "uncertain-write", "rename_symbol", 1);
    rig.backend.fail_business = Some(DispatchFailure::Uncertain(NexusError::new(
        NexusErrorCode::Disconnected,
        "injected response/transport uncertainty",
    )));
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &op, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::UnknownOutcome
    );
    assert_eq!(rig.snapshot(&op).status, OperationStatus::UnknownOutcome);
    assert!(!rig.snapshot(&op).execution_stopped);
    op
}

#[test]
fn client_cancel_of_unknown_running_write_still_uses_control_channel() {
    let mut rig = Rig::new();
    let op = unknown_operation(&mut rig);
    rig.sessions
        .cancel(
            &op.lease.client_id,
            &op,
            CancelReason::Client,
            &mut rig.backend,
        )
        .expect("requesting cancellation is distinct from replaying execution");
    assert!(
        matches!(
            rig.backend.controls.as_slice(),
            [SessionCommand::Cancel { identity, reason: CancelReason::Client }] if identity == &op
        ),
        "live unknown-outcome operation was not sent a cancellation request"
    );
    assert_eq!(rig.backend.writes, 1, "execution must never be replayed");
    assert_eq!(rig.snapshot(&op).status, OperationStatus::UnknownOutcome);
    assert!(!rig.snapshot(&op).execution_stopped);
    assert!(!rig
        .sessions
        .complete(&op, Completion::Cancelled)
        .expect("late confirmation only supplies stop evidence"));
    assert!(rig.snapshot(&op).execution_stopped);
    assert_eq!(rig.snapshot(&op).status, OperationStatus::UnknownOutcome);
    assert_eq!(rig.snapshot(&op).result, None::<serde_json::Value>);
}

#[test]
fn total_deadline_of_unknown_running_write_still_requests_stop() {
    let mut rig = Rig::new();
    let op = unknown_operation(&mut rig);
    rig.clock.advance(1001);
    rig.sessions
        .expire(&op.lease.client_id, &op, &mut rig.backend)
        .expect("expired unknown execution still needs a stop request");
    assert!(
        matches!(
            rig.backend.controls.as_slice(),
            [SessionCommand::Cancel { identity, reason: CancelReason::Deadline }] if identity == &op
        ),
        "total deadline did not reach the still-running uncertain operation"
    );
    assert_eq!(rig.backend.writes, 1);
    assert_eq!(rig.snapshot(&op).status, OperationStatus::UnknownOutcome);
    assert!(!rig.snapshot(&op).execution_stopped);
    assert!(!rig
        .sessions
        .complete(&op, Completion::Success(json!({"late": true})))
        .expect("late completion supplies stopping evidence without changing outcome"));
    assert_eq!(rig.snapshot(&op).status, OperationStatus::UnknownOutcome);
    assert!(rig.snapshot(&op).execution_stopped);
}

#[derive(Default)]
pub(super) struct DeferredBackend {
    pub(super) queued: Vec<SessionCommand>,
    pub(super) attempts: Vec<DeliveryAttempt>,
}
impl NexusBackend for DeferredBackend {
    fn send(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure> {
        self.attempts.push(attempt);
        self.queued.push(command);
        Ok(())
    }
    fn send_control(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure> {
        self.attempts.push(attempt);
        self.queued.push(command);
        Ok(())
    }
}

#[test]
fn enqueue_ok_then_single_request_uncertainty_retains_execution_and_other_lease() {
    let mut rig = Rig::new();
    let a = rig.connect("deferred-a", "shared", 1);
    let b = rig.connect("deferred-b", "shared", 1);
    let op = rig.queue(&a, "deferred-write", "rename_symbol", 120);
    let mut backend = DeferredBackend::default();
    rig.sessions
        .dispatch(&a.client_id, &op, &mut backend)
        .unwrap();
    assert_eq!(
        backend.queued.len(),
        1,
        "bounded enqueue succeeded before failure"
    );
    let attempt = backend.attempts.last().unwrap().clone();
    assert!(rig
        .sessions
        .delivery_failed(
            &attempt,
            DispatchFailure::Uncertain(NexusError::new(
                NexusErrorCode::Disconnected,
                "HTTP response lost after write"
            ))
        )
        .unwrap());
    let state = rig.snapshot(&op);
    assert_eq!(state.status, OperationStatus::UnknownOutcome);
    assert!(!state.execution_stopped);
    assert_eq!(
        rig.sessions.status(&b.client_id, &b).unwrap().phase,
        SessionPhase::Active
    );
    let next = rig.queue(&b, "deferred-next", "rename_symbol", 120);
    assert_eq!(
        rig.sessions
            .dispatch(&b.client_id, &next, &mut backend)
            .unwrap_err()
            .code,
        NexusErrorCode::Busy
    );
    assert_eq!(backend.queued.len(), 1, "unknown write is never replayed");
}

pub(super) fn transport_error(message: &str) -> NexusError {
    NexusError::new(NexusErrorCode::Disconnected, message)
}

pub(super) fn cancel(
    rig: &mut Rig,
    op: &OperationIdentity,
    reason: CancelReason,
) -> DeliveryAttempt {
    rig.sessions
        .cancel(&op.lease.client_id, op, reason, &mut rig.backend)
        .unwrap();
    rig.last_attempt()
}

#[test]
fn unknown_control_failures_preserve_outcome_and_retry_only_explicitly() {
    let mut rig = Rig::new();
    let op = unknown_operation(&mut rig);
    let original = rig.snapshot(&op).error.unwrap();
    let first = cancel(&mut rig, &op, CancelReason::Client);
    assert_eq!(rig.backend.controls.len(), 1);
    cancel(&mut rig, &op, CancelReason::Client);
    assert_eq!(
        rig.backend.controls.len(),
        1,
        "pending control is deduplicated"
    );
    assert!(rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::NotSent(transport_error("writer full"))
        )
        .unwrap());
    assert_eq!(rig.snapshot(&op).error, Some(original.clone()));
    assert!(!rig.snapshot(&op).execution_stopped);
    let second = cancel(&mut rig, &op, CancelReason::Client);
    assert_ne!(first.sequence, second.sequence);
    assert!(!rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::Uncertain(transport_error("old failure"))
        )
        .unwrap());
    assert!(!rig.sessions.delivery_acknowledged(&first).unwrap());
    assert!(rig.sessions.delivery_acknowledged(&second).unwrap());
    assert!(!rig.sessions.delivery_acknowledged(&second).unwrap());
    assert!(
        !rig.snapshot(&op).execution_stopped,
        "ACK is not stop evidence"
    );
    assert_eq!(
        rig.sessions
            .delivery_failed(
                &second,
                DispatchFailure::NotSent(transport_error("contradictory proof"))
            )
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidTransition
    );
    assert!(rig
        .sessions
        .delivery_failed(
            &second,
            DispatchFailure::Uncertain(transport_error("control HTTP lost"))
        )
        .unwrap());
    let state = rig.snapshot(&op);
    assert_eq!(state.error, Some(original.clone()));
    assert_eq!(
        state.cancel_delivery.unwrap().state,
        DeliveryState::Uncertain
    );
    assert_eq!(original.retry_advice(), RetryAdvice::NeverReplay);
    assert_eq!(rig.backend.writes, 1);
    rig.clock.advance(1000);
    let deadline = cancel(&mut rig, &op, CancelReason::Deadline);
    assert!(matches!(
        deadline.target,
        DeliveryTarget::Cancel {
            reason: CancelReason::Deadline,
            ..
        }
    ));
    let sent = rig.backend.controls.len();
    cancel(&mut rig, &op, CancelReason::Client);
    assert_eq!(
        rig.backend.controls.len(),
        sent,
        "client cannot downgrade pending deadline"
    );
    assert!(!rig.sessions.complete(&op, Completion::Cancelled).unwrap());
    assert_eq!(rig.snapshot(&op).error, Some(original));
    cancel(&mut rig, &op, CancelReason::Client);
    assert_eq!(rig.backend.controls.len(), sent, "no control after stop");
    assert!(!rig
        .sessions
        .delivery_failed(
            &deadline,
            DispatchFailure::Uncertain(transport_error("late control loss"))
        )
        .unwrap());
}

#[test]
fn unknown_cancel_rejects_wrong_client_full_identity_and_replaced_generation() {
    let mut rig = Rig::new();
    let op = unknown_operation(&mut rig);
    assert!(rig
        .sessions
        .cancel(
            &ClientId::new("intruder").unwrap(),
            &op,
            CancelReason::Client,
            &mut rig.backend
        )
        .is_err());
    let mut forged = op.clone();
    forged.request_id = RequestId::new("other-request").unwrap();
    assert!(rig
        .sessions
        .cancel(
            &op.lease.client_id,
            &forged,
            CancelReason::Client,
            &mut rig.backend
        )
        .is_err());
    assert!(rig.backend.controls.is_empty());
    let original = rig.snapshot(&op).error;
    rig.connect("successor", "instance", 2);
    assert!(
        rig.snapshot(&op).execution_stopped,
        "confirmed replacement retires the old owner"
    );
    assert_eq!(
        rig.sessions
            .cancel(
                &op.lease.client_id,
                &op,
                CancelReason::Client,
                &mut rig.backend
            )
            .unwrap_err()
            .code,
        NexusErrorCode::StaleGeneration
    );
    assert!(!rig
        .sessions
        .complete(&op, Completion::Success(json!({"old":true})))
        .unwrap());
    assert_eq!(rig.snapshot(&op).error, original);
    assert!(rig.backend.controls.is_empty());
}

#[test]
fn unknown_after_real_disconnect_can_still_request_identified_stop() {
    let mut rig = Rig::new();
    let lease = rig.connect("disconnected", "instance", 1);
    let op = rig.queue(&lease, "disconnect-control", "rename_symbol", 1);
    rig.dispatch(&op);
    assert!(rig.sessions.disconnected(&lease.instance_id, 1));
    let original = rig.snapshot(&op).error;
    cancel(&mut rig, &op, CancelReason::Client);
    rig.clock.advance(1000);
    rig.sessions
        .expire(&lease.client_id, &op, &mut rig.backend)
        .unwrap();
    assert_eq!(rig.backend.controls.len(), 2);
    assert_eq!(rig.snapshot(&op).error, original);
    assert!(!rig.snapshot(&op).execution_stopped);
}

#[test]
fn deferred_not_sent_releases_execute_without_replay_or_cross_lease_disconnect() {
    let mut rig = Rig::new();
    let a = rig.connect("proof-a", "shared", 1);
    let b = rig.connect("proof-b", "shared", 1);
    let op = rig.queue(&a, "deferred-not-sent", "rename_symbol", 120);
    let mut backend = DeferredBackend::default();
    rig.sessions
        .dispatch(&a.client_id, &op, &mut backend)
        .unwrap();
    let first = backend.attempts.last().unwrap().clone();
    assert!(rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::NotSent(transport_error("writer never sent bytes"))
        )
        .unwrap());
    assert!(!rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::Uncertain(transport_error("duplicate"))
        )
        .unwrap());
    assert_eq!(rig.snapshot(&op).status, OperationStatus::Failed);
    assert!(rig.snapshot(&op).execution_stopped);
    assert_eq!(
        rig.sessions.status(&b.client_id, &b).unwrap().phase,
        SessionPhase::Active
    );
    let next = rig.queue(&b, "proof-next", "rename_symbol", 120);
    rig.sessions
        .dispatch(&b.client_id, &next, &mut backend)
        .unwrap();
    assert!(!rig
        .sessions
        .delivery_failed(&first, DispatchFailure::NotSent(transport_error("late")))
        .unwrap());
    assert_eq!(rig.snapshot(&next).status, OperationStatus::Running);
    assert_eq!(
        backend.queued.len(),
        2,
        "no automatic replay of the first command"
    );
}

#[test]
fn native_completion_wins_over_late_transport_failure_and_forged_attempts() {
    let mut rig = Rig::new();
    let a = rig.connect("complete", "instance", 1);
    let op = rig.queue(&a, "completed-transport", "rename_symbol", 120);
    rig.dispatch(&op);
    let attempt = rig.last_attempt();
    let mut forged = attempt.clone();
    if let DeliveryTarget::Execute { identity } = &mut forged.target {
        identity.task_id = Some(TaskId::new("wrong-task").unwrap());
    }
    assert_eq!(
        rig.sessions
            .delivery_failed(
                &forged,
                DispatchFailure::Uncertain(transport_error("forged"))
            )
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidIdentity
    );
    assert!(rig
        .sessions
        .delivery_status(&ClientId::new("other").unwrap(), &attempt)
        .is_err());
    assert!(rig
        .sessions
        .complete(&op, Completion::Success(json!({"committed":true})))
        .unwrap());
    assert!(!rig
        .sessions
        .delivery_failed(
            &attempt,
            DispatchFailure::Uncertain(transport_error("late failure"))
        )
        .unwrap());
    assert_eq!(rig.snapshot(&op).result, Some(json!({"committed":true})));
}

#[test]
fn submillisecond_budget_expires_before_enqueue_and_triggers_unknown_stop() {
    use std::time::Duration;
    let mut rig = Rig::new();
    let lease = rig.connect("fractional", "instance", 1);
    let queued = rig.queue(&lease, "fractional-queue", "rename_symbol", 1);
    rig.clock.advance_duration(Duration::from_micros(999_001));
    let before = rig.backend.business.len();
    assert_eq!(
        rig.sessions
            .dispatch(&lease.client_id, &queued, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::QueueExpired
    );
    assert_eq!(rig.backend.business.len(), before);
    let op = unknown_operation(&mut rig);
    rig.clock.advance_duration(Duration::from_micros(999_001));
    rig.sessions
        .expire(&op.lease.client_id, &op, &mut rig.backend)
        .unwrap();
    assert!(matches!(
        rig.backend.controls.last(),
        Some(SessionCommand::Cancel {
            reason: CancelReason::Deadline,
            ..
        })
    ));
    assert!(!rig.snapshot(&op).execution_stopped);
}

#[test]
fn zero_generation_and_zero_attempt_are_rejected_without_registering_or_sending() {
    let mut rig = Rig::new();
    let (open, lease) = rig.begin_open("zero-generation", "instance", 0, 120);
    assert_eq!(
        rig.sessions
            .opened(&open, lease.clone(), capabilities())
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidLease
    );
    assert!(rig.sessions.status(&lease.client_id, &lease).is_err());
    let valid = rig.connect("valid", "instance", 1);
    let op = rig.queue(&valid, "wire-attempt", "rename_symbol", 120);
    rig.dispatch(&op);
    let attempt = rig.last_attempt();
    let mut wire = serde_json::to_value(&attempt).unwrap();
    assert_eq!(
        serde_json::from_value::<DeliveryAttempt>(wire.clone()).unwrap(),
        attempt
    );
    wire["sequence"] = json!(0);
    assert!(serde_json::from_value::<DeliveryAttempt>(wire).is_err());
}
