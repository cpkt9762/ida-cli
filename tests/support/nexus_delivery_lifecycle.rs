use super::failures::transport_error;
use super::support::*;
use ida_mcp::nexus::*;
use serde_json::json;

#[test]
fn deferred_open_uncertainty_and_open_failed_both_track_late_handle_for_cleanup() {
    for uncertain in [false, true] {
        let mut rig = Rig::new();
        let (open, lease) = rig.begin_open("late-failure", "instance", 1, 120);
        let attempt = rig.last_attempt();
        if uncertain {
            assert!(rig
                .sessions
                .delivery_failed(
                    &attempt,
                    DispatchFailure::Uncertain(transport_error("lost open response"))
                )
                .unwrap());
        } else {
            rig.sessions.open_failed(&open).unwrap();
        }
        assert!(matches!(
            rig.sessions
                .opened(&open, lease.clone(), capabilities())
                .unwrap(),
            OpenDisposition::ReleaseRequired { .. }
        ));
        assert_eq!(
            rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
            SessionPhase::ReleaseRequired
        );
        assert!(!rig
            .sessions
            .delivery_failed(
                &attempt,
                DispatchFailure::NotSent(transport_error("late contradictory failure"))
            )
            .unwrap());
        assert!(
            rig.sessions.open_failed(&open).is_err(),
            "cannot discard a tracked acquisition"
        );
        rig.sessions
            .release(&lease.client_id, &lease, &mut rig.backend)
            .unwrap();
        assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
        assert_eq!(
            rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
            SessionPhase::Released
        );
    }
}

#[test]
fn deferred_open_not_sent_tombstone_accepts_only_owned_late_acquisition_for_cleanup() {
    let mut rig = Rig::new();
    let (open, lease) = rig.begin_open("not-sent-open", "instance", 1, 120);
    assert!(rig
        .sessions
        .delivery_failed(
            &rig.last_attempt(),
            DispatchFailure::NotSent(transport_error("not sent"))
        )
        .unwrap());
    let mut wrong = open.clone();
    wrong.request_id = RequestId::new("forged-open").unwrap();
    assert!(rig
        .sessions
        .opened(&wrong, lease.clone(), capabilities())
        .is_err());
    assert!(
        rig.sessions.status(&lease.client_id, &lease).is_err(),
        "unregistered handle remains adapter cleanup responsibility"
    );
    assert!(matches!(
        rig.sessions
            .opened(&open, lease.clone(), capabilities())
            .unwrap(),
        OpenDisposition::ReleaseRequired { .. }
    ));
    assert!(
        rig.sessions
            .opened(&open, lease.clone(), capabilities())
            .is_err(),
        "duplicate acquisition cannot overwrite the tracked handle"
    );
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::ReleaseRequired
    );
}

#[test]
fn late_open_release_not_sent_is_retryable_and_old_confirmation_isolated() {
    let mut rig = Rig::new();
    let (open, lease) = rig.begin_open("release-required", "instance", 1, 1);
    rig.clock.advance(1000);
    assert!(matches!(
        rig.sessions
            .opened(&open, lease.clone(), capabilities())
            .unwrap(),
        OpenDisposition::ReleaseRequired { .. }
    ));
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
    let first = rig.last_attempt();
    assert!(rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::NotSent(transport_error("release writer failed"))
        )
        .unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::ReleaseRequired
    );
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
    let second = rig.last_attempt();
    assert_ne!(first.sequence, second.sequence);
    assert!(!rig.sessions.released(&first).unwrap());
    assert!(!rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::Uncertain(transport_error("old release failure"))
        )
        .unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::ReleaseRequested
    );
    assert!(rig.sessions.released(&second).unwrap());
    assert!(
        !rig.sessions.released(&second).unwrap(),
        "duplicate confirmation is inert"
    );
    assert!(!rig
        .sessions
        .delivery_failed(
            &second,
            DispatchFailure::NotSent(transport_error("after release"))
        )
        .unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Released
    );
}

#[test]
fn uncertain_release_and_real_disconnect_retain_pending_attempt_until_late_confirmation() {
    let mut rig = Rig::new();
    let a = rig.connect("release-a", "shared", 1);
    let b = rig.connect("release-b", "shared", 1);
    rig.sessions
        .release(&a.client_id, &a, &mut rig.backend)
        .unwrap();
    let attempt = rig.last_attempt();
    assert!(rig
        .sessions
        .delivery_failed(
            &attempt,
            DispatchFailure::Uncertain(transport_error("release HTTP lost"))
        )
        .unwrap());
    assert_eq!(
        rig.sessions.status(&a.client_id, &a).unwrap().phase,
        SessionPhase::ReleaseRequested
    );
    assert_eq!(
        rig.sessions.status(&b.client_id, &b).unwrap().phase,
        SessionPhase::Active
    );
    assert!(rig.sessions.disconnected(&a.instance_id, 1));
    let count = rig.backend.controls.len();
    rig.sessions
        .release(&a.client_id, &a, &mut rig.backend)
        .unwrap();
    assert_eq!(
        rig.backend.controls.len(),
        count,
        "uncertain release is not replayed on disconnect"
    );
    assert!(rig.sessions.released(&attempt).unwrap());
    assert_eq!(
        rig.sessions.status(&a.client_id, &a).unwrap().phase,
        SessionPhase::Released
    );
    assert_eq!(
        rig.sessions.status(&b.client_id, &b).unwrap().phase,
        SessionPhase::Disconnected
    );
}

#[test]
fn release_not_sent_after_disconnect_cannot_restore_active_or_fake_confirmation() {
    let mut rig = Rig::new();
    let lease = rig.connect("release-disconnected", "instance", 1);
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
    let first = rig.last_attempt();
    assert!(rig.sessions.disconnected(&lease.instance_id, 1));
    assert!(rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::NotSent(transport_error("not sent before disconnect"))
        )
        .unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Disconnected
    );
    assert!(!rig.sessions.released(&first).unwrap());
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
    assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
}

fn shutdown(rig: &mut Rig, lease: &SessionLease, name: &str) -> DeliveryAttempt {
    rig.sessions
        .shutdown(
            &lease.client_id,
            lease,
            ShutdownSpec {
                request: accepted(&rig.clock, name, "shutdown", json!({})),
                operation_id: OperationId::new(name).unwrap(),
                save: true,
            },
            &mut rig.backend,
        )
        .unwrap();
    rig.last_attempt()
}

#[test]
fn deferred_shutdown_not_sent_and_uncertain_never_confuse_successor_attempts() {
    let mut rig = Rig::new();
    let lease = rig.connect("shutdown", "instance", 1);
    let first = shutdown(&mut rig, &lease, "close-first");
    assert!(rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::NotSent(transport_error("shutdown not sent"))
        )
        .unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Active
    );
    let second = shutdown(&mut rig, &lease, "close-second");
    assert!(!rig.sessions.shutdown_completed(&first).unwrap());
    assert!(!rig.sessions.shutdown_rejected(&first).unwrap());
    assert!(!rig
        .sessions
        .delivery_failed(
            &first,
            DispatchFailure::Uncertain(transport_error("old shutdown loss"))
        )
        .unwrap());
    assert!(rig
        .sessions
        .delivery_failed(
            &second,
            DispatchFailure::Uncertain(transport_error("shutdown response lost"))
        )
        .unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::ShutdownRequested
    );
    assert!(rig
        .sessions
        .queue(
            &lease.client_id,
            &lease,
            accepted(
                &rig.clock,
                "after-uncertain-close",
                "rename_symbol",
                json!({})
            ),
            OperationId::new("after-uncertain-close").unwrap()
        )
        .is_err());
    assert!(
        rig.sessions.shutdown_rejected(&second).unwrap(),
        "definitive public API rejection permits new explicit work"
    );
    let third = shutdown(&mut rig, &lease, "close-third");
    assert!(!rig.sessions.shutdown_completed(&second).unwrap());
    assert!(rig.sessions.shutdown_completed(&third).unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Released
    );
}

#[test]
fn shutdown_failure_and_late_rejection_cannot_undo_real_disconnect() {
    let mut rig = Rig::new();
    let lease = rig.connect("shutdown-disconnect", "instance", 1);
    let attempt = shutdown(&mut rig, &lease, "close-disconnect");
    assert!(rig.sessions.disconnected(&lease.instance_id, 1));
    assert!(rig.sessions.shutdown_rejected(&attempt).unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Disconnected
    );
    assert!(!rig
        .sessions
        .delivery_failed(&attempt, DispatchFailure::NotSent(transport_error("stale")))
        .unwrap());
}

#[test]
fn pending_shutdown_blocks_release_after_real_disconnect() {
    let mut rig = Rig::new();
    let lease = rig.connect("shutdown-retained", "instance", 1);
    let attempt = shutdown(&mut rig, &lease, "shutdown-retained");
    assert!(rig.sessions.disconnected(&lease.instance_id, 1));
    let sent = rig.backend.controls.len();
    assert_eq!(
        rig.sessions
            .release(&lease.client_id, &lease, &mut rig.backend)
            .unwrap_err()
            .code,
        NexusErrorCode::CancelPending
    );
    assert_eq!(rig.backend.controls.len(), sent);
    assert!(rig.sessions.shutdown_rejected(&attempt).unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Disconnected
    );
    rig.sessions
        .release(&lease.client_id, &lease, &mut rig.backend)
        .unwrap();
    assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
}

#[test]
fn pending_shutdown_rejects_late_open_after_real_disconnect() {
    let mut rig = Rig::new();
    let lease = rig.connect("shutdown-open", "instance", 1);
    let attempt = shutdown(&mut rig, &lease, "shutdown-open");
    assert!(rig.sessions.disconnected(&lease.instance_id, 1));
    let (open, late) = rig.begin_open("late-during-disconnect", "instance", 1, 120);
    assert!(matches!(
        rig.sessions
            .opened(&open, late.clone(), capabilities())
            .unwrap(),
        OpenDisposition::ReleaseRequired {
            error: NexusError {
                code: NexusErrorCode::Busy,
                ..
            },
            ..
        }
    ));
    assert_eq!(
        rig.sessions.status(&late.client_id, &late).unwrap().phase,
        SessionPhase::ReleaseRequired
    );
    assert!(rig
        .sessions
        .delivery_failed(
            &attempt,
            DispatchFailure::NotSent(transport_error("shutdown never sent"))
        )
        .unwrap());
    assert_eq!(
        rig.sessions.status(&lease.client_id, &lease).unwrap().phase,
        SessionPhase::Disconnected
    );
    rig.sessions
        .release(&late.client_id, &late, &mut rig.backend)
        .unwrap();
    assert!(rig.sessions.released(&rig.last_attempt()).unwrap());
}
