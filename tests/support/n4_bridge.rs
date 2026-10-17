use super::*;
// Faithful baseline subscriber adapter. The reliable inherent method replaces
// the lossy broadcast path without requiring a version-specific test rewrite.
#[allow(dead_code)]
trait BaselineOpenReply {
    fn open_reply(&self, id: &OperationId)
        -> anyhow::Result<tokio::sync::oneshot::Receiver<Value>>;
}
impl BaselineOpenReply for State {
    fn open_reply(
        &self,
        id: &OperationId,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<Value>> {
        let mut events = self.events.subscribe();
        let id = id.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if event["attempt"]["target"]["identity"]["operation_id"] == id.as_str() {
                    let _ = sender.send(event);
                    return;
                }
            }
        });
        Ok(receiver)
    }
}
#[tokio::test(flavor = "current_thread")]
async fn n4_fix_open_delivery_survives_broadcast_lag() {
    let (events, _) = broadcast::channel(8);
    let state = State {
        helper: None,
        bridge_observer: None,
        bridge_exit: Mutex::new(None),
        observer_stop: tokio_util::sync::CancellationToken::new(),
        observation_faults: Mutex::new(HashMap::new()),
        custody_resources: Mutex::new(HashMap::new()),
        custody_replies: Mutex::new(HashMap::new()),
        startups: Mutex::new(HashMap::new()),
        custody_retirements: Mutex::new(HashMap::new()),
        retired_open_resources: Mutex::new(HashSet::new()),
        endpoint: NexusEndpoint::new(8),
        callbacks: Mutex::new(()),
        pending: Mutex::new(HashMap::new()),
        leases: Mutex::new(HashMap::new()),
        release_errors: Mutex::new(HashMap::new()),
        rejected_acquisitions: Mutex::new(Default::default()),
        events,
        open_replies: Mutex::new(HashMap::new()),
        open_reply_capacity: 8,
        failed: std::sync::atomic::AtomicBool::new(false),
        stop: tokio_util::sync::CancellationToken::new(),
    };
    let mut diagnostics = state.events.subscribe();
    let caps = NexusCapabilities {
        runtime: NexusRuntime {
            ida: Version(9, 5, 0),
            python: Version(3, 14, 7),
            nexus: Some(Version(0, 13, 4)),
            domain: Some(Version(0, 5, 1)),
        },
        methods: BTreeMap::new(),
    };
    let endpoint = NexusEndpoint::with_capabilities(8, Ok(caps.clone()));
    let mut lanes = endpoint.take_lanes().unwrap();
    let client = ClientId::new("open-client").unwrap();
    let operation = OperationId::new("open-test").unwrap();
    let reply = state.open_reply(&operation).unwrap();
    let lease = SessionLease {
        client_id: client.clone(),
        lease_id: LeaseId::new("open-lease").unwrap(),
        instance_id: InstanceId::new("open-owner").unwrap(),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    let identity = endpoint.transition(|s, t| {
        let identity = s
            .open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("open-request").unwrap(),
                    None,
                    "open",
                    json!({}),
                )
                .unwrap(),
                OpenSpec {
                    operation_id: operation,
                    path: "/test-copy.i64".into(),
                    options: json!({}),
                },
                t,
            )
            .unwrap();
        assert!(matches!(
            s.opened(&identity, lease.clone(), caps).unwrap(),
            OpenDisposition::Ready(_)
        ));
        // Cancellation can arrive after acquisition but before reply polling.
        assert_eq!(
            s.cancel_open(&client, &identity).unwrap_err().code,
            NexusErrorCode::InvalidTransition
        );
        identity
    });
    let opened = json!({"event":"opened", "lease":lease,
        "attempt":{"target":{"kind":"open","identity":identity}}});
    state.emit(opened.clone());
    for _ in 0..32 {
        state.emit(json!({"event":"other"}));
    }
    assert!(matches!(
        diagnostics.try_recv(),
        Err(broadcast::error::TryRecvError::Lagged(_))
    ));
    let delivered = reply
        .await
        .expect("open lease responsibility must survive Lagged");
    assert_eq!(delivered, opened);
    let owned: SessionLease = serde_json::from_value(delivered["lease"].clone()).unwrap();
    endpoint
        .transition(|s, t| s.release(&client, &owned, t))
        .unwrap();
    let mut delivery = lanes.control.recv().await.unwrap();
    delivery.begin().unwrap();
    let attempt = delivery.attempt.clone();
    delivery.acknowledged().unwrap();
    endpoint.transition(|s, _| {
        s.released(&attempt).unwrap();
        assert_eq!(
            s.status(&client, &owned).unwrap().phase,
            SessionPhase::Released,
            "Lagged/cancelled open must leave no ownerless Active lease"
        );
    });
}

#[tokio::test]
async fn n5_old_delivery_callbacks_preserve_second_attempt_and_terminal_state() {
    let mut caps = NexusCapabilities {
        runtime: NexusRuntime {
            ida: Version(9, 5, 0),
            python: Version(3, 14, 7),
            nexus: Some(Version(0, 13, 4)),
            domain: Some(Version(0, 5, 1)),
        },
        methods: BTreeMap::new(),
    };
    caps.methods
        .insert("batch_decompile".into(), MethodEffect::ReadOnly);
    let endpoint = NexusEndpoint::with_capabilities(8, Ok(caps.clone()));
    let mut lanes = endpoint.take_lanes().unwrap();
    let (events, _) = broadcast::channel(8);
    let state = Arc::new(State {
        helper: None,
        bridge_observer: None,
        bridge_exit: Mutex::new(None),
        observer_stop: tokio_util::sync::CancellationToken::new(),
        observation_faults: Mutex::new(HashMap::new()),
        custody_resources: Mutex::new(HashMap::new()),
        custody_replies: Mutex::new(HashMap::new()),
        startups: Mutex::new(HashMap::new()),
        custody_retirements: Mutex::new(HashMap::new()),
        retired_open_resources: Mutex::new(HashSet::new()),
        endpoint: endpoint.clone(),
        callbacks: Mutex::new(()),
        pending: Mutex::new(HashMap::new()),
        leases: Mutex::new(HashMap::new()),
        release_errors: Mutex::new(HashMap::new()),
        rejected_acquisitions: Mutex::new(Default::default()),
        events,
        open_replies: Mutex::new(HashMap::new()),
        open_reply_capacity: 8,
        failed: std::sync::atomic::AtomicBool::new(false),
        stop: tokio_util::sync::CancellationToken::new(),
    });
    let lease = SessionLease {
        client_id: ClientId::new("late-client").unwrap(),
        lease_id: LeaseId::new("late-lease").unwrap(),
        instance_id: InstanceId::new("late-owner").unwrap(),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    let opened = endpoint.transition(|s, t| {
        s.open(
            &lease.client_id,
            AcceptedRequest::new(
                &SystemClock,
                RequestId::new("late-open").unwrap(),
                None,
                "open",
                json!({}),
            )
            .unwrap(),
            OpenSpec {
                operation_id: OperationId::new("late-open-op").unwrap(),
                path: "/copy.i64".into(),
                options: json!({}),
            },
            t,
        )
        .unwrap()
    });
    let mut open = lanes.business.recv().await.unwrap();
    open.begin().unwrap();
    open.acknowledged().unwrap();
    let op = endpoint.transition(|s, _| {
        assert!(matches!(
            s.opened(&opened, lease.clone(), caps).unwrap(),
            OpenDisposition::Ready(_)
        ));
        s.queue(
            &lease.client_id,
            &lease,
            AcceptedRequest::new(
                &SystemClock,
                RequestId::new("late-batch").unwrap(),
                None,
                "batch_decompile",
                json!({"addresses":[]}),
            )
            .unwrap(),
            OperationId::new("late-batch-op").unwrap(),
        )
        .unwrap()
    });
    let (socket, _peer) = UnixStream::pair().unwrap();
    let (_, writer) = socket.into_split();
    let writer = Arc::new(AsyncMutex::new(writer));
    let mut attempts = Vec::new();
    for index in 0..2 {
        endpoint
            .transition(|s, t| s.dispatch(&lease.client_id, &op, t))
            .unwrap();
        if index == 1 {
            assert!(state.pending.lock().unwrap().is_empty());
            for event in ["completed", "yielded", "uncertain", "stopped"] {
                receiver::receive_event(json!({"event":event,"attempt":attempts[0],"result":"old",
                    "checkpoint":{"index":999},"error":{"code":"disconnected","message":"dispatch gap"}}), &writer, &state, false)
                    .await.expect("old callback in real dispatch/pending gap must be harmless");
            }
            assert_eq!(
                endpoint
                    .transition(|s, _| s.operation_status(&lease.client_id, &op))
                    .unwrap()
                    .status,
                OperationStatus::Running
            );
        }
        let mut delivery = lanes.business.recv().await.unwrap();
        delivery.begin().unwrap();
        let attempt = delivery.attempt.clone();
        delivery.acknowledged().unwrap();
        state.pending.lock().unwrap().insert(
            attempt.sequence.get(),
            Pending {
                attempt: attempt.clone(),
                granted: true,
                uncertain: false,
                stopped: false,
                open_disconnected: None,
            },
        );
        attempts.push(attempt.clone());
        if index == 0 {
            receiver::receive_event(
                json!({"event":"yielded","attempt":attempt,"checkpoint":{"index":1}}),
                &writer,
                &state,
                false,
            )
            .await
            .unwrap();
        }
    }
    for terminal in [false, true] {
        if terminal {
            receiver::receive_event(
                json!({"event":"completed","attempt":attempts[1],"result":"second"}),
                &writer,
                &state,
                false,
            )
            .await
            .unwrap();
        }
        for event in ["completed", "yielded", "uncertain", "stopped"] {
            receiver::receive_event(json!({"event":event,"attempt":attempts[0],"result":"old",
                "checkpoint":{"index":999},"error":{"code":"disconnected","message":"late old callback"}}),&writer,&state,false).await.expect("old callbacks must be harmless, including to the physical channel");
            let snapshot = endpoint
                .transition(|s, _| s.operation_status(&lease.client_id, &op))
                .unwrap();
            assert_eq!(
                snapshot.status,
                if terminal {
                    OperationStatus::Succeeded
                } else {
                    OperationStatus::Running
                }
            );
            assert_eq!(snapshot.execution_stopped, terminal);
            if terminal {
                assert_eq!(snapshot.result, Some(json!("second")));
            }
        }
    }
}
