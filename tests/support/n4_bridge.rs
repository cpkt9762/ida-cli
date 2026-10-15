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
        endpoint: NexusEndpoint::new(8),
        callbacks: Mutex::new(()),
        pending: Mutex::new(HashMap::new()),
        leases: Mutex::new(HashMap::new()),
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
