use super::*;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

// These independent fixtures share the process-wide two-slot Encode pool.
// Admit one Rig at a time, while keeping every scenario's A/B concurrency.
// This is synchronization before N1 enqueue, never a retry after Busy/NotSent.
static FIXTURE_GATE: AsyncMutex<()> = AsyncMutex::const_new(());

struct Peer {
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    adapter_writer: Writer,
    state: Arc<State>,
    opening: Option<OpenIdentity>,
}
impl Peer {
    async fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).expect("encode external bridge input");
        bytes.push(b'\n');
        self.write
            .write_all(&bytes)
            .await
            .expect("write external bridge input");
    }
    async fn read_frame(&mut self, stage: &str) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(2), receiver::read_line(&mut self.read))
            .await
            .unwrap_or_else(|_| {
                let progress = self.opening.as_ref().map(|identity| {
                    self.state
                        .endpoint
                        .transition(|s, _| s.open_progress(&identity.client_id, identity))
                });
                panic!("receiver fixture await timed out: {stage}; open_progress={progress:?}")
            })
            .expect("read production frame")
            .expect("frame before EOF")
    }
    async fn grant(&mut self) -> DeliveryAttempt {
        let frame = self.read_frame("delivery frame").await;
        let frame: Value = serde_json::from_slice(&frame).expect("production frame JSON");
        let attempt =
            serde_json::from_value(frame["attempt"].clone()).expect("exact production attempt");
        self.send(json!({"event":"dispatch_ready","frame":frame}))
            .await;
        let grant = self.read_frame("dispatch grant").await;
        let grant: Value = serde_json::from_slice(&grant).expect("grant JSON");
        assert_eq!(grant["grant"], true);
        attempt
    }
}
struct Rig {
    state: Arc<State>,
    business: Peer,
    control: Peer,
    events: broadcast::Receiver<Value>,
    caps: NexusCapabilities,
    _fixture: tokio::sync::MutexGuard<'static, ()>,
}
impl Rig {
    async fn new() -> Self {
        let fixture = tokio::time::timeout(Duration::from_secs(2), FIXTURE_GATE.lock())
            .await
            .expect("receiver fixture admission barrier");
        let caps = NexusCapabilities {
            runtime: NexusRuntime {
                ida: Version(9, 5, 0),
                python: Version(3, 14, 7),
                nexus: Some(Version(0, 13, 4)),
                domain: Some(Version(0, 5, 1)),
            },
            methods: BTreeMap::from([("execute_python".into(), MethodEffect::MayWrite)]),
        };
        let endpoint = NexusEndpoint::with_capabilities(16, Ok(caps.clone()));
        let lanes = endpoint
            .take_lanes()
            .expect("take actual N1 transport lanes");
        let (events, receive) = broadcast::channel(512);
        let state = Arc::new(State {
            helper: None,
            cache_root: std::env::temp_dir().join("unused-no-custody-root"),
            bridge_observer: None,
            bridge_exit: Mutex::new(None),
            observer_stop: tokio_util::sync::CancellationToken::new(),
            observation_faults: Mutex::new(HashMap::new()),
            custody_resources: Mutex::new(HashMap::new()),
            custody_replies: Mutex::new(HashMap::new()),
            startups: Mutex::new(HashMap::new()),
            custody_retirements: Mutex::new(HashMap::new()),
            retired_open_resources: Mutex::new(HashSet::new()),
            endpoint,
            callbacks: Mutex::new(()),
            pending: Mutex::new(HashMap::new()),
            leases: Mutex::new(HashMap::new()),
            release_errors: Mutex::new(HashMap::new()),
            release_facts: Mutex::new(HashMap::new()),
            owner_proofs: Mutex::new(HashMap::new()),
            startup_proofs: Mutex::new(HashMap::new()),
            rejected_acquisitions: Mutex::new(Default::default()),
            events,
            open_replies: Mutex::new(HashMap::new()),
            open_reply_capacity: 16,
            failed: std::sync::atomic::AtomicBool::new(false),
            stop: tokio_util::sync::CancellationToken::new(),
        });
        fn lane(
            state: Arc<State>,
            deliveries: tokio::sync::mpsc::Receiver<Delivery>,
            control: bool,
        ) -> Peer {
            let (stream, peer) = UnixStream::pair().expect("private physical stream pair");
            let writer = start_channel(stream, state.clone(), control);
            tokio::spawn(pump(deliveries, writer.clone(), state.clone()));
            let (read, write) = peer.into_split();
            Peer {
                read: BufReader::new(read),
                write,
                adapter_writer: writer,
                state,
                opening: None,
            }
        }
        let business = lane(state.clone(), lanes.business, false);
        let control = lane(state.clone(), lanes.control, true);
        Self {
            state,
            business,
            control,
            events: receive,
            caps,
            _fixture: fixture,
        }
    }
    async fn event(&mut self, name: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let event = self.events.recv().await.expect("receiver event");
                assert_ne!(
                    event["event"], "bridge_disconnected",
                    "logical event disconnected shared bridge: {event}"
                );
                if event["event"] == name {
                    return event;
                }
            }
        })
        .await
        .expect("event barrier")
    }
    async fn open(&mut self, name: &str) -> (SessionLease, DeliveryAttempt) {
        let identity = self
            .state
            .endpoint
            .transition(|s, t| {
                s.open(
                    &ClientId::new(name).expect("client"),
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new(name).expect("request"),
                        None,
                        "open",
                        json!({}),
                    )
                    .expect("accept open"),
                    OpenSpec {
                        operation_id: OperationId::new(name).expect("operation"),
                        path: "/private/r5-replay.i64".into(),
                        options: json!({}),
                    },
                    t,
                )
            })
            .expect("real N1 open");
        self.business.opening = Some(identity.clone());
        let attempt = self.business.grant().await;
        let lease = SessionLease {
            client_id: identity.client_id.clone(),
            lease_id: LeaseId::new(name).expect("lease"),
            instance_id: InstanceId::new("owner").expect("owner"),
            generation: 1,
            owner: OwnerKind::Managed,
        };
        self.business
            .send(
                json!({"event":"opened", "attempt":attempt,"lease":lease,"capabilities":self.caps}),
            )
            .await;
        self.event("opened").await;
        (lease, attempt)
    }
    async fn release(&mut self, lease: &SessionLease) -> DeliveryAttempt {
        self.state
            .endpoint
            .transition(|s, t| s.release(&lease.client_id, lease, t))
            .expect("N1 release");
        self.control.grant().await
    }
    async fn b_control(&mut self) {
        send(
            &self.control.adapter_writer,
            &json!({"local_status":"b-control"}),
        )
        .await
        .expect("production control write");
        let frame = self.control.read_frame("control barrier").await;
        let frame: Value = serde_json::from_slice(&frame).expect("control JSON");
        assert_eq!(frame["local_status"], "b-control");
        self.control
            .send(json!({"event":"local_status","id":"b-control"}))
            .await;
        self.event("local_status").await;
    }
    async fn b_query(&mut self, lease: &SessionLease) {
        let operation = self
            .state
            .endpoint
            .transition(|s, t| {
                let operation = s.queue(
                    &lease.client_id,
                    lease,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new("b-query").expect("request"),
                        None,
                        "execute_python",
                        json!({"code":"result = 42"}),
                    )
                    .expect("accept query"),
                    OperationId::new("b-query").expect("operation"),
                )?;
                s.dispatch(&lease.client_id, &operation, t)?;
                Ok::<_, NexusError>(operation)
            })
            .expect("B query remains dispatchable");
        let attempt = self.business.grant().await;
        self.business
            .send(json!({"event":"completed","attempt":attempt,"result":42}))
            .await;
        self.event("completed").await;
        let result = self
            .state
            .endpoint
            .transition(|s, _| s.operation_status(&lease.client_id, &operation))
            .expect("B authoritative result");
        assert_eq!(result.result, Some(json!(42)));
        assert_eq!(result.status, OperationStatus::Succeeded);
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        self.state.stop.cancel();
    }
}

#[tokio::test]
async fn r5_original_189_full_sequences_through_production_reader() {
    let input: Value = serde_json::from_str(include_str!("../fixtures/nexus_r5_wire.json"))
        .expect("frozen full legacy matrix");
    let mut records = Vec::new();
    for row in input["rows"].as_array().expect("rows") {
        let mut rig = Rig::new().await;
        let (a, _) = rig.open("a").await;
        let (b, _) = rig.open("b").await;
        let attempt = rig.release(&a).await;
        let wire = &input["wires"][row["wire"].as_u64().expect("wire index") as usize];
        let mut outcomes = Vec::new();
        for index in wire.as_array().expect("wire sequence") {
            let mut event = input["events"][index.as_u64().expect("event index") as usize].clone();
            event["attempt"] = json!(attempt);
            rig.control.send(event.clone()).await;
            // The same reader emits either the accepted event or an explicit rejection.
            let result = tokio::time::timeout(Duration::from_secs(2), rig.events.recv())
                .await
                .expect("replay event")
                .expect("event notification");
            assert_ne!(result["event"], "bridge_disconnected");
            assert!(
                result["event"] == event["event"] || result["event"] == "event_rejected",
                "{result}"
            );
            outcomes.push(json!({"input":event["event"],"outcome":result}));
        }
        rig.b_control().await;
        let a_status = rig
            .state
            .endpoint
            .transition(|s, _| s.status(&a.client_id, &a))
            .expect("A state");
        let b_status = rig
            .state
            .endpoint
            .transition(|s, _| s.status(&b.client_id, &b))
            .expect("B state");
        assert_eq!(b_status.phase, SessionPhase::Active);
        rig.b_query(&b).await;
        records.push(json!({"case":row,"events":outcomes,"a":a_status,"b":b_status,"b_control":true,"b_query":true,"scope":"replay-robustness-only"}));
    }
    assert_eq!(records.len(), 189);
    assert_eq!(
        records
            .iter()
            .filter(|r| r["case"]["historically_fatal"] == true)
            .count(),
        56
    );
    if let Some(root) = std::env::var_os("R5_ROOT") {
        std::fs::write(
            PathBuf::from(root).join("wire-replay.json"),
            serde_json::to_vec_pretty(&records).expect("encode full case evidence"),
        )
        .expect("write replay evidence");
    }
}

#[tokio::test]
async fn r5_bad_lines_identity_sideband_and_real_eof() {
    let mut rig = Rig::new().await;
    let (a, _) = rig.open("a").await;
    let (b, _) = rig.open("b").await;
    let attempt = rig.release(&a).await;
    rig.control
        .write
        .write_all(b"{bad JSON}\n")
        .await
        .expect("complete bad line");
    rig.event("event_rejected").await;
    for event in [
        json!({"event":"future_unknown","attempt":attempt}),
        json!({"event":"release_observation","schema":2,"release_protocol":1,"attempt":attempt}),
        json!({"event":"released","attempt":{"sequence":attempt.sequence,"target":{"kind":"release","lease":b}}}),
        json!({"event":"disconnected","lease":{"client_id":"a","lease_id":"a","instance_id":"wrong","generation":1,"owner":"managed"}}),
    ] {
        rig.control.send(event).await;
        rig.event("event_rejected").await;
    }
    rig.control.send(json!({"event":"release_observation","schema":1,"release_protocol":1,"attempt":attempt})).await;
    rig.event("release_observation").await;
    assert!(rig
        .state
        .pending
        .lock()
        .expect("pending")
        .contains_key(&attempt.sequence.get()));
    assert_ne!(
        rig.state
            .endpoint
            .transition(|s, _| s.status(&a.client_id, &a))
            .expect("A retained")
            .phase,
        SessionPhase::Released
    );
    rig.b_query(&b).await;
    rig.control.write.shutdown().await.expect("physical EOF");
    tokio::time::timeout(Duration::from_secs(2), rig.state.stop.cancelled())
        .await
        .expect("true EOF must fail bridge");
    assert_eq!(
        rig.state
            .endpoint
            .transition(|s, _| s.status(&b.client_id, &b))
            .expect("B physical disconnect")
            .phase,
        SessionPhase::Disconnected
    );
}

#[test]
fn r5_home_matches_python_table() {
    let cases: Value = serde_json::from_str(include_str!("../fixtures/nexus_r5_home.json"))
        .expect("shared home table");
    for case in cases.as_array().expect("cases") {
        let environment = &case["environment"];
        let path = crate::idb_store::ida_home_from(
            environment["IDA_CLI_HOME"]
                .as_str()
                .map(std::ffi::OsStr::new),
            environment["HOME"].as_str().map(std::ffi::OsStr::new),
        );
        assert_eq!(
            std::path::Path::new(case["cwd"].as_str().expect("cwd")).join(path),
            PathBuf::from(case["expected"].as_str().expect("expected"))
        );
    }
}

#[tokio::test]
async fn r5_late_acquisition_and_stop_remain_n1_responsibilities() {
    let mut rig = Rig::new().await;
    let (a, _) = rig.open("a").await;
    // A failed command no longer has pending, but N1's opening tombstone does.
    let client = ClientId::new("late").expect("client");
    let identity = rig
        .state
        .endpoint
        .transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("late").expect("request"),
                    None,
                    "open",
                    json!({}),
                )
                .expect("request accepted"),
                OpenSpec {
                    operation_id: OperationId::new("late").expect("operation"),
                    path: "/private/late.i64".into(),
                    options: json!({}),
                },
                t,
            )
        })
        .expect("open");
    let attempt = rig.business.grant().await;
    rig.business.send(json!({"event":"not_sent","attempt":attempt,"error":{"code":"operation_failed","message":"external input failed"}})).await;
    rig.event("not_sent").await;
    let late = SessionLease {
        client_id: client.clone(),
        lease_id: LeaseId::new("late").expect("lease"),
        instance_id: InstanceId::new("other-owner").expect("owner"),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    rig.business
        .send(json!({"event":"opened","attempt":attempt,"lease":late,"capabilities":rig.caps}))
        .await;
    rig.event("opened").await;
    assert_eq!(
        rig.state
            .endpoint
            .transition(|s, _| s.status(&client, &late))
            .expect("late tracked")
            .phase,
        SessionPhase::ReleaseRequired
    );
    assert_eq!(
        rig.state
            .endpoint
            .transition(|s, _| s.open_progress(&client, &identity))
            .expect("N1 original failure")
            .0,
        Some(late.clone())
    );
    rig.business
        .send(json!({"event":"opened","attempt":attempt,"lease":late,"capabilities":rig.caps}))
        .await;
    rig.event("event_rejected").await;
    assert!(
        rig.state
            .rejected_acquisitions
            .lock()
            .expect("retained")
            .is_empty(),
        "duplicate registered resource creates no orphan"
    );
    // Unknown resource is explicitly retained and blocks further acquisition, not B's work.
    let unknown = SessionLease {
        lease_id: LeaseId::new("unknown-resource").expect("lease"),
        ..late
    };
    rig.business
        .send(json!({"event":"opened","attempt":attempt,"lease":unknown,"capabilities":rig.caps}))
        .await;
    let rejected = rig.event("event_rejected").await;
    assert_eq!(rejected["resource_retained_by_bridge"], true);
    assert_eq!(
        rig.state
            .rejected_acquisitions
            .lock()
            .expect("retained")
            .get(&unknown),
        Some(&unknown)
    );
    for generation in 2..=20 {
        let conflict = SessionLease {
            generation,
            ..unknown.clone()
        };
        rig.business.send(json!({"event":"opened","attempt":attempt,"lease":conflict,"capabilities":rig.caps})).await;
        let rejected = rig.event("event_rejected").await;
        assert_eq!(
            rejected["lease"],
            json!(conflict),
            "every identity remains explicit even at capacity"
        );
        assert_eq!(rejected["resource_retained_by_bridge"], true);
    }
    assert_eq!(
        rig.state
            .rejected_acquisitions
            .lock()
            .expect("bounded latch")
            .len(),
        rig.state.open_reply_capacity
    );
    let denied_client = ClientId::new("blocked-acquisition").expect("client");
    rig.state
        .endpoint
        .transition(|s, t| {
            s.open(
                &denied_client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("blocked").expect("request"),
                    None,
                    "open",
                    json!({}),
                )
                .expect("accepted"),
                OpenSpec {
                    operation_id: OperationId::new("blocked").expect("operation"),
                    path: "/private/blocked.i64".into(),
                    options: json!({}),
                },
                t,
            )
        })
        .expect("queue open");
    let frame = rig.business.read_frame("blocked acquisition frame").await;
    let frame: Value = serde_json::from_slice(&frame).expect("JSON frame");
    rig.business
        .send(json!({"event":"dispatch_ready","frame":frame}))
        .await;
    let grant = rig.business.read_frame("denied acquisition grant").await;
    assert_eq!(
        serde_json::from_slice::<Value>(&grant).expect("grant JSON")["grant"],
        false
    );
    rig.b_control().await;
    rig.b_query(&a).await;
}

#[tokio::test]
async fn r5_frame_limits_and_partial_eof_are_connection_errors() {
    for bytes in [
        b"partial".to_vec(),
        vec![b'x'; super::super::transport::MAX_FRAME_BYTES + 1],
    ] {
        let mut reader = BufReader::new(bytes.as_slice());
        assert!(receiver::read_line(&mut reader).await.is_err());
    }
    let mut rig = Rig::new().await;
    let (a, _) = rig.open("a").await;
    rig.control
        .write
        .write_all(b"{partial")
        .await
        .expect("partial frame");
    rig.control.write.shutdown().await.expect("EOF");
    tokio::time::timeout(Duration::from_secs(2), rig.state.stop.cancelled())
        .await
        .expect("partial EOF disconnects");
    assert_eq!(
        rig.state
            .endpoint
            .transition(|s, _| s.status(&a.client_id, &a))
            .expect("status")
            .phase,
        SessionPhase::Disconnected
    );
}

#[tokio::test]
async fn r5_late_stop_after_command_cache_removal_keeps_unknown_outcome() {
    let mut rig = Rig::new().await;
    let (lease, _) = rig.open("late-stop").await;
    let operation = rig
        .state
        .endpoint
        .transition(|s, t| {
            let identity = s.queue(
                &lease.client_id,
                &lease,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("stop").expect("request"),
                    None,
                    "execute_python",
                    json!({}),
                )
                .expect("accept"),
                OperationId::new("stop").expect("operation"),
            )?;
            s.dispatch(&lease.client_id, &identity, t)?;
            Ok::<_, NexusError>(identity)
        })
        .expect("queue real operation");
    let attempt = rig.business.grant().await;
    rig.business
        .send(json!({"event":"uncertain","attempt":attempt,
        "error":{"code":"operation_failed","message":"lost actual response"}}))
        .await;
    rig.event("uncertain").await;
    let before = rig
        .state
        .endpoint
        .transition(|s, _| s.operation_status(&lease.client_id, &operation))
        .expect("N1 outcome");
    assert_eq!(before.status, OperationStatus::UnknownOutcome);
    assert!(!before.execution_stopped);
    // Evict only the adapter command cache; N1 remains the unmodified authority.
    rig.state
        .pending
        .lock()
        .expect("command cache")
        .remove(&attempt.sequence.get());
    rig.control
        .send(json!({"event":"stopped","attempt":attempt}))
        .await;
    rig.event("stopped").await;
    let after = rig
        .state
        .endpoint
        .transition(|s, _| s.operation_status(&lease.client_id, &operation))
        .expect("N1 retained outcome");
    assert_eq!(after.status, OperationStatus::UnknownOutcome);
    assert!(after.execution_stopped);
    assert_eq!(after.result, None);
    rig.control
        .send(json!({"event":"stopped","attempt":attempt}))
        .await;
    rig.event("event_rejected").await;
    rig.b_query(&lease).await;
}

#[tokio::test]
async fn r5_actual_grant_write_failure_remains_io_error() {
    let mut rig = Rig::new().await;
    let (lease, _) = rig.open("write-failure").await;
    rig.state
        .endpoint
        .transition(|s, t| s.release(&lease.client_id, &lease, t))
        .expect("release queued");
    let frame = rig.control.read_frame("grant write failure frame").await;
    let frame: Value = serde_json::from_slice(&frame).expect("frame JSON");
    let (stream, peer) = UnixStream::pair().expect("real failure stream");
    let (_, write) = stream.into_split();
    let writer = Arc::new(AsyncMutex::new(write));
    drop(peer); // An actually closed peer makes the production grant write fail.
    let result = receiver::receive_event(
        json!({"event":"dispatch_ready","frame":frame}),
        &writer,
        &rig.state,
        true,
    )
    .await;
    assert!(
        result.is_err(),
        "a physical write error must never become a logical drop: {result:?}"
    );
}

#[tokio::test]
async fn r2_duplicate_release_failure_cannot_replace_original_diagnostics() {
    let mut rig = Rig::new().await;
    let (lease, _) = rig.open("release-history").await;
    let attempt = rig.release(&lease).await;
    let original = json!({"event":"uncertain", "attempt":attempt,
        "outcome":{"lease_released":false,"ack_kind":null,"cause":"original lost ACK"},
        "error":{"code":"unknown_outcome","message":"original cause"}});
    rig.control.send(original.clone()).await;
    rig.event("uncertain").await;
    let before = rig.state.release_facts.lock().expect("facts").clone();
    let mut duplicate = original;
    duplicate["outcome"]["cause"] = json!("replacement");
    duplicate["error"]["message"] = json!("replacement");
    rig.control.send(duplicate).await;
    rig.event("event_rejected").await;
    assert_eq!(
        *rig.state.release_facts.lock().expect("facts"),
        before,
        "duplicate terminal replaced immutable original diagnosis"
    );
    rig.control
        .send(json!({"event":"released","attempt":attempt}))
        .await;
    rig.event("event_rejected").await;
    assert_eq!(
        *rig.state.release_facts.lock().expect("facts"),
        before,
        "a second terminal replaced the original unknown detach outcome"
    );
    let history = rig
        .state
        .endpoint
        .transition(|s, _| s.status(&lease.client_id, &lease))
        .expect("original delivery");
    assert_eq!(
        history
            .control_delivery
            .expect("delivery")
            .error
            .expect("cause")
            .cause
            .expect("original cause")
            .message,
        "original cause"
    );
}

// These are actual Rust/N1/control-reader contract tests with supplied terminal
// fields. The production guard + SDK/helper/writer case lives in nexus_r3b_fix4.
#[tokio::test]
async fn rr3_accepted_terminal_keeps_guard_across_empty_observations_and_typed_errors() {
    let mut rig = Rig::new().await;
    let (lease, _) = rig.open("rr3-fields").await;
    let error = NexusError::caused_by(
        NexusErrorCode::OperationFailed,
        "original command cause",
        NexusError::new(NexusErrorCode::ExecutionTimeout, "original nested cause"),
    );
    let observation_error =
        json!({"code":"operation_failed","message":"independent writer failure"});
    let mut evidence = Vec::new();
    for guard in [
        json!("known save refusal"),
        json!(""),
        Value::Null,
        json!("second save refusal"),
    ] {
        let attempt = rig.release(&lease).await;
        rig.control
            .send(json!({"event":"not_sent","attempt":attempt,"error":error,
            "save_guard_error":guard,"observation_error":observation_error,
            "outcome":{"stage":"preflight","detach_called":false,"save_guard_error":guard}}))
            .await;
        rig.event("not_sent").await;
        let status = rig
            .state
            .endpoint
            .transition(|s, _| s.status(&lease.client_id, &lease))
            .expect("exact N1 status");
        let delivery = status.control_delivery.expect("original delivery");
        assert_eq!(delivery.attempt, attempt);
        assert_eq!(delivery.state, DeliveryState::NotSent);
        assert_eq!(delivery.error, Some(error.clone()));
        let saved =
            rig.state.release_errors.lock().expect("save diagnostics")[&lease.lease_id].clone();
        assert_eq!(saved.0, lease);
        assert!(
            saved.1.contains("known save refusal"),
            "later empty observation cleared known refusal"
        );
        if guard == "second save refusal" {
            assert!(saved.1.contains("second save refusal"));
        }
        let facts = rig.state.release_facts.lock().expect("release facts")[&lease.lease_id].clone();
        assert_eq!(facts.0, lease);
        assert_eq!(facts.1["attempt"], json!(attempt));
        assert_eq!(facts.1["command_error"], json!(error));
        assert_eq!(facts.1["observation_error"], observation_error);
        assert_eq!(facts.1["preflight"]["save_guard_error"], guard);
        assert_eq!(
            facts.1["original_preflight"]["save_guard_error"],
            "known save refusal"
        );
        evidence
            .push(json!({"attempt":attempt,"error":error,"guard_field":guard,"retained":saved.1}));
    }
    if let Some(root) = std::env::var_os("R5_ROOT") {
        std::fs::write(
            PathBuf::from(root).join("rr3-field-contract.json"),
            serde_json::to_vec_pretty(&evidence).expect("contract JSON"),
        )
        .expect("contract evidence");
    }
}

#[tokio::test]
async fn rr3_rejected_and_duplicate_terminals_cannot_poison_save_diagnostics() {
    let mut rig = Rig::new().await;
    let (a, _) = rig.open("rr3-a").await;
    let (b, _) = rig.open("rr3-b").await;
    let attempt = rig.release(&a).await;
    let valid = json!({"event":"not_sent","attempt":attempt,"save_guard_error":"known refusal",
        "error":{"code":"operation_failed","message":"original error"},
        "outcome":{"stage":"preflight","detach_called":false,"save_guard_error":"known refusal"}});
    for variant in ["lease", "generation", "instance", "attempt", "rejected-ack"] {
        let mut event = valid.clone();
        match variant {
            "lease" => event["attempt"]["target"]["lease"] = json!(b),
            "generation" => {
                event["attempt"]["target"]["lease"]["generation"] = json!(a.generation + 1)
            }
            "instance" => {
                event["attempt"]["target"]["lease"]["instance_id"] = json!("foreign-instance")
            }
            "attempt" => event["attempt"]["sequence"] = json!(attempt.sequence.get() + 1),
            _ => {
                event["event"] = json!("released");
                event["outcome"]["lease_released"] = json!(false);
            }
        }
        event["save_guard_error"] = json!("foreign save diagnosis");
        rig.control.send(event).await;
        rig.event("event_rejected").await;
        assert!(
            rig.state
                .release_errors
                .lock()
                .expect("diagnostics")
                .is_empty(),
            "{variant} poisoned diagnostics"
        );
        assert!(
            rig.state.release_facts.lock().expect("facts").is_empty(),
            "{variant} poisoned facts"
        );
    }
    rig.control.send(valid.clone()).await;
    rig.event("not_sent").await;
    let errors = rig
        .state
        .release_errors
        .lock()
        .expect("diagnostics")
        .clone();
    let facts = rig.state.release_facts.lock().expect("facts").clone();
    let mut duplicate = valid;
    duplicate["save_guard_error"] = json!("duplicate save diagnosis");
    duplicate["error"]["message"] = json!("duplicate command error");
    rig.control.send(duplicate).await;
    rig.event("event_rejected").await;
    assert_eq!(
        *rig.state.release_errors.lock().expect("diagnostics"),
        errors
    );
    assert_eq!(*rig.state.release_facts.lock().expect("facts"), facts);
    assert!(
        !errors.contains_key(&b.lease_id),
        "another lease acquired diagnostic history"
    );
    rig.b_query(&b).await;
}
