use ida_mcp::nexus::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct TestClock(Arc<Mutex<Instant>>);

impl TestClock {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }
    pub fn advance(&self, ms: u64) {
        self.advance_duration(Duration::from_millis(ms));
    }
    pub fn advance_duration(&self, duration: Duration) {
        let mut now = self.0.lock().expect("test clock lock");
        *now += duration;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        *self.0.lock().expect("test clock lock")
    }
}

#[derive(Default)]
pub struct RecordingBackend {
    pub business: Vec<SessionCommand>,
    pub attempts: Vec<DeliveryAttempt>,
    pub controls: Vec<SessionCommand>,
    pub executed: Vec<ExecuteCommand>,
    pub writes: usize,
    pub fail_business: Option<DispatchFailure>,
    pub fail_control: Option<DispatchFailure>,
}

impl NexusBackend for RecordingBackend {
    fn send(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure> {
        self.attempts.push(attempt);
        self.business.push(command.clone());
        let failure = self.fail_business.take();
        if !matches!(failure, Some(DispatchFailure::NotSent(_))) {
            if let SessionCommand::Execute(execution) = command {
                if execution.effect == MethodEffect::MayWrite {
                    self.writes += 1;
                }
                self.executed.push(execution);
            }
        }
        failure.map_or(Ok(()), Err)
    }
    fn send_control(
        &mut self,
        command: SessionCommand,
        attempt: DeliveryAttempt,
    ) -> Result<(), DispatchFailure> {
        self.attempts.push(attempt);
        self.controls.push(command);
        self.fail_control.take().map_or(Ok(()), Err)
    }
}

pub fn capabilities() -> NexusCapabilities {
    NexusCapabilities {
        runtime: NexusRuntime {
            ida: Version(9, 5, 0),
            python: Version(3, 14, 7),
            nexus: Some(Version(0, 13, 4)),
            domain: Some(Version(0, 5, 1)),
        },
        methods: BTreeMap::from([
            ("list_functions".into(), MethodEffect::ReadOnly),
            ("rename_symbol".into(), MethodEffect::MayWrite),
        ]),
    }
}

pub fn accepted(clock: &TestClock, name: &str, method: &str, params: Value) -> AcceptedRequest {
    AcceptedRequest::new(
        clock,
        RequestId::new(format!("r-{name}")).unwrap(),
        Some(TaskId::new(format!("t-{name}")).unwrap()),
        method,
        params,
    )
    .expect("valid accepted request")
}

pub struct Rig {
    pub clock: TestClock,
    pub sessions: NexusSessions<TestClock>,
    pub backend: RecordingBackend,
}

impl Rig {
    pub fn new() -> Self {
        let clock = TestClock::new();
        Self {
            sessions: NexusSessions::new(clock.clone(), Ok(capabilities()), 128),
            clock,
            backend: RecordingBackend::default(),
        }
    }
    pub fn begin_open(
        &mut self,
        name: &str,
        instance: &str,
        generation: u64,
        timeout: u64,
    ) -> (OpenIdentity, SessionLease) {
        let lease = SessionLease {
            client_id: ClientId::new(format!("client-{name}")).unwrap(),
            lease_id: LeaseId::new(format!("lease-{name}")).unwrap(),
            instance_id: InstanceId::new(instance).unwrap(),
            generation,
            owner: OwnerKind::Managed,
        };
        let request = accepted(
            &self.clock,
            &format!("open-{name}"),
            "open",
            json!({"timeout_secs":timeout}),
        );
        let identity = self
            .sessions
            .open(
                &lease.client_id,
                request,
                OpenSpec {
                    operation_id: OperationId::new(format!("open-{name}")).unwrap(),
                    path: "/test/copy.i64".into(),
                    options: json!({"save":true}),
                },
                &mut self.backend,
            )
            .expect("open dispatch");
        (identity, lease)
    }
    pub fn connect(&mut self, name: &str, instance: &str, generation: u64) -> SessionLease {
        let (identity, lease) = self.begin_open(name, instance, generation, 120);
        assert!(matches!(
            self.sessions
                .opened(&identity, lease.clone(), capabilities())
                .expect("open confirmation"),
            OpenDisposition::Ready(_)
        ));
        lease
    }
    pub fn queue(
        &mut self,
        lease: &SessionLease,
        name: &str,
        method: &str,
        seconds: u64,
    ) -> OperationIdentity {
        self.sessions
            .queue(
                &lease.client_id,
                lease,
                accepted(&self.clock, name, method, json!({"timeout_secs":seconds})),
                OperationId::new(name).unwrap(),
            )
            .expect("queue request")
    }
    pub fn dispatch(&mut self, identity: &OperationIdentity) {
        self.sessions
            .dispatch(&identity.lease.client_id, identity, &mut self.backend)
            .expect("dispatch request");
    }
    pub fn last_attempt(&self) -> DeliveryAttempt {
        self.backend
            .attempts
            .last()
            .expect("recorded send attempt")
            .clone()
    }
    pub fn snapshot(&self, identity: &OperationIdentity) -> OperationSnapshot {
        self.sessions
            .operation_status(&identity.lease.client_id, identity)
            .expect("operation snapshot")
    }
}
