"""Protocol and capacity assertions without importing the IDA runtime."""
import importlib.util
import json
import os
import tempfile
from pathlib import Path
import socket
import sys
import threading
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location("bridge", Path(os.environ.get("N5_BRIDGE_SOURCE", Path(__file__).resolve().parents[2] / "nexus_bridge/bridge.py")))
bridge_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge_module)


class Handle:
    connected = True
    instance = SimpleNamespace(record_id="owner-1", pid=123, idb_path="test.i64", backend="idalib")
    recovery = "none"

    def __init__(self):
        self.calls = []
        self.closed = False
        self.started = threading.Event()
        self.resume = threading.Event()
        self.disconnect = False

    def execute_python(self, code, **options):
        if code.startswith("import time as _n5_time\n"):
            guard, code = code.split("# nexus owner deadline checked\n", 1)
            exec(guard, {})  # Exercise the actual deadline check, then the fixture.
        self.calls.append((code, options))
        if "get_kernel_version" in code:
            return {"result": "9.5"}
        if code == "block":
            self.started.set()
            assert self.resume.wait(3), "test did not release execution barrier"
        if self.disconnect and code == "disconnect":
            from ida_nexus import NexusConnectionError
            raise NexusConnectionError("injected response connection failure")
        return {"result": code}

    def set_disconnect_callback(self, callback):
        self.callback = callback

    def cancel_operation(self, operation_id):
        self.cancelled = operation_id
        return True

    def cancel_operation_outcome(self, operation_id):
        calls = getattr(self, "control_calls", {})
        self.control_calls = calls
        calls[operation_id] = calls.get(operation_id, 0) + 1
        self.cancelled = operation_id
        self.cancel_operation(operation_id)
        return {"status": "cancelled" if calls[operation_id] == 1 else "not_pending",
                "execution_stopped": calls[operation_id] > 1,
                "attempt_sequence": sum(calls.values()), "failure": None}

    def cancel_active(self, **_options):
        return False

    def close(self, **_options):
        self.closed = True


class Harness:
    def __init__(self, directory, monkeypatch):
        import ida_nexus
        self.handle = Handle()
        self.opens = []
        def open_handle(path, **options):
            self.opens.append((path, options))
            return self.handle
        monkeypatch.setattr(ida_nexus.DatabaseHandle, "open", open_handle)
        monkeypatch.setattr(ida_nexus, "discover_databases", lambda **_kw: [])
        monkeypatch.setattr(bridge_module, "readiness", lambda: {"capabilities": {"runtime": {}, "methods": {}}})
        monkeypatch.setenv("IDA_CLI_HOME", str(directory))
        self.listeners = []
        for name in ("b", "c"):
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(directory / name))
            listener.listen(1)
            self.listeners.append(listener)
        self.bridge = bridge_module.Bridge(str(directory / "b"), str(directory / "c"), 4)
        self.sockets = [listener.accept()[0] for listener in self.listeners]
        for stream in self.sockets:
            stream.settimeout(3)
        self.inputs = [stream.makefile("rb") for stream in self.sockets]
        self.sequence = 0

    def send(self, lane, message):
        self.sockets[lane].sendall(json.dumps(message).encode() + b"\n")

    def receive(self, lane=0):
        return json.loads(self.inputs[lane].readline())

    def frame(self, payload):
        self.sequence += 1
        return {"nexus_frame": 2, "expires_monotonic_ns": 1, "attempt": {"sequence": self.sequence}, "payload": payload}

    def dispatch(self, lane, payload, allow=True):
        frame = self.frame(payload)
        self.send(lane, frame)
        ready = self.receive(lane)
        assert ready == {"event": "dispatch_ready", "frame": frame}
        self.send(lane, {"grant": allow, "sequence": self.sequence, "remaining_ms": 1000})
        return frame

    def open(self):
        self.dispatch(0, {"command": "open", "identity": {"client_id": "client-1"}, "path": "sample", "options": {}})
        opened = self.receive()
        assert opened["event"] == "opened", opened
        self.lease = opened["lease"]
        return opened

    def execute(self, code, operation="op-1"):
        return {"command": "execute", "identity": {"lease": self.lease, "operation_id": operation}, "method": "execute_python", "params": {"code": code}}

    def close(self):
        self.handle.resume.set()
        self.bridge.close()
        for stream in self.sockets:
            stream.close()
        for stream in self.inputs:
            stream.close()
        for listener in self.listeners:
            listener.close()


@pytest.fixture
def harness(tmp_path, monkeypatch):
    with tempfile.TemporaryDirectory(dir=os.environ["N3_TEST_IPC_ROOT"]) as directory:
        test = Harness(Path(directory), monkeypatch)
        try:
            yield test
        finally:
            test.close()


def test_readiness_never_loads_ida_runtime():
    assert "idapro" not in sys.modules
    assert "ida_domain" not in sys.modules


def test_no_api_invocation_until_grant(harness):
    frame = harness.frame({"command": "open", "identity": {"client_id": "client"}, "path": "sample", "options": {}})
    harness.send(0, frame)
    assert harness.receive()["event"] == "dispatch_ready"
    assert harness.opens == []
    harness.send(0, {"grant": False, "sequence": frame["attempt"]["sequence"]})
    # A following frame is a protocol barrier after rejection.
    opened = harness.open()
    assert len(harness.opens) == 1
    assert opened["lease"]["generation"] == 1


def test_status_and_cancel_have_independent_connection_and_executor(harness):
    harness.open()
    for number in range(4):
        harness.dispatch(0, harness.execute("block", f"op-{number}"))
        assert harness.receive()["event"] == "ack"
    assert harness.handle.started.wait(1)
    harness.send(1, {"local_status": "status-barrier"})
    status = harness.receive(1)
    assert status["id"] == "status-barrier"
    assert status["held"][0]["lease"] == harness.lease
    assert status["owners"] == []
    harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": "op-0"}})
    assert harness.receive(1)["event"] == "cancel_ack"
    assert harness.handle.cancelled == "op-0"
    assert all(options["timeout"] is None for code, options in harness.handle.calls)
    harness.handle.resume.set()
    assert [harness.receive()["event"] for _ in range(4)] == ["completed"] * 4


def test_business_capacity_rejects_without_invocation(harness):
    harness.open()
    for number in range(4):
        harness.dispatch(0, harness.execute("block", f"op-{number}"))
        assert harness.receive()["event"] == "ack"
    harness.send(0, harness.frame(harness.execute("must-not-run", "excess")))
    assert harness.receive()["error"]["code"] == "busy"
    harness.handle.resume.set()
    for _ in range(4):
        assert harness.receive()["event"] == "completed"
    assert not any(code == "must-not-run" for code, _ in harness.handle.calls)


def test_unknown_result_requires_causal_control_stop_proof(harness):
    harness.open()
    harness.handle.disconnect = True
    original = harness.dispatch(0, harness.execute("disconnect"))
    assert harness.receive()["event"] == "ack"
    assert harness.receive()["event"] == "uncertain"
    harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": "op-1"}})
    assert harness.receive(1)["event"] == "cancel_ack"
    stopped = harness.receive(1)
    assert stopped["event"] == "stopped"
    assert stopped["attempt"] == original["attempt"]
    assert stopped["proof"] == "causal_cancel_not_pending"
    codes = [code for code, _ in harness.handle.calls]
    assert codes.count("disconnect") == 1
    assert "result = None" not in codes
    assert harness.handle.control_calls["op-1"] == 2


def test_release_only_closes_held_exact_lease(harness):
    harness.open()
    harness.dispatch(1, {"command": "release", "lease": {**harness.lease, "client_id": "foreign"}})
    assert harness.receive(1)["event"] == "failed"
    assert not harness.handle.closed
    harness.dispatch(1, {"command": "release", "lease": harness.lease})
    assert harness.receive(1)["event"] == "released"
    assert harness.handle.closed


def test_proof_failure_retries_without_losing_unknown_or_claiming_stop(harness, monkeypatch):
    harness.open()
    harness.handle.disconnect = True
    original = harness.handle.cancel_operation_outcome
    release = threading.Event()
    def fail_proof(operation_id):
        count = getattr(harness.handle, "proof_attempts", 0) + 1
        harness.handle.proof_attempts = count
        if count == 2:
            return {"status": "failed", "execution_stopped": False, "failure": "transport", "attempt_sequence": count}
        if count == 3:
            assert release.wait(3), "release retry barrier"
        return original(operation_id)
    monkeypatch.setattr(harness.handle, "cancel_operation_outcome", fail_proof)
    harness.dispatch(0, harness.execute("disconnect"))
    assert harness.receive()["event"] == "ack"
    assert harness.receive()["event"] == "uncertain"
    harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": "op-1"}})
    assert harness.receive(1)["event"] == "cancel_ack"
    assert harness.receive(1)["event"] == "stop_unconfirmed"
    assert "op-1" in harness.bridge.unknown
    release.set()
    assert harness.receive(1)["event"] == "stopped"
    assert harness.handle.proof_attempts == 3


def test_full_proof_pool_queues_and_eventually_proves_every_unknown(harness, monkeypatch):
    harness.open()
    harness.handle.disconnect = True
    original = harness.handle.cancel_operation_outcome
    release = threading.Event()
    def blocked_proof(operation_id):
        if threading.current_thread().name.startswith("nexus-proof"):
            assert release.wait(3), "release stop proof barrier"
        return original(operation_id)
    monkeypatch.setattr(harness.handle, "cancel_operation_outcome", blocked_proof)
    try:
        for number in range(4):
            harness.dispatch(0, harness.execute("disconnect", f"unknown-{number}"))
            assert harness.receive()["event"] == "ack"
            assert harness.receive()["event"] == "uncertain"
            harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": f"unknown-{number}"}})
            assert harness.receive(1)["event"] == "cancel_ack"
        harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": "next-control"}})
        assert harness.receive(1)["event"] == "cancel_ack"
    finally:
        release.set()
    assert [harness.receive(1)["event"] for _ in range(4)] == ["stopped"] * 4
    assert not harness.bridge.unknown


def test_wrong_physical_lane_stops_protocol(harness):
    harness.send(1, harness.frame({"command": "open"}))
    assert harness.bridge.stopped.wait(1)
    assert not harness.opens


def test_eof_stops_bridge(harness):
    harness.sockets[0].shutdown(socket.SHUT_WR)
    assert harness.bridge.stopped.wait(1), "EOF must initiate owned lease cleanup"


def test_proof_deadline_preserves_unknown_and_never_claims_stop(harness, monkeypatch):
    harness.open()
    harness.handle.disconnect = True
    original = harness.handle.cancel_operation_outcome
    def failure(operation_id):
        if threading.current_thread().name.startswith("nexus-proof"):
            return {"status": "failed", "execution_stopped": False, "failure": "transport", "attempt_sequence": 2}
        return original(operation_id)
    monkeypatch.setattr(harness.handle, "cancel_operation_outcome", failure)
    harness.dispatch(0, harness.execute("disconnect"))
    assert harness.receive()["event"] == "ack"
    assert harness.receive()["event"] == "uncertain"
    harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": "op-1"}})
    assert harness.receive(1)["event"] == "cancel_ack"
    assert harness.receive(1)["event"] == "stop_unconfirmed"
    # Explicit deadline barrier, without timing a sleep against the supervisor.
    with harness.bridge.lock:
        harness.bridge.executing["op-1"]["deadline"] = 0
    harness.bridge.proof_wakeup.set()
    while True:
        event = harness.receive(1)
        assert event["event"] == "stop_unconfirmed", "failure/expiry cannot prove stop"
        if "deadline expired" in event["error"]["message"]:
            break
    assert "op-1" in harness.bridge.unknown
    assert harness.bridge.executing["op-1"]["expired"]


def test_old_attempt_callback_cannot_change_second_delivery(harness, monkeypatch):
    """Late disconnect/finally from slice one cannot mutate slice two."""
    harness.open()
    gates = {name: threading.Event() for name in ("old", "new")}
    started = {name: threading.Event() for name in gates}
    original = harness.handle.execute_python
    def controlled(code, **options):
        if code.startswith("import time as _n5_time\n"):
            guard, code = code.split("# nexus owner deadline checked\n", 1)
            exec(guard, {})
        if code in gates:
            started[code].set()
            assert gates[code].wait(3), "attempt release barrier"
        return original(code, **options)
    monkeypatch.setattr(harness.handle, "execute_python", controlled)
    try:
        old = harness.dispatch(0, harness.execute("old"))
        assert harness.receive()["event"] == "ack"
        assert started["old"].wait(1)
        new = harness.dispatch(0, harness.execute("new"))
        assert harness.receive()["event"] == "ack"
        assert started["new"].wait(1)
        harness.bridge.mark_unknown("op-1", old["attempt"])
        current = harness.bridge.executing["op-1"]
        assert current["attempt"] == new["attempt"]
        assert current["unknown"] is False
        assert "op-1" not in harness.bridge.unknown
        gates["old"].set()
        assert harness.receive()["attempt"] == old["attempt"]
        assert harness.bridge.executing["op-1"] is current
        gates["new"].set()
        assert harness.receive()["attempt"] == new["attempt"]
    finally:
        for gate in gates.values():
            gate.set()


def test_close_removes_owned_lifetime_socket(harness):
    path = Path(harness.bridge.lifetime_path)
    assert path.is_socket()
    harness.bridge.close()
    assert not path.exists(), "normal close must unlink the lifetime endpoint"


def test_close_preserves_replacement_at_lifetime_path(harness):
    path = Path(harness.bridge.lifetime_path)
    path.unlink()
    path.write_text("replacement must survive")
    harness.bridge.close()
    assert path.read_text() == "replacement must survive"


_deep = 0
for _level in range(128):
    _deep = [_deep]


@pytest.mark.parametrize("bad", ["\ud800", float("nan"), object(), {"cycle": None},
                                _deep],
                         ids=["utf8-surrogate", "nonfinite", "unsupported", "cycle", "depth"])
def test_f2_bad_result_is_request_local(harness, monkeypatch, bad):
    harness.open()
    first = harness.lease
    harness.open()
    second = harness.lease
    if isinstance(bad, dict):
        bad["cycle"] = bad
    original = harness.handle.execute_python
    def execute(code, **options):
        if code.endswith("bad-result"):
            return {"result": bad}
        return original(code, **options)
    monkeypatch.setattr(harness.handle, "execute_python", execute)
    harness.lease = first
    harness.dispatch(0, harness.execute("bad-result"))
    assert harness.receive()["event"] == "ack"
    failure = harness.receive()
    assert failure["event"] == "remote_error", failure
    assert failure["error"]["code"] == "operation_failed"
    assert "response encoding failed" in failure["error"]["message"]
    assert not harness.bridge.stopped.is_set()
    for lease in (first, second):
        harness.lease = lease
        harness.dispatch(0, harness.execute("healthy", "after-" + lease["lease_id"]))
        assert harness.receive()["event"] == "ack"
        assert harness.receive()["result"]["result"] == "healthy"
    harness.send(1, {"local_status": "encoding-survival"})
    assert len(harness.receive(1)["held"]) == 2
