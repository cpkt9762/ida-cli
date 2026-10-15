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

SPEC = importlib.util.spec_from_file_location("bridge", Path(__file__).resolve().parents[2] / "nexus_bridge/bridge.py")
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


def test_unknown_result_requires_successor_stop_proof(harness):
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
    assert stopped["proof"] == "same_lease_serialized_successor_completed"
    codes = [code for code, _ in harness.handle.calls]
    assert codes.count("disconnect") == 1
    assert codes[-1] == "result = None"


def test_release_only_closes_held_exact_lease(harness):
    harness.open()
    harness.dispatch(1, {"command": "release", "lease": {**harness.lease, "client_id": "foreign"}})
    assert harness.receive(1)["event"] == "failed"
    assert not harness.handle.closed
    harness.dispatch(1, {"command": "release", "lease": harness.lease})
    assert harness.receive(1)["event"] == "released"
    assert harness.handle.closed


def test_cancellation_ack_without_successor_does_not_claim_stop(harness, monkeypatch):
    harness.open()
    harness.handle.disconnect = True
    execute = harness.handle.execute_python
    def fail_proof(code, **options):
        if code == "result = None":
            from ida_nexus import NexusConnectionError
            raise NexusConnectionError("successor not confirmed")
        return execute(code, **options)
    monkeypatch.setattr(harness.handle, "execute_python", fail_proof)
    harness.dispatch(0, harness.execute("disconnect"))
    assert harness.receive()["event"] == "ack"
    assert harness.receive()["event"] == "uncertain"
    harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": "op-1"}})
    assert harness.receive(1)["event"] == "cancel_ack"
    assert harness.receive(1)["event"] == "stop_unconfirmed"
    assert "op-1" in harness.bridge.unknown


def test_blocked_stop_proofs_do_not_occupy_cancellation_capacity(harness, monkeypatch):
    harness.open()
    harness.handle.disconnect = True
    execute = harness.handle.execute_python
    release = threading.Event()
    def blocked_proof(code, **options):
        if code == "result = None":
            assert release.wait(3), "test must release stop proof barrier"
            return {"result": None}
        return execute(code, **options)
    monkeypatch.setattr(harness.handle, "execute_python", blocked_proof)
    try:
        for number in range(4):
            harness.dispatch(0, harness.execute("disconnect", f"unknown-{number}"))
            assert harness.receive()["event"] == "ack"
            assert harness.receive()["event"] == "uncertain"
            harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": f"unknown-{number}"}})
            assert harness.receive(1)["event"] == "cancel_ack"
            if number >= 2:
                assert harness.receive(1)["event"] == "stop_unconfirmed"
        harness.dispatch(1, {"command": "cancel", "identity": {"lease": harness.lease, "operation_id": "next-control"}})
        assert harness.receive(1)["event"] == "cancel_ack"
    finally:
        release.set()
    assert [harness.receive(1)["event"] for _ in range(2)] == ["stopped", "stopped"]


def test_wrong_physical_lane_stops_protocol(harness):
    harness.send(1, harness.frame({"command": "open"}))
    assert harness.bridge.stopped.wait(1)
    assert not harness.opens


def test_eof_stops_bridge(harness):
    harness.sockets[0].shutdown(socket.SHUT_WR)
    assert harness.bridge.stopped.wait(1), "EOF must initiate owned lease cleanup"
