"""Exercise the installed client patch with controlled transport outcomes."""
import json
import os
from types import SimpleNamespace

import pytest
from ida_nexus import DatabaseHandle, NexusConnectionError, RemoteError


class Connection:
    def __init__(self, payload=None, failure=False):
        self.payload = payload or {"ok": True, "result": {}}
        self.failure = failure
        self.requests = []
        self.status = 200

    def request(self, method, endpoint, **options):
        self.requests.append((method, endpoint, options.get("body")))
        if self.failure:
            raise OSError("injected transport failure")

    def getresponse(self):
        return self

    def read(self):
        return json.dumps(self.payload).encode()

    def close(self):
        pass


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(DatabaseHandle, "_open_lease", lambda *_a: (None, None, None))
    monkeypatch.setattr(DatabaseHandle, "_monitor_lease", lambda *_a: None)
    monkeypatch.setattr(DatabaseHandle, "_release_remote_lease", lambda *_a: False)
    monkeypatch.setattr(DatabaseHandle, "_crashed_database_state", lambda *_a: None)
    instance = SimpleNamespace(backend="idalib", managed=True, pid=os.getpid(), port=1, _token=os.urandom(16).hex())
    handle = DatabaseHandle("fixture", instance)
    try:
        yield handle
    finally:
        handle.close()


def fail_request(client, monkeypatch, operation):
    connection = Connection(failure=True)
    monkeypatch.setattr(client, "_rpc_connection_for", lambda *_a: connection)
    with pytest.raises(NexusConnectionError):
        client._request("/execute_python", {}, operation_id=operation)
    assert len(connection.requests) == 1


def test_collection_is_bounded_and_never_evicts_uncertain_identity(client, monkeypatch):
    for number in range(64):
        fail_request(client, monkeypatch, str(number))
    untouched = Connection()
    monkeypatch.setattr(client, "_rpc_connection_for", lambda *_a: untouched)
    with pytest.raises(NexusConnectionError, match="capacity exhausted"):
        client._request("/execute_python", {}, operation_id="overflow")
    assert untouched.requests == []
    assert set(client._uncertain_operations) == {str(number) for number in range(64)}


def test_only_handle_owned_identity_can_use_independent_cancel(client, monkeypatch):
    fail_request(client, monkeypatch, "unknown")
    control = Connection({"result": {"cancelled": True}})
    monkeypatch.setattr("ida_nexus.handle.http.client.HTTPConnection", lambda *_a, **_kw: control)
    assert client.cancel_operation("foreign") is False
    assert control.requests == []
    assert client.cancel_active() is False
    assert client.cancel_operation("unknown") is True
    assert len(control.requests) == 1
    body = json.loads(control.requests[0][2])
    assert body == {"lease_id": client._lease_id, "operation_id": "unknown"}
    assert "unknown" in client._uncertain_operations, "ACK cannot prove execution stopped"
    control.payload = {"result": {"cancelled": False}}
    assert client.cancel_operation("unknown") is False
    assert not client._uncertain_operations


def test_health_error_and_success_cannot_clear_unknown_without_causal_cancel(client, monkeypatch):
    fail_request(client, monkeypatch, "unknown")
    connection = Connection()
    monkeypatch.setattr(client, "_rpc_connection_for", lambda *_a: connection)
    client._request("/health", {})
    assert "unknown" in client._uncertain_operations
    connection.payload = {"error": {"code": "rejected", "message": "known failure"}}
    with pytest.raises(RemoteError):
        client._request("/execute_python", {}, operation_id="known-error")
    assert set(client._uncertain_operations) == {"unknown"}
    connection.payload = {"ok": True, "result": {}}
    client._request("/execute_python", {}, operation_id="unconfirmed-successor")
    assert set(client._uncertain_operations) == {"unknown"}, "backend lock is not FIFO"
    control = Connection({"result": {"cancelled": False}})
    monkeypatch.setattr("ida_nexus.handle.http.client.HTTPConnection", lambda *_a, **_kw: control)
    assert client.cancel_operation("unknown") is False
    assert "unknown" in client._uncertain_operations, "false may precede POST registration"
    control.payload = {"result": {"cancelled": True}}
    assert client.cancel_operation("unknown") is True
    client._request("/execute_python", {}, operation_id="successor")
    assert "unknown" in client._uncertain_operations
    control.payload = {"result": {"cancelled": False}}
    outcome = client.cancel_operation_outcome("unknown")
    assert outcome["status"] == "not_pending" and outcome["execution_stopped"]
    assert not client._uncertain_operations
    assert client.cancel_operation("successor") is False


def test_close_clears_unknown_identities(client, monkeypatch):
    fail_request(client, monkeypatch, "unknown")
    client.close()
    assert not client._uncertain_operations


def test_change_subscription_close_does_not_require_handle_cancel_state(client, monkeypatch):
    from ida_nexus.handle import DatabaseChangeSubscription
    monkeypatch.setattr(DatabaseChangeSubscription, "_open", lambda *_: None)
    subscription = DatabaseChangeSubscription(client)
    subscription.close()
    subscription.close()
    assert client.connected


def test_control_response_close_failure_is_not_authoritative_absence(client, monkeypatch):
    fail_request(client, monkeypatch, "unknown")
    ack = Connection({"result": {"cancelled": True}})
    monkeypatch.setattr("ida_nexus.handle.http.client.HTTPConnection", lambda *_a, **_kw: ack)
    assert client.cancel_operation("unknown")
    class CloseFailure(Connection):
        def getresponse(self):
            response = Connection({"result": {"cancelled": False}})
            def close():
                raise OSError("control response close failed")
            response.close = close
            return response
    monkeypatch.setattr("ida_nexus.handle.http.client.HTTPConnection", lambda *_a, **_kw: CloseFailure())
    outcome = client.cancel_operation_outcome("unknown")
    assert outcome["status"] == "failed" and outcome["failure"] == "transport"
    assert not outcome["execution_stopped"]
    assert "unknown" in client._uncertain_operations


@pytest.mark.parametrize("close_error", [OSError, RuntimeError])
def test_control_connection_close_failure_preserves_authoritative_stop(client, monkeypatch, close_error):
    fail_request(client, monkeypatch, "unknown")
    ack = Connection({"result": {"cancelled": True}})
    monkeypatch.setattr("ida_nexus.handle.http.client.HTTPConnection", lambda *_a, **_kw: ack)
    assert client.cancel_operation("unknown")
    class ConnectionCloseFailure(Connection):
        def getresponse(self):
            # Distinct objects: HTTPResponse.close succeeds, HTTPConnection.close fails.
            return Connection({"result": {"cancelled": False}})

        def close(self):
            raise close_error("control connection close failed after parsed result")
    monkeypatch.setattr("ida_nexus.handle.http.client.HTTPConnection", lambda *_a, **_kw: ConnectionCloseFailure())
    outcome = client.cancel_operation_outcome("unknown")
    assert outcome["status"] == "not_pending" and outcome["execution_stopped"]
    assert outcome["attempt_sequence"] > outcome["ack_cutoff"]
    assert outcome["cleanup_failure"] == "transport"
    assert outcome["cleanup_failure_type"] == close_error.__name__
    assert "unknown" not in client._uncertain_operations
