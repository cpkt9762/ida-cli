"""F1 transport barriers for causal cancellation and cancel_active fairness."""
import concurrent.futures
import threading

from test_client_patch import Connection, client, fail_request


def test_p11_delayed_success_cannot_retire_later_running_unknown(client, monkeypatch):
    fail_request(client, monkeypatch, "U")
    entered, resume = threading.Event(), threading.Event()
    success = Connection()
    read = success.read
    def delayed_read():
        entered.set()
        assert resume.wait(3), "release successful response barrier"
        return read()
    success.read = delayed_read
    monkeypatch.setattr(client, "_rpc_connection_for", lambda *_: success)
    control = Connection({"result": {"cancelled": True}})
    monkeypatch.setattr("ida_nexus.handle.http.client.HTTPConnection", lambda *_a, **_k: control)
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        future = pool.submit(client._request, "/execute_python", {}, operation_id="S")
        assert entered.wait(1)
        try:
            assert client.cancel_operation("U") is True
        finally:
            resume.set()
        future.result(timeout=2)
    assert "U" in client._uncertain_operations, "late S response cannot prove U stopped"


def test_p11_false_issued_before_true_ack_cannot_retire_unknown(client, monkeypatch):
    fail_request(client, monkeypatch, "U")
    entered, resume = threading.Event(), threading.Event()
    stale = Connection({"result": {"cancelled": False}})
    read = stale.read
    def delayed_false():
        entered.set()
        assert resume.wait(3), "release old false response barrier"
        return read()
    stale.read = delayed_false
    fresh = Connection({"result": {"cancelled": True}})
    monkeypatch.setattr("ida_nexus.handle.http.client.HTTPConnection",
                        lambda *_a, **_k: stale if threading.current_thread().name.startswith("old-false") else fresh)
    with concurrent.futures.ThreadPoolExecutor(1, thread_name_prefix="old-false") as pool:
        future = pool.submit(client.cancel_operation, "U")
        assert entered.wait(1)
        try:
            assert client.cancel_operation("U") is True
        finally:
            resume.set()
        assert future.result(timeout=2) is False
    assert "U" in client._uncertain_operations, "request issuance must follow true ACK"
    fresh.payload = {"result": {"cancelled": False}}
    assert client.cancel_operation("U") is False
    assert "U" not in client._uncertain_operations


def test_p26_cancel_active_ignores_stale_unknowns(client, monkeypatch):
    fail_request(client, monkeypatch, "stale")
    calls = []
    monkeypatch.setattr(client, "cancel_operation", lambda op: calls.append(op) or False)
    assert client.cancel_active(timeout=0) is False
    assert calls == [], "cancel_active retains original active-only meaning; bridge cancels exact IDs"
