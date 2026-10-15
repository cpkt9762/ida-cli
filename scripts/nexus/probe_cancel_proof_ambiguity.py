#!/usr/bin/env python3
"""F1 blocker: public cancel bool conflates authoritative absence and failed control.

No IDA runtime/owner is started. Transport faults affect only in-memory test
connections; the installed client source is neither modified nor replaced.
Exit 2 proves the legacy ambiguity; exit 0 validates the structured outcomes.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ida_nexus import DatabaseHandle, NexusConnectionError
import ida_nexus.handle as handle_module


class Connection:
    status = 200
    def __init__(self, mode):
        self.mode = mode
        self.requests = 0
    def request(self, *_args, **_kwargs):
        self.requests += 1
    def getresponse(self):
        if self.mode == "transport_error":
            raise http.client.RemoteDisconnected("injected control response loss")
        return self
    def read(self):
        if self.mode == "invalid_json":
            return b"not-json"
        return json.dumps({"result": {"cancelled": self.mode == "true"}}).encode()
    def close(self):
        pass


def scenario(mode):
    instance = SimpleNamespace(backend="idalib", managed=True, pid=os.getpid(), port=1,
                               _token=os.urandom(16).hex())
    with patch.object(DatabaseHandle, "_open_lease", lambda *_: (None, None, None)), \
         patch.object(DatabaseHandle, "_monitor_lease", lambda *_: None), \
         patch.object(DatabaseHandle, "_release_remote_lease", lambda *_: False), \
         patch.object(DatabaseHandle, "_crashed_database_state", lambda *_: None):
        handle = DatabaseHandle("test-only", instance)
        try:
            execution_connection = Connection("transport_error")
            with patch.object(handle, "_rpc_connection_for", lambda *_: execution_connection):
                try:
                    handle.execute_python("result = 'never replay'", operation_id="original", timeout=None)
                except NexusConnectionError:
                    pass
                else:
                    raise AssertionError("execution transport injection must fail")
            ack_connection = Connection("true")
            with patch.object(handle_module.http.client, "HTTPConnection", lambda *_a, **_k: ack_connection):
                ack = handle.cancel_operation("original")
            assert ack is True and ack_connection.requests == 1
            assert execution_connection.requests == 1, "uncertain execution must not replay"
            proof_connection = Connection(mode)
            with patch.object(handle_module.http.client, "HTTPConnection", lambda *_a, **_k: proof_connection):
                proof_result = (handle.cancel_operation_outcome("original")
                                if hasattr(handle, "cancel_operation_outcome") else handle.cancel_operation("original"))
            assert proof_connection.requests == 1, "must issue after the true ACK"
            return {"injected_control_outcome": mode,
                    "execution_requests": execution_connection.requests,
                    "control_requests": ack_connection.requests + proof_connection.requests,
                    "public_observation": {"ack": ack, "subsequent_cancel": proof_result,
                                           "connected": handle.connected},
                    # Test evidence only. Production bridge may not read private state.
                    "unknown_retained_test_observation": "original" in handle._uncertain_operations}
        finally:
            handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    rows = [scenario(mode) for mode in ("false", "transport_error", "invalid_json")]
    ambiguous = all(row["public_observation"] == rows[0]["public_observation"] for row in rows)
    if not ambiguous:
        outcomes = [row["public_observation"]["subsequent_cancel"] for row in rows]
        assert outcomes[0]["status"] == "not_pending" and outcomes[0]["execution_stopped"]
        assert [outcome["failure"] for outcome in outcomes[1:]] == ["transport", "parse"]
        assert all(outcome["status"] == "failed" and not outcome["execution_stopped"] for outcome in outcomes[1:])
        assert all(outcome["attempt_sequence"] == 2 for outcome in outcomes)
    assert rows[0]["unknown_retained_test_observation"] is False
    assert all(row["unknown_retained_test_observation"] is True for row in rows[1:])
    result = {"status": "BLOCKED_PUBLIC_CANCEL_PROOF_AMBIGUITY" if ambiguous else "PASS",
              "actual_scenarios": len(rows), "scenarios": rows,
              "client_source": handle_module.__file__, "owners_started": 0}
    args.evidence.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 2 if ambiguous else 0


if __name__ == "__main__":
    raise SystemExit(main())
