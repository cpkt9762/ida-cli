"""Candidate U1 public API with controlled HTTP/SSE and real direct children."""
import http.client
import inspect
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, os.environ["R0_CANDIDATE"])
from ida_nexus import DatabaseHandle, DatabaseOpenOptions, NexusConnectionError
from ida_nexus.handle import _ACQUIRED_PENDING
import ida_nexus._resolver as resolver
from process_identity import identity
from r0_common import durable
from r0_transport import Boundary

ROOT = Path(os.environ["R0_CASE_ROOT"]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)


class SDKPrototypes(unittest.TestCase):
    def test_observer_errors_before_acquisition_are_not_transport_retries(self):
        rows = []
        for stage in ("Resolved", "BeforeAttach", "AttachMayBeSent", "AttachFailed", "ReconnectResolved"):
            for error_type in (ValueError, OSError, NexusConnectionError):
                label = "observer-" + stage + "-" + error_type.__name__
                with self.subTest(label=label), Boundary(ROOT / label, "reject") as boundary:
                    events = []
                    cause = error_type("controlled " + label)
                    def observe(value, _entry):
                        events.append(value)
                        if value == stage:
                            raise cause
                    result = DatabaseHandle.open_outcome(str(boundary.path),
                        options=DatabaseOpenOptions(spawn=False), observer=observe)
                    self.assertIs(result["cause"], cause)
                    self.assertIsNone(result["handle"])
                    self.assertNotIn("Acquired", events)
                    self.assertEqual(sum(x["endpoint"] == "lease_rejected" for x in boundary.requests),
                                     1 if stage in ("AttachFailed", "ReconnectResolved") else 0)
                    self.assertEqual(result["sdk_reconnect_used"], stage == "ReconnectResolved")
                    rows.append({"stage":stage,"error":error_type.__name__,"events":events,
                                 "failure_kind":result["failure_kind"]})
        durable(ROOT / "observer-errors.json", rows)

    def test_post_acquired_stage_errors_preserve_custody_without_reconnect(self):
        rows = []
        for stage in ("AttachSucceeded", "AttachFailed"):
            for error_type in (ValueError, NexusConnectionError):
                label = stage + "-" + error_type.__name__
                with self.subTest(label=label), Boundary(ROOT / label) as boundary:
                    events, handles = [], []
                    notification = error_type("controlled " + label)
                    acquisition = ValueError("controlled acquired callback failure")
                    def observe(value, entry):
                        events.append(value)
                        if value == "Acquired":
                            handles.append(entry)
                            if stage == "AttachFailed":
                                raise acquisition
                        if value == stage:
                            raise notification
                    result = DatabaseHandle.open_outcome(str(boundary.path),
                        options=DatabaseOpenOptions(spawn=False), observer=observe)
                    try:
                        self.assertEqual(len(handles), 1)
                        self.assertEqual(sum(x["endpoint"] == "lease" for x in boundary.requests), 1)
                        self.assertIs(result["handle"], handles[0])
                        self.assertEqual(result["failure_kind"], "cleanup_required")
                        self.assertIs(result["cause"], acquisition if stage == "AttachFailed" else notification)
                        if stage == "AttachFailed":
                            self.assertIs(result["observer_errors"][0]["cause"], notification)
                        self.assertFalse(result["sdk_reconnect_used"])
                        self.assertNotIn("ReconnectResolved", events)
                        self.assertIs(_ACQUIRED_PENDING[id(handles[0])], handles[0])
                        attempt = result["attempts"][0]
                        self.assertEqual(attempt["failure_kind"], "cleanup_required")
                        self.assertEqual(attempt["obligation"], "exact_handle")
                        self.assertIs(attempt["handle"], handles[0])
                        self.assertEqual(sum(x["endpoint"] == "/release_lease" for x in boundary.requests), 0)
                    finally:
                        for handle in handles:
                            handle.close_outcome(wait_for_database=False, timeout=1)
                    self.assertEqual(sum(x["endpoint"] == "/release_lease" for x in boundary.requests), 1)
                    self.assertNotIn(id(handles[0]), _ACQUIRED_PENDING)
                    rows.append({"stage":stage, "error":error_type.__name__, "accepted":1,
                        "acquired":1, "failure_kind":result["failure_kind"],
                        "cause":type(result["cause"]).__name__, "events":events,
                        "observer_errors":[type(x["cause"]).__name__ for x in result["observer_errors"]],
                        "release_calls":1})
        durable(ROOT / "stage-errors.json", rows)

    def test_cleanup_without_valid_ack_never_supplies_release(self):
        rows = []
        for error_type in (OSError, ValueError, RuntimeError):
            with self.subTest(error=error_type.__name__), Boundary(ROOT / ('no-ack-' + error_type.__name__)) as boundary:
                handle = DatabaseHandle.attach(boundary.instance)
                original = http.client.HTTPConnection
                def factory(*args, **kwargs):
                    connection = original(*args, **kwargs)
                    getresponse = connection.getresponse
                    def response():
                        value = getresponse()
                        read, close = value.read, value.close
                        def invalid(*args, **kwargs):
                            read(*args, **kwargs)
                            return b'{}'
                        def fail():
                            close()
                            raise error_type('controlled cleanup without valid ACK')
                        value.read, value.close = invalid, fail
                        return value
                    connection.getresponse = response
                    return connection
                with patch.object(http.client, 'HTTPConnection', factory):
                    first = handle.close_outcome(wait_for_database=False, timeout=1)
                self.assertFalse(first['lease_released'])
                self.assertNotIn('ack_kind', first)
                self.assertEqual(first['failure'], 'invalid_response')
                self.assertEqual(first['cleanup_failure_type'], error_type.__name__)
                self.assertEqual(handle.close_outcome(wait_for_database=False, timeout=1), first)
                self.assertEqual(sum(x['endpoint'] == '/release_lease' for x in boundary.requests), 1)
                rows.append({'error':error_type.__name__, 'outcome':first})
        durable(ROOT / 'no-ack.json', rows)

    def test_each_attach_attempt_preserves_unknown_across_reconnect(self):
        records = []
        for sequence in (("unknown", "reject"), ("unknown", "success"),
                         ("unknown", "unknown"), ("reject", "reject")):
            with self.subTest(sequence=sequence), Boundary(ROOT / ("attempts-" + "-".join(sequence)),
                    "reject" if sequence[0] == "reject" else "healthy") as boundary:
                original = http.client.HTTPConnection
                seen = []
                class FaultConnection(original):
                    def request(self, method, path, *args, **kwargs):
                        self.is_attach = "sse=1" in path
                        return super().request(method, path, *args, **kwargs)

                    def getresponse(self):
                        response = super().getresponse()
                        if getattr(self, "is_attach", False):
                            index = len(seen)
                            seen.append(response.status)
                            if index == 0 and sequence[1] == "reject":
                                boundary.scenario = "reject"
                            if sequence[index] == "unknown":
                                response.close()
                                raise OSError("controlled response lost after accepted attach")
                        return response
                with patch.object(http.client, "HTTPConnection", FaultConnection):
                    result = DatabaseHandle.open_outcome(str(boundary.path),
                        options=DatabaseOpenOptions(spawn=False))
                try:
                    self.assertTrue(result["sdk_reconnect_used"])
                    self.assertEqual(len(result["attempts"]), 2)
                    self.assertEqual(len(seen), 2, "preserve original two-attempt compatibility")
                    for index, attempt in enumerate(result["attempts"]):
                        self.assertEqual(attempt["attempt"], index+1)
                        self.assertEqual(attempt["instance"], boundary.instance)
                        expected = {"unknown":"unknown_attach", "reject":"lease_absent", "success":None}[sequence[index]]
                        self.assertEqual(attempt["failure_kind"], expected)
                        self.assertEqual(attempt["obligation"], "unknown_attach" if expected == "unknown_attach"
                            else "exact_handle" if expected is None else None)
                    unknown = sequence.count("unknown")
                    self.assertEqual(len(result["unresolved_attempts"]), unknown)
                    self.assertEqual(result["failure_kind"], "unknown_attach" if unknown else "lease_absent")
                    self.assertEqual(result["handle"] is not None, sequence[1] == "success")
                    self.assertEqual(sum(x["endpoint"] == "/release_lease" for x in boundary.requests), 0)
                    records.append({"sequence":sequence, "failure_kind":result["failure_kind"],
                        "unresolved":unknown, "success_handle":result["handle"] is not None,
                        "attempts":[{k:(type(v).__name__ if k == "cause" else
                            v.record_id if k == "instance" else bool(v) if k == "handle" else v)
                            for k,v in a.items()} for a in result["attempts"]]})
                finally:
                    if result["handle"] is not None:
                        self.assertTrue(result["handle"].close_outcome(wait_for_database=False, timeout=1)["lease_released"])
                        self.assertEqual(len(result["unresolved_attempts"]), unknown,
                                         "new successful handle close does not prove old attempt absent")
        durable(ROOT / "attempts.json", records)

    def test_ack_latched_before_all_cleanup_exception_classes(self):
        records = []
        for last in (False, True):
            for phase in ("response", "connection"):
                for error_type in (OSError, ValueError, RuntimeError):
                    label = f"latch-{last}-{phase}-{error_type.__name__}"
                    with self.subTest(label=label), Boundary(ROOT / label) as boundary:
                        handle = DatabaseHandle.attach(boundary.instance)
                        other = None if last else DatabaseHandle.attach(boundary.instance)
                        original = http.client.HTTPConnection
                        def factory(*args, **kwargs):
                            connection = original(*args, **kwargs)
                            getresponse = connection.getresponse
                            def response():
                                value = getresponse()
                                close = value.close if phase == "response" else connection.close
                                def fail():
                                    # Observe object latch while still inside cleanup.
                                    self.assertTrue(handle._close_outcome["lease_released"])
                                    self.assertEqual(handle._close_outcome["ack_kind"], "last" if last else "nonlast")
                                    close()
                                    raise error_type("controlled cleanup after parsed ACK")
                                if phase == "response":
                                    value.close = fail
                                else:
                                    connection.close = fail
                                return value
                            connection.getresponse = response
                            return connection
                        try:
                            with patch.object(http.client, "HTTPConnection", factory):
                                first = handle.close_outcome(wait_for_database=False, timeout=1)
                            again = handle.close_outcome(wait_for_database=False, timeout=1)
                            self.assertEqual(first, again)
                            self.assertTrue(first["lease_released"])
                            self.assertEqual(first["ack_kind"], "last" if last else "nonlast")
                            self.assertEqual(first["shutdown_pending"], last)
                            self.assertIsNone(first["failure"])
                            self.assertIn({"phase":"response" if phase == "response" else "transport",
                                "type":error_type.__name__}, first["cleanup_failures"])
                            calls = sum(x.get("lease_id") == handle._lease_id and x["endpoint"] == "/release_lease"
                                        for x in boundary.requests)
                            self.assertEqual(calls, 1)
                            records.append({"last":last,"phase":phase,"error":error_type.__name__,
                                            "outcome":first,"release_calls":calls})
                        finally:
                            handle.close_outcome(wait_for_database=False, timeout=1)
                            if other is not None:
                                other.close_outcome(wait_for_database=False, timeout=1)
        durable(ROOT / "ack-matrix.json", records)

    def test_observer_is_keyword_only_and_old_positional_options_stay_compatible(self):
        self.assertFalse(DatabaseOpenOptions(False).spawn)
        self.assertEqual(resolver.WorkerLaunchOptions(None, "/private/tmp").worker_cwd, "/private/tmp")
        for options in (DatabaseOpenOptions, resolver.WorkerLaunchOptions):
            self.assertEqual(inspect.signature(options).parameters["acquisition_observer"].kind,
                             inspect.Parameter.KEYWORD_ONLY)
            self.assertTrue(options.__doc__)

    def test_early_acquired_callback_and_thread_failure_custody(self):
        events = []
        original_start = threading.Thread.start
        with Boundary(ROOT / "acquired") as boundary:
            def start(thread):
                if thread.name.startswith("ida-nexus-lease-"):
                    self.assertEqual(events[-1][0], "acquired")
                    raise RuntimeError("controlled monitor start failure")
                return original_start(thread)
            with patch.object(threading.Thread, "start", start):
                outcome = DatabaseHandle.attach_outcome(boundary.instance,
                    on_acquired=lambda handle: events.append(("acquired", handle)))
            self.assertIs(outcome["handle"], events[0][1])
            self.assertIs(_ACQUIRED_PENDING[id(outcome["handle"])], outcome["handle"])
            self.assertEqual(outcome["failure_kind"], "cleanup_required")
            self.assertEqual(len(boundary.leases), 1)
            # start failed: join on the unstarted thread currently also fails.
            # Its ACK must survive that independent cleanup error.
            closed = outcome["handle"].close_outcome(wait_for_database=False, timeout=1)
            self.assertTrue(closed["lease_released"])
            self.assertNotIn(id(outcome["handle"]), _ACQUIRED_PENDING)
            self.assertEqual(closed["cleanup_failure_type"], "RuntimeError")
        with Boundary(ROOT / "callback") as boundary:
            def fail(handle):
                events.append(("callback", handle))
                raise ValueError("controlled custody callback failure")
            result = DatabaseHandle.attach_outcome(boundary.instance, on_acquired=fail)
            self.assertIs(result["handle"], events[-1][1])
            self.assertIsInstance(result["cause"].cause, ValueError)
            self.assertTrue(result["handle"].close_outcome(wait_for_database=False, timeout=1)["lease_released"])

    def test_open_reconnect_and_operation_identity(self):
        with Boundary(ROOT / "reconnect", "reject") as boundary:
            outcome = DatabaseHandle.open_outcome(str(boundary.path), options=DatabaseOpenOptions(spawn=False))
            self.assertEqual(outcome["failure_kind"], "lease_absent")
            self.assertTrue(outcome["sdk_reconnect_used"])
            self.assertEqual(outcome["first_instance"], boundary.instance)
            self.assertEqual(outcome["instance"], boundary.instance)
            self.assertEqual(sum(x["endpoint"] == "lease_rejected" for x in boundary.requests), 2)
        with Boundary(ROOT / "operation") as boundary:
            outcome = DatabaseHandle.open_outcome(str(boundary.path), options=DatabaseOpenOptions(spawn=False))
            self.assertIsNone(outcome["cause"])
            handle = outcome["handle"]
            try:
                self.assertEqual(handle.execute_python("result=42", operation_id="r0-exact-operation")["result"], 42)
                self.assertEqual(boundary.requests[-1]["operation_id"], "r0-exact-operation")
            finally:
                self.assertTrue(handle.close_outcome(wait_for_database=False, timeout=1)["lease_released"])

    def test_attach_transport_boundaries_are_not_certain_absence(self):
        connection_class = http.client.HTTPConnection
        results = []
        with Boundary(ROOT / "handshake") as boundary:
            validation = DatabaseHandle.attach_outcome(boundary.instance, keepalive=-1)
            self.assertEqual(validation["failure_kind"], "not_sent")
            self.assertEqual(validation["stage"], "BeforeAttach")
            for failure in ("request", "getresponse", "missing_socket"):
                def factory(*args, **kwargs):
                    connection = connection_class(*args, **kwargs)
                    if failure in ("request", "getresponse"):
                        def fail(*_a, **_kw):
                            raise OSError("controlled " + failure)
                        setattr(connection, failure, fail)
                    else:
                        original = connection.getresponse
                        def response():
                            value = original()
                            connection.sock = None
                            # Keep real transport reachable for explicit cleanup.
                            value.fp.raw._sock.close()
                            value.fp = None
                            return value
                        connection.getresponse = response
                    return connection
                with patch.object(http.client, "HTTPConnection", factory):
                    outcome = DatabaseHandle.attach_outcome(boundary.instance)
                self.assertIsNone(outcome["handle"])
                self.assertEqual(outcome["failure_kind"], "unknown_attach")
                results.append({"input": failure, "outcome": outcome["failure_kind"]})
        durable(ROOT / "attach.json", results)

    def test_parsed_ack_survives_response_and_rpc_cleanup_unknown_never_replays(self):
        connection_class = http.client.HTTPConnection
        results = []
        for failure in ("response", "rpc"):
            with Boundary(ROOT / ("ack-" + failure)) as boundary:
                first = DatabaseHandle.attach(boundary.instance)
                second = DatabaseHandle.attach(boundary.instance)
                def factory(*args, **kwargs):
                    connection = connection_class(*args, **kwargs)
                    original = connection.getresponse
                    def response():
                        result = original()
                        close = result.close
                        def fail():
                            close()
                            raise OSError("controlled response cleanup")
                        result.close = fail
                        return result
                    connection.getresponse = response
                    return connection
                if failure == "response":
                    with patch.object(http.client, "HTTPConnection", factory):
                        outcome = first.close_outcome(wait_for_database=False, timeout=1)
                else:
                    first.execute_python("result=1")
                    connection = first._rpc_connection
                    close = connection.close
                    def fail():
                        close()
                        raise OSError("controlled rpc cleanup")
                    connection.close = fail
                    outcome = first.close_outcome(wait_for_database=False, timeout=1)
                self.assertEqual(outcome["ack_kind"], "nonlast")
                self.assertTrue(outcome["lease_released"])
                self.assertIn("cleanup_failure", outcome)
                last = second.close_outcome(wait_for_database=False, timeout=1)
                self.assertEqual(last["ack_kind"], "last")
                self.assertEqual(last["status"], "final_pending")
                results.append({"fault": failure, "nonlast": outcome, "last": last})
        with Boundary(ROOT / "unknown", "lost-ack") as boundary:
            handle = DatabaseHandle.attach(boundary.instance)
            first = handle.close_outcome(wait_for_database=False, timeout=1)
            second = handle.close_outcome(wait_for_database=False, timeout=1)
            self.assertFalse(first["lease_released"])
            self.assertEqual(first, second)
            self.assertEqual(sum(x["endpoint"] == "/release_lease" for x in boundary.requests), 1)
            results.append({"unknown": first, "release_calls": 1})
        durable(ROOT / "ack.json", results)

    def test_spawn_intent_direct_child_identity_before_log_failure(self):
        path = ROOT / "direct-child"
        # The executable is an OS input; SDK Popen and launch options are real.
        path.write_text("#!/bin/sh\nexec /bin/sleep 1\n")
        path.chmod(0o700)
        records, children = [], []
        def observe(stage, value):
            records.append(stage)
            if stage == "Spawned":
                process = value["process"]
                children.append(process)
                records.append({"pid": process.pid, "identity": identity(process.pid)})
                self.assertIsNotNone(records[-1]["identity"])
                raise RuntimeError("controlled post-Popen pre-log fault")
        options = resolver.WorkerLaunchOptions(acquisition_observer=observe)
        try:
            with patch.object(resolver, "_find_console_script", return_value=str(path)):
                with self.assertRaisesRegex(RuntimeError, "post-Popen"):
                    resolver.spawn_worker(str(ROOT / "input"), str(ROOT / "input.i64"), 1, options)
            self.assertEqual(records[:2], ["LaunchIntent", "Spawned"])
            self.assertEqual(len(children), 1)
            # cat can already exit on DEVNULL; creation evidence remains authoritative.
            self.assertIsInstance(children[0], subprocess.Popen)
        finally:
            for child in children:
                child.wait(timeout=3)
        durable(ROOT / "spawn.json", {"events": records, "children_reaped": True,
                "obligation": "Spawned exception retains exact direct-child responsibility"})

    def test_ready_failure_retains_spawn_and_launch_intent_precedes_creation(self):
        executable = ROOT / "never-ready"
        executable.write_text("#!/bin/sh\nexec /bin/sleep 0.1\n")
        executable.chmod(0o700)
        source = ROOT / "never-ready-input"
        source.write_bytes(b"private OS input; no IDA launch")
        stages, children, identities = [], [], []
        def observe(stage, value):
            stages.append(stage)
            if stage == "Spawned":
                children.append(value["process"])
                identities.append({"pid":value["pid"], "identity":identity(value["pid"])})
                self.assertEqual(stages[:2], ["LaunchIntent", "Spawned"])
        try:
            with patch.object(resolver, "_find_console_script", return_value=str(executable)):
                outcome = DatabaseHandle.open_outcome(str(source),
                    options=DatabaseOpenOptions(startup_timeout=2), observer=observe)
            self.assertIsNone(outcome["handle"])
            self.assertIsNotNone(outcome["cause"])
            self.assertEqual([stage for stage,_ in outcome["launches"]], ["LaunchIntent","Spawned","LogReady"])
            self.assertEqual(len(children), 1)
        finally:
            for child in children:
                child.wait(timeout=3)
        # Intent callback failure is definitely before Popen; it still remains
        # a durable startup obligation until its origin reconciles the intent.
        def refuse(stage, _value):
            if stage == "LaunchIntent":
                raise RuntimeError("controlled before-Popen refusal")
        with patch.object(resolver, "_find_console_script", return_value=str(executable)):
            outcome = DatabaseHandle.open_outcome(str(source),
                options=DatabaseOpenOptions(startup_timeout=2), observer=refuse)
        self.assertEqual([stage for stage,_ in outcome["launches"]], ["LaunchIntent"])
        self.assertIsNone(outcome["handle"])
        durable(ROOT / "ready.json", {"stages":stages, "children_reaped":True,
            "child_processes":identities,
            "before_popen":"LaunchIntent only", "failure_obligation":"startup_unconfirmed"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
