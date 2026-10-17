"""Installed R1 SDK regression matrix; the frozen R0 prototype stays unchanged."""
import threading
import unittest
from unittest.mock import patch

import r0_sdk
from ida_nexus import DatabaseHandle, DatabaseOpenOptions, NexusConnectionError
from ida_nexus.handle import _ACQUIRED_PENDING, LeaseOpenFailure
import ida_nexus._resolver as resolver
from process_identity import identity
from r0_common import durable
from r0_transport import Boundary

ROOT = r0_sdk.ROOT


class SDKBoundaries(r0_sdk.SDKPrototypes):
    # R1 freezes cause as the original exception for both outcome APIs. The R0
    # prototype exposed a wrapper only for attach_outcome. Nine tests remain
    # unchanged; the ready test additionally asserts the new BeforeResolve.
    def test_early_acquired_callback_and_thread_failure_custody(self):
        events = []
        start = threading.Thread.start
        failure = RuntimeError("controlled monitor start failure")
        with Boundary(ROOT / "acquired") as boundary:
            def fail(thread):
                if thread.name.startswith("ida-nexus-lease-"):
                    self.assertEqual(events[-1][0], "acquired")
                    raise failure
                return start(thread)
            with patch.object(threading.Thread, "start", fail):
                result = DatabaseHandle.attach_outcome(boundary.instance,
                    on_acquired=lambda handle: events.append(("acquired", handle)))
            handle = result["handle"]
            try:
                self.assertIs(handle, events[0][1])
                self.assertIs(result["cause"], failure)
                self.assertIs(_ACQUIRED_PENDING[id(handle)], handle)
                self.assertEqual(result["failure_kind"], "cleanup_required")
                self.assertEqual(len(boundary.leases), 1)
            finally:
                closed = handle.close_outcome(wait_for_database=False, timeout=1)
            self.assertTrue(closed["lease_released"])
            self.assertNotIn(id(handle), _ACQUIRED_PENDING)
            self.assertIn({"phase": "monitor", "type": "RuntimeError"}, closed["cleanup_failures"])
        with Boundary(ROOT / "callback") as boundary:
            cause = ValueError("controlled custody callback failure")
            def reject(handle):
                events.append(("callback", handle))
                raise cause
            result = DatabaseHandle.attach_outcome(boundary.instance, on_acquired=reject)
            try:
                self.assertIs(result["handle"], events[-1][1])
                self.assertIs(result["cause"], cause)
                self.assertIs(_ACQUIRED_PENDING[id(result["handle"])], result["handle"])
            finally:
                self.assertTrue(result["handle"].close_outcome(wait_for_database=False, timeout=1)["lease_released"])

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
                    if stage == "AttachFailed":
                        self.assertIsInstance(result["cause"], LeaseOpenFailure)
                        self.assertEqual(result["cause"].status, 503)
                        self.assertIs(result["observer_errors"][0]["cause"], cause)
                    else:
                        self.assertIs(result["cause"], cause)
                    self.assertIsNone(result["handle"])
                    self.assertNotIn("Acquired", events)
                    self.assertEqual(sum(x["endpoint"] == "lease_rejected" for x in boundary.requests),
                                     1 if stage in ("AttachFailed", "ReconnectResolved") else 0)
                    self.assertEqual(result["sdk_reconnect_used"], stage == "ReconnectResolved")
                    rows.append({"stage": stage, "error": error_type.__name__, "events": events,
                                 "failure_kind": result["failure_kind"]})
        durable(ROOT / "observer-errors.json", rows)

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
                identities.append({"pid": value["pid"], "identity": identity(value["pid"])})
                self.assertEqual(stages[:3], ["BeforeResolve", "LaunchIntent", "Spawned"])
        try:
            with patch.object(resolver, "_find_console_script", return_value=str(executable)):
                outcome = DatabaseHandle.open_outcome(str(source),
                    options=DatabaseOpenOptions(startup_timeout=2), observer=observe)
            self.assertIsNone(outcome["handle"])
            self.assertIsNotNone(outcome["cause"])
            self.assertEqual([stage for stage, _ in outcome["launches"]], ["LaunchIntent", "Spawned", "LogReady"])
            self.assertEqual(len(children), 1)
        finally:
            for child in children:
                child.wait(timeout=3)
        def refuse(stage, _value):
            if stage == "LaunchIntent":
                raise RuntimeError("controlled before-Popen refusal")
        with patch.object(resolver, "_find_console_script", return_value=str(executable)):
            outcome = DatabaseHandle.open_outcome(str(source),
                options=DatabaseOpenOptions(startup_timeout=2), observer=refuse)
        self.assertEqual([stage for stage, _ in outcome["launches"]], ["LaunchIntent"])
        self.assertIsNone(outcome["handle"])
        durable(ROOT / "ready.json", {"stages": stages, "children_reaped": True,
            "child_processes": identities, "before_popen": "LaunchIntent only",
            "failure_obligation": "startup_unconfirmed"})


if __name__ == "__main__":
    # The loader sees only this module's subclass, not r0_sdk's TestCase object.
    unittest.main(verbosity=2)
