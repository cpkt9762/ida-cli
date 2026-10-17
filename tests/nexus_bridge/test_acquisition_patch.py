"""R1 semantics on installed modules, including real HTTP/SSE and reentry."""
from concurrent.futures import ThreadPoolExecutor
import http.client
import inspect
import json
import os
from pathlib import Path
import sys
import threading
import typing
from unittest.mock import patch

import pytest
from ida_nexus import DatabaseHandle, DatabaseOpenOptions, NexusConnectionError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'support'))
from r0_transport import Boundary as TransportBoundary


class Boundary(TransportBoundary):
    def __init__(self, root, scenario="healthy"):
        super().__init__(root, scenario, stub_ida=False)

ROOT = Path(os.environ['R1_CASE_ROOT'])


# This test runs unchanged on the fresh three-patch SDK as a semantic red.
def test_parsed_ack_survives_cleanup():
    with Boundary(ROOT / 'ack-semantic') as boundary:
        h = DatabaseHandle.attach(boundary.instance)
        original = http.client.HTTPConnection
        cause = OSError('cleanup after valid ACK')
        def factory(*args, **kwargs):
            c = original(*args, **kwargs)
            getresponse = c.getresponse
            def response():
                r = getresponse()
                close = r.close
                def fail():
                    close()
                    raise cause
                r.close = fail
                return r
            c.getresponse = response
            return c
        with patch.object(http.client, 'HTTPConnection', factory):
            outcome = h.close_outcome(wait_for_database=False, timeout=1)
        assert outcome['lease_released'] is True
        assert outcome['ack_kind'] == 'last'
        assert h.close_outcome(timeout=1) == outcome
        assert len([r for r in boundary.requests if r['endpoint'] == '/release_lease']) == 1


def test_types_signatures_and_complete_contract():
    from ida_nexus.handle import AcquisitionOutcome, AttachAttempt
    from ida_nexus.options import AcquisitionStage
    import ida_nexus._resolver as resolver
    assert DatabaseOpenOptions(False).spawn is False
    assert resolver.WorkerLaunchOptions(None, '/private/tmp').worker_cwd == '/private/tmp'
    for cls in (DatabaseOpenOptions, resolver.WorkerLaunchOptions):
        assert inspect.signature(cls).parameters['acquisition_observer'].kind == inspect.Parameter.KEYWORD_ONLY
        assert typing.get_type_hints(cls)['acquisition_observer'] is not object
    for method in (DatabaseHandle.open_outcome, DatabaseHandle.attach_outcome):
        signature = inspect.signature(method)
        assert all(p.kind != inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values())
        assert typing.get_type_hints(method)['return'] is AcquisitionOutcome
    assert 'AttachMayBeSent' in typing.get_args(AcquisitionStage)
    assert {'instance','stage','http_status','obligation','handle','cause'} <= typing.get_type_hints(AttachAttempt).keys()
    with Boundary(ROOT / 'types') as b:
        # Upstream wait_autoanalysis returns a flat AnalysisResult. The frozen
        # R0 boundary's generic endpoint envelope was never used for this API.
        handler = b.server.RequestHandlerClass
        reply = handler.reply
        def analysis_reply(request, payload, status=200):
            if request.path == '/wait_autoanalysis':
                payload = payload['result']
            return reply(request, payload, status)
        handler.reply = analysis_reply
        result = DatabaseHandle.attach_outcome(b.instance)
        try:
            assert set(result) == AcquisitionOutcome.__required_keys__
            assert result['first_instance'] is b.instance
            assert result['attempts'][0]['instance'] is b.instance
            assert result['handle'].execute_python('result=42', operation_id='r1-exact-execute')['result'] == 42
            assert b.requests[-1]['operation_id'] == 'r1-exact-execute'
            # Exercise the existing wait parameter without adding another ID API.
            result['handle'].wait_autoanalysis(operation_id='r1-exact-wait', timeout=1)
            assert b.requests[-1]['operation_id'] == 'r1-exact-wait'
        finally:
            result['handle'].close_outcome(wait_for_database=False, timeout=1)
        (ROOT / 'contract-keys.json').write_text(json.dumps({'outcome':sorted(result),
            'attempt':sorted(result['attempts'][0]), 'open_signature':str(inspect.signature(DatabaseHandle.open_outcome))}))


@pytest.mark.parametrize('mode', ['claim-fail', 'close-fail', 'recursive', 'close-success'])
def test_acquired_reentry_claim_and_close(mode):
    from ida_nexus.handle import _ACQUIRED_PENDING
    with Boundary(ROOT / mode) as b:
        cause = NexusConnectionError('observer is not transport')
        acquired = []
        def accept(h):
            assert _ACQUIRED_PENDING[id(h)] is h
            acquired.append(h)
            if mode == 'claim-fail':
                assert h.claim_acquired() is h
                assert h.claim_acquired() is h
                raise cause
            if mode.startswith('close'):
                assert h.close_outcome(wait_for_database=False, timeout=1)['lease_released']
                if mode == 'close-fail':
                    raise cause
            if mode == 'recursive':
                inner = DatabaseHandle.attach_outcome(b.instance)
                assert inner['handle'] is not h
                assert inner['handle'].close_outcome(wait_for_database=False, timeout=1)['lease_released']
        result = DatabaseHandle.attach_outcome(b.instance, on_acquired=accept)
        h = result['handle']
        try:
            assert h is acquired[0]
            assert not result['sdk_reconnect_used']
            assert result['cause'] is (cause if mode.endswith('fail') else None)
            assert id(h) not in _ACQUIRED_PENDING
            if mode.startswith('close'):
                assert h._lease_thread is None
            assert len([r for r in b.requests if r['endpoint'] == 'lease']) == (2 if mode == 'recursive' else 1)
        finally:
            h.close_outcome(wait_for_database=False, timeout=1)


def test_constructor_failure_retains_exact_handle_before_any_thread():
    from ida_nexus.handle import _ACQUIRED_PENDING
    with Boundary(ROOT / 'thread-constructor') as b:
        factory = threading.Thread
        cause = OSError('monitor constructor failure')
        def thread(*args, **kwargs):
            if kwargs.get('name', '').startswith('ida-nexus-lease-'):
                raise cause
            return factory(*args, **kwargs)
        with patch.object(threading, 'Thread', thread):
            result = DatabaseHandle.attach_outcome(b.instance)
        h = result['handle']
        try:
            assert result['cause'] is cause
            assert _ACQUIRED_PENDING[id(h)] is h
            assert result['attempts'][0]['obligation'] == 'exact_handle'
            assert len(b.leases) == 1
        finally:
            assert h.close_outcome(wait_for_database=False, timeout=1)['lease_released']
        assert id(h) not in _ACQUIRED_PENDING


@pytest.mark.parametrize('lost_ack', [False, True])
def test_close_claim_race_and_response_reentry(lost_ack):
    with Boundary(ROOT / ('race-' + str(lost_ack)), 'lost-ack' if lost_ack else 'healthy') as b:
        h = DatabaseHandle.attach(b.instance)
        entered, resume = threading.Event(), threading.Event()
        original = http.client.HTTPConnection
        snapshots = []
        def factory(*args, **kwargs):
            c = original(*args, **kwargs)
            read = c.getresponse
            def response():
                entered.set()
                assert resume.wait(3), 'release response barrier'
                r = read()
                close = r.close
                def cleanup():
                    snapshots.append(h.close_outcome(timeout=1))
                    h.close(timeout=1)
                    close()
                r.close = cleanup
                return r
            c.getresponse = response
            return c
        with patch.object(http.client, 'HTTPConnection', factory), ThreadPoolExecutor(3) as pool:
            first = pool.submit(h.close_outcome, wait_for_database=False, timeout=2)
            assert entered.wait(1)
            claim = pool.submit(h.claim_acquired)
            second = pool.submit(h.close_outcome, wait_for_database=False, timeout=2)
            try:
                assert claim.result(timeout=1) is h
            finally:
                resume.set()
            a, c = first.result(timeout=3), second.result(timeout=3)
        assert a == c == h.close_outcome(timeout=1)
        assert a['lease_released'] is not lost_ack
        assert len([r for r in b.requests if r['endpoint'] == '/release_lease']) == 1
        if not lost_ack:
            assert snapshots[0]['ack_kind'] == 'last'
            assert snapshots[0]['lease_released']
        a.setdefault('cleanup_failures', []).append({'phase':'caller', 'type':'mutated'})
        assert {'phase':'caller','type':'mutated'} not in h.close_outcome().get('cleanup_failures', [])


def test_parameter_and_observer_refusal_are_before_send():
    with Boundary(ROOT / 'before-send') as b:
        cause = OSError('observer refuses request')
        def observe(stage, value):
            if stage == 'AttachMayBeSent':
                raise cause
        result = DatabaseHandle.attach_outcome(b.instance, on_stage=observe)
        assert result['cause'] is cause
        assert result['failure_kind'] == 'not_sent'
        assert result['stage'] == 'BeforeAttach'
        assert result['unresolved_attempts'] == []
        assert not b.requests
        invalid = DatabaseHandle.attach_outcome(b.instance, keepalive=-1)
        assert invalid['failure_kind'] == 'not_sent'
        assert isinstance(invalid['cause'], ValueError)
        assert not b.requests


def test_callback_inflight_claim_close_from_other_thread():
    from ida_nexus.handle import _ACQUIRED_PENDING
    with Boundary(ROOT / 'inflight-callback') as b, ThreadPoolExecutor(2) as pool:
        entered, resume = threading.Event(), threading.Event()
        handles = []
        def acquired(h):
            handles.append(h)
            entered.set()
            assert resume.wait(3), 'finish acquired callback after external cleanup'
        future = pool.submit(DatabaseHandle.attach_outcome, b.instance, on_acquired=acquired)
        assert entered.wait(1)
        h = handles[0]
        try:
            assert _ACQUIRED_PENDING[id(h)] is h
            assert pool.submit(h.claim_acquired).result(timeout=1) is h
            assert h.close_outcome(wait_for_database=False, timeout=1)['lease_released']
        finally:
            resume.set()
        result = future.result(timeout=2)
        assert result['handle'] is h and result['cause'] is None
        assert h._lease_thread is None
        assert id(h) not in _ACQUIRED_PENDING
        assert len([r for r in b.requests if r['endpoint'] == '/release_lease']) == 1


def test_legacy_monitor_failure_keeps_original_exception_and_never_reconnects():
    from ida_nexus.handle import _ACQUIRED_PENDING
    with Boundary(ROOT / 'legacy-monitor') as b:
        factory = threading.Thread
        cause = NexusConnectionError('legacy monitor constructor fault')
        def thread(*args, **kwargs):
            if kwargs.get('name', '').startswith('ida-nexus-lease-'):
                raise cause
            return factory(*args, **kwargs)
        with patch.object(threading, 'Thread', thread), pytest.raises(NexusConnectionError) as caught:
            DatabaseHandle.open(str(b.path), options=DatabaseOpenOptions(spawn=False))
        assert caught.value is cause
        h = cause.handle
        try:
            assert _ACQUIRED_PENDING[id(h)] is h
            assert len([r for r in b.requests if r['endpoint'] == 'lease']) == 1
        finally:
            assert h.close_outcome(wait_for_database=False, timeout=1)['lease_released']
        assert id(h) not in _ACQUIRED_PENDING


@pytest.mark.parametrize('name', ['handle.py', '_resolver.py', 'options.py'])
def test_readiness_checks_each_loaded_sdk_module(name, monkeypatch):
    import bridge
    import ida_nexus
    from protocol import SDK_FILES
    manifest = json.loads((Path(__file__).resolve().parents[2] / 'scripts/nexus/client-sdk-contract.json').read_text())
    assert SDK_FILES == manifest['files']
    source = Path(ida_nexus.__file__).resolve().parent / name
    original = Path.read_bytes
    def altered(path):
        value = original(path)
        return value + b'\n# incompatible SDK source\n' if path.resolve() == source else value
    monkeypatch.setattr(Path, 'read_bytes', altered)
    ready = bridge.readiness()
    assert ready['ready'] is False
    assert 'ProtocolMismatch' in ready['error']['message']
    assert name in ready['error']['message']


def test_reconnect_keeps_distinct_original_instances_and_old_unknown():
    with Boundary(ROOT / 'instance-a') as a, Boundary(ROOT / 'instance-b') as b:
        original = http.client.HTTPConnection
        class LostFirstResponse(original):
            def request(self, method, url, *args, **kwargs):
                self.is_attach = 'sse=1' in url
                return super().request(method, url, *args, **kwargs)
            def getresponse(self):
                response = super().getresponse()
                if self.port == a.instance.port and getattr(self, 'is_attach', False):
                    response.close()
                    raise OSError('first owner response lost')
                return response
        with patch('ida_nexus.handle.resolve_instance', side_effect=[a.instance, b.instance]), \
                patch.object(http.client, 'HTTPConnection', LostFirstResponse):
            result = DatabaseHandle.open_outcome(str(a.path), options=DatabaseOpenOptions(spawn=False))
        h = result['handle']
        try:
            assert result['first_instance'] is a.instance
            assert result['instance'] is b.instance
            assert result['attempts'][0]['instance'] is a.instance
            assert result['attempts'][1]['instance'] is b.instance
            assert result['unresolved_attempts'] == [result['attempts'][0]]
            assert result['failure_kind'] == 'unknown_attach' and result['sdk_reconnect_used']
            assert h.instance is b.instance
        finally:
            assert h.close_outcome(wait_for_database=False, timeout=1)['lease_released']
        assert result['unresolved_attempts'][0]['instance'] is a.instance
        assert result['unresolved_attempts'][0]['obligation'] == 'unknown_attach'


def test_popen_failure_keeps_preallocated_intent_without_inventing_child():
    import subprocess
    source = ROOT / 'spawn-input'
    source.write_bytes(b'private controlled spawn input')
    cause = OSError('controlled process creation failure')
    with patch.object(subprocess, 'Popen', side_effect=cause):
        result = DatabaseHandle.open_outcome(str(source))
    assert result['cause'] is cause and result['handle'] is None
    assert result['stage'] == 'LaunchIntent'
    assert result['failure_kind'] == 'startup_unconfirmed'
    assert [stage for stage, value in result['launches']] == ['LaunchIntent']
    assert result['launches'][0][1]['suffix']
    assert 'process' not in result['launches'][0][1]
    assert result['attempts'] == []


def test_before_resolve_observer_refusal_never_calls_resolver():
    cause = NexusConnectionError('observer refuses resolution')
    events = []
    def refuse(stage, value):
        events.append((stage, value))
        raise cause
    with patch('ida_nexus.handle.resolve_instance') as resolve:
        result = DatabaseHandle.open_outcome(str(ROOT / 'not-resolved'), observer=refuse)
    resolve.assert_not_called()
    assert events == [('BeforeResolve', {'path': str(ROOT / 'not-resolved'), 'reconnect': False})]
    assert result['cause'] is cause and result['failure_kind'] == 'not_sent'
    assert not result['sdk_reconnect_used'] and result['attempts'] == []


def test_failed_second_resolve_keeps_retry_fact_and_first_unknown():
    with Boundary(ROOT / 'resolve-failure') as b:
        original = http.client.HTTPConnection
        class LostResponse(original):
            def getresponse(self):
                response = super().getresponse()
                response.close()
                raise OSError('lease response lost')
        cause = TimeoutError('second resolve timed out')
        events = []
        with patch('ida_nexus.handle.resolve_instance', side_effect=[b.instance, cause]), \
                patch.object(http.client, 'HTTPConnection', LostResponse):
            result = DatabaseHandle.open_outcome(str(b.path), observer=lambda stage, value: events.append((stage, value)))
        assert result['cause'] is cause and result['sdk_reconnect_used']
        assert result['failure_kind'] == 'unknown_attach'
        assert result['unresolved_attempts'] == result['attempts']
        assert len(result['attempts']) == 1 and result['first_instance'] is b.instance
        assert events[-1] == ('BeforeResolve', {'path': str(b.path), 'reconnect': True})
