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


@pytest.mark.parametrize('observation', ['false', 'oserror', 'runtimeerror'])
def test_legacy_observation_contract(observation):
    """Also runs unchanged against the historical three-patch SDK."""
    with Boundary(ROOT / ('legacy-observation-' + observation)) as b:
        h = DatabaseHandle.attach(b.instance)
        monitor = h._lease_thread
        cause = {'false': None, 'oserror': OSError('public observation failed'),
                 'runtimeerror': RuntimeError('public observation failed')}[observation]
        with patch('ida_nexus.handle.wait_database_released', return_value=False,
                   side_effect=cause) as observe:
            try:
                with pytest.raises(Exception) as caught:
                    h.close(wait_for_database=True, timeout=0.1)
                if cause is None:
                    assert type(caught.value) is NexusConnectionError
                    assert str(caught.value) == 'timed out after 0.1s waiting for the IDB to close'
                else:
                    assert caught.value is cause
                observe.assert_called_once()
            finally:
                h.close(wait_for_database=False)
        assert not monitor.is_alive()
        assert h._lease_response is h._lease_connection is h._lease_socket is None
        assert len([r for r in b.requests if r['endpoint'] == '/release_lease']) == 1


@pytest.mark.parametrize('observation', ['false', 'oserror', 'runtimeerror'])
@pytest.mark.parametrize('nonlast', [False, True])
def test_structured_observation_preserves_ack(nonlast, observation):
    with Boundary(ROOT / f'observation-{nonlast}-{observation}') as b:
        h = DatabaseHandle.attach(b.instance)
        sibling = DatabaseHandle.attach(b.instance) if nonlast else None
        cause = {'false': None, 'oserror': OSError('public observation failed'),
                 'runtimeerror': RuntimeError('public observation failed')}[observation]
        try:
            with patch('ida_nexus.handle.wait_database_released', return_value=False,
                       side_effect=cause) as observe:
                result = h.close_outcome(wait_for_database=True, timeout=0.1)
            assert result['lease_released'] and not result['owner_released']
            assert result['ack_kind'] == ('nonlast' if nonlast else 'last')
            assert result['owner_pending'] is not nonlast
            assert result['failure'] is None
            if nonlast:
                observe.assert_not_called()
                assert 'observation_failure' not in result
            else:
                observe.assert_called_once()
                assert result['observation_failure'] == ('timeout' if cause is None else 'exception')
                if cause is not None:
                    assert result['observation_failure_type'] == type(cause).__name__
                    assert {'phase': 'owner_observation', 'type': type(cause).__name__} in result['cleanup_failures']
            assert h.close_outcome(timeout=0) == result
        finally:
            h.close(wait_for_database=False)
            if sibling is not None:
                sibling.close(wait_for_database=False)
        assert len([r for r in b.requests if r['endpoint'] == '/release_lease'
                    and r['lease_id'] == h._lease_id]) == 1


@pytest.mark.parametrize('observation', ['false', 'exception'])
def test_release_primary_survives_cleanup_and_observation(observation):
    with Boundary(ROOT / ('release-primary-' + observation)) as b:
        h = DatabaseHandle.attach(b.instance)
        monitor = h._lease_thread
        primary = RuntimeError('release response cleanup failed')
        secondary = OSError('public observation failed')
        rpc_error = RuntimeError('RPC cleanup failed')
        original = http.client.HTTPConnection
        class ReleaseCleanupFailure(original):
            def getresponse(self):
                response = super().getresponse()
                close = response.close
                def fail():
                    close()
                    raise primary
                response.close = fail
                return response
        class RpcCleanupFailure:
            def close(self):
                raise rpc_error
        h._rpc_connection = RpcCleanupFailure()
        try:
            with patch.object(http.client, 'HTTPConnection', ReleaseCleanupFailure), \
                    patch('ida_nexus.handle.wait_database_released', return_value=False,
                          side_effect=secondary if observation == 'exception' else None):
                with pytest.raises(RuntimeError) as caught:
                    h.close(wait_for_database=True, timeout=0.1)
            assert caught.value is primary
            result = h.close_outcome(timeout=0)
            assert result['lease_released'] and result['ack_kind'] == 'last'
            assert result['owner_pending'] and not result['owner_released']
            assert result['observation_failure'] == ('exception' if observation == 'exception' else 'timeout')
            phases = [item['phase'] for item in result['cleanup_failures']]
            assert 'response' in phases and 'rpc' in phases
            if observation == 'exception':
                assert 'owner_observation' in phases
        finally:
            h.close(wait_for_database=False)
        assert not monitor.is_alive()
        assert h._lease_response is h._lease_connection is h._lease_socket is None
        assert len([r for r in b.requests if r['endpoint'] == '/release_lease']) == 1


@pytest.mark.parametrize('phase', ['before-ack', 'last', 'nonlast', 'lost-ack', 'invalid-ack'])
def test_concurrent_close_deadline_preserves_published_facts(phase):
    """Real HTTP plus deterministic cleanup barrier; never sets SDK outcome."""
    with Boundary(ROOT / ('short-close-' + phase), 'lost-ack' if phase == 'lost-ack' else 'healthy') as b:
        if phase == 'invalid-ack':
            handler = b.server.RequestHandlerClass
            reply = handler.reply
            def invalid(request, payload, status=200):
                if request.path == '/release_lease':
                    payload = {'ok': True, 'result': {'released': True, 'shutdown_pending': 'invalid'}}
                return reply(request, payload, status)
            handler.reply = invalid
        h = DatabaseHandle.attach(b.instance)
        sibling = DatabaseHandle.attach(b.instance) if phase == 'nonlast' else None
        monitor = h._lease_thread
        entered, resume = threading.Event(), threading.Event()
        original = http.client.HTTPConnection
        completed, errors, reentered = [], [], []
        def barrier():
            if not entered.is_set():
                reentered.append(h.close_outcome(timeout=0))
                h.close(timeout=0)
                entered.set()
                assert resume.wait(3), 'release the first close cleanup barrier'
        class PausedRelease(original):
            def getresponse(self):
                if phase == 'before-ack':
                    barrier()
                response = super().getresponse()
                close = response.close
                def cleanup():
                    if phase not in ('before-ack', 'lost-ack'):
                        barrier()
                    close()
                response.close = cleanup
                return response
            def close(self):
                if phase == 'lost-ack':
                    barrier()
                super().close()
        def first_close():
            try:
                completed.append(h.close_outcome(wait_for_database=False, timeout=2))
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=first_close, name='r1-short-close')
        try:
            with patch.object(http.client, 'HTTPConnection', PausedRelease):
                thread.start()
                assert entered.wait(2), 'first close reached the HTTP/cleanup barrier'
                for budget in (0.01, 0):
                    result = h.close_outcome(wait_for_database=False, timeout=budget)
                    assert result['lease_released'] is (phase in ('last', 'nonlast'))
                    assert result['close_in_progress'] is True
                    assert result['wait_failure'] == 'deadline'
                    if phase in ('last', 'nonlast'):
                        assert result['ack_kind'] == phase
                        assert result['owner_pending'] is (phase == 'last')
                        assert result['failure'] is None
                    else:
                        assert result['status'] == 'uncertain' and 'ack_kind' not in result
                    assert not result['owner_released']
                    assert h.claim_acquired() is h
                    result.setdefault('cleanup_failures', []).append({'phase': 'caller', 'type': 'mutated'})
                resume.set()
                thread.join(4)
            assert not thread.is_alive() and not errors, errors
            final = completed[0]
            assert h.close_outcome(timeout=0) == final
            assert 'wait_failure' not in final and 'close_in_progress' not in final
            assert not any(item['phase'] == 'caller' for item in final.get('cleanup_failures', []))
            assert final['lease_released'] is (phase not in ('lost-ack', 'invalid-ack'))
            assert reentered[0]['lease_released'] is (phase in ('last', 'nonlast'))
            assert not monitor.is_alive()
        finally:
            resume.set()
            if thread.ident is not None:
                thread.join(4)
            h.close(wait_for_database=False)
            if sibling is not None:
                sibling.close(wait_for_database=False)
        assert not thread.is_alive()
        assert len([r for r in b.requests if r['endpoint'] == '/release_lease'
                    and r['lease_id'] == h._lease_id]) == 1
