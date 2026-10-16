"""Lose a real final release ACK behind an owned IDB-close barrier.

Old cancel-only client: --expect-unpatched exits 2 after proving false success.
New client: uncertainty then public owner lifetime proof exits 0. No replay.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]


def wait_for(path, timeout=5):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"close barrier missing: {path.name}")
        threading.Event().wait(0.005)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expect-unpatched', action='store_true')
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(REPO / 'scripts'))
    from verify_nexus_n0 import Environment, owned_nexus_spawn
    env = Environment(args.root)
    if env.root.is_relative_to(REPO) or REPO.is_relative_to(env.root):
        parser.error('use a fresh external environment')
    if env.ledger.exists() or (env.root / 'close-proof.json').exists():
        parser.error('refusing a used environment')
    if not (env.root / 'profile/.n0-isolated-profile').is_file():
        parser.error('isolated N0 profile required')
    if Path(sys.executable).parent.resolve() != env.root / 'venv/bin':
        parser.error("use this environment's venv/bin/python")
    os.environ.clear()
    os.environ.update(env.variables())
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions, wait_database_released
    from ida_nexus import _resolver
    from lifecycle import release_handle
    from bridge import guarded_source
    original_spawn = _resolver.spawn_worker
    def spawn(*args, **kwargs):
        return owned_nexus_spawn(env, original_spawn, *args, **kwargs)
    def resolve(*args, **kwargs):
        return _resolver.resolve_instance(*args, **kwargs, spawner=spawn)
    def interrupted(sig, _frame):
        raise InterruptedError(f'probe signal {sig}')
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    handle = instance = None
    entered, allow = env.root / 'close-entered', env.root / 'allow-close'
    rows = {'status': 'FAIL', 'client_patch': env.client_patch_status()}
    assert rows['client_patch']['close_applied'] != args.expect_unpatched
    try:
        with env.exclusive():
            with patch('ida_nexus.handle.resolve_instance', side_effect=resolve):
                handle = DatabaseHandle.open(str(env.root / 'fixtures/mini'), options=DatabaseOpenOptions(
                    startup_timeout=10, worker_env=env.variables(), worker_cwd=env.root))
            instance = handle.instance
            code = f'''import ida_domain.database as db_module
from pathlib import Path
import time
db_module._probe_real_close = db_module.Database.close
def delayed_close(self, save=None):
    Path({str(entered)!r}).touch()
    end = time.monotonic() + 15
    while not Path({str(allow)!r}).exists():
        if time.monotonic() >= end:
            raise TimeoutError('probe close barrier expired')
        time.sleep(.005)
    return db_module._probe_real_close(self, save=save)
db_module.Database.close = delayed_close
result=True
'''
            assert handle.execute_python(guarded_source(code, {
                'method': 'close-proof-probe', 'requested_path': str(env.root / 'fixtures/mini'),
                'record_id': instance.record_id}), timeout=3)['result'] is True
            original_request = http.client.HTTPConnection.request
            original_response = http.client.HTTPConnection.getresponse
            requests = []
            def request(connection, method, url, *args, **kwargs):
                connection.probe_release = method == 'POST' and url == '/release_lease'
                if connection.probe_release:
                    requests.append(url)  # Never record headers or lease secrets.
                return original_request(connection, method, url, *args, **kwargs)
            def response(connection):
                reply = original_response(connection)
                if getattr(connection, 'probe_release', False):
                    payload = json.loads(reply.read())
                    rows['actual_final_ack'] = payload['result']
                    reply.close()
                    raise http.client.RemoteDisconnected('probe dropped committed final release ACK')
                return reply
            events = []
            def publish(name, outcome):
                events.append({'event': name, 'outcome': outcome})
                if name == 'uncertain':
                    wait_for(entered)
                    assert not wait_database_released(instance, timeout=0)
                    allow.touch()  # Causal release, never a timed sleep.
            with patch.object(http.client.HTTPConnection, 'request', request), patch.object(
                    http.client.HTTPConnection, 'getresponse', response):
                if args.expect_unpatched:
                    assert handle.close(wait_for_database=True, timeout=3) is None
                    wait_for(entered)
                    assert not wait_database_released(instance, timeout=0)
                    rows['false_success_without_owner_proof'] = True
                else:
                    result = release_handle(handle, time.monotonic() + 5, publish)
                    assert events[0]['event'] == 'uncertain'
                    assert result['status'] == 'owner_released'
                    assert wait_database_released(instance, timeout=0)
                    assert handle.close_outcome()['status'] == 'uncertain', 'no replay/cached outcome'
                    rows['reconciled'] = result
            assert len(requests) == 1, requests
            assert rows['actual_final_ack'] == {'released': True, 'shutdown_pending': True}
            rows.update(status='RED' if args.expect_unpatched else 'PASS', events=events,
                        release_requests=len(requests), pid=instance.pid, idb=instance.idb_path)
    finally:
        allow.touch()
        if instance is not None:
            rows['released_after_barrier'] = wait_database_released(instance, timeout=5)
        if handle is not None:
            handle.close(wait_for_database=True, timeout=3)
        signalled = env.cleanup()
        env.assert_clean()
        assert not env.residual_sockets()
        rows['audit'] = {'cleanup': 'CLEAN', 'records': len(env.entries()),
                         'sockets': env.residual_sockets(), 'signalled': signalled}
        (env.root / 'close-proof.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(json.dumps(rows))
    return 2 if args.expect_unpatched else 0


if __name__ == '__main__':
    sys.path.insert(0, str(REPO / 'nexus_bridge'))
    raise SystemExit(main())
