"""R1 installed-client public tiny-IDA chain. Unsupported SDK control exits 2.

Use a fresh prepared root. No private client hook, server change or persistent
custody is installed. A public callback records only this probe's launch facts.
"""
import argparse
import hashlib
import http.client
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import subprocess
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--expect-unpatched', action='store_true')
    args = parser.parse_args()
    sys.path.insert(0, str(REPO / 'tests/support'))
    from nexus_env import Environment
    env = Environment(args.root)
    if Path(sys.executable).parent.resolve() != env.root / 'venv/bin':
        parser.error("use this environment's venv/bin/python")
    if env.ledger.exists() or (env.root / 'sdk-boundary.json').exists():
        parser.error('fresh prepared root required')
    os.environ.clear()
    os.environ.update(env.variables())
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions, NexusConnectionError, wait_database_released
    contract = json.loads((REPO / 'scripts/nexus/client-sdk-contract.json').read_text())
    modules = {}
    for name in contract['files']:
        module = importlib.import_module('ida_nexus.' + name.removesuffix('.py'))
        path = Path(module.__file__).resolve()
        assert path.is_relative_to(env.root / 'venv')
        modules[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    supported = (all(modules[n]['sha256'] == h for n, h in contract['files'].items())
                 and all(hasattr(DatabaseHandle, n) for n in ('open_outcome', 'attach_outcome', 'claim_acquired')))
    assert supported is not args.expect_unpatched
    result = {'status': 'RED' if args.expect_unpatched else 'FAIL', 'sdk_modules': modules,
              'versions': {n: importlib.metadata.version(n) for n in ('ida-nexus', 'ida-domain')},
              'python': list(sys.version_info[:3]), 'owner_observation': 0,
              'custody': 'unavailable; R3a dependency'}
    if args.expect_unpatched:
        result['missing_boundary'] = True
        (env.root / 'sdk-boundary.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
        return 2
    handles, children, stages, operation_ids = [], [], [], []
    intent = None
    def observe(stage, value):
        nonlocal intent
        stages.append(stage)
        if stage == 'LaunchIntent':
            intent = env._begin_creation(['SDK-public-spawn', value['suffix']])
        elif stage == 'Spawned':
            child = value['process']
            children.append(child)
            env.record(child, child.args, intent=intent)
            intent = None
    request = http.client.HTTPConnection.request
    def record_request(connection, method, url, body=None, headers=None, **options):
        if url in ('/execute_python', '/wait_autoanalysis'):
            payload = json.loads(body)
            operation_ids.append(payload.get('operation_id'))
        return request(connection, method, url, body=body, headers=headers or {}, **options)
    def options(label):
        return DatabaseOpenOptions(output_database=env.root / 'fixtures' / (label + '.i64'),
            auto_analysis=False, startup_timeout=30, worker_env=env.variables(),
            worker_cwd=env.root, acquisition_observer=observe)
    try:
        with env.exclusive(), patch.object(http.client.HTTPConnection, 'request', record_request):
            legacy = DatabaseHandle.open(str(env.root / 'fixtures/mini'), options=options('legacy'))
            handles.append(legacy)
            attached = DatabaseHandle.attach(legacy.instance)
            handles.append(attached)
            assert attached.execute_python('result=42', operation_id='r1-legacy-execute')['result'] == 42
            assert attached.close() is None
            assert legacy.execute_python('import ida_kernwin\nresult=ida_kernwin.get_kernel_version()',
                operation_id='r1-owner-version')['result'] == '9.5'
            assert legacy.close(wait_for_database=True, timeout=20) is None
            assert wait_database_released(legacy.instance, timeout=0)
            result['legacy'] = {'open_attach_execute_close': True, 'owner_version': '9.5', 'owner_released': True}
            acquired = []
            cause = NexusConnectionError('probe public callback failure after real SSE')
            def refuse(handle):
                acquired.append(handle)
                handles.append(handle)
                raise cause
            outcome = DatabaseHandle.open_outcome(str(env.root / 'fixtures/mini'),
                options=options('outcome'), on_acquired=refuse)
            handle = outcome['handle']
            assert handle is acquired[0] and outcome['cause'] is cause
            assert outcome['failure_kind'] == 'cleanup_required' and not outcome['sdk_reconnect_used']
            assert not wait_database_released(handle.instance, timeout=0)
            assert handle.claim_acquired() is handle
            other = DatabaseHandle.attach_outcome(handle.instance)
            sibling = other['handle']
            handles.append(sibling)
            assert other['cause'] is None
            assert sibling.execute_python('result=43', operation_id='r1-outcome-execute')['result'] == 43
            assert sibling.wait_autoanalysis(timeout=10, operation_id='r1-outcome-wait')['complete']
            nonlast = sibling.close_outcome(wait_for_database=False, timeout=3)
            assert nonlast['ack_kind'] == 'nonlast' and nonlast['lease_released']
            last = handle.close_outcome(wait_for_database=True, timeout=20)
            assert last['ack_kind'] == 'last' and last['lease_released'] and last['owner_released']
            assert handle.close_outcome(timeout=1) == last
            result['outcome'] = {'callback_failure_retains_real_handle': True, 'claim': True,
                'attempts': len(outcome['attempts']), 'nonlast': nonlast, 'last': last}
            assert {'r1-legacy-execute', 'r1-owner-version', 'r1-outcome-execute', 'r1-outcome-wait'} <= set(operation_ids)
            result.update(status='PASS', stages=stages, operation_ids=operation_ids)
    except BaseException as exc:
        result['error_type'] = type(exc).__name__
        raise
    finally:
        cleanup_errors = []
        for handle in reversed(handles):
            try:
                handle.close_outcome(wait_for_database=True, timeout=5)
            except Exception as exc:
                cleanup_errors.append(type(exc).__name__)
        # Always reach exact ledger cleanup, even if public acquisition failed
        # after Popen but before a handle existed. Preserve the primary error.
        # Public lifetime release precedes Python process teardown. Reap each
        # exact held Popen before fallback cleanup can signal a healthy worker.
        # A bounded wait failure is recorded and still reaches owned cleanup.
        child_exits, child_wait_errors = [], []
        for child in children:
            try:
                child_exits.append({'pid': child.pid, 'returncode': child.wait(timeout=5)})
            except (OSError, subprocess.TimeoutExpired) as exc:
                child_wait_errors.append({'pid': child.pid, 'type': type(exc).__name__})
        forced = env.cleanup()
        env.assert_clean()
        result['audit'] = {'forced_cleanup': forced, 'sockets': env.residual_sockets(),
                           'child_exits': child_exits, 'child_wait_errors': child_wait_errors,
                           'cleanup_errors': cleanup_errors, 'records': len(env.entries()), 'unfinished_intents': [p.name for p in env.intents.glob('*.json')]}
        (env.root / 'sdk-boundary.json').write_text(json.dumps(result, indent=2) + '\n')
        if result['status'] == 'PASS':
            assert not forced and not cleanup_errors and not child_wait_errors
            assert all(child['returncode'] == 0 for child in child_exits)
            assert not result['audit']['sockets'] and not result['audit']['unfinished_intents']
    print(json.dumps({'status': result['status'], 'evidence': str(env.root / 'sdk-boundary.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
