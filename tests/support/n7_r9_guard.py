"""Real owner fault injection; every IDB is a private copy of a prepared seed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts'))
from compare_nexus_baseline import Candidate, Environment


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--root', type=Path, required=True)
    args.add_argument('--binary', type=Path, required=True)
    args.add_argument('--seed', type=Path, required=True)
    args.add_argument('--bridge', type=Path)
    args.add_argument('--bad-seed', type=Path)
    parsed = args.parse_args()
    env = Environment(parsed.root)
    extra = {'N6_TEST_BRIDGE_SOURCE': str(parsed.bridge)} if parsed.bridge else {}
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    results, clients = {}, []

    def start(path, label, **kwargs):
        client = Candidate(env, parsed.binary, path, label, transport='stdio',
                           extra=extra | kwargs, allow_open_error=True)
        clients.append(client)
        return client

    def close(client):
        result = client.call('close_idb', {'close_token': client.opened['close_token']})
        client.opened = None
        client.stop()
        clients.remove(client)
        return result

    def copy(name):
        path = env.root / 'fixtures' / (name+'.i64')
        shutil.copyfile(parsed.seed, path)
        return path

    try:
        path = copy('guard-loss')
        before = digest(path)
        first = start(path, 'loss-a')
        second = start(path, 'loss-b')
        assert first.opened and second.opened, (first.open_result, second.open_result)
        original = first.call('get_database_info', {})
        mutation = first.call('run_script', {'code': "import ida_netnode\nida_netnode.netnode('Root Node', 0, False).kill()"})
        save = second.call('run_script', {'code': "import ida_loader\nassert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)"})
        after_save = digest(path)
        close_first = close(first)
        close_last = close(second)
        after_close = digest(path)
        reopened = start(path, 'loss-reopen')
        info = reopened.call('get_database_info', {}) if reopened.opened else reopened.open_result
        if reopened.opened:
            close(reopened)
        else:
            reopened.stop(); clients.remove(reopened)
        message = lambda value: 'Root Node' in str(value) and 'original file retained' in str(value)
        results['loss'] = {'before': before, 'after_save': after_save, 'after_close': after_close,
            'mutation': mutation, 'save': save, 'first_close': close_first, 'last_close': close_last,
            'before_info': original, 'reopened_info': info,
            'protected': before == after_save == after_close and all(map(message, (mutation, save, close_first, close_last)))
                and info.get('result', {}).get('input_file_size', 0) > 0}
        attribution = []
        for log in (env.root / 'state/logs').glob('*.log'):
            for line in log.read_text(errors='replace').splitlines():
                marker = 'Root Node save protection: '
                if marker in line:
                    entry = json.loads(line.split(marker, 1)[1])
                    if entry['actual_idb_path'] == str(path.resolve()) and entry['first_transition']:
                        attribution.append(entry)
        results['loss']['attribution'] = attribution
        results['loss']['protected'] &= any(
            item['operation'].get('method') == 'run_script' and item['operation'].get('operation_id')
            and item['operation'].get('lease', {}).get('lease_id')
            and item['previous_sample']['stage'] == 'before' for item in attribution)

        path = copy('guard-open-loss')
        before = digest(path)
        client = start(path, 'open-loss', N7_R9_LOSS_ON_OPEN='1')
        opened = client.open_result
        if client.opened:
            close(client)
        else:
            client.stop(); clients.remove(client)
        after = digest(path)
        reopened = start(path, 'open-reopen')
        info = reopened.call('get_database_info', {}) if reopened.opened else reopened.open_result
        if reopened.opened:
            close(reopened)
        else:
            reopened.stop(); clients.remove(reopened)
        results['open_loss'] = {'open': opened, 'before': before, 'after': after,
            'reopen': info, 'protected': 'error' in opened and message(opened)
                and before == after and info.get('result', {}).get('input_file_size', 0) > 0}

        path = copy('guard-normal')
        client = start(path, 'normal')
        changed = client.call('run_script', {'code': "import ida_bytes, ida_ida\nassert ida_bytes.set_cmt(ida_ida.inf_get_min_ea(), 'r9 guard normal persistence', False)"})
        saved = client.call('run_script', {'code': "import ida_loader\nassert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)"})
        closed = close(client)
        client = start(path, 'normal-reopen')
        persisted = client.call('run_script', {'code': "import ida_bytes, ida_ida\nprint(ida_bytes.get_cmt(ida_ida.inf_get_min_ea(), False))"})
        close(client)
        results['normal'] = {'changed': changed, 'saved': saved, 'closed': closed,
            'persisted': persisted, 'protected': 'result' in closed
                and 'r9 guard normal persistence' in str(persisted)}
        if parsed.bad_seed:
            path = env.root/'fixtures/guard-preexisting.i64'
            shutil.copyfile(parsed.bad_seed, path)
            before = digest(path)
            client = start(path, 'preexisting')
            opened = client.open_result
            if client.opened:
                close(client)
            else:
                client.stop(); clients.remove(client)
            results['preexisting'] = {'open': opened, 'before': before, 'after': digest(path),
                'protected': 'error' in opened and before == digest(path)}
    finally:
        for client in clients:
            try:
                client.opened = None
                client.stop()
            except Exception as exc:
                results.setdefault('cleanup_errors', []).append(type(exc).__name__)
        env.cleanup()
        env.assert_clean()
        (env.root / 'r9-guard-result.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(results))
    assert all(value['protected'] for value in results.values()), results


if __name__ == '__main__':
    main()
