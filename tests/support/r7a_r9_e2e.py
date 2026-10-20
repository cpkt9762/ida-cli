"""Actual Tools/N1/SDK initial Root retry limit and no mid-session reopen."""
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


class ReleaseClient(Candidate):
    def call(self, method, params):
        if method != 'close_idb':
            return super().call(method, params)
        response = self.client.rpc('tools/call', {'name': method, 'arguments': params})
        result = response['result']
        content = result['content']
        assert len(content) in (1, 2) and all(item['type'] == 'text' for item in content), result
        lifecycle = None
        if len(content) == 2:
            extra = json.loads(content[1]['text'])
            assert set(extra) == {'lifecycle'} and isinstance(extra['lifecycle'], dict), extra
            lifecycle = extra['lifecycle']
            assert lifecycle['lease']['lease_id'] and lifecycle['owner']['record_id'], lifecycle
        return {'error' if result.get('isError') else 'result': content[0]['text'],
                'lifecycle': lifecycle}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--seed', type=Path, required=True)
    args = parser.parse_args()
    env = Environment(args.root)
    os.environ.update(env.variables())
    os.environ['N3_IPC_ROOT'] = str(env.root / 'i')
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    results = []
    client = None
    with env.exclusive():
        try:
            for losses in (1, 3, 0):
                name = 'losses-' + str(losses)
                path = env.root / 'fixtures' / (name + '.i64')
                trace = env.root / (name + '.jsonl')
                shutil.copyfile(args.seed, path)
                before = digest(path)
                client = ReleaseClient(env, args.binary, path, name, transport='stdio', allow_open_error=True,
                    extra={'IDA_NEXUS_BRIDGE_SCRIPT': str(REPO / 'tests/support/r7a_real_bridge.py'),
                           'R7A_ROOT_FAILURES': str(losses), 'R7A_ROOT_TRACE': str(trace)})
                opening = client.open_result
                owners = [row for row in map(json.loads, trace.read_text().splitlines()) if 'ordinal' in row]
                if losses == 3:
                    assert 'error' in opening and '3 attempts' in str(opening), opening
                    assert len(owners) == 3 and len({row['owner'] for row in owners}) == 3, owners
                    assert before == digest(path), 'three refused initial opens modified seed'
                else:
                    assert client.opened, opening
                    assert len(owners) == losses + 1, owners
                    if losses == 1:
                        checkpoints = [row for row in map(json.loads, trace.read_text().splitlines())
                                       if 'before_retry_ordinal' in row]
                        assert len(checkpoints) == 1 and checkpoints[0]['packed_sha256'] == before, checkpoints
                    if losses == 0:
                        lost = client.call('run_script', {'code':
                            "import ida_netnode\nida_netnode.netnode('Root Node',0,False).kill()"})
                        assert 'Root Node' in str(lost) and 'original file retained' in str(lost), lost
                        rejected = client.call('get_database_info', {})
                        assert 'Root Node' in str(rejected), rejected
                        assert [row for row in map(json.loads, trace.read_text().splitlines()) if 'ordinal' in row] == owners
                    closed = client.call('close_idb', {'close_token': client.opened['close_token']})
                    client.opened = None
                    if losses == 0:
                        assert 'error' in closed and 'Root Node' in str(closed), closed
                    else:
                        assert 'result' in closed, closed
                client.stop()
                client = None
                if losses != 1:
                    assert before == digest(path), 'refused save overwrote packed seed'
                results.append({'losses': losses, 'open': opening, 'owners': owners,
                                'before': before, 'after': digest(path), 'status': 'PASS'})
        finally:
            if client is not None:
                client.opened = None
                client.stop()
            forced = env.cleanup()
            env.assert_clean()
            (env.root / 'r7a-r9-result.json').write_text(json.dumps(
                {'cases': results, 'cleanup_signalled': forced}, indent=2) + '\n')
    assert len(results) == 3 and not forced, results
    print(json.dumps({'r9_real': 'PASS', 'cases': len(results)}))


if __name__ == '__main__':
    main()
