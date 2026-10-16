"""N6 prebuilt-copy metadata checkpoints only, in one fresh prepared environment."""
import argparse
import json
import os
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO/'scripts'))
from compare_nexus_n6 import (Candidate, Environment, Process, METADATA_SOURCE,
                              metadata_checkpoint, prebuilt_pair, script_result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--inject-missing', action='store_true', help='validate forensic capture; not an r9 reproduction')
    args = parser.parse_args()
    env = Environment(args.root)
    results = []
    try:
        for label, native in ([('n6-tools', False)] if args.inject_missing else [('n6-tools', False), ('n6', True)]):
            samples = prebuilt_pair(env, args.binary, label)
            old = new = None
            row = {'label': label, 'status': 'FAIL'}
            try:
                if native:
                    variables = env.variables() | {'IDA_CLI_HOME': str(env.root/'native-home'), 'TMPDIR': os.environ['TMPDIR']}
                    Path(variables['IDA_CLI_HOME']).mkdir()
                    old = Process(env, [str(args.baseline), 'serve-worker'], variables, 'r9-native')
                    assert 'result' in old.rpc('open', {'path': str(samples[0])})
                else:
                    old = Candidate(env, args.baseline, samples[0], 'n6-tool-baseline', transport='stdio', inline='8000000')
                new = Candidate(env, args.binary, samples[1], 'n6-tool-nexus' if not native else 'n6-candidate', transport='stdio', inline='8000000')
                if args.inject_missing:
                    code = '''import ctypes, ida_ida
delete = ctypes.CDLL(None).delinf
delete.argtypes = [ctypes.c_int]
delete.restype = ctypes.c_bool
for key in (ida_ida.INF_MD5, ida_ida.INF_SHA256, ida_ida.INF_INPUT_FILE_PATH):
    assert delete(key)
set_value = ctypes.CDLL(None).setinf
set_value.argtypes = [ctypes.c_int, ctypes.c_uint64]
set_value.restype = ctypes.c_bool
assert set_value(ida_ida.INF_FSIZE, 0)
'''
                    assert new.call('run_script', {'code': code})['result']['success']
                    try:
                        metadata_checkpoint(env, old, new, 'intentional missing-metadata forensic validation')
                    except (AssertionError, OSError, KeyError):
                        record = json.loads((env.root/'n6-metadata-checkpoints.jsonl').read_text().splitlines()[-1])
                        evidence = record['owner_evidence']
                        assert evidence['actual_idb_path'] == str(samples[1])
                        assert evidence['record_id'] and evidence['before_open']['sha256']
                        assert evidence['disk_now']['sha256'] == evidence['before_open']['sha256']
                        assert evidence['raw']['retrieve_input_file_sha256']['value'] is None
                        assert evidence['public_instances']
                        log = env.root/'state/logs'/(evidence['record_id']+'.log')
                        assert 'missing input metadata:' in log.read_text()
                        row.update(status='EXPECTED_CHECKPOINT_FAILURE', owner_evidence=evidence)
                        continue
                    raise AssertionError('strict checkpoint accepted intentionally missing metadata')
                metadata_checkpoint(env, old, new, label+' reopened prebuilt copies')
                before = json.loads((env.root/(label+'-prebuilt-idb.json')).read_text())['before_open_fingerprints'][2]
                context = {'requested_path': str(samples[1]), 'before_open': before}
                code = METADATA_SOURCE.read_text() + f'\nimport json\nprint(json.dumps(input_metadata_evidence({context!r}, stage="successful checkpoint")))'
                row['owner_evidence'] = script_result(new.call('run_script', {'code': code}))
                row['status'] = 'PASS'
            finally:
                results.append(row)
                if old:
                    if native:
                        old.rpc('close'); old.rpc('shutdown'); old.wait()
                    else:
                        old.stop()
                if new:
                    new.stop()
    finally:
        (env.root/'metadata-repro.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(results))


if __name__ == '__main__':
    main()
