"""Targeted real packed-IDB legacy maintenance; private prepared environment only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]


def native(args):
    import idapro
    path = args.seed or args.read
    assert idapro.open_database(str(path), bool(args.seed)) == 0
    try:
        import ida_bytes
        import ida_loader
        import idautils
        if args.seed:
            import ida_auto
            assert ida_auto.auto_wait()
            address = next(idautils.Functions())
            value = ida_bytes.get_byte(address) ^ 1
            assert ida_bytes.set_cmt(address, 'N8 legacy retained edits', False)
            assert ida_bytes.patch_byte(address, value)
            assert ida_loader.save_database(str(path)+'.i64', ida_loader.DBFL_COMP)
            args.record.write_text(json.dumps({'address': address, 'byte': value}))
        else:
            expected = json.loads(args.record.read_text())
            assert ida_bytes.get_cmt(expected['address'], False) == 'N8 legacy retained edits'
            assert ida_bytes.get_byte(expected['address']) == expected['byte']
            if args.ready_fd is not None:
                os.write(args.ready_fd, b'1')
                assert os.read(args.release_fd, 1) == b'1'
    finally:
        idapro.close_database(bool(args.seed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--case-dir', default='real')
    parser.add_argument('--crash-evidence', type=Path)
    parser.add_argument('--crash-backup', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--seed', type=Path)
    parser.add_argument('--read', type=Path)
    parser.add_argument('--record', type=Path)
    parser.add_argument('--ready-fd', type=int)
    parser.add_argument('--release-fd', type=int)
    args = parser.parse_args()
    if args.crash_evidence:
        sys.path[:0] = [str(REPO/'nexus_bridge'), str(REPO/'nexus_bridge/custody')]
        import legacy_cache
        home = Path(os.environ['IDA_CLI_HOME'])
        group = next((home/'idb').glob('*.i64')).name
        def crash(stage):
            if stage == 'after_remove':
                os._exit(77)
        legacy_cache.apply(home/'idb', 'clean', group, [home], [Path(os.environ['IDA_NEXUS_STATE_DIR'])],
                           args.crash_backup, json.loads(args.crash_evidence.read_text()), hook=crash)
        raise AssertionError('crash boundary never reached')
    if args.seed or args.read:
        native(args)
        return
    root = args.root.resolve(strict=True)
    environment = root/'environment'
    run = root/args.case_dir
    run.mkdir(mode=0o700)  # refuse reuse
    home, cache, state, backups = run/'home', run/'home/idb', run/'state', run/'backups'
    for path in (home, cache, state, backups):
        path.mkdir(mode=0o700)
    (home/'.startup.lock').touch(mode=0o644)
    (home/'.startup.lock').chmod(0o644)
    python = environment/'venv/bin/python'
    env = {k: os.environ[k] for k in ('PATH', 'USER', 'LOGNAME') if k in os.environ}
    env.update(HOME=str(home), IDA_CLI_HOME=str(home), IDA_NEXUS_STATE_DIR=str(state),
               IDADIR='/Applications/IDA Professional 9.5.app/Contents/MacOS',
               IDAUSR=str(environment/'profile'), IDAPYTHON_VENV_EXECUTABLE=str(python),
               IDA_NEXUS_PYTHON=str(python), TMPDIR=str(root/'tmp'),
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', IDA_CLI_LEGACY_TOOL=str(args.binary))
    results = []

    def command(label, argv, *, expected=0, seconds=30):
        before = subprocess.check_output(['uptime'], text=True).strip()
        result = subprocess.run(['timeout', str(seconds)+'s', *map(str, argv)], env=env,
                                text=True, capture_output=True, check=False)
        (run/(label+'.stdout')).write_text(result.stdout)
        (run/(label+'.stderr')).write_text(result.stderr)
        results.append({'label': label, 'argv': list(map(str, argv)), 'exit': result.returncode,
                        'uptime_before': before, 'uptime_after': subprocess.check_output(['uptime'], text=True).strip()})
        (run/'commands.json').write_text(json.dumps(results, indent=2))
        assert result.returncode == expected, (label, result.returncode, result.stderr, result.stdout)
        return result.stdout

    def cli(label, *arguments, expected=0):
        return json.loads(command(label, [args.binary, 'cache-legacy', '--root', cache, *arguments], expected=expected)) if expected == 0 else command(label, [args.binary, 'cache-legacy', '--root', cache, *arguments], expected=expected)

    def evidence(label, mode, backup):
        extra = [] if mode == 'restore' else ['--group', group]
        row = cli(label+'-plan', '--mode', mode, '--backup', backup, *extra)
        plan = row['plan']
        value = {k: plan[k] for k in ('schema', 'root', 'router_homes', 'state_roots', 'boot_id')}
        value.update(plan_sha256=row['plan_sha256'], uid=os.getuid(), operator='isolated fixture process',
                     exclusion_method='all fixture openers are controlled by this script; no external clients use private roots',
                     confirmation=row['confirmation'], offline_scope=row['required_offline_scope'],
                     started_at=time.time()-1, expires_at=time.time()+120)
        path = run/(label+'-offline.json')
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return ['--mode', mode, '--backup', backup, *extra, '--apply', '--offline-evidence', path]

    sample = run/'sample'
    shutil.copyfile(environment/'fixtures/mini', sample)
    key = command('content-key', [args.binary, 'cache-legacy', '--content-key', sample]).strip()
    snapshot = run/('sample.'+key+'.dylib')
    sample.rename(snapshot)
    record = run/'edits.json'
    command('seed', [python, __file__, '--seed', snapshot, '--record', record], seconds=180)
    group = snapshot.name+'.i64'
    shutil.copyfile(snapshot, cache/snapshot.name)
    shutil.copyfile(Path(str(snapshot)+'.i64'), cache/group)
    entry = {'hash': key, 'original_path': str(sample), 'binary_type': 'native', 'size': snapshot.stat().st_size,
             'created_at': '1Z', 'last_accessed': '1Z'}
    (cache/'index.json').write_text(json.dumps({key: entry}))
    originals = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in cache.iterdir()}
    preview = cli('dry-run')
    assert preview['dry_run'] and len(preview['groups']) == 1
    assert preview['groups'][0]['packed'] is True
    assert originals == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in cache.iterdir()}
    # Read-only preview never reaps stale/malformed registrations.
    (state/'instances').mkdir(mode=0o700)
    (state/'instances/unexplained.json').write_text('{malformed; no token}')
    preview = cli('dry-run-registry')
    assert preview['groups'][0]['openers'] is not None
    assert (state/'instances/unexplained.json').read_text() == '{malformed; no token}'
    (state/'instances/unexplained.json').unlink()
    # Real independent IDA opener; causal pipe barriers, no timing sleeps.
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    with (run/'held.stdout').open('w') as out, (run/'held.stderr').open('w') as err:
        holder = subprocess.Popen(['timeout', '30s', str(python), __file__, '--read', str(cache/group),
                                   '--record', str(record), '--ready-fd', str(ready_write),
                                   '--release-fd', str(release_read)], env=env, stdout=out, stderr=err,
                                  pass_fds=(ready_write, release_read))
        os.close(ready_write)
        os.close(release_read)
        try:
            assert select.select([ready_read], [], [], 20)[0], 'IDA opener never reached barrier'
            assert os.read(ready_read, 1) == b'1'
            backup = backups/'online-refused'
            cli('online-refused', *evidence('online', 'clean', backup), expected=1)
            assert not backup.exists()
        finally:
            os.write(release_write, b'1')
            os.close(release_write)
            os.close(ready_read)
            assert holder.wait(timeout=10) == 0
    backup = backups/'migration'
    result = cli('migrate', *evidence('migration', 'migrate', backup))
    migrated = cache/'generations'/result['generation']/'input.i64'
    assert hashlib.sha256(migrated.read_bytes()).hexdigest() == originals[group]
    command('read-migrated', [python, __file__, '--read', migrated, '--record', record], seconds=180)
    cli('restore-migrated', *evidence('restore-migration', 'restore', backup))
    assert originals == {n: hashlib.sha256((cache/n).read_bytes()).hexdigest() for n in originals}
    backup = backups/'cleanup'
    cli('clean', *evidence('cleanup', 'clean', backup))
    assert not (cache/group).exists()
    cli('restore', *evidence('restore-cleanup', 'restore', backup))
    assert originals == {n: hashlib.sha256((cache/n).read_bytes()).hexdigest() for n in originals}
    command('read-restored', [python, __file__, '--read', cache/group, '--record', record], seconds=180)
    backup = backups/'hard-interruption'
    crash_arguments = evidence('hard-interruption', 'clean', backup)
    crash_evidence = crash_arguments[-1]
    command('hard-interruption', [python, __file__, '--crash-evidence', crash_evidence,
                                '--crash-backup', backup], expected=77, seconds=120)
    assert (backup/'manifest.json').is_file()
    assert not (cache/snapshot.name).exists(), 'interruption must occur after an actual removal'
    cli('restore-interrupted', *evidence('restore-interrupted', 'restore', backup))
    assert originals == {n: hashlib.sha256((cache/n).read_bytes()).hexdigest() for n in originals}
    command('read-interrupted-restored', [python, __file__, '--read', cache/group, '--record', record], seconds=180)
    assert not list(state.rglob('*.json')), 'no Nexus owner registrations may remain'
    assert not list(cache.glob('*.id0')), 'no IDA component locks may remain'
    (run/'result.json').write_text(json.dumps({'status': 'PASS', 'cases': ['dry-run', 'dry-run-registry',
        'online-refused', 'migrate-read-edits', 'clean-restore-read-edits', 'hard-interruption-restore-read-edits'], 'key': key, 'originals': originals}, indent=2))
    print('PASS real N8 legacy cache: dry-run/online refusal/migration and cleanup restore with edits read back')


if __name__ == '__main__':
    main()
