"""Preview, migrate, clean or restore legacy flat IDB cache groups.

Default is a read-only preview. Applying requires a reviewed plan and explicit,
continuous operator-maintained offline exclusion; negative probes alone do not
prove that independent IDA, remote writers or automatic restarts are excluded.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

if '__verified_source__' not in globals():
    sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parent/'custody')]

import legacy_cache_files as files
import legacy_cache_offline as offline
from target_coordination import encoded

COMPONENTS = {'.id0', '.id1', '.id2', '.nam', '.til', '.imcp'}
LEGACY = re.compile(r'.+\.([0-9a-f]{12})\.dylib\.i64\Z')


def inventory(root, states, *, probe=offline.observe):
    files.directory(root)
    indices = files.metadata(root)
    groups = []
    names = sorted(p.name for p in root.iterdir())
    for name in names:
        if not name.endswith('.i64'):
            continue
        path, stem = root/name, name[:-4]
        match = LEGACY.fullmatch(name)
        key = match[1] if match else None
        members = [files.fingerprint(root/n) for n in names if n == stem or n.startswith(stem+'.')]
        unsafe = any('unsafe' in item for item in members)
        observation = ({'packed': None, 'openers': 'unknown: unsafe group member'} if unsafe
                       else probe(path, states))
        groups.append({'idb': name, 'content_key': key, 'files': members,
                       'bytes': sum(p.get('bytes', 0) for p in members),
                       'components': [p['name'] for p in members if Path(p['name']).suffix in COMPONENTS],
                       'unknown_files': [p['name'] for p in members if p['name'] not in (name, stem)
                                         and Path(p['name']).suffix not in COMPONENTS],
                       'legacy_index': indices['index.json']['value'].get(key),
                       'generation_index': indices['nexus-index.json']['value'].get(key),
                       **observation})
    return groups


def load_manifest(backup, root):
    files.directory(backup, private=True)
    value = json.loads(files.read(backup/'manifest.json'))
    if (type(value) is not dict or value.get('schema') != 1 or value.get('root') != offline.binding(root)
            or value.get('mode') not in ('migrate', 'clean') or type(value.get('files')) is not list
            or type(value.get('indices')) is not dict or not value['files']):
        raise ValueError('invalid backup manifest or changed cache-root identity')
    files.safe_name(value['group'])
    match = LEGACY.fullmatch(value['group'])
    if match is None or value.get('content_key') != match[1]:
        raise ValueError('invalid backup legacy identity')
    seen = set()
    for item in value['files']:
        name = files.safe_name(item['name'])
        if name in seen or name not in (value['group'], value['group'][:-4]):
            raise ValueError('invalid or duplicate backup group member')
        seen.add(name)
        if not files.matches(backup/'files'/name, item):
            raise ValueError('backup member hash mismatch')
    if value['group'] not in seen:
        raise ValueError('backup has no database')
    for name in ('index.json', 'nexus-index.json'):
        item = value['indices'][name]
        if item['before'] is not None and files.digest(files.read(backup/'indices'/name)) != item['before']:
            raise ValueError('backup index hash mismatch')
    return value


def plan(root, mode, group, homes, states, backup, *, probe=offline.observe):
    files.directory(root)
    base = {'schema': 1, 'root': offline.binding(root), 'boot_id': offline.boot(), 'mode': mode,
            'router_homes': [offline.binding(p) for p in homes],
            'state_roots': [offline.binding(p) for p in states], 'backup': str(backup),
            'indices': files.metadata(root)}
    if mode == 'restore':
        manifest = load_manifest(backup, root)
        base.update(group=manifest['group'], backup_sha256=files.digest(files.read(backup/'manifest.json')),
                    files=[files.fingerprint(root/p['name']) if (root/p['name']).exists()
                           or (root/p['name']).is_symlink() else {'name': p['name'], 'missing': True}
                           for p in manifest['files']])
    else:
        selected = [p for p in inventory(root, states, probe=probe) if p['idb'] == group]
        if len(selected) != 1:
            raise ValueError('exactly one existing flat group must be selected')
        base['group'] = selected[0]
    return base, files.digest(encoded(base))


def validate_group(group, mode, groups):
    if not group['content_key']:
        raise ValueError('legacy filename has no unambiguous content key')
    if any('unsafe' in p for p in group['files']) or group['unknown_files'] or group['components']:
        raise ValueError('unsafe, unknown or unpacked component; original retained')
    if group['packed'] is not True or group['openers'] is not None:
        raise ValueError('packed/offline proof vetoed; original retained')
    if len([p for p in groups if p['content_key'] == group['content_key']]) != 1:
        raise ValueError('multiple flat groups share a content key; select a policy externally')
    if mode == 'migrate' and group['generation_index'] is not None:
        raise ValueError('content key already has a generation index; healthy generations are never replaced')
    entry = group['legacy_index']
    if entry is not None and (type(entry) is not dict or entry.get('hash') != group['content_key']):
        raise ValueError('legacy index identity mismatch')


def content_key(path):
    executable = os.environ.get('IDA_CLI_LEGACY_TOOL')
    if not executable:
        raise RuntimeError('content-key verification requires the ida-cli cache-legacy entrypoint')
    result = subprocess.run(['timeout', '10s', executable, 'cache-legacy', '--content-key', str(path)],
                            capture_output=True, text=True, check=False)
    if result.returncode or not re.fullmatch(r'[0-9a-f]{12}\n?', result.stdout):
        raise RuntimeError('content-key verification failed')
    return result.stdout.strip()


def inspect_copy(backup, idb_name):
    """Open only a disposable private copy; never save/open the original."""
    probe = backup/('probe-' + uuid.uuid4().hex)
    probe.mkdir(mode=0o700)
    source = backup/'files'/idb_name
    files.copy_verified(source, probe/'probe.i64', files.fingerprint(source))
    result = subprocess.run(['timeout', '30s', *offline.child_argv('--inspect-copy', str(probe/'probe.i64'),
                             '--result', str(probe/'result.json'))], capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError('private packed IDB inspection failed; copy retained at ' + str(probe))
    value = json.loads(files.read(probe/'result.json'))
    return value


def inspect_database(path, result):
    files.directory(path.parent, private=True)
    if (path.name != 'probe.i64' or not re.fullmatch(r'probe-[0-9a-f]{32}', path.parent.name)
            or result != path.parent/'result.json' or 'unsafe' in files.fingerprint(path)):
        raise ValueError('private disposable verification copy required')
    import idapro
    if idapro.open_database(str(path), False) != 0:
        raise RuntimeError('IDA refused packed verification copy')
    try:
        import ida_nalt
        value = ida_nalt.retrieve_input_file_sha256()
        if not value or len(value) != 32:
            raise RuntimeError('IDB has no proven input SHA256')
        input_sha256 = value.hex()
    finally:
        idapro.close_database(False)
    from ida_nexus import probe_database_state
    state = probe_database_state(path)
    if state['state'] != 'packed' or state['unpacked_files'] or state.get('error'):
        raise RuntimeError('verification copy did not close to packed state')
    # Written only after open, metadata read, close and packed recheck finish.
    files.create(result, encoded({'input_sha256': input_sha256, 'packed_after_close': True}))


def prepare_backup(root, backup, group, mode, plan_hash, *, inspect=inspect_copy, key_fn=content_key):
    files.directory(backup.parent, private=True)
    if backup == root or backup.is_relative_to(root) or root.is_relative_to(backup):
        raise ValueError('backup must be outside the cache')
    backup.mkdir(mode=0o700)
    files.sync(backup.parent)
    for name in ('files', 'indices'):
        (backup/name).mkdir(mode=0o700)
    for item in group['files']:
        files.copy_verified(root/item['name'], backup/'files'/item['name'], item)
    indices = {}
    updates = {}
    for name in ('index.json', 'nexus-index.json'):
        raw, value = files.index(root/name)
        original_value = encoded(value)
        if raw is not None:
            files.create(backup/'indices'/name, raw)
        if name == 'index.json':
            value.pop(group['content_key'], None)
        elif mode == 'migrate':
            value[group['content_key']] = 'generations/legacy-' + plan_hash[:24] + '/input.i64'
        after = raw if encoded(value) == original_value else encoded(value)
        indices[name] = {'before': files.digest(raw) if raw is not None else None,
                         'after': files.digest(after) if after is not None else None}
        updates[name] = after
    verified = inspect(backup, group['idb'])
    snapshot = group['idb'][:-4]
    if mode == 'migrate':
        if snapshot not in {p['name'] for p in group['files']}:
            # No guess from a mutable original_path: an explicit matching input
            # snapshot is required for generations/prepared_paths content keys.
            raise ValueError('migration requires the verified flat input snapshot; clean/restore remain available')
        source = backup/'files'/snapshot
        if files.fingerprint(source)['sha256'] != verified['input_sha256'] or key_fn(source) != group['content_key']:
            raise ValueError('input snapshot does not match IDB SHA256 and content key')
    manifest = {'schema': 1, 'root': offline.binding(root), 'mode': mode, 'group': group['idb'],
                'content_key': group['content_key'], 'files': group['files'], 'indices': indices,
                'plan_sha256': plan_hash, 'verification': verified,
                'generation': 'legacy-' + plan_hash[:24] if mode == 'migrate' else None}
    files.create(backup/'manifest.json', encoded(manifest))
    files.sync(backup)
    load_manifest(backup, root)
    return manifest, updates


def publish_generation(root, backup, manifest):
    from cache_store import rename_group
    container = root/'generations'
    if not container.exists():
        container.mkdir(mode=0o700)
        files.sync(root)
    files.directory(container)
    stage = container/('.n8tool-' + uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    members = {p['name']: p for p in manifest['files']}
    group = manifest['group']
    for old, new in ((group, 'input.i64'), (group[:-4], 'input')):
        files.copy_verified(backup/'files'/old, stage/new, members[old])
    files.create(stage/'generation.json', encoded({'version': 1, 'key': manifest['content_key']}))
    files.sync(stage)
    rename_group(stage, container/manifest['generation'])
    files.sync(container)


def apply(root, mode, group_name, homes, states, backup, evidence, *,
          probe=offline.observe, inspect=inspect_copy, key_fn=content_key, hook=lambda _: None):
    initial, plan_hash = plan(root, mode, group_name, homes, states, backup, probe=probe)
    offline.validate(evidence, plan_hash, root, homes, states)
    # Reject unsafe names/links before Target canonicalization can touch any
    # other directory. In particular a symlink IDB is never an authority alias.
    if mode == 'restore':
        if any('unsafe' in item for item in initial['files']):
            raise ValueError('unsafe restore destination; originals retained')
    else:
        validate_group(initial['group'], mode, inventory(root, states, probe=probe))
    group_name = initial['group'] if mode == 'restore' else initial['group']['idb']
    active_probe = offline.active_observe if probe is offline.observe else probe
    targets = [root/group_name]
    with offline.locked(root, homes, targets):
        fresh, fresh_hash = plan(root, mode, group_name, homes, states, backup, probe=probe)
        if fresh_hash != plan_hash:
            raise RuntimeError('reviewed plan changed under exclusion locks')
        check = lambda: offline.validate(evidence, plan_hash, root, homes, states)
        check()
        if mode == 'restore':
            manifest = load_manifest(backup, root)
            # Missing originals still need a public owner/component veto.
            for path in targets:
                if path.exists():
                    offline.assert_unoccupied([path], states, probe=active_probe)
                else:
                    value = active_probe(path, states)
                    if value.get('openers') is not None or value.get('state', 'missing') != 'missing':
                        raise RuntimeError('restore target occupancy unknown')
            check()
            files.restore_files(root, backup, manifest)
            return {'restored': group_name, 'backup': str(backup)}
        group = fresh['group']
        validate_group(group, mode, inventory(root, states, probe=probe))
        offline.assert_unoccupied(targets, states, probe=active_probe)
        manifest, updates = prepare_backup(root, backup, group, mode, plan_hash, inspect=inspect, key_fn=key_fn)
        try:
            hook('after_backup')
            check()
            current, current_hash = plan(root, mode, group_name, homes, states, backup, probe=probe)
            if current_hash != plan_hash:
                raise RuntimeError('source or index changed during backup')
            if mode == 'migrate':
                publish_generation(root, backup, manifest)
            hook('after_generation')
            check()
            offline.assert_unoccupied(targets, states, probe=active_probe)
            for name, data in updates.items():
                before = files.read(backup/'indices'/name) if manifest['indices'][name]['before'] is not None else None
                if data != before:
                    files.replace(root/name, data, before)
            hook('after_index')
            for item in group['files']:
                check()
                offline.assert_unoccupied(targets, states, probe=active_probe)
                path = root/item['name']
                if files.fingerprint(path) != item:
                    raise RuntimeError('original changed before removal')
                path.unlink()
                files.sync(root)
                hook('after_remove')
            return {'mode': mode, 'group': group_name, 'backup': str(backup),
                    'generation': manifest['generation'], 'verified': manifest['verification']}
        except BaseException as failure:
            # Restore exact approved bytes/indices while all locks are held.
            # Collisions fail visibly, preserve the backup and require explicit
            # restoration; a process crash uses the same idempotent entrypoint.
            try:
                for path in targets:
                    value = active_probe(path, states)
                    if value.get('openers') is not None or not (value.get('packed') is True or value.get('state') == 'missing'):
                        raise RuntimeError('rollback target now occupied or unknown')
                files.restore_files(root, backup, manifest)
            except Exception as rollback:
                raise RuntimeError(f'operation failed: {failure}; rollback blocked: {rollback}; verified backup retained at {backup}') from failure
            raise


def paths(values):
    result = sorted({Path(p) for p in values})
    for path in result:
        files.directory(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(os.environ.get('IDA_CLI_HOME', str(Path.home()/'.ida')))/'idb')
    parser.add_argument('--mode', choices=('migrate', 'clean', 'restore'))
    parser.add_argument('--group', help='exact root-level legacy .i64 filename')
    parser.add_argument('--backup', type=Path, help='new private directory outside cache; existing backup for restore')
    parser.add_argument('--router-home', action='append', default=[])
    parser.add_argument('--state-root', action='append', default=[])
    parser.add_argument('--apply', action='store_true', help='execute the exact plan bound by --offline-evidence')
    parser.add_argument('--offline-evidence', type=Path, help='private JSON proving operator-maintained offline exclusion')
    parser.add_argument('--observe', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--observe-readonly', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--inspect-copy', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--result', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.observe or args.observe_readonly:
            print(json.dumps(offline.public_observation(args.observe or args.observe_readonly, read_only=bool(args.observe_readonly))))
            return
        if args.inspect_copy:
            inspect_database(args.inspect_copy, args.result)
            return
        root = files.directory(args.root)
        states = paths(args.state_root or ([os.environ['IDA_NEXUS_STATE_DIR']] if os.environ.get('IDA_NEXUS_STATE_DIR') else []))
        homes = paths(args.router_home or [os.environ.get('IDA_CLI_HOME', str(Path.home()/'.ida'))])
        if args.mode is None:
            if args.apply:
                raise ValueError('--apply requires an explicit mode')
            print(json.dumps({'dry_run': True, 'groups': inventory(root, states),
                              'offline_proof': 'not established; negative probes alone are insufficient'}))
            return
        if not args.backup or (args.mode != 'restore' and not args.group):
            raise ValueError('mode requires --backup and an exact --group (except restore)')
        if args.group:
            files.safe_name(args.group)
        if args.apply:
            if not args.offline_evidence:
                raise ValueError('--apply requires plan-bound --offline-evidence')
            evidence = json.loads(files.read(args.offline_evidence))
            result = apply(root, args.mode, args.group, homes, states, args.backup, evidence)
        else:
            value, plan_hash = plan(root, args.mode, args.group, homes, states, args.backup)
            result = {'dry_run': True, 'plan': value, 'plan_sha256': plan_hash,
                      'required_offline_scope': offline.SCOPE, 'confirmation': offline.CONFIRMATION,
                      'offline_proof': 'operator must establish and maintain exclusion; this preview is not proof'}
        print(json.dumps(result))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        parser.exit(1, 'legacy cache maintenance refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
