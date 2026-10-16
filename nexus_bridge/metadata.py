"""Read-only, public-API evidence for missing input metadata in an IDA owner."""


def idb_fingerprint(path, deadline=None):
    import hashlib
    import time
    from pathlib import Path
    target = Path(path)
    try:
        before = target.stat()
        digest = hashlib.sha256()
        with target.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError('diagnostic hash deadline')
                digest.update(chunk)
        after = target.stat()
        return {'path': str(target), 'sha256': digest.hexdigest(),
                'size': after.st_size, 'mtime_ns': after.st_mtime_ns,
                'inode': after.st_ino,
                'stable_during_read': (before.st_ino, before.st_size, before.st_mtime_ns)
                    == (after.st_ino, after.st_size, after.st_mtime_ns)}
    except OSError as exc:
        return {'path': str(target), 'error': type(exc).__name__}


def idb_context(path, deadline=None, *, forensic_hash=None):
    """Stat by default; complete reads require an explicit forensic opt-in."""
    import os
    from pathlib import Path
    if forensic_hash is None:
        forensic_hash = os.environ.get('IDA_CLI_NEXUS_FORENSIC_HASH', '0') == '1'
    if forensic_hash:
        return idb_fingerprint(path, deadline)
    target = Path(path)
    try:
        value = target.stat()
        return {'path': str(target), 'size': value.st_size,
                'mtime_ns': value.st_mtime_ns, 'inode': value.st_ino,
                'device': value.st_dev}
    except OSError as exc:
        return {'path': str(target), 'error': type(exc).__name__}


def input_metadata_evidence(context=None, stage='checkpoint'):
    import os
    import sys
    import types
    import ida_auto
    import ida_loader
    import ida_nalt
    context = context or {}
    name = '_ida_cli_nexus_metadata_v1'
    if name not in sys.modules:
        sys.modules[name] = types.SimpleNamespace(paths=[])
    history = sys.modules[name].paths
    def optional(function):
        try:
            return function()
        except Exception as exc:
            return {'error': type(exc).__name__}
    path = optional(lambda: ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
    previous = list(history)
    if path not in history:
        history.append(path)
    raw = {}
    for getter in ('get_input_file_path', 'get_root_filename', 'retrieve_input_file_size',
                   'retrieve_input_file_md5', 'retrieve_input_file_sha256'):
        try:
            value = getattr(ida_nalt, getter)()
            raw[getter] = {'type': type(value).__name__,
                           'value': value.hex() if isinstance(value, bytes) else value}
        except Exception as exc:
            raw[getter] = {'error': type(exc).__name__}
    result = {'stage': stage, 'owner_pid': os.getpid(), 'actual_idb_path': path,
              'raw': raw, 'before_open': context.get('before_open'),
              'requested_path': context.get('requested_path'),
              'record_id': context.get('record_id'),
              'disk_now': idb_context(path, context.get('deadline'),
                  forensic_hash=context.get('forensic_hash')) if isinstance(path, str) and path else None,
              'previously_observed_idbs': previous,
              'observed_multiple_databases': any(p != path for p in previous),
              'history_scope': 'observations since adapter instrumentation; earlier history unknown',
              'auto_is_ok': optional(lambda: ida_auto.auto_is_ok()),
              'auto_state': optional(lambda: ida_auto.get_auto_state())}
    try:
        from ida_nexus import discover_databases
        result['public_instances'] = [
            {'record_id': item.instance.record_id, 'pid': item.instance.pid,
             'idb_path': item.instance.idb_path, 'state': item.state.value}
            for item in discover_databases(timeout=0.2)]
        if result['record_id'] is None:
            matches = [x['record_id'] for x in result['public_instances'] if x['pid'] == os.getpid()]
            result['record_id'] = matches[0] if len(matches) == 1 else None
    except Exception as exc:
        result['public_instances_error'] = type(exc).__name__
    return result


def warn_missing_input_metadata(value, context=None):
    # This boundary covers diagnostics only. Root Node protection is separate
    # and must still fail closed before opening, executing or saving.
    try:
        if (value['input_file_path'] and value['input_file_size']
                and value['md5'] != '0' * 32 and value['sha256'] != '0' * 64):
            return
        import json
        detail = json.dumps(input_metadata_evidence(context), ensure_ascii=True)
        message = 'missing input metadata: %s'
    except Exception as exc:
        detail = type(exc).__name__
        message = 'input metadata diagnostic failed: %s'
    import logging
    import sys
    logger = logging.getLogger('ida_cli.metadata')
    if not logger.handlers:
        # Nexus captures per-operation stderr; retain evidence in the owner log.
        handler = logging.StreamHandler(sys.__stderr__)
        handler.setFormatter(logging.Formatter('%(levelname)s %(name)s: %(message)s'))
        logger.addHandler(handler)
        logger.propagate = False
    logger.warning(message, detail)
