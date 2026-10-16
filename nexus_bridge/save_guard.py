"""Owner-local Root Node sampling and public IDA save/close protection."""
import json
import logging
import os
import sys
import time

ERROR = ('database state abnormal: Root Node is missing or its presence cannot be confirmed; '
         'saving refused; original file retained at the last successful save')
_state = None
_failed_state = None
_history = []


def _optional(function):
    try:
        return function()
    except Exception as exc:
        return {'error': type(exc).__name__}


def _metadata():
    import ida_nalt
    result = {}
    for name in ('get_input_file_path', 'retrieve_input_file_size',
                 'retrieve_input_file_md5', 'retrieve_input_file_sha256'):
        value = _optional(lambda: getattr(ida_nalt, name)())
        result[name] = value.hex() if isinstance(value, bytes) else value
    return result


def _database_flags():
    import ida_loader
    return {name: _optional(lambda: ida_loader.is_database_flag(getattr(ida_loader, name)))
            for name in ('DBFL_KILL', 'DBFL_COMP', 'DBFL_BAK', 'DBFL_TEMP')}


def database_context():
    """Read-only paths, packing preferences, flags and directory entries."""
    from pathlib import Path
    import ida_ida
    import ida_loader
    import threading
    paths = {name: _optional(lambda: ida_loader.get_path(getattr(ida_loader, name)))
             for name in ('PATH_TYPE_CMD', 'PATH_TYPE_IDB', 'PATH_TYPE_ID0')}
    directories = {}
    for path in paths.values():
        if not isinstance(path, str) or not path:
            continue
        parent = str(Path(path).parent)
        if parent in directories:
            continue
        def entries():
            result = []
            for item in sorted(Path(parent).iterdir()):
                def describe():
                    value = item.lstat()
                    return {'name': item.name, 'size': value.st_size,
                            'mtime_ns': value.st_mtime_ns, 'inode': value.st_ino,
                            'device': value.st_dev, 'mode': value.st_mode}
                result.append({'name': item.name, 'stat': _optional(describe)})
            return result
        directories[parent] = _optional(entries)
    return {'observed_at': time.monotonic(), 'paths': paths, 'directories': directories,
            'thread': {'current': threading.get_ident(), 'main': threading.main_thread().ident,
                       'name': threading.current_thread().name},
            'database_flags': _database_flags(),
            # These are save preferences, not proof of which file was loaded.
            'packing_preferences': {name: _optional(lambda: getattr(ida_ida, name)())
                for name in ('inf_pack_idb', 'inf_compress_idb', 'inf_get_lflags')}}


def _delayed_probes(context):
    """Observe once after poisoning; later recovery never authorizes saving."""
    import ida_netnode
    started = time.monotonic()
    deadline = min(started + 1.0, (context or {}).get('deadline', started + 1.0))
    result = []
    for delay in (0.05, 0.2, 1.0):
        target = started + delay
        if target > deadline:
            break
        time.sleep(max(0.0, target - time.monotonic()))
        result.append({'elapsed': time.monotonic() - started,
                       'root_present': _optional(lambda: bool(ida_netnode.netnode.exist('Root Node'))),
                       'metadata': _metadata(), 'database': _optional(database_context)})
    return result


def _log(value):
    logger = logging.getLogger('ida_cli.save_guard')
    if not logger.handlers:
        handler = logging.StreamHandler(sys.__stderr__)
        handler.setFormatter(logging.Formatter('%(levelname)s %(name)s: %(message)s'))
        logger.addHandler(handler)
        logger.propagate = False
    logger.error('Root Node save protection: %s', json.dumps(value, ensure_ascii=True))


def _discard_on_close():
    import ida_loader
    # TEMP prevents packed writeback; KILL removes the abnormal unpacked copy.
    # Neither flag prevents an explicit save_database, which needs its own check.
    for flag in (ida_loader.DBFL_TEMP, ida_loader.DBFL_KILL):
        ida_loader.set_database_flag(flag)
        if not ida_loader.is_database_flag(flag):
            raise RuntimeError('could not arm Root Node close protection')


def sample(stage, context=None, refuse=True):
    state = _state or _failed_state
    if state is None:
        raise RuntimeError('Root Node save protection unavailable: guard is not installed')
    now = time.monotonic()
    try:
        import ida_netnode
        present = bool(ida_netnode.netnode.exist('Root Node'))
        failure = state.get('identity_error')
        if failure:
            present = False
    except Exception as exc:
        present, failure = False, type(exc).__name__
    previous = state['last_sample']
    if not present or state['poisoned'] or state.get('install_error'):
        flags_before_protection = _optional(_database_flags)
        # Latch failure before arming: a flag exception must never look healthy.
        first = state['first_failure'] is None
        state['poisoned'] = True
        state['close_safe'] = False
        if first:
            state['first_failure'] = {'stage': stage, 'previous_sample': previous,
                'operation': dict(context or state['operation']), 'sample_time': now,
                'root_present': present, 'probe_error': failure}
        try:
            _discard_on_close()
        except Exception as exc:
            state['protection_error'] = type(exc).__name__ + ': ' + str(exc)
            raise RuntimeError('Root Node save protection unavailable; owner and exact lease retained: '
                               + state['protection_error']) from exc
        state['close_safe'] = True
        database = _optional(database_context)
        state['last_failure_boundary'] = {'stage': stage, 'sample_time': now,
            'root_present': present, 'operation': dict(context or state['operation']),
            'database': database}
        if not first:
            logging.getLogger('ida_cli.save_guard').error(
                'Root Node protected boundary: %s',
                json.dumps(state['last_failure_boundary'], ensure_ascii=True))
        if first:
            import ida_loader
            evidence = {'stage': stage, 'operation': dict(context or state['operation']),
                        'owner_pid': os.getpid(), 'root_present': present,
                        'probe_error': failure, 'previous_sample': previous,
                        'sample_time': now, 'opened_at': state['opened_at'],
                        'elapsed_since_open': now - state['opened_at'],
                        'adapter_open_started': state['context'].get('open_started'),
                        'elapsed_since_adapter_open': now - state['context'].get('open_started', state['opened_at']),
                        'initial_metadata': state['initial_metadata'],
                        'current_metadata': _metadata(), 'previous_idbs': list(_history),
                        'history_scope': 'since owner guard installation; earlier history unknown',
                        'actual_idb_path': _optional(lambda: ida_loader.get_path(ida_loader.PATH_TYPE_IDB)),
                        'requested_path': state['context'].get('requested_path'),
                        'record_id': state['context'].get('record_id'),
                        'flags_before_protection': flags_before_protection,
                        'database_at_failure': database,
                        'first_transition': previous is not None and previous['root_present']}
            state['first_failure'] = evidence
            _log(evidence)
            # Emit the immediate snapshot before any bounded delay, so a killed
            # operation cannot erase the decisive first-failure evidence.
            delayed = _optional(lambda: _delayed_probes(context))
            evidence['delayed_probes'] = delayed
            logging.getLogger('ida_cli.save_guard').error(
                'Root Node delayed probes: %s', json.dumps({
                    'record_id': evidence['record_id'], 'sample_time': now,
                    'probes': delayed}, ensure_ascii=True))
        state['last_sample'] = {'time': now, 'stage': stage, 'root_present': present,
                                'operation': dict(context or state['operation'])}
        message = ('Root Node save protection unavailable: ' + state['install_error']
                   if state.get('install_error') else ERROR)
        if refuse:
            raise RuntimeError(message)
        return message
    state['last_sample'] = {'time': now, 'stage': stage, 'root_present': True,
                            'operation': dict(context or state['operation'])}
    return None


def install(context):
    global _state, _failed_state
    import ida_idp
    import ida_loader
    path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    if _failed_state is not None:
        return
    if _state is not None:
        if _state['path'] != path:
            # A changed active database in a live owner is itself uncertain.
            _state['identity_error'] = 'active database path changed within owner'
        return
    now = time.monotonic()
    candidate = {'path': path, 'context': dict(context), 'opened_at': now,
              'operation': dict(context), 'last_sample': None, 'poisoned': False,
              'initial_metadata': _metadata(), 'first_failure': None, 'close_safe': False}
    _history.append(path)

    class CloseGuard(ida_idp.IDB_Hooks):
        def savebase(self):
            # Notification return values cannot veto. Public flags can suppress
            # automatic close writeback, including after the adapter disconnects.
            sample('automatic-save', refuse=False)

        def closebase(self):
            sample('automatic-close', refuse=False)

    try:
        hook = CloseGuard()
        if not hook.hook():
            raise RuntimeError('IDB_Hooks.hook returned false')
    except Exception as exc:
        candidate['install_error'] = type(exc).__name__ + ': ' + str(exc)
        _failed_state = candidate
        return
    candidate['hook'] = hook
    candidate['close_safe'] = True
    _state = candidate


def begin(context, refuse=True):
    install(context)
    (_state or _failed_state)['operation'] = dict(context)
    return sample('before', context, refuse=refuse)


def finish(context, refuse=True):
    return sample('after', context, refuse=refuse)


def save_database(outfile=None, flags=0):
    """For adapter-owned explicit saves; scripts calling IDA directly bypass it."""
    import ida_loader
    sample('explicit-save')
    return ida_loader.save_database(outfile, flags)


def close_status():
    """Read-only guard evidence; missing/failed protection never authorizes close."""
    state = _state or _failed_state
    evidence = state.get('first_failure') if state else None
    safe = bool(state and state['close_safe'])
    if safe and state['poisoned']:
        try:
            import ida_loader
            safe = all(ida_loader.is_database_flag(flag)
                       for flag in (ida_loader.DBFL_TEMP, ida_loader.DBFL_KILL))
        except Exception:
            safe = False
    return {'close_safe': safe,
            'initial': bool(evidence and evidence['previous_sample'] is None
                            and not state.get('install_error')),
            'evidence': evidence,
            'protection_error': state.get('protection_error') if state else 'not installed'}
