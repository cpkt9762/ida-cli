"""Owner-local Root Node sampling and public IDA save/close protection."""
import json
import logging
import os
import sys
import time

ERROR = ('database state abnormal: Root Node is missing or its presence cannot be confirmed; '
         'saving refused; original file retained at the last successful save')
_state = None
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
    state = _state
    if state is None:
        raise RuntimeError('Root Node save guard is not installed')
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
    if not present or state['poisoned']:
        _discard_on_close()
        if not state['poisoned']:
            state['poisoned'] = True
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
                        'first_transition': previous is not None and previous['root_present']}
            state['first_failure'] = evidence
            _log(evidence)
        state['last_sample'] = {'time': now, 'stage': stage, 'root_present': present,
                                'operation': dict(context or state['operation'])}
        if refuse:
            raise RuntimeError(ERROR)
        return ERROR
    state['last_sample'] = {'time': now, 'stage': stage, 'root_present': True,
                            'operation': dict(context or state['operation'])}
    return None


def install(context):
    global _state
    import ida_idp
    import ida_loader
    path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    if _state is not None:
        if _state['path'] != path:
            # A changed active database in a live owner is itself uncertain.
            _state['identity_error'] = 'active database path changed within owner'
        return
    now = time.monotonic()
    _state = {'path': path, 'context': dict(context), 'opened_at': now,
              'operation': dict(context), 'last_sample': None, 'poisoned': False,
              'initial_metadata': _metadata(), 'first_failure': None}
    _history.append(path)

    class CloseGuard(ida_idp.IDB_Hooks):
        def savebase(self):
            # Notification return values cannot veto. Public flags can suppress
            # automatic close writeback, including after the adapter disconnects.
            sample('automatic-save', refuse=False)

        def closebase(self):
            sample('automatic-close', refuse=False)

    hook = CloseGuard()
    if not hook.hook():
        _discard_on_close()
        raise RuntimeError('could not install Root Node close protection')
    _state['hook'] = hook


def begin(context, refuse=True):
    install(context)
    _state['operation'] = dict(context)
    return sample('before', context, refuse=refuse)


def finish(context, refuse=True):
    return sample('after', context, refuse=refuse)


def save_database(outfile=None, flags=0):
    """For adapter-owned explicit saves; scripts calling IDA directly bypass it."""
    import ida_loader
    sample('explicit-save')
    return ida_loader.save_database(outfile, flags)
