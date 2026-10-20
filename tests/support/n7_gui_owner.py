"""Run inside the dedicated E23 Qt GUI, independently of Nexus requests."""

import json
import os
from pathlib import Path
import sys
import traceback

ROOT = Path(os.environ['N7C_GUI_ROOT'])
sys.path.insert(0, os.environ['N7C_GUI_SITE'])


def publish(name, value):
    assert isinstance(name, str) and Path(name).name == name and Path(name).suffix == '.json'
    temporary = ROOT / (name + '.tmp')
    temporary.write_text(json.dumps(value))
    temporary.replace(ROOT / name)


def observe():
    import ida_bytes
    import ida_loader
    import ida_kernwin
    return {'pid': os.getpid(), 'path': ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
            'address': ADDRESS, 'comment': ida_bytes.get_cmt(ADDRESS, False),
            'gui': bool(ida_kernwin.is_idaq()),
            'interactive': os.environ.get('IDA_IS_INTERACTIVE')}


def tick():
    import ida_bytes
    import ida_kernwin
    request = ROOT / 'request.json'
    if not request.exists():
        return 20
    try:
        command = json.loads(request.read_text())
        request.unlink()
        if command['action'] == 'write':
            assert ida_bytes.set_cmt(ADDRESS, command['comment'], False)
        else:
            assert command['action'] == 'read', command
        ida_kernwin.jumpto(ADDRESS)
        ida_kernwin.refresh_idaview_anyway()
        publish(command['response'], observe())
    except Exception:
        publish('error.json', {'error': traceback.format_exc()})
        return -1
    return 20


try:
    import ida_auto
    import ida_kernwin
    import ida_loader
    import ida_name
    assert ida_kernwin.is_idaq(), 'E23 requires the actual Qt GUI'
    assert os.environ.get('IDA_IS_INTERACTIVE') == '1'
    assert ida_auto.auto_wait()
    ADDRESS = ida_name.get_name_ea(0xffffffffffffffff, '_main')
    if ADDRESS == 0xffffffffffffffff:
        ADDRESS = ida_name.get_name_ea(0xffffffffffffffff, 'main')
    assert ADDRESS != 0xffffffffffffffff, 'compiled mini main must exist'
    plugin = ida_loader.load_plugin(str(ROOT / 'ida_nexus_plugin.py'))
    assert plugin is not None, 'Nexus plugin did not load'
    import ida_nexus.plugin
    ida_nexus.plugin.start()
    TIMER = ida_kernwin.register_timer(20, tick)
    assert TIMER is not None
    publish('ready.json', observe())
except Exception:
    publish('error.json', {'error': traceback.format_exc()})
