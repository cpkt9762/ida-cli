"""Test-only native OS-source substitution; production U6 validation is unchanged.

This process is selected only by the Rust nexus-test-support build. It does not
claim a host reboot or alter SDK outcomes, target identities or journal history.
"""
import copy
import json
import os
from pathlib import Path
import runpy
import sys

def observed_scope(native_scope, path, incarnation):
    current = native_scope(path, incarnation)
    source = Path(os.environ['R2_BOOT_SOURCE_INPUT'])
    if source.exists():
        overrides = json.loads(source.read_text())
        for key, value in overrides.items():
            current[key] = dict(current[key], **value) if isinstance(value, dict) else copy.deepcopy(value)
    return current


if __name__ == '__main__':
    bootstrap = sys.argv.pop(1)
    sys.argv[0] = bootstrap
    entry = runpy.run_path(bootstrap, run_name='verified_os_input')['load_entry']()
    if hasattr(entry, 'Observer'):
        # A simulated later boot must be uniform for the current consumer,
        # target writers and fresh acquisitions. Keep actual helper/peer birth
        # for authentication; substitute only the current OS boot input.
        native_receive = entry.Observer.receive
        def receive(self, value):
            result = native_receive(self, value)
            marker = Path(os.environ['R2_BOOT_SOURCE_INPUT'] + '.boot')
            if value['kind'] == 'heartbeat' and marker.exists():
                result['identity'] = dict(result['identity'], boot_id=marker.read_text())
            return result
        entry.Observer.receive = receive
    else:
        native_scope = entry.creation_scope
        entry.creation_scope = lambda path, incarnation: observed_scope(native_scope, path, incarnation)
    entry.main()
