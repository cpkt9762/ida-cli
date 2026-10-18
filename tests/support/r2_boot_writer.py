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

bootstrap = sys.argv.pop(1)
sys.argv[0] = bootstrap
entry = runpy.run_path(bootstrap, run_name='verified_os_input')['load_entry']()
native_scope = entry.creation_scope


def observed_scope(path, incarnation):
    current = native_scope(path, incarnation)
    source = Path(os.environ['R2_BOOT_SOURCE_INPUT'])
    if source.exists():
        overrides = json.loads(source.read_text())
        for key, value in overrides.items():
            current[key] = dict(current[key], **value) if isinstance(value, dict) else copy.deepcopy(value)
    return current


entry.creation_scope = observed_scope
entry.main()
