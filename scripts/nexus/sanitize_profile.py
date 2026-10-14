"""Retain only already accepted EULA records in the caller's isolated IDAUSR."""

import os
from pathlib import Path
import sys
import sysconfig

profile = Path(os.environ["IDAUSR"])
if not (profile / ".n0-isolated-profile").is_file():
    raise RuntimeError("refusing to modify a profile without the N0 isolation marker")

import idapro
import ida_registry

accepted = sys.argv[1:]
if not accepted or any(ida_registry.reg_read_int(name, 0) != 1 for name in accepted):
    raise RuntimeError("existing EULA acceptance is missing; no terms were accepted")
for name in ida_registry.reg_subkey_subkeys(""):
    if not ida_registry.reg_delete_tree(name):
        raise RuntimeError("cannot remove copied registry subtree")
for name in ida_registry.reg_subkey_values(""):
    if name not in accepted and not ida_registry.reg_delete(name):
        raise RuntimeError("cannot remove copied registry setting")
if any(ida_registry.reg_read_int(name, 0) != 1 for name in accepted):
    raise RuntimeError("existing EULA records changed while preparing profile")
filename = sysconfig.get_config_var("LDLIBRARY")
candidates = [Path(sysconfig.get_config_var(name)) / filename
              for name in ("LIBDIR", "PYTHONFRAMEWORKPREFIX") if sysconfig.get_config_var(name)]
library = next((candidate for candidate in candidates if candidate.is_file()), None)
if library is None:
    raise RuntimeError("Python shared library is missing; legacy IDAPython is BLOCKED")
# Native ida-cli needs IDAPython's documented runtime selector. This writes
# only the isolated profile, never idapyswitch's global configuration.
ida_registry.reg_write_string("Python3TargetDLL", str(library.resolve()))
print("Python library:", library.resolve())
print("IDA version:", idapro.get_library_version())
print("PROFILE_SANITIZED")
