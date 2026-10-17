#!/usr/bin/env python3
"""Installation bootstrap prototype. Invoke only via r0_maintenance_launch.sh."""
import sys
import os


def main():
    if os.__spec__.origin != "frozen":
        raise RuntimeError("trusted frozen os required")
    # Only interpreter-owned stdlib/extension/site paths survive before other imports.
    trusted = os.path.realpath(sys.base_prefix)
    venv = os.path.realpath(sys.prefix)
    sys.path[:] = [p for p in sys.path if p and os.path.isabs(p) and
                   any(os.path.realpath(p).startswith(base + os.sep) for base in (trusted, venv))]
    import hashlib
    import json
    import stat
    root = os.path.dirname(os.path.realpath(__file__))
    for path in (root, __file__, os.path.join(root, "manifest.json")):
        info = os.lstat(path)
        if info.st_uid != os.getuid() or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise RuntimeError("untrusted installation permissions")
    with open(os.path.join(root, "manifest.json")) as stream:
        manifest = json.load(stream)
    for name, expected in manifest.items():
        if name != os.path.basename(name) or name in ("", ".", ".."):
            raise RuntimeError("invalid manifest component")
        path = os.path.join(root, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise RuntimeError("untrusted module")
        with open(path, "rb") as stream:
            if hashlib.sha256(stream.read()).hexdigest() != expected:
                raise RuntimeError("manifest mismatch")
    sys.path.insert(0, root)
    import r0_maintenance_payload
    print(json.dumps({"source":r0_maintenance_payload.__file__, "mode":sys.argv[1:],
                      "prototype_only":True}))


if __name__ == "__main__":
    main()
