#!/usr/bin/env python3
"""Run the existing preparer with verified local download sources (R0 only)."""
import argparse
import importlib.util
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--wheels", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    spec = importlib.util.spec_from_file_location("prepare", REPO / "scripts/prepare_nexus_env.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = module.run

    def local_run(root, label, command, **kwargs):
        if label == "download":
            index = command.index("--index-url")
            command[index:index + 2] = ["--no-index", "--find-links", str(args.wheels.resolve())]
        elif label == "clone":
            command = ["git", "clone", "--quiet", "--no-hardlinks", "--local",
                       str(args.source.resolve()), command[-1]]
        return original(root, label, command, **kwargs)

    module.run = local_run
    # Keep the historical generator's exact aa5 baseline. Never silently apply
    # the formal R1 patch and then try to patch that product a second time.
    sys.argv = [str(REPO / "scripts/prepare_nexus_env.py"), "--sdk-baseline", "r0", *remaining]
    module.main()


if __name__ == "__main__":
    main()
