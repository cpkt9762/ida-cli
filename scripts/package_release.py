#!/usr/bin/env python3
"""Package the executable and complete pinned Nexus runtime preparation assets."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    runtime = repo / 'scripts/nexus'
    lock = json.loads((runtime / 'runtime-lock.json').read_text())
    for name, expected in lock['assets'].items():
        if Path(name).name != name or hashlib.sha256((runtime / name).read_bytes()).hexdigest() != expected:
            raise ValueError('runtime asset hash mismatch: ' + name)
    assets = ['README.md', 'README.zh-CN.md', 'LICENSE', 'scripts/install.sh',
              'scripts/prepare_nexus_env.py', 'scripts/nexus/runtime-lock.json']
    assets.extend('scripts/nexus/' + name for name in lock['assets'])
    # Refuse an existing archive; callers choose a fresh staging destination.
    with args.output.open('xb') as output, tarfile.open(fileobj=output, mode='w:gz') as archive:
        archive.add(args.binary.resolve(strict=True), arcname='ida-cli', recursive=False)
        for name in assets:
            archive.add(repo / name, arcname=name, recursive=False)
    print(hashlib.sha256(args.output.read_bytes()).hexdigest(), args.output)


if __name__ == '__main__':
    main()
