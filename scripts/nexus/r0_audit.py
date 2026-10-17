#!/usr/bin/env python3
"""Audit only named private R0 roots; optionally withdraw dead owned test records."""
import argparse
import json
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/support"))
from process_identity import identity, same_process


def audit(root, cleanup):
    root = root.resolve(strict=True)
    if not root.name.startswith(("n7r0.", "n7rf1.")) or root.parent != Path("/private/tmp").resolve():
        raise ValueError("audit accepts only explicitly named /tmp/n7r0.* or /tmp/n7rf1.* roots")
    records = []
    for pattern in ("**/process.json", "**/owned-processes/*.json"):
        for path in root.glob(pattern):
            records.append(json.loads(path.read_text()))
    for path in root.glob("**/processes.jsonl"):
        records.extend(json.loads(line) for line in path.read_text().splitlines())
    # Direct SDK fault children are already waitpid-reaped, but audit them too.
    for path in root.glob("**/spawn.json"):
        for entry in json.loads(path.read_text())["events"]:
            if isinstance(entry, dict) and "pid" in entry:
                records.append(entry)
    for path in root.glob("**/ready.json"):
        records.extend(json.loads(path.read_text()).get("child_processes", []))
    known = {record["pid"]:record for record in records if "pid" in record}
    live, unknown, removed, registrations, sockets = [], [], [], [], []
    for pid, record in known.items():
        current = identity(pid)
        if current is not None:
            if same_process(current, record.get("identity", record.get("birth"))):
                live.append(pid)
            elif record.get("identity") is None:
                unknown.append({"pid":pid,"reason":"missing recorded birth; cannot attribute a live generation"})
            # A different native birth proves this test's generation has gone.
    for path in root.glob("**/instances/*.json"):
        if path.is_symlink():
            unknown.append({"path":str(path),"reason":"symlink registration"})
            continue
        payload = json.loads(path.read_text())
        pid = payload["pid"]
        registrations.append(str(path))
        if pid not in known:
            unknown.append({"path":str(path),"reason":"no matching owned process record"})
        elif identity(pid) is None and cleanup:
            path.unlink()
            removed.append(str(path))
        else:
            unknown.append({"path":str(path),"reason":"registration retained; owner not proved absent or cleanup disabled"})
    for path in root.rglob("*"):
        if stat.S_ISSOCK(path.lstat().st_mode):
            sockets.append(str(path))
            owner_path = path.parent.parent / "process.json"
            if path.name in ("b", "c", "l") and owner_path.is_file():
                owner = json.loads(owner_path.read_text())
                if owner["pid"] in known and identity(owner["pid"]) is None and cleanup:
                    path.unlink()
                    removed.append(str(path))
                    continue
            unknown.append({"path":str(path),"reason":"socket retained; requires exact dead owner attribution"})
    return {"root":str(root), "owned_processes":len(known), "live_owned":live,
            "unknown":unknown,"registrations_observed":registrations,"sockets_observed":sockets,
            "removed_dead_owned_records":removed,
            "signals_sent":0,"clean":not live and not unknown}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup-stale", action="store_true")
    args = parser.parse_args()
    results = [audit(root, args.cleanup_stale) for root in args.root]
    args.output.write_text(json.dumps(results, indent=2))
    print(json.dumps({"output":str(args.output),"clean":all(result["clean"] for result in results)}))
    raise SystemExit(0 if all(result["clean"] for result in results) else 1)


if __name__ == "__main__":
    main()
