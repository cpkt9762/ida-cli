#!/usr/bin/env python3
"""Serial, fresh-root R0 runner. Nothing is installed or connected to user state."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--stage", action="append", choices=("primitives", "sdk", "real", "rust"), required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--idasdk", type=Path)
    parser.add_argument("--target-dir", type=Path, help="explicit private cargo cache; sole serial writer only")
    parser.add_argument("--cargo-home", type=Path, default=Path.home() / ".cargo")
    parser.add_argument("--rustup-home", type=Path, default=Path.home() / ".rustup")
    args = parser.parse_args()
    root = args.root.resolve()
    if len(os.fsencode(str(root))) > 45:
        parser.error("choose a short /tmp/n7r0.* root for Unix sockets")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / "home").mkdir(mode=0o700)
    (root / "tmp").mkdir(mode=0o700)
    args.report.mkdir(parents=True, exist_ok=True)
    environment = args.environment.resolve(strict=True)
    manifest = json.loads((environment / "environment.json").read_text())
    python = str(environment / "venv/bin/python")
    variables = {"HOME":str(root / "home"), "TMPDIR":str(root / "tmp"),
        "PATH":os.pathsep.join((str(args.cargo_home / "bin"), "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")),
        "PYTHONDONTWRITEBYTECODE":"1", "PYTHONUNBUFFERED":"1", "LANG":"C.UTF-8"}
    results = {"root":str(root), "environment":str(environment), "stages":{}}
    candidate = args.candidate.resolve() if args.candidate else root / "candidate"

    def run(label, command, seconds=30, extra=None):
        # Every child compilation/check/test has a shell-side timeout in recorder.
        with (args.report / "progress.md").open("a") as stream:
            stream.write(f"\n- {root.name}/{label}: timeout {seconds}s; " +
                         ("private multi-process fault shard" if seconds == 120 else
                          "fresh build or tiny real IDA startup/cleanup" if seconds == 180 else "bounded local check") + "\n")
        values = dict(variables, **(extra or {}))
        invocation = [sys.executable, str(REPO / "scripts/nexus/r0_record.py"),
            "--report", str(args.report), "--label", root.name + "-" + label,
            "--seconds", str(seconds), "--", "env", "-i",
            *(f"{k}={v}" for k,v in values.items()), *command]
        subprocess.run(invocation, cwd=REPO, check=True)

    for stage in args.stage:
        if stage == "primitives":
            for name in ("os", "transfer", "records", "durable", "install", "v1_checks", "contract_checks"):
                case = root / name
                run(name, [python, "-B", f"tests/support/r0_{name}.py"], 120,
                    {"R0_CASE_ROOT":str(case), "IDA_NEXUS_STATE_DIR":str(case / "state"),
                     "R0_IDA_ROOT":manifest["ida_dir"]})
                results["stages"][name] = str(case)
        elif stage == "sdk":
            site = list((environment / "venv/lib").glob("python*/site-packages"))
            if len(site) != 1:
                raise RuntimeError("ambiguous prepared Python package directory")
            run("candidate", [python, "scripts/nexus/r0_sdk_candidate.py", "--source", str(site[0]), "--target", str(candidate)])
            case = root / "sdk"
            run("sdk", [python, "-B", "tests/support/r0_sdk.py"], 120,
                {"R0_CANDIDATE":str(candidate), "R0_CASE_ROOT":str(case), "IDA_NEXUS_STATE_DIR":str(case / "state")})
            results["stages"]["sdk"] = str(case)
            results["candidate"] = str(candidate)
        elif stage == "real":
            run("real", [python, "-B", "tests/support/r0_real_ida.py", "--env",str(environment),
                "--case",str(root / "real"),"--candidate",str(candidate)], 180)
            results["stages"]["real"] = str(root / "real")
        else:
            if args.idasdk is None:
                parser.error("--idasdk required for rust")
            extra = {"CARGO_HOME":str(args.cargo_home), "RUSTUP_HOME":str(args.rustup_home),
                "CARGO_TARGET_DIR":str(args.target_dir or root / "target"), "IDASDK":str(args.idasdk), "IDADIR":manifest["ida_dir"],
                 "IDA_CLI_HOME":str(root / "rust/cli"),
                "R0_CASE_ROOT":str(root / "rust"), "R0_PYTHON":python,
                "IDA_NEXUS_PYTHON":python, "IDA_NEXUS_IPC_ROOT":str(root / "rust/ipc")}
            target = ["--features","nexus-test-support","--test","nexus_r0_prototypes"]
            run("rust-check", ["cargo","check",*target],180,extra)
            run("rust-clippy", ["cargo","clippy",*target,"--","-D","warnings"],180,extra)
            run("rust-build", ["cargo","test",*target,"--no-run"],180,extra)
            run("rust-red", ["cargo","test",*target,"current_product_red_baselines","--","--exact","--nocapture","--test-threads=1"],120,extra)
            results["stages"]["rust"] = str(root / "rust")
        (root / "run.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
