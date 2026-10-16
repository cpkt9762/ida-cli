#!/usr/bin/python3
"""Disposable JSON-RPC worker; never loads IDA or opens a real database."""
import json
import pathlib
import os
import socket
import sys

config = json.loads(pathlib.Path(__file__).with_suffix(".json").read_text())
with open(pathlib.Path(config["methods"]).parent.parent / "n2-process-identities.jsonl", "a") as audit:
    audit.write(json.dumps({"pid": os.getpid(), "pgid": None,
                           "kind": "f2-worker-start", "owned_spawn": True}) + "\n")
# Distinguish OS/Python startup from request dispatch in barrier failures.
pathlib.Path(config["methods"]).with_name("worker-started").touch()
if config.get("startup_socket"):
    with socket.socket(socket.AF_UNIX) as startup:
        startup.connect(config["startup_socket"])
        startup.sendall(b"ready\n")
        startup.recv(1)
for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    with open(config["methods"], "a") as log:
        log.write(method + "\n")
    if method == config.get("blocked"):
        barrier = socket.socket(socket.AF_UNIX)
        barrier.connect(config["socket"])
        barrier.sendall(b"started\n")
        barrier.recv(1)
        barrier.close()
    response = {"jsonrpc": "2.0", "id": request["id"]}
    if method == config["failure"]:
        response["error"] = {"code": -32000, "message": config.get("error", "Function not found: entrypoint")}
    else:
        response["result"] = {
            "open": {"opened": True},
            "get_function_by_name": {"address": "0x100"},
            "build_callgraph": {
                "edges": [{"from": "0x100", "to": "0x200"},
                          {"from": "0x100", "to": "0x300"},
                          {"from": "0x200", "to": "0x400"}],
                "nodes": []},
            "rename_symbol": {"renamed": True},
        }.get(method, {})
    print(json.dumps(response), flush=True)
