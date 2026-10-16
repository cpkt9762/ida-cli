#!/usr/bin/python3
"""Disposable MCP-open protocol fixture. Never imports IDA or Nexus."""
import json
import os
import pathlib
import socket
import sys

config = json.loads(pathlib.Path(__file__).with_suffix(".json").read_text())
with open(pathlib.Path(config["methods"]).parent.parent / "n2-process-identities.jsonl", "a") as audit:
    audit.write(json.dumps({"pid": os.getpid(), "pgid": None,
                           "kind": "f5-mcp-open-" + config["case"],
                           "owned_spawn": True}) + "\n")
if config.get("startup_socket"):
    with socket.socket(socket.AF_UNIX) as startup:
        startup.connect(config["startup_socket"])
        startup.sendall(b"ready\n")
        assert startup.recv(1) == b"x"
opens = 0
for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    if method == "open":
        opens += 1
    with open(config["methods"], "a") as log:
        log.write(method + "\n")
    if method == config.get("blocked"):
        with socket.socket(socket.AF_UNIX) as barrier:
            barrier.connect(config["socket"])
            barrier.sendall(b"started\n")
            barrier.recv(1)
    response = {"jsonrpc": "2.0", "id": request["id"]}
    if method == "open" and opens == config.get("fail_open"):
        response["error"] = {"code": -32000, "message": "fixture open error"}
    elif method == "open":
        response["result"] = config.get("open_result", {"opened": True})
    else:
        response["result"] = {}
    print(json.dumps(response), flush=True)
