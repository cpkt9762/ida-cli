# ida-cli

Headless IDA CLI and MCP server for binary analysis with automatic runtime backend selection.

[中文说明](README.zh-CN.md)

## Overview

`ida-cli` exposes IDA Pro analysis over:

- CLI over Unix socket
- MCP over stdio
- MCP over Streamable HTTP

It supports two runtime modes:

- `native-linked`
  Uses the vendored `idalib` backend for newer runtimes that can safely open databases in-process.
- `idat-compat`
  Uses `idat` + IDAPython as a compatibility backend for older runtimes that would otherwise crash in `open_database_quiet()`.

On the current branch, older 9.x runtimes such as the tested local 9.1 installation are routed to `idat-compat` automatically.

## What Works Today

On the tested local IDA 9.1 runtime, `ida-cli` can already:

- Open raw binaries and reuse cached databases
- List and resolve functions
- Disassemble by address or function
- Decompile functions
- Show address info, segments, strings, imports, exports, entry points, globals
- Read bytes, strings, and integers
- Query xrefs to/from an address
- Search text and byte patterns
- Run IDAPython snippets

The sample `example2-devirt.bin` was verified end-to-end:

- `list-functions` found `main` at `0x140001000`
- `decompile --addr 0x140001000` succeeded

Some write-heavy and advanced type-editing operations still require further parity work in `idat-compat`.

## Quick Start

### Run the server

```bash
export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"
export IDASDKDIR=/tmp/ida-sdk-sdk3

cargo build --bin ida-cli
./target/debug/ida-cli serve
```

### Use the CLI

```bash
./target/debug/ida-cli --path /path/to/example2-devirt.bin list-functions --limit 20
./target/debug/ida-cli --path /path/to/example2-devirt.bin decompile --addr 0x140001000
./target/debug/ida-cli --path /path/to/example2-devirt.bin raw '{"method":"get_xrefs_to","params":{"path":"/path/to/example2-devirt.bin","address":"0x140001000"}}'
```

### Probe the selected runtime backend

```bash
./target/debug/ida-cli probe-runtime
```

Example output on the tested 9.1 installation:

```json
{"runtime":{"major":9,"minor":0,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

## Build Requirements

- Rust 1.77+
- LLVM/Clang
- IDA installation via `IDADIR`
- IDA SDK via `IDASDKDIR` or `IDALIB_SDK`

The SDK lookup accepts both layouts:

- `/path/to/ida-sdk`
- `/path/to/ida-sdk/src`

## Runtime Notes

### `native-linked`

This backend links against the vendored `idalib` line and is intended for newer compatible runtimes.

### `idat-compat`

This backend shells out to `idat`, runs short IDAPython scripts, and returns structured JSON results to the router. It exists to keep older runtimes operational without hard-crashing workers.

### Cache and socket paths

- Database cache: `~/.ida/idb/`
- Logs: `~/.ida/logs/server.log`
- CLI discovery socket: `/tmp/ida-cli.socket`
- Large JSON response cache: `/tmp/ida-cli-out/`

## Documentation

- [docs/BUILDING.md](docs/BUILDING.md)
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md)
- [docs/TOOLS.md](docs/TOOLS.md)

## License

MIT
