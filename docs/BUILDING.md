# Building from Source

## Requirements

- macOS or Linux host
- Rust 1.77+
- LLVM / Clang
- An IDA installation, provided via `IDADIR` or discoverable from common
  install paths
- An IDA SDK, provided via `IDASDKDIR` or `IDALIB_SDK`

`ida-cli` links against the vendored `idalib` at build time. At runtime it
probes the active IDA install and picks a backend automatically:

- `idat-compat` — IDA 9.0–9.2, shells out to `idat` + IDAPython
- `native-linked` — IDA 9.3+, opens the database in-process via `idalib`

The build tree is not restricted to one exact installed IDA runtime, but the
SDK must still be present during compilation.

## Clone and Build

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"   # or a Linux install
export IDASDKDIR="/path/to/ida-sdk"                                     # root or ida-sdk/src

cargo build --bin ida-cli
```

Release build:

```bash
cargo build --release --bin ida-cli
```

## SDK Path Rules

The SDK path may point to either layout:

- the SDK root, for example `/path/to/ida-sdk`
- the nested `src` directory, for example `/path/to/ida-sdk/src`

The build script accepts both as long as it can locate:

- `include/pro.h`
- platform libraries under `lib/...`

## Runtime Selection

At runtime, `ida-cli` probes the active IDA installation and selects a
worker backend automatically:

```bash
./target/debug/ida-cli probe-runtime
```

Typical outputs:

```json
{"runtime":{"major":9,"minor":1,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

```json
{"runtime":{"major":9,"minor":3,"build":260213},"backend":"native-linked","supported":true,"reason":null}
```

## Binary Names

The primary executable is `target/debug/ida-cli` or `target/release/ida-cli`.
A diagnostic-only `multi_idb_probe` binary lives under `src/bin/` and is
only built with `cargo build --bin multi_idb_probe`.

## Common Commands

Start a long-lived service (stdio MCP, router mode):

```bash
./target/debug/ida-cli serve
```

Use the flat CLI (auto-starts a local HTTP server in the background):

```bash
./target/debug/ida-cli --path /path/to/binary list-functions --limit 20
./target/debug/ida-cli --path /path/to/binary decompile --addr 0x140001000
```

Run an explicit HTTP endpoint when you need one:

```bash
./target/debug/ida-cli serve-http --bind 127.0.0.1:8765
```

## Output Paths

- Server log: `~/.ida/logs/server.log`
- Cached databases: `~/.ida/idb/`
- Server Unix socket: `~/.ida/server.sock`
- Server PID file: `~/.ida/server.pid`
- CLI discovery file: `/tmp/ida-cli.socket`
- Large response cache: `/tmp/ida-cli-out/`

## Notes

- Host support is macOS and Linux only.
- Runtime support starts at IDA 9.0.
- IDA 9.0–9.2 uses `idat-compat`; IDA 9.3+ uses `native-linked`.
- Cross-compilation is not supported.
