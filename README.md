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

On the current branch, older 9.x runtimes such as the tested local 9.1 and 9.3 installations are routed to `idat-compat` automatically.

## What Works Today

On the tested local IDA 9.1 and 9.3 runtimes, `ida-cli` can already:

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

### Install `ida-cli`

Recommended: use the installer script. It downloads the latest tagged release when one exists, otherwise it can fall back to a local source build.

```bash
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --add-path
```

Useful variants:

```bash
# Install a specific release
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --tag v0.9.3 --add-path

# Build directly from a branch or ref
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --ref master --build-from-source --add-path
```

Notes:

- The installer places the launcher in `~/.local/bin/ida-cli` by default.
- `--add-path` appends that bin directory to your shell rc file.
- If `IDASDKDIR` / `IDALIB_SDK` is not already set and the script needs a local build, it will clone the open-source `HexRaysSA/ida-sdk` automatically.
- If you keep multiple IDA installations side by side, export `IDADIR` explicitly before installing or running `ida-cli`.

### Build from source

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/path/to/ida/Contents/MacOS"
export IDASDKDIR="/path/to/ida-sdk"

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

Example output on the tested 9.3 installation:

```json
{"runtime":{"major":9,"minor":0,"build":260213},"backend":"idat-compat","supported":true,"reason":null}
```

### Install the skill

The tested command is `npx skills add`, not `npx skill add`.

```bash
# List the skill exposed by this repository
npx -y skills add https://github.com/cpkt9762/ida-cli --list

# Install the ida-cli skill for Codex
npx -y skills add https://github.com/cpkt9762/ida-cli --skill ida-cli --agent codex --yes --global
```

This was verified locally: the CLI detected the `ida-cli` skill from `skill/SKILL.md` and installed it to `~/.agents/skills/ida-cli`.

After installation, the skill ships its own bootstrap wrapper:

```bash
~/.agents/skills/ida-cli/scripts/ida-cli.sh --help
~/.agents/skills/ida-cli/scripts/ida-cli.sh probe-runtime
~/.agents/skills/ida-cli/scripts/ida-cli.sh --path /path/to/binary list-functions --limit 20
```

That wrapper installs `ida-cli` automatically if it is missing, then runs the requested command.

## Build Requirements

- Rust 1.77+
- LLVM/Clang
- IDA installation via `IDADIR` (supports IDA 9.1 – 9.3)
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

## CI and Releases

GitHub Actions now uses the open-source `HexRaysSA/ida-sdk` on hosted runners so it can compile and test the current tree without relying on a private machine layout.

Current workflow behavior:

- Pushes and pull requests against `master` run validation
- Tagged pushes like `v0.9.3` build release archives for Linux, macOS, and Windows
- Releases attach `install.sh` plus platform archives

The release archives are built against SDK stubs, while the installed launcher resolves your local IDA runtime through `IDADIR` or common install paths before starting `ida-cli`.

## Documentation

- [docs/BUILDING.md](docs/BUILDING.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md)
- [docs/TOOLS.md](docs/TOOLS.md)

## License

MIT
