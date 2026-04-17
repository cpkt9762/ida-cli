# ida-cli

Headless IDA CLI and skill-first toolkit for binary analysis on macOS and
Linux. `ida-cli` auto-selects a runtime backend, auto-starts a local server
when needed, and exposes the same surface as a flat CLI, a stdio MCP
transport, and a Streamable HTTP MCP transport.

[中文说明](README.zh-CN.md)

## Two User-Facing Entrypoints

- the local `ida-cli` binary (client + service in one executable)
- the installable `ida-cli` skill (`skill/SKILL.md`) for agent environments

The underlying worker / router service layer is started and shut down by the
CLI automatically. You only need to run `serve` / `serve-http` explicitly
when you actually want a long-lived, externally addressable service.

## Support Matrix

### Host Platforms

- Supported: macOS, Linux
- Not supported: Windows

### IDA Runtime Policy

| IDA version | Backend | Notes |
|---|---|---|
| `< 9.0` | unsupported | — |
| `9.0 – 9.2` | `idat-compat` | shells out to `idat` + IDAPython |
| `9.3+` | `native-linked` | links against vendored `idalib` |

Backend selection is made at runtime by `probe-runtime`. Building still
requires an IDA SDK because the vendored native layer is linked against it;
at runtime the CLI opens IDA itself from `IDADIR` or a normalised common
install path.

## Current Capabilities

On supported IDA 9.x runtimes, `ida-cli` can:

- open raw PE / ELF / Mach-O binaries and reuse cached `.i64` databases
- list and resolve functions, disassemble by address or name, decompile via
  Hex-Rays
- query segments, strings, imports, exports, entry points, global symbols
- resolve address ↔ segment / function / symbol context
- read bytes / strings / integers, apply `read_*` and `convert_number` helpers
- query xrefs to / from an address (including xrefs to strings and struct
  fields)
- build callgraphs, basic blocks, and control-flow paths
- search text, immediates, bytes, instructions, operands, pseudocode
- declare / apply types, rename symbols and locals, set comments
- run IDAPython snippets via `run_script`

Open items: some write-heavy and advanced type-editing operations are still
partial on `idat-compat`. See [docs/TOOLS.md](docs/TOOLS.md) for the
generated tool list.

## Quick Start

### Recommended: Install the Skill

The default entrypoint is the `ida-cli` skill, not a manual CLI install.

```bash
# list the skill exposed by this repository
npx -y skills add https://github.com/cpkt9762/ida-cli --list

# install the ida-cli skill for Codex
npx -y skills add https://github.com/cpkt9762/ida-cli --skill ida-cli --agent codex --yes --global
```

After install, the skill ships its own bootstrap wrapper:

```bash
~/.agents/skills/ida-cli/scripts/ida-cli.sh --help
~/.agents/skills/ida-cli/scripts/ida-cli.sh probe-runtime
~/.agents/skills/ida-cli/scripts/ida-cli.sh --path /path/to/binary list-functions --limit 20
```

If `ida-cli` is missing, the wrapper installs it through the repository
installer before forwarding the command.

### Direct CLI Install (Optional)

Use this only if you want the standalone CLI without going through the
skill.

```bash
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --add-path
```

Useful variants:

```bash
# install a specific release
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --tag v0.9.3 --add-path

# build directly from a branch or ref
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --ref master --build-from-source --add-path
```

Notes:

- The installer places the launcher in `~/.local/bin/ida-cli` by default.
- `--add-path` appends that bin directory to your shell rc file.
- If neither `IDASDKDIR` nor `IDALIB_SDK` is set and a local build is
  required, the installer clones the open-source `HexRaysSA/ida-sdk`
  automatically.
- When multiple IDA installations are present, export `IDADIR` explicitly
  before installing or running `ida-cli`.

### Build from Source

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"   # or a Linux install
export IDASDKDIR="/path/to/ida-sdk"                                     # root or ida-sdk/src

cargo build --bin ida-cli
./target/debug/ida-cli --help
```

### Use the CLI

`ida-cli` is client-first. Any client subcommand auto-starts a local
Streamable-HTTP server bound to a random port and writes
`/tmp/ida-cli.socket` for discovery:

```bash
./target/debug/ida-cli --path /path/to/sample.bin list-functions --limit 20
./target/debug/ida-cli --path /path/to/sample.bin decompile --addr 0x140001000
./target/debug/ida-cli --path /path/to/sample.bin raw '{"method":"get_xrefs_to","params":{"address":"0x140001000"}}'
```

Commands whose first argument is a service subcommand (`serve`,
`serve-http`, `serve-worker`, `probe-runtime`) enter service mode instead:

```bash
./target/debug/ida-cli serve                          # stdio MCP transport
./target/debug/ida-cli serve-http --bind 127.0.0.1:8765
./target/debug/ida-cli probe-runtime
```

Example backend-probe output:

```json
{"runtime":{"major":9,"minor":1,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

```json
{"runtime":{"major":9,"minor":3,"build":260213},"backend":"native-linked","supported":true,"reason":null}
```

For the complete CLI surface see
[skill/references/cli-tool-reference.md](skill/references/cli-tool-reference.md).

## Build Requirements

- Rust 1.77+
- LLVM / Clang
- macOS or Linux host
- An IDA installation via `IDADIR` (runtime support starts at IDA 9.0)
- An IDA SDK via `IDASDKDIR` or `IDALIB_SDK`

The SDK path may point to either layout:

- `/path/to/ida-sdk`
- `/path/to/ida-sdk/src`

## Runtime Notes

### `idat-compat`

IDA 9.0–9.2 compatibility backend. It shells out to `idat`, runs short
IDAPython scripts, and returns structured JSON back to the CLI runtime.

### `native-linked`

IDA 9.3+ backend. Links against the vendored `idalib` line and opens
databases in-process.

### Cache and Local Runtime Paths

- Database cache: `~/.ida/idb/`
- Logs: `~/.ida/logs/server.log`
- Server Unix socket: `~/.ida/server.sock`
- Server PID file: `~/.ida/server.pid`
- CLI discovery file (maps the flat CLI to the live socket): `/tmp/ida-cli.socket`
- Large JSON response cache: `/tmp/ida-cli-out/`

## CI and Releases

GitHub Actions compiles and tests the tree on hosted runners against the
open-source `HexRaysSA/ida-sdk`, so CI does not depend on any private
machine layout.

Current workflow behavior:

- pushes and pull requests against `master` run validation
- tagged pushes like `v0.9.3` build release archives for Linux and macOS
- releases attach `install.sh` plus platform archives

Release binaries are built against SDK stubs. At install time the launcher
generated by `install.sh` resolves your local IDA runtime through `IDADIR`
or a normalised set of common install paths before invoking `ida-cli`.

## Documentation

- [docs/BUILDING.md](docs/BUILDING.md) — build from source
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — router, backends, federation
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) — stdio, streamable HTTP, multi-IDB
- [docs/TOOLS.md](docs/TOOLS.md) — generated tool catalog
- [docs/TESTING.md](docs/TESTING.md) — integration and unit tests
- [skill/SKILL.md](skill/SKILL.md) — skill bootstrap and usage policy
- [skill/references/cli-tool-reference.md](skill/references/cli-tool-reference.md) — complete CLI surface

## License

MIT
