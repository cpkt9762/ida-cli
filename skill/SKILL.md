---
name: ida-cli
description: "Reverse engineering and binary analysis with IDA Pro and ida-cli. Use when driving headless IDA workflows from the shell or from an agent loop: disassembly, decompilation, cross-references, struct recovery, type work, patching, FLIRT, IDAPython scripting, emulation-based call tracing, and devirtualization of commercial VM protectors (Themida / VMProtect / Code Virtualizer / WinLicense). Covers the ida-cli flat CLI, the router service, stdio + streamable HTTP transports, the installable skill bootstrap, and the bundled `vm_devirt.py` emulator. Supports PE, ELF, Mach-O, and firmware binaries."
---

# ida-cli Reverse Engineering

General reverse engineering methodology plus a practical `ida-cli` bootstrap
and workflow. The CLI is a thin client on top of an auto-managed local
server that talks to IDA through a worker per database.

---

## Part 0: Zero-Config Bootstrap

Install the skill once:

```bash
npx -y skills add https://github.com/cpkt9762/ida-cli --skill ida-cli --agent codex --yes --global
```

After installation, do not assume the user already has `ida-cli` on PATH or
a live server running.

### Boot Rule

- On first use in a new environment, run `scripts/ida-cli.sh --help`.
- The wrapper detects whether `ida-cli` is available on PATH or at
  `~/.local/bin/ida-cli`.
- If the binary is missing, the wrapper downloads and runs the repository
  installer, then re-runs the smoke test.

### Runtime Rule

- Before real analysis, run `scripts/ida-cli.sh probe-runtime`.
- Do not guess whether the host will pick `native-linked` or `idat-compat`.
- If multiple IDA installations are present, export `IDADIR` explicitly:
  - `export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"`
  - `export IDADIR=/opt/ida-pro-9.3`

### Use Rule

- Prefer `scripts/ida-cli.sh` as the single entrypoint inside the skill.
- Do not ask the user to run `serve` or `serve-http` for routine work. Any
  client subcommand auto-starts a local HTTP server bound to a random port
  and writes `/tmp/ida-cli.socket` for discovery.
- Run `serve-http --bind ...` explicitly only when a long-lived, addressable
  HTTP control plane is actually required.

### Zero-Config Commands

```bash
# 1. install ida-cli or confirm it is available
scripts/ida-cli.sh --help

# 2. probe the selected runtime backend
scripts/ida-cli.sh probe-runtime

# 3. routine analysis (client mode, auto-starts a server)
scripts/ida-cli.sh --path /path/to/sample.bin list-functions --limit 20
scripts/ida-cli.sh --path /path/to/sample.bin decompile --addr 0x140001000

# 4. only when a shared HTTP endpoint is actually needed
scripts/ida-cli.sh serve-http --bind 127.0.0.1:8765
```

### Environment Knobs

- Installer target: `~/.local/bin/ida-cli`
- Pin the source repository / ref:
  - `IDA_CLI_REPO=cpkt9762/ida-cli`
  - `IDA_CLI_INSTALL_REF=master`
- Pass extra installer arguments:
  - `IDA_CLI_INSTALL_ARGS="--add-path"`
- Pin a specific IDA installation:
  - `export IDADIR=/path/to/ida/Contents/MacOS`

Within this skill, `scripts/ida-cli.sh` is the single entrypoint for install,
download, execution, and verification.

---

## Part 1: CLI Surface

`ida-cli` has two faces:

1. **Flat client** — what the skill uses. Sends one request per invocation.
2. **Service** — `serve` (stdio MCP), `serve-http` (Streamable HTTP MCP),
   `serve-worker` (internal subprocess), `probe-runtime` (internal).

When the binary name is `ida-cli` and the first argument is not a service
subcommand, the CLI parses its arguments as a client call and routes the
request through the local socket.

### Direct Subcommands (Client Mode)

```bash
ida-cli --path <file> list-functions [--filter NAME] [--limit 100] [--offset 0]
ida-cli --path <file> decompile --addr 0x1000
ida-cli --path <file> disasm --addr 0x1000 [--count 20]
ida-cli --path <file> disasm --name main [--count 20]
ida-cli --path <file> xrefs-to --addr 0x1000
ida-cli --path <file> list-strings [--query X] [--limit 100]
ida-cli --path <file> list-segments
```

Service / queue helpers:

```bash
ida-cli --path <file> prewarm [--keep-warm] [--queue]
ida-cli prewarm-many samples.txt [--jobs 4]
ida-cli --path <file> enqueue <method> [--priority 0] [--dedupe-key K] [--params '{...}']
ida-cli task-status <id>
ida-cli list-tasks
ida-cli cancel-task <id>
ida-cli status
ida-cli --path <file> close
ida-cli shutdown
```

### Everything Else: `raw` / `pipe`

The flat subcommands cover the most common reads. For everything else use
`raw` for a single request or `pipe` for a stdin batch. Both take JSON-RPC
payloads whose `method` field must match an MCP method name (see
[cli-tool-reference.md](references/cli-tool-reference.md)).

```bash
ida-cli --path <file> raw '{"method":"get_function_by_name","params":{"name":"main"}}'
ida-cli --path <file> raw '{"method":"rename_symbol","params":{"address":"0x1000","new_name":"parse_header"}}'
ida-cli --path <file> raw '{"method":"batch_decompile","params":{"addresses":["0x1000","0x2000"]}}'

ida-cli --json --path <file> pipe <<'EOF'
{"method":"list_functions","params":{"limit":5}}
{"method":"get_xrefs_from","params":{"address":"0x1000"}}
EOF
```

### Output Modes

```bash
ida-cli --json    --path <file> list-functions --limit 5   # pretty JSON
ida-cli --compact --path <file> list-functions --limit 5   # single-line JSON
```

### File Types

| Type | Behavior |
|---|---|
| `.i64` / `.idb` | reopens the existing IDA database directly |
| raw PE / ELF / Mach-O | analysed and cached as `.i64` alongside the input |

### Local Runtime Paths

- Database cache: `~/.ida/idb/`
- Log: `~/.ida/logs/server.log`
- Server Unix socket: `~/.ida/server.sock`
- PID file: `~/.ida/server.pid`
- Discovery file (maps flat CLI → socket): `/tmp/ida-cli.socket`
- Large response cache: `/tmp/ida-cli-out/`

### Failure Recovery

If the local server wedges:

```bash
ida-cli shutdown
pkill -9 -f "ida-cli"
rm -f ~/.ida/server.sock ~/.ida/server.pid ~/.ida/.startup.lock /tmp/ida-cli.socket
```

Then rerun the original client subcommand and let it restart the server.

---

## Part 2: General Reverse Engineering Methodology

### Key Principles

- **F5 first, disasm second (HARD RULE)** — always attempt decompilation once
  before dropping to disassembly.
- **10-second F5 gate (HARD RULE)** — if decompilation clearly fails or
  `decompile_function` stalls beyond 10 seconds, treat the target as
  currently non-decompilable and move to disassembly.
- **Rename as you go (HARD RULE)** — rename every function the moment its
  purpose is understood. Do not accumulate `sub_XXXXX` names.
- **Iterate aggressively** — F5 → apply types → rename → F5 again → validate
  new offsets → repeat.
- **Treat constants literally** — if IDA shows `0x6E`, write `110` until you
  have evidence for higher-level meaning.
- **Use disassembly for small diffs** — a 1-10 value mismatch usually means
  an off-by-one, saturation, or width issue.
- **Keep an analysis log (HARD RULE)** — after each analysed function, log
  address, rename, and purpose.

### Decompilation Strategy

Drop to disassembly when:

- `decompile_function` returns an error
- `decompile_function` exceeds 10 seconds
- pseudocode shows obvious artifacts

Do not keep retrying in a loop once the gate fires. Move down one layer:

1. stop repeated decompilation attempts
2. work from disassembly and basic blocks
3. recover control flow via xrefs and callgraph
4. rename, comment, and apply types from disassembly evidence
5. patch or simplify only with a clear reason
6. retry decompilation after the blockers are resolved

Common "stop F5 and switch to disassembly" signals:

- one dispatcher block dominates the function
- heavy indirect branching or computed jumps
- obvious flattening state variables
- VM-like decode-dispatch-execute loops
- opaque predicates with constant-looking outcomes
- exception-driven or CFG-breaking control flow

Dedicated playbook: [obfuscation-triage.md](references/obfuscation-triage.md).

Common decompiler lies:

| Symptom | Pseudocode | Real instruction pattern |
|---|---|---|
| Constant folding | `result = x * 1718750 / 1000000` | `MUL` + `UDIV` with literal constants |
| Hidden `+1/-1` | `discount = bias * 110 / 64` | there is still an `ADD #1` after division |
| Type confusion | `int v10 = *(int *)(ctx + 0x1DC)` | real load is `LDR W8` and behaves like `u32` |
| Hidden saturation | `result = a - b` | `SUBS` + conditional select to zero |

### Naming Strategy

Rename functions as soon as they are understood.

| Prefix | Meaning |
|---|---|
| `check_` / `validate_` | validation |
| `parse_` / `deserialize_` | parsing / deserialization |
| `compute_` / `calc_` | computation |
| `dispatch_` | dispatch entrypoint |
| `init_` / `setup_` | initialization |

After renaming a callee, re-decompile the caller immediately. Readability
compounds quickly.

### Analysis Log

Record findings in real time. At minimum, log:

- function address
- old name → new name
- one-sentence purpose
- newly recovered structs
- recovered arithmetic formulas
- error-code mappings
- open questions

Suggested format:

```text
## Analysis Log: <binary_name>

### Functions Reversed
| # | Address | Old Name | New Name | Purpose |
|---|---------|----------|----------|---------|
| 1 | 0x1234  | sub_1234 | parse_header | Parse the message header from the input buffer |

### Structs Identified
| Struct | Size | Key Fields | Used By |
|--------|------|-----------|---------|
| MsgHeader | 0x40 | +0x00 magic, +0x04 msg_type, +0x08 payload_len | parse_header |

### Open Questions
- sub_9ABC: likely initializes a lookup table, not yet proven
```

### Struct Recovery

Recover structs from repeated `*(ptr + 0xNNN)` patterns.

Typical ARM64 load-width mapping:

```text
LDR  X8, [X0, #0x130]   -> u64
LDR  W8, [X0, #0x144]   -> u32
LDRH W8, [X0, #0x168]   -> u16
LDRB W8, [X0, #0x178]   -> u8
```

Recommended loop:

1. decompile, collect pointer+offset accesses
2. confirm widths in disassembly
3. read live values if needed
4. declare the struct
5. apply the type
6. re-decompile and confirm fields replace raw offsets
7. use xrefs on struct fields to propagate understanding

### Call Graph Navigation

Never read giant dispatchers linearly. Use a leaf-first strategy:

1. build the call graph from the entrypoint
2. decompile leaf functions
3. rename each leaf immediately
4. re-decompile callers
5. repeat upward

### Search Strategy

Remember little-endian byte order on x86 and ARM64:

```bash
ida-cli --path <file> raw '{"method":"search_bytes","params":{"pattern":"6E 00 00 00"}}'
ida-cli --path <file> raw '{"method":"search_text","params":{"targets":["110","10000"],"kind":"imm"}}'
ida-cli --path <file> raw '{"method":"search_pseudocode","params":{"pattern":"amount"}}'
ida-cli --path <file> raw '{"method":"search_instructions","params":{"patterns":["MUL","UDIV"]}}'
```

### Formula Extraction

Rules:

1. translate constants literally
2. preserve operation order exactly as IDA shows it
3. use `u128` for multi-step 64-bit multiplication chains
4. watch for saturating behaviour
5. verify suspicious arithmetic in disassembly

Diff triage:

| Diff range | Typical cause | Fix |
|---|---|---|
| `> 100` | wrong formula or wrong scale | rebuild from constants |
| `10-100` | wrong operator or operand | verify MUL / DIV / ADD / SUB |
| `1-10` | off-by-one or saturation | compare instruction by instruction |
| `0` | exact match | done |

### Structured Decompilation

Use `decompile_structured` when arithmetic chains are too complex for manual
comparison.

Look for:

- `mul`, `div`, `add`, `sub` nodes
- helper calls such as `__umulh`, `__multi3`, `__udivti3`
- numeric leaves
- variable references

Generate the expression from the AST, then cross-check with disassembly.

---

## Part 3: Common Workflows

### Workflow 1: Binary Orientation

```bash
ida-cli --path <file> raw '{"method":"get_database_info"}'
ida-cli --path <file> list-segments
ida-cli --path <file> raw '{"method":"list_exports"}'
ida-cli --path <file> raw '{"method":"list_imports"}'
ida-cli --path <file> list-functions --limit 50
ida-cli --path <file> raw '{"method":"build_callgraph","params":{"roots":["0x1000"],"max_depth":3}}'
```

### Workflow 2: Struct Reconstruction

1. decompile and collect offsets
2. confirm widths in disassembly
3. read values if needed
4. declare the struct
5. apply the type
6. re-decompile
7. follow field xrefs

### Workflow 3: Arithmetic Verification

```bash
ida-cli --path <file> decompile --addr 0x1000
ida-cli --path <file> raw '{"method":"get_pseudocode_at","params":{"address":"0x1024"}}'
ida-cli --path <file> disasm --addr 0x1000 --count 200
ida-cli --path <file> raw '{"method":"search_instructions","params":{"patterns":["MUL","UDIV"]}}'
ida-cli --path <file> raw '{"method":"search_instruction_operands","params":{"patterns":["#0x6E"]}}'
```

### Workflow 3b: Obfuscation Triage After F5 Failure

If decompilation fails immediately or exceeds the 10-second gate:

1. stop retrying decompilation
2. use `disasm --addr 0x... --count N` for the full body
3. build control-flow understanding from basic blocks, xrefs, and call graph
4. mark dispatcher branches, opaque predicates, flattening state variables
5. rename symbols and annotate intent directly from disassembly
6. retry decompilation only after meaningful progress has been made

### Workflow 3c: Strong Obfuscation Signals

Move immediately into disassembly-first mode when any of these are true:

1. one central block dispatches on a state variable
2. most edges return to the same controller block
3. branch targets are computed indirectly
4. the function looks like a bytecode interpreter or handler VM
5. branches rely on opaque arithmetic that does not simplify in pseudocode
6. exception flow or anti-analysis logic destabilises the decompiler

Dedicated reference page: [obfuscation-triage.md](references/obfuscation-triage.md).

### Workflow 3d: Commercial VM Protection (Themida / VMProtect / Code Virtualizer / WinLicense)

If the target is a Windows x86-64 PE and any of these hold, the target is a
commercial VM protector, not ordinary obfuscation:

1. the function body is a single `jmp` / `push+ret` / `call` that lands in a
   section named `.themida`, `.vlizer`, `.vmp0`/`vmp1`/`vmp2`, `.winlice`,
   `.pelock`, `.svmp`, `.xxx`, or any other non-standard RX section
2. the IAT is stripped and APIs resolve through a dark `.rdata` pointer table
3. pseudocode degenerates into thousands of dispatched handlers
4. IDA segfaults, stalls, or shows a bytecode-style decode loop

In that case do **not** try to reverse handlers. Run the bundled
emulation-based devirtualizer, open the patched PE in IDA, and decompile
normally:

```bash
pip install -r skill/scripts/vm_devirt_requirements.txt

python3 skill/scripts/vm_devirt.py protected.bin --auto -o protected-devirt.bin

ida-cli --path protected-devirt.bin list-functions --limit 20
ida-cli --path protected-devirt.bin decompile --addr 0x140001000
```

Full methodology, the capability matrix, and the post-devirt IDA workflow
live in [vm-devirt.md](references/vm-devirt.md).

### Workflow 4: Error Code Mapping

1. search immediate values
2. resolve the containing function
3. inspect the pseudocode context
4. add comments
5. search for similar return sites

### Workflow 5: Table and Dispatch Analysis

1. search strings like `factory` or `registry`
2. follow xrefs
3. identify the table builder
4. scan the table
5. resolve and decompile each function pointer

### Workflow 6: Multi-Database Analysis

1. open multiple databases (one `--path` per request; the server spawns one
   worker per database automatically)
2. share the handle returned by `open_idb` across concurrent agents
3. parallelise read-heavy work
4. serialise write-heavy work
5. close cleanly with `close_idb` (HTTP/SSE requires the `close_token`
   returned by `open_idb`)

### Workflow 7: Batch Annotation

Dispatch through `raw` when needed:

- `batch_rename`
- `set_function_prototype`
- `set_function_comment`
- `rename_stack_variable`
- `set_stack_variable_type`
- `create_enum`
- `batch_decompile`

### Workflow 8: Dynamic Debugging

The `dbg_*` method family covers debugger loading, process start/attach,
breakpoints, stepping, register inspection, memory reads/writes, and thread
inspection. It is only available on runtimes that expose the debugger; the
headless `idat-compat` path does not.

When ASLR is active, address-based debug operations must use rebased runtime
addresses unless the method explicitly accepts IDB addresses.

---

## Part 4: Error Recovery

### Decompilation Failure

- if the failure is explicit, or the decompiler stalls past 10 seconds,
  classify the function as strong-obfuscation
- stop repeated F5 attempts
- use `get_pseudocode_at` only for narrow, already-promising ranges
- move to disassembly, basic blocks, xrefs, and callgraph work
- retry decompilation only after the function has been partially untangled

### Incomplete Auto Analysis

If `get_analysis_status` reports `auto_is_ok=false`:

- run `run_auto_analysis`
- or poll until analysis finishes

Do not trust xrefs or decompilation quality before analysis is complete.

### Timeout Handling

- `run_script` defaults to 120 seconds and can go up to 600
- very large `batch_decompile` calls should be split into smaller batches
- the CLI’s `--timeout` flag controls per-request timeout from the client
  side

### Common Mistakes

1. Starting at the biggest entrypoint instead of leaf functions
2. Renaming callees but not re-decompiling callers
3. Trusting arithmetic without checking disassembly
4. Forgetting little-endian byte order in searches
5. Ignoring xref fan-out counts
6. Trusting signed pseudocode types without checking load width
7. Re-opening the raw binary instead of the cached `.i64`
8. Querying before auto analysis finishes

---

## Part 5: References

Load only the reference that matches the current task. Do not read them all
by default.

| Reference | Use when |
|---|---|
| [cli-tool-reference.md](references/cli-tool-reference.md) | CLI command patterns and capability lookup |
| [obfuscation-triage.md](references/obfuscation-triage.md) | F5 failure, flattening, VM handlers, opaque predicates, disassembly-first work |
| [vm-devirt.md](references/vm-devirt.md) | commercial VM protectors (Themida / VMProtect / Code Virtualizer / WinLicense) — emulation-based devirtualization with `scripts/vm_devirt.py` |
| [counterfactual-patch.md](references/counterfactual-patch.md) | counterfactual patching workflows |
| [headless-api.md](references/headless-api.md) | headless IDA execution and API choice |
| [idapython-cheatsheet.md](references/idapython-cheatsheet.md) | writing IDAPython scripts |
| [ida-domain-api.md](references/ida-domain-api.md) | full IDA Domain API reference |
| [idalib-headless.md](references/idalib-headless.md) | idalib / idapro headless usage |
| [binary-analysis-patterns.md](references/binary-analysis-patterns.md) | malware, vuln research, firmware analysis patterns |
| [plugin-development.md](references/plugin-development.md) | IDA plugin development |
