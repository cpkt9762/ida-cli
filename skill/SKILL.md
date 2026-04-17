---
name: ida-cli
description: "Reverse engineering and binary analysis with IDA Pro and ida-cli. Use when writing IDAPython scripts, using the IDA Domain API or idalib, analyzing binaries in IDA Pro, or operating the ida-cli headless server and CLI. Covers disassembly, decompilation, cross-references, type recovery, byte patching, headless automation, plugin development, FLIRT signatures, and CLI-first workflows. Supports PE, ELF, Mach-O, and firmware binaries."
---

# IDA CLI Reverse Engineering

General reverse engineering methodology plus a practical ida-cli bootstrap and workflow.

---

## Part 0: Zero-Config Bootstrap

Install the skill with:

`npx -y skills add https://github.com/cpkt9762/ida-cli --skill ida-cli --agent codex --yes --global`

After that, do not assume the user has already installed, configured, or started `ida-cli`.

### Boot Rule

- On first use in a new environment, run `scripts/ida-cli.sh --help`.
- This wrapper checks whether `ida-cli` is already available.
- If the binary is missing, it automatically downloads and installs it through the repository installer.
- After installation, it runs a `--help` smoke test before continuing.

### Runtime Rule

- Before starting real analysis, run `scripts/ida-cli.sh probe-runtime`.
- Do not guess whether the machine will select `native-linked` or `idat-compat`.
- If multiple IDA installations are present, set `IDADIR` explicitly before probing.

### Use Rule

- Prefer `scripts/ida-cli.sh` as the single entrypoint.
- Do not ask the user to start the server manually for routine work.
- The flat `ida-cli` CLI auto-manages the local socket server.
- Only run `serve-http` explicitly when a long-lived HTTP control plane is actually required.

### Zero-Config Commands

```bash
# 1. Install ida-cli or confirm it is available
scripts/ida-cli.sh --help

# 2. Probe the selected runtime backend
scripts/ida-cli.sh probe-runtime

# 3. Analyze a binary directly
scripts/ida-cli.sh --path /path/to/sample.bin list-functions --limit 20
scripts/ida-cli.sh --path /path/to/sample.bin decompile --addr 0x140001000

# 4. Start HTTP only when needed
scripts/ida-cli.sh serve-http --bind 127.0.0.1:8765
```

### Environment Notes

- Default install path: `~/.local/bin/ida-cli`
- To pin the repository or branch:
  - `IDA_CLI_REPO=cpkt9762/ida-cli`
  - `IDA_CLI_INSTALL_REF=master`
- To pass extra installer arguments:
  - `IDA_CLI_INSTALL_ARGS="--add-path"`
- To pin a specific IDA installation:
  - `export IDADIR=/path/to/ida/Contents/MacOS`

Within this skill, `scripts/ida-cli.sh` is the single entrypoint for install, download, execution, and verification.

---

## Part 1: General Reverse Engineering Methodology

### Key Principles

- **F5 first, disasm second (HARD RULE)** — Always decompile before dropping to disassembly. Switch to disassembly only when decompilation fails, times out, or clearly lies.
- **Rename as you go (HARD RULE)** — Rename every function immediately after understanding its purpose. Do not keep a backlog of `sub_XXXXX` names.
- **Iterate aggressively** — F5 → apply types → rename → F5 again → validate new offsets → repeat.
- **Treat constants literally** — If IDA shows `0x6E`, write `110` until you have evidence for higher-level meaning.
- **Use disassembly when the diff is small** — A 1-10 value mismatch usually means an off-by-one, saturation behavior, or width issue.
- **Keep an analysis log (HARD RULE)** — After each analyzed function, append one log entry with address, rename, and purpose.

### Decompilation Strategy

Drop to disassembly when:

- F5 errors out
- F5 times out on a very large function
- The pseudocode shows obvious artifacts

Common decompiler lies:

| Symptom | Pseudocode | Real instruction pattern |
|---|---|---|
| Constant folding | `result = x * 1718750 / 1000000` | `MUL` + `UDIV` with literal constants |
| Hidden `+1/-1` | `discount = bias * 110 / 64` | There is still an `ADD #1` after division |
| Type confusion | `int v10 = *(int *)(ctx + 0x1DC)` | Real load is `LDR W8` and behaves like `u32` |
| Hidden saturation | `result = a - b` | `SUBS` + conditional select to zero |

### Naming Strategy

Rename functions as soon as they are understood.

Suggested prefixes:

| Prefix | Meaning |
|---|---|
| `check_` / `validate_` | validation |
| `parse_` / `deserialize_` | parsing / deserialization |
| `compute_` / `calc_` | computation |
| `dispatch_` | dispatch entrypoint |
| `init_` / `setup_` | initialization |

After renaming a callee, re-decompile the caller immediately. The readability improvement compounds quickly.

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
LDR X8, [X0, #0x130]   -> u64
LDR W8, [X0, #0x144]   -> u32
LDRH W8, [X0, #0x168]  -> u16
LDRB W8, [X0, #0x178]  -> u8
```

Recommended loop:

1. Decompile and collect pointer+offset accesses.
2. Confirm widths in disassembly.
3. Read live values with byte/word/dword/qword helpers when needed.
4. Declare the struct type.
5. Apply the type.
6. Re-decompile and confirm fields replace raw offsets.
7. Use xrefs on struct fields to propagate understanding.

### Call Graph Navigation

Do not read giant dispatchers linearly.

Use a leaf-first strategy:

1. `build_callgraph` from the entrypoint
2. Decompile leaf functions
3. Rename each leaf immediately
4. Re-decompile callers
5. Repeat upward

### Search Strategy

Remember little-endian byte order on x86 and ARM64:

```text
search_bytes(pattern: "6E 00 00 00")
search_bytes(pattern: "80 96 98 00")
```

Use:

- `search_text(kind: "imm", targets: ["110", "10000"])`
- `search_pseudocode(pattern: "amount")`
- `search_instructions(patterns: ["MUL", "UDIV"])`

### Formula Extraction

Rules:

1. Translate constants literally.
2. Preserve operation order exactly as IDA shows it.
3. Use `u128` for multi-step 64-bit multiplication chains.
4. Watch for saturating behavior.
5. Verify suspicious arithmetic in disassembly.

Diff triage:

| Diff range | Typical cause | Fix |
|---|---|---|
| `> 100` | wrong formula or wrong scale | rebuild from constants |
| `10-100` | wrong operator or operand | verify MUL / DIV / ADD / SUB |
| `1-10` | off-by-one or saturation | compare instruction by instruction |
| `0` | exact match | done |

### Structured Decompilation

Use `decompile_structured` when arithmetic chains are too complex for manual comparison.

Look for:

- `mul`, `div`, `add`, `sub` nodes
- helper calls such as `__umulh`, `__multi3`, `__udivti3`
- numeric leaves
- variable references

Generate the expression from the AST, then cross-check with disassembly.

---

## Part 2: MCP and CLI Quick Reference

The IDA MCP server exposes dozens of tools. Use the reference page for common arguments:

- [mcp-tool-reference.md](references/mcp-tool-reference.md)

For CLI-first work, prefer `ida-cli` over raw MCP when the same operation is available.

### CLI Examples

```bash
ida-cli --path <file> list-functions --limit 20
ida-cli --path <file> get-function-by-name --name main
ida-cli --path <file> decompile-function --address 0x1234
ida-cli --path <file> disassemble-function --name func_name --count 20
ida-cli --path <file> rename-symbol --address 0x1234 --new-name parse_pool
ida-cli --path <file> get-callees --address 0x1234
ida-cli --path <file> build-callgraph --roots 0x1234 --max-depth 3
ida-cli --path <file> search-pseudocode --pattern "amount" --limit 10
ida-cli --path <file> get-xrefs-to --address 0x1234
ida-cli --path <file> batch-decompile --addresses "0x1234,0x5678"
```

Output modes:

```bash
ida-cli --json --path <file> list-functions --limit 5
ida-cli --compact --path <file> list-functions --limit 5
```

### File Types

| Type | Behavior |
|---|---|
| `.i64` / `.idb` | open the existing IDA database directly |
| raw PE / ELF / Mach-O | analyze the binary and cache the database |

### Concurrency Notes

- Different files map to different worker processes.
- Multiple clients can operate on the same file safely, but write-heavy changes should still be serialized deliberately.
- Cold-start races are guarded by the server bootstrap lock.

### Failure Recovery

If the local server wedges:

```bash
ida-cli server-stop
pkill -9 -f "ida-cli"
rm -f ~/.ida/server.sock ~/.ida/server.pid ~/.ida/startup.lock
```

Then retry the CLI call and let it restart automatically.

---

## Part 3: Common Workflows

### Workflow 1: Binary Orientation

1. `get_database_info()`
2. `list_segments()`
3. `list_exports()`
4. `list_imports()`
5. `list_functions(limit: 50)`
6. `build_callgraph(...)`

### Workflow 2: Struct Reconstruction

1. Decompile and collect offsets
2. Confirm widths in disassembly
3. Read values if needed
4. Declare the struct
5. Apply the type
6. Re-decompile
7. Follow field xrefs

### Workflow 3: Arithmetic Verification

1. `decompile_function`
2. `get_pseudocode_at`
3. `disassemble_function_at`
4. `search_instructions`
5. `search_instruction_operands`
6. Compare operand order and widths

### Workflow 4: Error Code Mapping

1. Search immediate values
2. Resolve the containing function
3. Inspect the pseudocode context
4. Add comments
5. Search for similar return sites

### Workflow 5: Table and Dispatch Analysis

1. Search strings like `factory` or `registry`
2. Follow xrefs
3. Identify the table builder
4. Scan the table
5. Resolve and decompile each function pointer

### Workflow 6: Multi-Database Analysis

1. Open multiple databases
2. Share handles across concurrent agents
3. Parallelize read-heavy work
4. Serialize write-heavy work
5. Close cleanly after analysis

### Workflow 7: Batch Annotation

Use:

- `batch_rename`
- `set_function_prototype`
- `set_function_comment`
- `rename_stack_variable`
- `set_stack_variable_type`
- `create_enum`
- `batch_decompile`

### Workflow 8: Dynamic Debugging

Use the `dbg_*` tool family for:

- debugger loading
- process start / attach
- breakpoints
- stepping
- register inspection
- memory reads and writes
- thread inspection

When ASLR is active, address-based debug operations must use rebased runtime addresses unless the tool explicitly accepts IDB addresses.

---

## Part 4: Error Recovery

### Decompilation Failure

If decompilation fails:

- use `get_pseudocode_at` on a smaller range
- fall back to disassembly
- split the problem with `build_callgraph`

### Incomplete Auto Analysis

If `get_analysis_status` reports `auto_is_ok=false`:

- run `run_auto_analysis`
- or poll until analysis finishes

Do not trust xrefs or decompilation quality before analysis is complete.

### Timeout Handling

- `run_script` defaults to 120 seconds and can go up to 600
- very large `batch_decompile` calls should be split into smaller batches

### Common Mistakes

1. Starting at the biggest entrypoint instead of leaf functions
2. Renaming callees but not re-decompiling callers
3. Trusting arithmetic without checking disassembly
4. Forgetting little-endian byte order in searches
5. Ignoring xref fan-out counts
6. Trusting signed pseudocode types without checking load width
7. Re-opening the raw binary instead of the `.i64`
8. Querying before auto analysis finishes

---

## Part 5: References

Load only the reference that matches the current task. Do not read them all by default.

| Reference | Use when |
|---|---|
| [mcp-tool-reference.md](references/mcp-tool-reference.md) | tool parameters or capability lookup |
| [counterfactual-patch.md](references/counterfactual-patch.md) | counterfactual patching workflows |
| [headless-api.md](references/headless-api.md) | headless IDA execution and API choice |
| [idapython-cheatsheet.md](references/idapython-cheatsheet.md) | writing IDAPython scripts |
| [ida-domain-api.md](references/ida-domain-api.md) | full IDA Domain API reference |
| [idalib-headless.md](references/idalib-headless.md) | idalib / idapro headless usage |
| [binary-analysis-patterns.md](references/binary-analysis-patterns.md) | malware, vuln research, firmware analysis patterns |
| [plugin-development.md](references/plugin-development.md) | IDA plugin development |
