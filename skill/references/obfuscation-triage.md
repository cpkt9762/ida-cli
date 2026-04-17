# Obfuscation Triage

Use this page when a function is hostile to decompilation and needs a
disassembly-first workflow.

## When to Classify a Function as Obfuscated

Treat a function as currently non-decompilable when any of these are true:

- `decompile_function` fails explicitly
- F5 or `decompile_function` stalls for more than 10 seconds
- the pseudocode is mostly nonsense despite obvious code being present
- repeated retries produce no meaningful improvement

Once any of those conditions triggers, stop retrying F5 in a loop. Move down
to disassembly and only retry decompilation after meaningful progress has
been made.

## Common Obfuscation Signals

### Flattened Control Flow

Look for:

- one central dispatcher block
- a state variable that is read and rewritten constantly
- many branches converging back to the same block

Typical workflow (the flat CLI exposes `disasm`; the rest goes through
`raw`):

```bash
ida-cli --path <file> disasm --addr 0x1000 --count 300
ida-cli --path <file> raw '{"method":"get_basic_blocks","params":{"address":"0x1000"}}'
ida-cli --path <file> raw '{"method":"build_callgraph","params":{"roots":["0x1000"],"max_depth":2}}'
```

### Heavy Indirect Branching

Look for:

- frequent `jmp reg`, `br xN`, `blr xN`
- jump tables or handler tables
- computed targets based on a state byte or opcode

Useful commands:

```bash
ida-cli --path <file> raw '{"method":"search_instructions","params":{"patterns":["jmp","call","br","blr"]}}'
ida-cli --path <file> raw '{"method":"read_bytes","params":{"address":"0x1000","size":64}}'
ida-cli --path <file> xrefs-to --addr 0x1000
```

### Opaque Predicates

Look for:

- branches that appear complex but are effectively constant
- arithmetic on flags or constants that always collapses one way
- repeated compare / test patterns with no meaningful entropy source

What to do:

1. compare the branch condition in disassembly
2. recover the exact constants and widths
3. comment the branch outcome hypothesis
4. verify by tracing predecessor values

### Handler VMs

Look for:

- bytecode fetch loops
- one register or stack slot used as a virtual instruction pointer
- repeated decode-dispatch-execute structure
- dense tiny handlers with shared prologue/epilogue shapes

Focus on:

- the dispatcher
- bytecode format
- handler table
- operand decode helpers

Do not expect decompilation to help much until the VM structure is mapped.

### Exception-Driven or CFG-Breaking Code

Look for:

- abnormal control flow through exceptions
- anti-analysis traps
- impossible-looking edges in pseudocode
- basic blocks that only make sense in raw disassembly

Prefer:

- basic block review
- xrefs
- breakpoint-assisted runtime inspection
- selective commenting and renaming

## Disassembly-First Workflow

Once the 10-second gate triggers:

1. Stop repeated decompilation.
2. Dump the full function body with disassembly.
3. Recover block boundaries and branch targets.
4. Identify state variables, dispatch variables, and indirect targets.
5. Rename helpers and annotate control-flow roles.
6. Use callgraph and xrefs to peel the function outward.
7. Retry decompilation only after the function is less opaque.

Suggested commands:

```bash
ida-cli --path <file> disasm --addr 0x1000 --count 400
ida-cli --path <file> raw '{"method":"get_basic_blocks","params":{"address":"0x1000"}}'
ida-cli --path <file> raw '{"method":"get_xrefs_from","params":{"address":"0x1000"}}'
ida-cli --path <file> raw '{"method":"get_callees","params":{"address":"0x1000"}}'
ida-cli --path <file> raw '{"method":"search_instructions","params":{"patterns":["cmp","test","cmov","jmp","br","blr"]}}'
```

## When to Retry F5

Retry decompilation only after at least one of these has happened:

- the dispatcher structure is understood
- key helper functions have been renamed
- obvious type confusion has been fixed
- noisy blocks have been isolated
- patches or comments have clarified critical paths

If none of that changed, another F5 attempt is usually wasted time.

## Analysis Output Expectations

For strongly obfuscated functions, the minimum useful deliverable is:

- a control-flow summary
- key block addresses
- state variable or dispatch variable description
- renamed helper functions
- comments on opaque branches
- a list of open questions

That is already meaningful progress, even before good pseudocode exists.
