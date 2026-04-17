# VM Devirtualization via Emulation (`vm_devirt.py`)

Use this reference when a function is protected by a commercial x86-64 PE
virtualizer — Themida, VMProtect, Code Virtualizer, WinLicense, or similar —
and manual handler reversing is not a good use of time.

The bundled tool is `skill/scripts/vm_devirt.py`. It turns the VM body back
into native code and writes a new `.devrt` section so the PE is cleanly
decompilable by IDA / Hex-Rays.

## When to Reach for This

Trigger conditions:

- the function lives in a suspicious section (`.vlizer`, `.vmp0`/`vmp1`/`vmp2`,
  `.themida`, `.winlice`, `.pelock`, `.svmp`, `.xxx`) or any non-standard
  RWX / RX section the protector created
- the entry is a single `jmp <vm>`, `push <vm>; ret`, or `call <vm>` that
  jumps into that section
- IDA / Hex-Rays stalls, segfaults, or produces pseudocode full of opaque
  dispatch on a state variable
- the IAT is stripped and APIs resolve through a dark `.rdata` pointer table

Do **not** start here for ordinary obfuscation, opaque predicates, or small
junk-code passes. See [obfuscation-triage.md](obfuscation-triage.md) first.

## Core Invariant

Every VM protector must satisfy the same rule:

> The VM's externally observable effect must equal the original code.

Externally observable ≈ every call through the IAT and every write to
caller-visible state. Because of that constraint we do **not** reverse the
handler table. We emulate the VM end-to-end with Unicorn, intercept the API
boundaries, and diff the CPU state across each boundary to recover native
`mov` / `lea` / `call` sequences.

| Don't do | Do do |
|---|---|
| reverse the handler table | trust the ABI: API calls must happen through the IAT |
| decrypt the VM bytecode | trust the Win64 calling convention |
| fingerprint protector version | let the VM produce its externally visible effect |
| rebuild dispatch logic | sentinel-track data flow across call boundaries |

### The Win64 volatile-clobber trick

After every intercepted call the tool clobbers `rcx, rdx, r8, r9, r10, r11`
(Win64 volatile set) with unique `0xDEAD…` sentinels. That forces the VM to
reload every argument from its virtual register file before the next call,
so the register diff can rebuild the **full** argument setup for every
call site. Without the clobber, the VM would carry stale arg values and we
would miss half the `mov rcx, …` instructions.

## Pipeline

```
Phase 1 — full emulation
    ├─ map every PE section into Unicorn
    ├─ fake PEB / LDR with 80 fake DLL PEs (74K+ exports) so PEB walks resolve
    ├─ fake TEB at gs:[0x30] / gs:[0x60] to defeat anti-debug checks
    ├─ CPUID / SYSCALL hooks so anti-emu probes see a plausible Intel CPU
    ├─ IAT + dark .rdata pointers replaced by sentinel addresses
    ├─ EP init pass (optional) — let the protector's init code resolve its
    │   own API names into the .rdata slots, harvest them for naming
    ├─ every intercepted call:
    │     • tag return value as CAFE sentinel
    │     • clobber volatile regs with DEAD sentinels
    │     • snapshot frame + registers
    └─ VM transitions back to .text → treat as VM exit

Phase 2 — register / frame diff (7-level classifier)
    for each call boundary:
        reg == prev[rax]        → mov reg, rax
        reg == prev[other_reg]  → mov reg, other_reg
        reg is IAT sentinel     → mov reg, [iat_slot]
        reg ≈ frame_rsp         → lea reg, [rsp + off]
        reg in .rdata / .data   → lea reg, [data]
        else                    → mov reg, imm
    track stack writes under the frame

Phase 3 — emit
    ├─ Keystone two-pass assembly with RIP-relative fixups
    ├─ append new .devrt section (RX) + new import descriptor
    ├─ patch the original VM entry to `jmp .devrt`
    └─ rewrite dark .rdata slots to point at the new IAT entries
```

## Quickstart

```bash
# Install deps once (or use a venv):
pip install -r skill/scripts/vm_devirt_requirements.txt

# Fully automatic: EP init + scan every VM function + emit patched PE
python3 skill/scripts/vm_devirt.py protected.bin --auto

# Single function only (fastest, useful for RE drill-down)
python3 skill/scripts/vm_devirt.py protected.bin 0x140001000 -o out.bin

# Skip EP init — 3 seconds, but API calls stay unnamed
python3 skill/scripts/vm_devirt.py protected.bin --auto --no-ep

# Give EP init more time so more API names resolve
python3 skill/scripts/vm_devirt.py protected.bin --auto --ep-timeout 300
```

Inputs: PE32+ (x86-64) Windows PE only. PE32 (32-bit) is rejected.

Artifacts: defaults to `<input>-devirt.bin` next to the input; override with
`-o`. The tool never modifies the source file.

## Typical Workflow with `ida-cli`

1. **Confirm VM vs ordinary obfuscation.** Use `ida-cli` to inspect the
   target function and its section:

   ```bash
   ida-cli --path protected.bin list-segments
   ida-cli --path protected.bin raw '{"method":"get_address_info","params":{"address":"0x140001000"}}'
   ida-cli --path protected.bin disasm --addr 0x140001000 --count 20
   ```

   If the function is just a `jmp 0x140xxxxxx` into a non-standard section,
   it is a VM stub. Good candidate for `vm_devirt.py`.

2. **Run devirtualization.**

   ```bash
   python3 skill/scripts/vm_devirt.py protected.bin --auto -o protected-devirt.bin
   ```

   Watch stdout:
   - `VM section: .themida` / `.vlizer` etc. — section auto-detected
   - `EP init: ... .rdata slots resolved (N unique APIs)` — how many API
     names came back
   - `.devrt: M function(s), … bytes, K new imports` — final section
   - `[OK] Patched PE -> protected-devirt.bin`

3. **Re-open in IDA via `ida-cli`.** Point it at the devirtualized output
   (NOT the original) and let IDA cache a fresh `.i64`:

   ```bash
   ida-cli --path protected-devirt.bin list-functions --limit 20
   ida-cli --path protected-devirt.bin decompile --addr 0x140001000
   ida-cli --path protected-devirt.bin raw '{"method":"list_imports"}'
   ```

   The decompilation should now look normal.

4. **Annotate back into the original project** if you want: the devirt PE
   and the original share the same VA layout for `.text`, so any renames /
   types from the patched one transfer cleanly when applied at the matching
   VA via `rename_symbol`, `set_function_prototype`, etc.

## Missing Modules

If the protector imports a DLL / SYS that is not in `win_exports.json`:

- Tool prints:
  ```
  [!] EP init: 1 module(s) NOT in win_exports.json — need manual export dump:
      custom.dll  →  run: dumpbin /exports custom.dll
  ```
- Add the exports to `skill/scripts/win_exports.json` under
  `exports.custom.dll = [...]`. Use `dumpbin /exports` or pefile to get the
  list:
  ```python
  import pefile
  pe = pefile.PE("custom.dll")
  print("\n".join(e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name))
  ```

`win_exports.json` ships with Windows 11-22000 System32 (3263 modules,
116K+ exports) so most protectors resolve everything out-of-the-box.

## Capability Matrix

| Code pattern | Status | Notes |
|---|---|---|
| Windows API call (direct, IAT, `.rdata` thunk, PEB walk) | Full | Most common path |
| CRT internals (`ucrtbase`, `vcruntime140`, `msvcrt`) | Full | EP init resolves them |
| Internal `.text` function call | Supported | stack-walk detects return address in VM section |
| Function-pointer / vtable call | Supported | same detector as above |
| `.text` thunk (`jmp [rip+disp]`) | Supported | pass-through into API sentinel |
| Pure computation (`a + b`, hashing) | Constant-folded | only observed values survive |
| Conditional branch (`if / else`) | Single-path | only the executed branch is reconstructed |
| Loops | Unrolled | emulation cannot tell "loop" from "linear run" |

The three "single-path" cases are fundamental limitations of the
observability methodology, not tool bugs. To recover arithmetic / branches
/ loops you need handler-level symbolic execution (Triton / Miasm), which
is a different project class.

## Runtime Notes

- Emulation is CPU-bound and single-threaded. Expect 30 s – 2 min per
  binary depending on how aggressive the init unpacking loop is.
- `MAX_INSNS = 200_000_000` inside the script caps each VM function. Raise
  it only if you see "Emulation error" logs right at the budget.
- The tool pokes `/tmp`-style sentinel memory through Unicorn's allocator;
  nothing gets written to disk except the output PE.

## Failure Modes

| Symptom | Likely cause | Remedy |
|---|---|---|
| `No VM section detected` | Protector uses a bespoke section name with standard flags | Add the name to `KNOWN_VM_SECTIONS` in the script |
| `VM did not exit` | Emulation hit `MAX_INSNS` before the function returned | Raise `MAX_INSNS`; check for infinite unpacking loops |
| `JMP rel32 overflow` | New section ended up >2 GB from the VM stub | Shrink other sections or strip debug info first |
| IAT in output still looks dark | EP init timed out | `--ep-timeout 300` or higher, and re-check missing DLLs |
| Too many `dark_<n>` calls | Protector resolves APIs via a path EP init did not hit | Extend the preload list in `_EP_CORE_DLLS` or run once with `--ep-timeout 600` |

## When Not to Use

If the function is just obfuscated native code (junk instructions, opaque
predicates, control-flow flattening without a VM interpreter), stay in
disassembly-first mode per
[obfuscation-triage.md](obfuscation-triage.md). Running `vm_devirt.py` on
non-VM code will either fail fast ("No VM section detected") or produce
useless single-path snapshots.

## Related References

- [obfuscation-triage.md](obfuscation-triage.md) — decide VM vs flattening
  vs opaque predicates before invoking this tool
- [counterfactual-patch.md](counterfactual-patch.md) — once devirtualized,
  verify semantic equivalence by patching inputs and comparing outcomes
- [cli-tool-reference.md](cli-tool-reference.md) — `ida-cli` surface for
  pre- and post-devirt analysis
