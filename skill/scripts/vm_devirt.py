#!/usr/bin/env python3
"""
Generic x86-64 PE VM Devirtualizer
==================================

Emulation-based devirtualizer for VM-protected Windows PE binaries. Covers
Themida, VMProtect, Code Virtualizer, WinLicense, and any other x86-64
commercial protector that virtualises native blobs while preserving their
observable semantics.

Methodology
-----------
We never try to reverse individual VM handlers. We lean on the single
invariant every VM must satisfy:

    The VM's externally observable effect must equal the original code.

External effects show up as calls through the IAT / dark thunks. By
emulating the whole VM with Unicorn, intercepting those calls, and diffing
the register / stack frame across each call boundary, we can rebuild a
native x86-64 instruction stream that IDA / Hex-Rays decompile cleanly.

Two phases:

  Phase 1 — Full emulation of the VM with import-call interception.
  Phase 2 — Register-state differential analysis across call boundaries
             to reconstruct native x86-64 code.

Outputs a patched PE with devirtualized native code in a new `.devrt`
section, plus a fresh import descriptor so IDA resolves API references.

Dependencies: pefile, capstone, unicorn, keystone-engine. Install via
`pip install -r vm_devirt_requirements.txt`.
"""

from __future__ import annotations
import argparse, struct, re, os, time
from collections import OrderedDict, Counter
from typing import Optional

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RSP
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_64,
                     UC_HOOK_CODE, UC_HOOK_INSN,
                     UC_HOOK_MEM_READ_UNMAPPED,
                     UC_HOOK_MEM_WRITE_UNMAPPED,
                     UC_HOOK_MEM_WRITE)
from unicorn.x86_const import *

# ═══════════════════════════ ABI & Registers ═══════════════════════

GP_REGS = OrderedDict([
    ("rax", UC_X86_REG_RAX), ("rbx", UC_X86_REG_RBX),
    ("rcx", UC_X86_REG_RCX), ("rdx", UC_X86_REG_RDX),
    ("rsi", UC_X86_REG_RSI), ("rdi", UC_X86_REG_RDI),
    ("rbp", UC_X86_REG_RBP), ("rsp", UC_X86_REG_RSP),
    ("r8",  UC_X86_REG_R8),  ("r9",  UC_X86_REG_R9),
    ("r10", UC_X86_REG_R10), ("r11", UC_X86_REG_R11),
    ("r12", UC_X86_REG_R12), ("r13", UC_X86_REG_R13),
    ("r14", UC_X86_REG_R14), ("r15", UC_X86_REG_R15),
])

FP_REGS = [UC_X86_REG_FP0, UC_X86_REG_FP1, UC_X86_REG_FP2, UC_X86_REG_FP3,
           UC_X86_REG_FP4, UC_X86_REG_FP5, UC_X86_REG_FP6, UC_X86_REG_FP7]

R32 = {r: r.replace("r", "e", 1) if len(r) == 3 and not r[1:].isdigit()
        else r + "d" if r.startswith("r") and r[1:].isdigit()
        else r
       for r in GP_REGS if r != "rsp"}

# Win64 ABI: volatile (caller-saved) registers, clobbered by any call
WIN64_VOLATILE = ["rcx", "rdx", "r8", "r9", "r10", "r11"]

# ═══════════════════════════ Sentinel Values ═══════════════════════

class Sentinel:
    """Manages all synthetic marker values used during emulation.

    Two families of sentinels, distinguished by their top 16 bits:
      CAFE — fake return values from intercepted calls
      DEAD — clobber values written to volatile regs after calls

    No hardcoded per-register tags; tags are derived from the
    register name hash so new registers work automatically.
    """
    _RET_HI  = 0xCAFE_0000_0000_0000
    _CLOB_HI = 0xDEAD_0000_0000_0000

    @staticmethod
    def ret_val(call_idx: int) -> int:
        return Sentinel._RET_HI | (call_idx & 0xFFFF_FFFF)

    @staticmethod
    def is_ret(v: int) -> bool:
        return (v >> 48) == (Sentinel._RET_HI >> 48)

    @staticmethod
    def clobber(reg_name: str, call_idx: int) -> int:
        tag = sum(ord(c) for c in reg_name) & 0xFFFF
        return Sentinel._CLOB_HI | (tag << 16) | (call_idx & 0xFFFF)

    @staticmethod
    def is_clobber(v: int) -> bool:
        return (v >> 48) == (Sentinel._CLOB_HI >> 48)

    @staticmethod
    def is_synthetic(v: int) -> bool:
        return Sentinel.is_ret(v) or Sentinel.is_clobber(v)

# ═══════════════════════════ PE Constants ═══════════════════════

IMAGE_SCN_CNT_CODE        = 0x00000020
IMAGE_SCN_MEM_EXECUTE     = 0x20000000
IMAGE_SCN_MEM_READ        = 0x40000000
IMAGE_SCN_MEM_WRITE       = 0x80000000

DEVRT_CHARACTERISTICS = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ

KNOWN_STANDARD_SECTIONS = frozenset([
    ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc",
    ".tls", ".bss", ".idata", ".edata", ".debug", ".CRT",
    ".gfids", ".00cfg",
])

KNOWN_VM_SECTIONS = frozenset([
    ".vlizer", ".vmp0", ".vmp1", ".vmp2", ".themida",
    ".winlice", ".pelock", ".svmp", ".xxx",
])

KNOWN_MARKER_DLLS = frozenset([
    "virtualizersdk32.dll", "virtualizersdk64.dll",
    "thewidasdk32.dll", "thewidasdk64.dll",
    "codevirtualizer32.dll", "codevirtualizer64.dll",
])

# ═══════════════════════════ Layout Constants ═══════════════════════

EMU_STACK_SIZE = 0x20_0000
EMU_TEB_SIZE   = 0x2000
MAX_INSNS      = 200_000_000
DEFAULT_FRAME  = 0x200

# ═══════════════════════════ Windows Export DB ═══════════════════════

_WIN_EXPORTS_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "win_exports.json")

FAKE_DLL_EXPORTS: dict[str, list[str]] = {}

WIN_FUNC_TO_DLLS: dict[str, list[str]] = {}

PEB_LDR_MIN_EXPORTS = 10
PEB_LDR_MAX_DLLS    = 80

_MUST_HAVE_DLLS = frozenset([
    "kernel32", "ntdll", "kernelbase", "user32", "advapi32",
    "ucrtbase", "vcruntime140", "msvcrt", "gdi32", "ws2_32",
    "ole32", "oleaut32", "shell32", "crypt32", "bcrypt",
    "sechost", "rpcrt4", "combase", "msvcp140",
])

_ALL_EXPORTS: dict[str, list[str]] = {}

def _norm_mod(name: str) -> str:
    """Normalize module name: strip path, lowercase, keep extension."""
    return os.path.basename(name).lower()

def _init_exports():
    """Load the full DLL/SYS export database from win_exports.json.

    PEB/LDR fake modules: top modules by export count + all must-have
    modules regardless of rank.  Supports both .dll and .sys.
    """
    import json as _json
    if os.path.exists(_WIN_EXPORTS_JSON):
        with open(_WIN_EXPORTS_JSON, "r") as f:
            db = _json.load(f)
        _ALL_EXPORTS.update(db.get("exports", {}))
        n_mods = len(_ALL_EXPORTS)
        n_funcs = sum(len(v) for v in _ALL_EXPORTS.values())
        print(f"[*] Loaded {_WIN_EXPORTS_JSON}: "
              f"{n_mods} modules, {n_funcs} exports")
    else:
        print(f"[!] {_WIN_EXPORTS_JSON} not found")

    included: set[str] = set()
    for mod_key, exports in _ALL_EXPORTS.items():
        stem = _norm_mod(mod_key).replace(".dll", "").replace(".sys", "")
        if stem in _MUST_HAVE_DLLS and exports:
            mod_name = _norm_mod(mod_key)
            if not (mod_name.endswith(".dll") or mod_name.endswith(".sys")):
                mod_name += ".dll"
            FAKE_DLL_EXPORTS[mod_name] = exports
            included.add(mod_key)

    ranked = sorted(_ALL_EXPORTS.items(),
                    key=lambda kv: len(kv[1]), reverse=True)
    for mod_key, exports in ranked:
        if len(FAKE_DLL_EXPORTS) >= PEB_LDR_MAX_DLLS:
            break
        if mod_key in included:
            continue
        if len(exports) < PEB_LDR_MIN_EXPORTS:
            continue
        mod_name = _norm_mod(mod_key)
        if not (mod_name.endswith(".dll") or mod_name.endswith(".sys")):
            mod_name += ".dll"
        FAKE_DLL_EXPORTS[mod_name] = exports
        included.add(mod_key)

    for mod, funcs in _ALL_EXPORTS.items():
        for fn in funcs:
            WIN_FUNC_TO_DLLS.setdefault(fn, []).append(mod)

_init_exports()

# ═══════════════════════════ Assembler ═══════════════════════════

class Assembler:
    """Thin wrapper around Keystone/Capstone with address-aware assembly."""

    def __init__(self):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

    def asm_lines(self, lines: list[str], base: int) -> bytes:
        sizes = []
        for ln in lines:
            try:
                enc, _ = self.ks.asm(ln, base + sum(sizes))
                sizes.append(len(enc))
            except KsError as e:
                raise RuntimeError(f"Keystone: '{ln}': {e}")
        code = bytearray()
        addr = base
        for ln, sz in zip(lines, sizes):
            enc, _ = self.ks.asm(ln, addr)
            code.extend(enc)
            addr += sz
        return bytes(code)

    def disasm(self, code: bytes, base: int):
        return list(self.cs.disasm(code, base))


# ═══════════════════════════ Devirtualizer ═══════════════════════

class VMDevirtualizer:

    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        self.pe = pefile.PE(pe_path)
        self.ib = self.pe.OPTIONAL_HEADER.ImageBase
        self.asm = Assembler()

        self.sections: dict[str, dict] = {}
        for s in self.pe.sections:
            nm = s.Name.decode("utf-8", "replace").rstrip("\x00")
            va = self.ib + s.VirtualAddress
            self.sections[nm] = {
                "va": va, "end": va + s.Misc_VirtualSize,
                "vsize": s.Misc_VirtualSize,
                "rsize": s.SizeOfRawData, "obj": s,
            }

        self.hook_map: dict[int, dict] = {}
        self.events: list[dict] = []
        self._is_pe32plus = (self.pe.OPTIONAL_HEADER.Magic == 0x20b)
        self.addr_freq = Counter()
        self.n_insns = 0
        self.in_vm = False
        self.vm_exit_addr: Optional[int] = None
        self.pre_vm_regs: dict = {}
        self.frame_rsp = 0
        self.frame_size = DEFAULT_FRAME
        self.func_va = 0
        self.mu: Optional[Uc] = None
        self.vm_sec_name: Optional[str] = None
        self._code_sec: Optional[str] = None  # section containing func_va
        self._dark_call_counter = 0
        self._new_imports: list[dict] = []
        self._fprem_pending_fixup = False
        self._fprem_fixup_data = (0, 0, 0)

    # ─────── safe address allocation ───────

    def _init_alloc_cursor(self):
        ceil = max(s["end"] for s in self.sections.values())
        self._alloc_cursor = ((ceil + 0x100_0000) + 0xFFFF) & ~0xFFFF

    def _alloc(self, size: int, align: int = 0x10000) -> int:
        """Sequential allocator — each call returns a non-overlapping region."""
        if not hasattr(self, "_alloc_cursor"):
            self._init_alloc_cursor()
        base = (self._alloc_cursor + align - 1) & ~(align - 1)
        self._alloc_cursor = base + size
        return base

    # ─────── PE / memory setup ───────

    def _detect_vm_section(self) -> Optional[str]:
        for nm in self.sections:
            if nm.lower() in KNOWN_VM_SECTIONS:
                return nm
        for nm, sec in self.sections.items():
            if nm.lower() in KNOWN_STANDARD_SECTIONS:
                continue
            chars = sec["obj"].Characteristics
            if (chars & IMAGE_SCN_MEM_EXECUTE) and (chars & IMAGE_SCN_MEM_READ):
                return nm
        return None

    def _detect_frame_size(self, func_va: int) -> int:
        cs = self._code_section()
        ts, sec = cs["va"], cs["obj"]
        code = sec.get_data()[func_va - ts: func_va - ts + 64]
        for insn in self.asm.disasm(code, func_va):
            if insn.mnemonic == "sub" and len(insn.operands) == 2:
                if (insn.operands[0].type == X86_OP_REG and
                        insn.operands[0].reg == X86_REG_RSP):
                    return insn.operands[1].imm
        return DEFAULT_FRAME

    def _create_emu(self) -> Uc:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        for sec in self.sections.values():
            va = sec["va"]
            sz = max((max(sec["vsize"], sec["rsize"]) + 0xFFF) & ~0xFFF, 0x1000)
            try:
                mu.mem_map(va, sz)
                d = sec["obj"].get_data()
                if d:
                    mu.mem_write(va, d[:min(len(d), sz)])
            except UcError:
                pass

        self._init_alloc_cursor()

        stack_base = self._alloc(EMU_STACK_SIZE)
        self._stack_base = stack_base
        mu.mem_map(stack_base, EMU_STACK_SIZE)

        teb_base = self._alloc(EMU_TEB_SIZE, 0x1000)
        self._teb_base = teb_base
        peb_base = teb_base + 0x1000
        mu.mem_map(teb_base, EMU_TEB_SIZE)
        teb = bytearray(0x1000)
        struct.pack_into("<Q", teb, 0x30, teb_base)
        struct.pack_into("<Q", teb, 0x60, peb_base)
        mu.mem_write(teb_base, bytes(teb))
        mu.mem_write(peb_base, bytes(0x1000))
        mu.reg_write(UC_X86_REG_GS_BASE, teb_base)

        self._setup_peb_ldr(mu, peb_base)

        def _on_unmap(uc, _access, addr, _sz, _val, _data):
            try:
                uc.mem_map(addr & ~0xFFF, 0x1000)
            except UcError:
                pass
            return True
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, _on_unmap)
        mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, _on_unmap)

        return mu

    # ─────── PEB / LDR fake module chain ───────

    def _setup_peb_ldr(self, mu: Uc, peb_base: int):
        """Build PEB → PEB_LDR_DATA → fake DLL modules with export tables.

        When Themida's VM resolves APIs via PEB walking, it traverses
        InLoadOrderModuleList, finds a DLL by name, then walks its PE
        export table to locate the function address.  We create minimal
        fake PE images with valid export directories so the VM finds
        our sentinel hook addresses.
        """
        ldr_base = self._alloc(0x1000, 0x1000)
        mu.mem_map(ldr_base, 0x1000)

        ENTRY_SIZE = 0x120
        n_dlls = len(FAKE_DLL_EXPORTS)
        entries_base = self._alloc(ENTRY_SIZE * (n_dlls + 1), 0x1000)
        mu.mem_map(entries_base, ((ENTRY_SIZE * (n_dlls + 1)) + 0xFFF) & ~0xFFF)

        strings_base = self._alloc(0x4000, 0x1000)
        mu.mem_map(strings_base, 0x4000)

        entry_addrs: list[int] = []
        str_cursor = strings_base
        n_hooked = 0
        self._fake_pe_bases: dict[str, int] = {}

        for dll_name, exports in FAKE_DLL_EXPORTS.items():
            pe_base, pe_size = self._build_fake_pe(mu, dll_name, exports)
            self._fake_pe_bases[dll_name.lower()] = pe_base
            self._fake_pe_bases[dll_name.lower().replace(".dll", "")] = pe_base

            entry_va = entries_base + len(entry_addrs) * ENTRY_SIZE
            entry_addrs.append(entry_va)
            entry = bytearray(ENTRY_SIZE)

            struct.pack_into("<Q", entry, 0x30, pe_base)
            struct.pack_into("<Q", entry, 0x38, 0)
            struct.pack_into("<I", entry, 0x40, pe_size)

            uname = dll_name.encode("utf-16-le")
            mu.mem_write(str_cursor, uname + b"\x00\x00")
            struct.pack_into("<H", entry, 0x58, len(uname))
            struct.pack_into("<H", entry, 0x5A, len(uname) + 2)
            struct.pack_into("<Q", entry, 0x60, str_cursor)
            str_cursor += len(uname) + 2
            str_cursor = (str_cursor + 1) & ~1

            full = f"C:\\Windows\\System32\\{dll_name}".encode("utf-16-le")
            mu.mem_write(str_cursor, full + b"\x00\x00")
            struct.pack_into("<H", entry, 0x48, len(full))
            struct.pack_into("<H", entry, 0x4A, len(full) + 2)
            struct.pack_into("<Q", entry, 0x50, str_cursor)
            str_cursor += len(full) + 2
            str_cursor = (str_cursor + 1) & ~1

            mu.mem_write(entry_va, bytes(entry))
            n_hooked += len(exports)

        for i, addr in enumerate(entry_addrs):
            nxt = entry_addrs[(i + 1) % len(entry_addrs)]
            prv = entry_addrs[(i - 1) % len(entry_addrs)]
            for list_off in (0x00, 0x10, 0x20):
                mu.mem_write(addr + list_off,
                             struct.pack("<QQ", nxt + list_off,
                                         prv + list_off))

        ldr = bytearray(0x58)
        struct.pack_into("<I", ldr, 0x00, 0x58)
        struct.pack_into("<B", ldr, 0x04, 1)
        first = entry_addrs[0] if entry_addrs else ldr_base + 0x10
        last  = entry_addrs[-1] if entry_addrs else ldr_base + 0x10
        for off in (0x10, 0x20, 0x30):
            struct.pack_into("<Q", ldr, off, first + (off - 0x10))
            struct.pack_into("<Q", ldr, off + 8, last + (off - 0x10))
        mu.mem_write(ldr_base, bytes(ldr))

        peb_patch = bytearray(8)
        struct.pack_into("<Q", peb_patch, 0, ldr_base)
        mu.mem_write(peb_base + 0x18, bytes(peb_patch))

        print(f"[*] PEB/LDR: {n_dlls} fake modules, "
              f"{n_hooked} exports hooked")

    def _build_fake_pe(self, mu: Uc, dll_name: str,
                       exports: list[str]) -> tuple[int, int]:
        """Create a minimal PE image with a valid export directory.

        Stub addresses live inside the image so their RVAs fit 32 bits.
        Each stub is 0xCC (int3) — execution there raises UC_ERR and
        the exception handler finds the address in hook_map.

        Returns (base_va, image_size).
        """
        n = len(exports)
        names_blob = bytearray()
        name_offsets: list[int] = []
        for fname in exports:
            name_offsets.append(len(names_blob))
            names_blob.extend(fname.encode("ascii") + b"\x00")
        dll_name_off = len(names_blob)
        names_blob.extend(dll_name.encode("ascii") + b"\x00")

        HDR      = 0x200
        exp_off  = HDR                           # IMAGE_EXPORT_DIRECTORY
        eat_off  = exp_off + 40                  # AddressOfFunctions
        ent_off  = eat_off + n * 4               # AddressOfNames
        eot_off  = ent_off + n * 4               # AddressOfNameOrdinals
        nms_off  = (eot_off + n * 2 + 3) & ~3    # name strings
        stub_off = (nms_off + len(names_blob) + 0xFFF) & ~0xFFF
        total    = (stub_off + n * 0x10 + 0xFFF) & ~0xFFF

        pe_base = self._alloc(total, 0x10000)
        mu.mem_map(pe_base, total)
        img = bytearray(total)

        # --- DOS header ---
        img[0:2] = b"MZ"
        struct.pack_into("<I", img, 0x3C, 0x80)

        # --- PE file header (at 0x84, 20 bytes) ---
        img[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", img, 0x84, 0x8664)   # Machine AMD64
        struct.pack_into("<H", img, 0x86, 0)         # NumberOfSections
        struct.pack_into("<H", img, 0x94, 0xF0)      # SizeOfOptionalHeader
        struct.pack_into("<H", img, 0x96, 0x2022)    # Characteristics

        # --- PE32+ optional header (at 0x98, 0xF0 bytes) ---
        struct.pack_into("<H", img, 0x98, 0x20b)     # Magic PE32+
        struct.pack_into("<Q", img, 0xB0, pe_base)   # ImageBase
        struct.pack_into("<I", img, 0xB8, 0x1000)    # SectionAlignment
        struct.pack_into("<I", img, 0xBC, 0x200)     # FileAlignment
        struct.pack_into("<I", img, 0xD0, total)     # SizeOfImage
        struct.pack_into("<I", img, 0xD4, HDR)       # SizeOfHeaders
        struct.pack_into("<I", img, 0x104, 0x10)     # NumberOfRvaAndSizes

        # --- DataDirectory[0] = Export (at 0x108) ---
        struct.pack_into("<I", img, 0x108, exp_off)
        struct.pack_into("<I", img, 0x10C, 40)

        # --- IMAGE_EXPORT_DIRECTORY (at exp_off) ---
        struct.pack_into("<I", img, exp_off + 12, nms_off + dll_name_off)
        struct.pack_into("<I", img, exp_off + 16, 1)       # Base
        struct.pack_into("<I", img, exp_off + 20, n)       # NumberOfFunctions
        struct.pack_into("<I", img, exp_off + 24, n)       # NumberOfNames
        struct.pack_into("<I", img, exp_off + 28, eat_off) # AddrOfFunctions
        struct.pack_into("<I", img, exp_off + 32, ent_off) # AddrOfNames
        struct.pack_into("<I", img, exp_off + 36, eot_off) # AddrOfNameOrdinals

        # --- tables ---
        for i, fname in enumerate(exports):
            s_rva = stub_off + i * 0x10
            struct.pack_into("<I", img, eat_off + i * 4, s_rva)
            struct.pack_into("<I", img, ent_off + i * 4,
                             nms_off + name_offsets[i])
            struct.pack_into("<H", img, eot_off + i * 2, i)

            stub_va = pe_base + s_rva
            func_sym = re.sub(r"[^a-zA-Z0-9_]", "_",
                              f"{dll_name}_{fname}")
            self.hook_map[stub_va] = {
                "dll": dll_name, "func": fname,
                "iat": 0, "hook": stub_va, "sym": func_sym,
            }

        img[nms_off: nms_off + len(names_blob)] = names_blob

        # fill stubs with INT3
        for i in range(n):
            off = stub_off + i * 0x10
            img[off: off + 0x10] = b"\xCC" * 0x10

        mu.mem_write(pe_base, bytes(img))
        return pe_base, total

    def _fill_iat(self, mu: Uc):
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return
        fake = self._alloc(0x10000)
        for de in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = de.dll.decode("utf-8", "replace")
            rva = de.struct.FirstThunk
            for i, imp in enumerate(de.imports):
                fn = (imp.name.decode("utf-8", "replace")
                      if imp.name else f"ord_{imp.ordinal}")
                iat = self.ib + rva + i * (8 if self._is_pe32plus else 4)
                sym = re.sub(r"[^a-zA-Z0-9_]", "_", f"{dll}_{fn}")
                info = {"dll": dll, "func": fn, "iat": iat,
                        "hook": fake, "sym": sym}
                self.hook_map[fake] = info
                mu.mem_write(iat, struct.pack("<Q", fake))
                fake += 0x10

    def _fill_rdata_hooks(self, mu: Uc):
        """Replace dark function pointers in .rdata with sentinels.

        If EP init already resolved a slot (in self._ep_resolved),
        the hook_map entry carries the real API name.
        """
        sec = self.sections.get(".rdata")
        if not sec:
            return
        ep_res = getattr(self, "_ep_resolved", {})
        rdata_rva = sec["obj"].VirtualAddress
        rdata_end_rva = rdata_rva + sec["vsize"]
        rdata_mid_rva = rdata_rva + sec["vsize"] // 4
        sentinel_base = self._alloc(0x20000)
        seen_vals: dict[int, int] = {}
        n = 0
        va = sec["va"]
        data = sec["obj"].get_data()
        vsize = min(len(data), sec["vsize"])
        self._rdata_dark_slots: dict[int, int] = {}
        n_named = 0
        for off in range(0, vsize - 7, 8):
            val = struct.unpack_from("<Q", data, off)[0]
            if not (rdata_mid_rva <= val < rdata_end_rva + 0x1000):
                continue
            slot_va = va + off
            self._rdata_dark_slots[slot_va] = val
            if val in seen_vals:
                sentinel = seen_vals[val]
            else:
                sentinel = sentinel_base + n * 0x10
                seen_vals[val] = sentinel
                n += 1
            if sentinel not in self.hook_map:
                ep_name = ep_res.get(slot_va)
                if ep_name and "!" in ep_name:
                    dll, func = ep_name.split("!", 1)
                    sym = re.sub(r"[^a-zA-Z0-9_]", "_",
                                 f"{dll}_{func}")
                    n_named += 1
                else:
                    dll, func = "?", f"slot_{slot_va:x}"
                    sym = func
                self.hook_map[sentinel] = {
                    "dll": dll, "func": func,
                    "iat": slot_va, "hook": sentinel, "sym": sym,
                }
            mu.mem_write(slot_va, struct.pack("<Q", sentinel))
        if n:
            print(f"[*] Pre-filled {n} dark .rdata slots "
                  f"({n_named} named by EP init)")

    def _scan_vm_functions(self) -> list[int]:
        """Find all functions in .text that have a jmp/call into the VM."""
        results = []
        vm_sec = self.vm_sec_name
        if not vm_sec or vm_sec not in self.sections:
            return results
        vs = self.sections[vm_sec]["va"]
        ve = self.sections[vm_sec]["end"]
        for nm, sec in self.sections.items():
            chars = sec["obj"].Characteristics
            if not (chars & IMAGE_SCN_MEM_EXECUTE):
                continue
            if nm == vm_sec:
                continue
            data = sec["obj"].get_data()
            base = sec["va"]
            for insn in self.asm.disasm(data, base):
                if insn.mnemonic not in ("jmp", "call"):
                    continue
                if not insn.operands:
                    continue
                op = insn.operands[0]
                if op.type == X86_OP_IMM and vs <= op.imm < ve:
                    func_start = self._find_func_start(insn.address, sec)
                    if func_start and func_start not in results:
                        results.append(func_start)
        return results

    def _find_func_start(self, vm_jmp_addr: int, sec: dict) -> Optional[int]:
        """Walk backwards from a VM-entry jmp to find the function start."""
        base = sec["va"]
        data = sec["obj"].get_data()
        search_start = max(0, vm_jmp_addr - base - 256)
        chunk = data[search_start: vm_jmp_addr - base + 16]
        insns = list(self.asm.disasm(chunk, base + search_start))
        for i, insn in enumerate(insns):
            if insn.address == vm_jmp_addr:
                for j in range(i - 1, max(i - 30, -1), -1):
                    prev = insns[j]
                    if prev.mnemonic == "int3" or prev.mnemonic == "ret":
                        return insns[j + 1].address if j + 1 < len(insns) else None
                return insns[0].address
        return None

    # ─────── FPREM anti-emulation fix ───────
    #
    # Unicorn (via QEMU softfloat) produces NaN/Inf AND wrong C2=0 when
    # the exponent difference D = exp(ST0)-exp(ST1) is >= 64.  Real x87
    # hardware performs iterative partial reduction (up to 63 bits per
    # step), setting C2=1 each time.  Anti-emulation code checks C2 after
    # a single FPREM to detect emulators.
    #
    # Fix: before FPREM executes, compute the correct partial result in
    # Python using arbitrary-precision arithmetic, then overwrite
    # Unicorn's wrong result afterward.

    def _fprem_detect(self, uc, addr, sz):
        """Detect FPREM/FPREM1 and pre-compute correct partial result."""
        if sz != 2:
            return
        try:
            ib = bytes(uc.mem_read(addr, 2))
        except UcError:
            return
        if ib[0] != 0xD9 or ib[1] not in (0xF8, 0xF5):
            return
        try:
            fpsw = uc.reg_read(UC_X86_REG_FPSW)
            top = (fpsw >> 11) & 7
            st0 = uc.reg_read(FP_REGS[top])
            st1 = uc.reg_read(FP_REGS[(top + 1) & 7])
            if not (isinstance(st0, tuple) and isinstance(st1, tuple)):
                return
            m0, e0f = st0
            m1, e1f = st1
            e0 = e0f & 0x7FFF
            e1 = e1f & 0x7FFF
            D = e0 - e1
            if D < 64 or m1 == 0:
                return
            s0 = (e0f >> 15) & 1
            N = 63
            QQ = (m0 << N) // m1
            new_raw = (m0 << N) % m1
            if new_raw == 0:
                new_m, new_ef = 0, s0 << 15
            else:
                shift = 63 - (new_raw.bit_length() - 1)
                new_m = (new_raw << shift) & 0xFFFFFFFFFFFFFFFF
                new_e = max(e0 - N - shift, 1)
                new_ef = (s0 << 15) | (new_e & 0x7FFF)
            self._fprem_fixup_data = (new_m, new_ef, top)
            self._fprem_pending_fixup = True
        except Exception:
            pass

    def _fprem_apply_fixup(self, uc):
        """Overwrite Unicorn's wrong FPREM result and set C2=1."""
        if not self._fprem_pending_fixup:
            return
        self._fprem_pending_fixup = False
        try:
            new_m, new_ef, top = self._fprem_fixup_data
            uc.reg_write(FP_REGS[top], (new_m, new_ef))
            fpsw = uc.reg_read(UC_X86_REG_FPSW)
            uc.reg_write(UC_X86_REG_FPSW, fpsw | 0x0400)
        except Exception:
            pass

    # ─────── helpers ───────

    def _regs(self, mu: Uc) -> dict:
        return {n: mu.reg_read(r) for n, r in GP_REGS.items()}

    def _frame_snap(self, mu: Uc, rsp: int, scan_bytes: int = 0) -> dict:
        if scan_bytes <= 0:
            scan_bytes = min(self.frame_size, 0x200)
        f = {}
        try:
            for o in range(0, scan_bytes, 4):
                f[("d", o)] = struct.unpack("<I", bytes(mu.mem_read(rsp + o, 4)))[0]
            for o in range(0, scan_bytes, 8):
                f[("q", o)] = struct.unpack("<Q", bytes(mu.mem_read(rsp + o, 8)))[0]
        except UcError:
            pass
        return f

    def _find_vm_entry(self, fva: int) -> Optional[dict]:
        """Detect VM entry: jmp VM, push VM;ret, or call VM."""
        vm_sec = self.vm_sec_name
        if not vm_sec or vm_sec not in self.sections:
            return None
        vs = self.sections[vm_sec]["va"]
        ve = self.sections[vm_sec]["end"]
        cs = self._code_section()
        ts, sec = cs["va"], cs["obj"]
        code = sec.get_data()[fva - ts: fva - ts + 256]
        insns = self.asm.disasm(code, fva)
        for i, insn in enumerate(insns):
            if insn.mnemonic == "jmp" and insn.operands:
                op = insn.operands[0]
                if op.type == X86_OP_IMM and vs <= op.imm < ve:
                    return {"jmp": insn.address, "target": op.imm}
            if insn.mnemonic == "call" and insn.operands:
                op = insn.operands[0]
                if op.type == X86_OP_IMM and vs <= op.imm < ve:
                    return {"jmp": insn.address, "target": op.imm}
            if (insn.mnemonic == "push" and insn.operands and
                    insn.operands[0].type == X86_OP_IMM):
                target = insn.operands[0].imm
                if vs <= target < ve and i + 1 < len(insns):
                    nxt = insns[i + 1]
                    if nxt.mnemonic in ("ret", "retn"):
                        return {"jmp": insn.address, "target": target}
        return None

    def _sec_of(self, va: int) -> Optional[str]:
        """Find which section contains a given VA."""
        for nm, sec in self.sections.items():
            if sec["va"] <= va < sec["end"]:
                return nm
        return None

    def _code_section(self) -> dict:
        """Return the section dict containing func_va."""
        nm = self._code_sec or ".text"
        return self.sections[nm]

    def _is_data_addr(self, a: int) -> bool:
        for n in (".rdata", ".data", ".text"):
            if n in self.sections:
                s = self.sections[n]
                if s["va"] <= a < s["end"]:
                    return True
        return False

    def _is_marker_dll(self, dll_name: str) -> bool:
        return dll_name.lower() in KNOWN_MARKER_DLLS

    def _find_reg_src(self, dst: str, val: int, prev: dict) -> Optional[str]:
        if val == 0:
            return None
        for r in GP_REGS:
            if r != dst and r != "rsp" and prev.get(r) == val:
                return r
        return None

    def _va_to_raw(self, va: int) -> Optional[int]:
        rva = va - self.ib
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                return s.PointerToRawData + (rva - s.VirtualAddress)
        return None

    # ─────── call interception ───────

    def _on_call(self, mu: Uc, addr: int) -> int:
        info = self.hook_map[addr]
        regs = self._regs(mu)
        via = next((r for r, v in regs.items()
                     if v == addr and r != "rsp"), None)
        call_idx = len(self.events)
        ret = Sentinel.ret_val(call_idx)
        frsp = regs["rsp"] + 8
        ev = {
            "i": call_idx,
            "dll": info["dll"], "func": info["func"],
            "iat": info["iat"], "hook": info["hook"],
            "regs": regs, "ret": ret, "via": via,
            "frame": self._frame_snap(mu, frsp),
        }
        self.events.append(ev)
        mu.reg_write(UC_X86_REG_RAX, ret)

        for rn in WIN64_VOLATILE:
            mu.reg_write(GP_REGS[rn], Sentinel.clobber(rn, call_idx))

        rsp = regs["rsp"]
        ra = struct.unpack("<Q", bytes(mu.mem_read(rsp, 8)))[0]
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        return ra

    # ─────── dark call interception (Themida-resolved APIs) ───────

    def _on_dark_call(self, mu: Uc, addr: int) -> int:
        """Handle API call to an address resolved by Themida (not in IAT)."""
        regs = self._regs(mu)
        call_idx = len(self.events)
        ret = Sentinel.ret_val(call_idx)
        rsp = regs["rsp"]
        ra = struct.unpack("<Q", bytes(mu.mem_read(rsp, 8)))[0]
        frsp = rsp + 8
        dark_idx = self._dark_call_counter
        self._dark_call_counter += 1
        ev = {
            "i": call_idx,
            "dll": "?", "func": f"dark_{dark_idx}",
            "iat": 0, "hook": addr,
            "regs": regs, "ret": ret, "via": None,
            "frame": self._frame_snap(mu, frsp),
            "dark": True, "dark_addr": addr,
        }
        self.events.append(ev)
        mu.reg_write(UC_X86_REG_RAX, ret)
        for rn in WIN64_VOLATILE:
            mu.reg_write(GP_REGS[rn], Sentinel.clobber(rn, call_idx))
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        return ra

    def _identify_dark_apis(self):
        """Resolve unknown API calls via hook_map lookup.

        All API naming comes from PEB/LDR fake exports or EP init
        resolution.  No heuristic matchers — pure data-driven.
        """
        seen_syms: set[str] = set()
        for ev in self.events:
            if ev["dll"] != "?" and not ev.get("dark"):
                continue
            hook_addr = ev.get("dark_addr", ev["hook"])
            info = self.hook_map.get(hook_addr)
            if info and info["dll"] != "?":
                ev["dll"], ev["func"] = info["dll"], info["func"]

            sym = re.sub(r"[^a-zA-Z0-9_]", "_",
                         f"{ev['dll']}_{ev['func']}")
            if info:
                info.update(dll=ev["dll"], func=ev["func"], sym=sym)
            has_iat = ev.get("iat", 0) != 0
            if sym not in seen_syms and not has_iat:
                seen_syms.add(sym)
                self._new_imports.append({
                    "dll": ev["dll"], "func": ev["func"], "sym": sym,
                })

    # ─────── Phase 1: full emulation ───────

    def _emulate(self, func_va: int, vms: int, vme: int):
        mu = self._create_emu()
        self._fill_iat(mu)
        self._fill_rdata_hooks(mu)
        self.mu = mu

        sp = self._stack_base + EMU_STACK_SIZE - 0x10000
        mu.mem_write(sp - 0x1000, b"\xcc" * 0x2000)
        mu.reg_write(UC_X86_REG_RSP, sp)
        mu.reg_write(UC_X86_REG_RFLAGS, 0x246)
        mu.mem_write(sp, struct.pack("<Q", 0xDEAD_DEAD_DEAD_DEAD))

        self._text_run = 0
        self._text_start = 0
        RETURN_SENTINEL = 0xDEAD_DEAD_DEAD_DEAD

        def hook_code(uc, a, sz, _):
            self._fprem_apply_fixup(uc)
            self.n_insns += 1
            if self.n_insns > MAX_INSNS:
                uc.emu_stop(); return
            self._fprem_detect(uc, a, sz)
            if not self.in_vm:
                if vms <= a < vme:
                    self.in_vm = True
                    self.pre_vm_regs = self._regs(uc)
                    self.frame_rsp = self.pre_vm_regs["rsp"]
            else:
                if vms <= a < vme:
                    self.addr_freq[a] += 1
                    self._text_run = 0
                elif a in self.hook_map:
                    self._text_run = 0
                elif a == RETURN_SENTINEL:
                    if self._text_start:
                        self.vm_exit_addr = self._text_start
                    uc.emu_stop()
                else:
                    if self._text_run == 0:
                        self._text_start = a
                    self._text_run += 1
                    try:
                        b = bytes(uc.mem_read(a, 2))
                        if b[0] == 0xFF and b[1] == 0x25:
                            return
                    except UcError:
                        pass
                    if self._text_run > 50:
                        rsp = uc.reg_read(UC_X86_REG_RSP)
                        is_call = False
                        try:
                            for i in range(8):
                                ret = struct.unpack("<Q", bytes(
                                    uc.mem_read(rsp + i * 8, 8)))[0]
                                if vms <= ret < vme:
                                    is_call = True
                                    break
                        except UcError:
                            pass
                        if is_call:
                            return
                        self.vm_exit_addr = self._text_start
                        uc.emu_stop()

        mu.hook_add(UC_HOOK_CODE, hook_code)

        # CPUID hook — return plausible Intel CPU info so VM feature
        # detection doesn't break; also defeats cpuid-based anti-emu.
        def on_cpuid(uc):
            leaf = uc.reg_read(UC_X86_REG_EAX)
            if leaf == 0:
                uc.reg_write(UC_X86_REG_EAX, 0x16)
                uc.reg_write(UC_X86_REG_EBX, 0x756E6547)  # Genu
                uc.reg_write(UC_X86_REG_EDX, 0x49656E69)  # ineI
                uc.reg_write(UC_X86_REG_ECX, 0x6C65746E)  # ntel
            elif leaf == 1:
                uc.reg_write(UC_X86_REG_EAX, 0x000906EA)
                uc.reg_write(UC_X86_REG_EBX, 0x00100800)
                uc.reg_write(UC_X86_REG_ECX, 0xFEDA3203)
                uc.reg_write(UC_X86_REG_EDX, 0x178BFBFF)
            elif leaf == 0x80000000:
                uc.reg_write(UC_X86_REG_EAX, 0x80000008)
            else:
                for r in (UC_X86_REG_EAX, UC_X86_REG_EBX,
                          UC_X86_REG_ECX, UC_X86_REG_EDX):
                    uc.reg_write(r, 0)
        try:
            mu.hook_add(UC_HOOK_INSN, on_cpuid, arg1=UC_X86_INS_CPUID)
        except Exception:
            pass

        # SYSCALL hook — just skip (return 0 in rax)
        def on_syscall(uc):
            uc.reg_write(UC_X86_REG_RAX, 0)
        try:
            mu.hook_add(UC_HOOK_INSN, on_syscall, arg1=UC_X86_INS_SYSCALL)
        except Exception:
            pass

        ip = func_va
        while True:
            try:
                mu.emu_start(ip, 0, timeout=0, count=MAX_INSNS)
                break
            except UcError as e:
                rip = mu.reg_read(UC_X86_REG_RIP)
                if rip in self.hook_map:
                    ip = self._on_call(mu, rip)
                    continue
                if self.in_vm and self._sec_of(rip) is None:
                    if rip == 0xDEAD_DEAD_DEAD_DEAD:
                        if self._text_start:
                            self.vm_exit_addr = self._text_start
                        break
                    ip = self._on_dark_call(mu, rip)
                    self._text_run = 0
                    continue
                print(f"[!] Emulation error at 0x{rip:x}: {e}")
                break

    # ─────── per-function state reset ───────

    def _reset_func_state(self):
        self.hook_map.clear()
        self.events = []
        self.n_insns = 0
        self.in_vm = False
        self.vm_exit_addr = None
        self.pre_vm_regs = {}
        self.frame_rsp = 0
        self.frame_size = DEFAULT_FRAME
        self.addr_freq = Counter()
        self._dark_call_counter = 0
        self._new_imports = []
        self._fprem_pending_fixup = False
        self._fprem_fixup_data = (0, 0, 0)
        self._text_run = 0
        self._text_start = 0
        if hasattr(self, "_alloc_cursor"):
            del self._alloc_cursor

    # ─────── single-function driver ───────

    def _devirt_one(self, func_va: int, quiet: bool = False
                    ) -> Optional[dict]:
        """Devirtualize one function.  Returns result dict or None."""
        self._reset_func_state()
        self.func_va = func_va
        self._code_sec = self._sec_of(func_va)
        if not self._code_sec:
            return None
        self.frame_size = self._detect_frame_size(func_va)
        vm_info = self._find_vm_entry(func_va)
        if not vm_info:
            return None
        vms = self.sections[self.vm_sec_name]["va"]
        vme = self.sections[self.vm_sec_name]["end"]

        if not quiet:
            print(f"\n[*] ── func 0x{func_va:x}  frame=0x{self.frame_size:x}"
                  f"  entry=0x{vm_info['jmp']:x}→0x{vm_info['target']:x}")

        self._emulate(func_va, vms, vme)
        if not self.vm_exit_addr:
            if not quiet:
                print(f"    [!] VM did not exit")
            return None

        unknown = sum(1 for ev in self.events if ev["dll"] == "?")
        if unknown or self._dark_call_counter > 0:
            self._identify_dark_apis()
        n_id = sum(1 for ev in self.events if ev["dll"] != "?")

        if not quiet:
            print(f"    emulated {self.n_insns} insns, "
                  f"{len(self.events)} calls ({n_id} identified), "
                  f"exit→0x{self.vm_exit_addr:x}")

        asm_lines = self._reconstruct()
        return {
            "func_va": func_va, "vm_entry": vm_info,
            "vm_exit": self.vm_exit_addr,
            "asm_lines": asm_lines, "events": list(self.events),
            "frame_size": self.frame_size,
            "hook_map_snapshot": dict(self.hook_map),
        }

    # ─────── main driver (single function) ───────

    def run(self, func_va: int, output: Optional[str] = None) -> bool:
        if not self._is_pe32plus:
            print("[!] PE32 (32-bit) not supported yet, only PE32+ (x64)")
            return False
        self.vm_sec_name = self._detect_vm_section()
        if not self.vm_sec_name:
            print("[!] No VM section detected"); return False
        print(f"[*] VM section: {self.vm_sec_name}")

        result = self._devirt_one(func_va)
        if not result:
            print("[!] Devirtualization failed"); return False

        self._print_trace()
        self._print_asm(result["asm_lines"])

        if output:
            ok = self._generate_multi_pe([result], output)
            if ok:
                print(f"\n[OK] Patched PE -> {output}")
        return True

    # ─────── EP init emulation ───────

    _APISET_MAP = {
        "api-ms-win-crt": "ucrtbase",
        "api-ms-win-core": "kernel32",
    }

    _EP_CORE_DLLS = [
        "kernel32.dll", "ntdll.dll", "kernelbase.dll",
        "user32.dll", "advapi32.dll",
        "ucrtbase.dll", "vcruntime140.dll", "msvcrt.dll",
    ]

    def _resolve_apiset(self, mod_name: str) -> int:
        """Resolve a module name (incl. API-set redirects) to a fake PE base."""
        nl = _norm_mod(mod_name).replace(".dll", "").replace(".sys", "")
        for k, v in self._dll_bases.items():
            if k.replace(".dll", "").replace(".sys", "") == nl:
                return v
        for prefix, target in self._APISET_MAP.items():
            if nl.startswith(prefix):
                for k, v in self._dll_bases.items():
                    if k.replace(".dll", "").replace(".sys", "") == target:
                        return v
        return 0

    def _ep_smart_ret(self, mu: Uc, fn: str,
                      rcx: int, rdx: int, r8: int, r9: int) -> int:
        """Return plausible values for Windows APIs during EP init."""
        if fn == "GetProcessHeap":
            return self._ep_heap_base
        if fn in ("RtlAllocateHeap", "HeapAlloc"):
            sz = max(r8 if r8 > 0 else 0x100, 0x100)
            p = (self._ep_heap_cursor + 0xF) & ~0xF
            self._ep_heap_cursor = p + sz
            if self._ep_heap_cursor > self._ep_heap_base + 0x3F0000:
                self._ep_heap_cursor = self._ep_heap_base + 0x1000
            return p
        if fn in ("HeapFree", "RtlFreeHeap"):
            return 1
        if "Critical" in fn:
            return 0
        if fn == "VirtualAlloc":
            sz = max(rdx, 0x1000)
            p = self._alloc(sz)
            try:
                mu.mem_map(p, (sz + 0xFFF) & ~0xFFF)
            except UcError:
                pass
            return p
        if fn == "VirtualProtect":
            try:
                mu.mem_write(r9, struct.pack("<I", 0x40))
            except UcError:
                pass
            return 1
        if fn in ("VirtualFree", "CloseHandle", "FreeLibrary",
                   "SetCurrentDirectoryW"):
            return 1
        if fn == "GetCurrentProcess":
            return 0xFFFFFFFFFFFFFFFF
        if fn == "GetCurrentThread":
            return 0xFFFFFFFFFFFFFFFE
        if fn in ("GetCurrentProcessId", "GetCurrentThreadId"):
            return 0x1234
        if fn in ("GetLastError", "SetLastError", "IsDebuggerPresent"):
            return 0
        if fn == "IsProcessorFeaturePresent":
            return 1
        if fn in ("GetModuleHandleA", "GetModuleHandleW"):
            if rcx == 0:
                return self.ib
            nm = self._read_cstr(mu, rcx)
            r = self._resolve_apiset(nm)
            if not r and nm and len(nm) > 3:
                r = self._ep_hot_load(mu, nm)
            return r if r else self.ib
        if fn in ("LoadLibraryA", "LoadLibraryW",
                   "LoadLibraryExA", "LoadLibraryExW"):
            nm = self._read_cstr(mu, rcx)
            r = self._resolve_apiset(nm)
            if not r and nm and len(nm) > 3:
                r = self._ep_hot_load(mu, nm)
            return r
        if fn == "GetProcAddress":
            fname = self._read_cstr(mu, rdx)
            if fname and len(fname) > 2:
                for sva, sname in self.hook_map.items():
                    if isinstance(sname, dict):
                        if sname.get("func") == fname:
                            return sva
                    elif isinstance(sname, str) and sname.endswith(
                            "!" + fname):
                        return sva
            return 0
        if fn in ("GetUserDefaultUILanguage", "GetACP", "GetOEMCP"):
            return 0x0409
        if fn == "GetVersion":
            return 0x0A000000
        if fn in ("GetTickCount", "GetTickCount64"):
            return 0x12345678
        if fn in ("Sleep", "SleepEx"):
            return 0
        if fn == "GetCurrentDirectoryW":
            try:
                mu.mem_write(rdx, b"C\x00:\x00\\\x00\x00\x00")
            except UcError:
                pass
            return 3
        if fn in ("GetModuleFileNameW",):
            p = "C:\\p.exe".encode("utf-16-le") + b"\x00\x00"
            try:
                mu.mem_write(rdx, p)
            except UcError:
                pass
            return len(p) // 2 - 1
        if fn in ("GetModuleFileNameA",):
            try:
                mu.mem_write(rdx, b"C:\\p.exe\x00")
            except UcError:
                pass
            return 7
        if fn in ("OpenThread", "OpenProcess"):
            return 0xAAAA
        if fn in ("MultiByteToWideChar", "WideCharToMultiByte"):
            return 1
        if fn in ("RegOpenKeyA", "RegOpenKeyExA",
                   "RegOpenKeyW", "RegOpenKeyExW"):
            try:
                rsp = mu.reg_read(UC_X86_REG_RSP)
                ohp = struct.unpack("<Q",
                                    bytes(mu.mem_read(rsp + 0x28, 8)))[0]
                mu.mem_write(ohp, struct.pack("<Q", 0xBEEF))
            except UcError:
                pass
            return 0
        if fn in ("RegQueryValueExA", "RegQueryValueExW"):
            return 2
        if fn == "RegCloseKey":
            return 0
        if fn == "GetSystemFirmwareTable":
            if r8 and r9 > 0:
                try:
                    mu.mem_write(r8, bytes(min(r9, 0x100)))
                except UcError:
                    pass
            return min(r9, 0x100) if r9 > 0 else 0x100
        if fn == "OpenProcessToken":
            try:
                mu.mem_write(rdx, struct.pack("<Q", 0xCCCC))
            except UcError:
                pass
            return 1
        if fn in ("OpenThreadToken", "GetTokenInformation"):
            return 0
        if fn == "GetCommandLineA":
            return self._ep_heap_base
        if fn == "GetStdHandle":
            return 0x100 + ((rcx & 0xF) * 0x10)
        if fn == "RtlAddVectoredExceptionHandler":
            return 0xDDDD
        if fn == "SetUnhandledExceptionFilter":
            return 0
        if fn in ("ExitProcess", "TerminateProcess"):
            return 0
        if fn.startswith("Nt") or fn.startswith("Rtl"):
            return 0
        return 0

    def _ep_hot_load(self, mu: Uc, dll_name: str) -> int:
        """Dynamically load a missing DLL during EP init.

        Looks up win_exports.json; if found, builds a fake PE on the fly
        and adds it to PEB/LDR.  If not found, records as truly missing.
        """
        norm = _norm_mod(dll_name)
        stem = norm.replace(".dll", "").replace(".sys", "")

        for prefix, target in self._APISET_MAP.items():
            if stem.startswith(prefix):
                r = self._resolve_apiset(target + ".dll")
                if r:
                    return r

        if norm in self._dll_bases or stem in self._dll_bases:
            return self._dll_bases.get(norm, self._dll_bases.get(stem, 0))

        exports = _ALL_EXPORTS.get(norm,
                  _ALL_EXPORTS.get(stem,
                  _ALL_EXPORTS.get(norm.replace(".dll", ""),
                  _ALL_EXPORTS.get(norm.replace(".sys", ""), []))))
        if not exports:
            self._ep_missing_dlls.add(norm)
            return 0

        base, _ = self._build_fake_pe(mu, norm, exports)
        self._dll_bases[norm] = base
        self._dll_bases[stem] = base
        self._fake_pe_bases[norm] = base
        self._fake_pe_bases[stem] = base
        print(f"[*] EP init: hot-loaded {norm} "
              f"({len(exports)} exports) at 0x{base:x}")
        return base

    @staticmethod
    def _read_cstr(mu: Uc, addr: int) -> str:
        try:
            raw = bytes(mu.mem_read(addr, 256))
            return raw[:raw.index(0)].decode("ascii", "replace").lower()
        except (UcError, ValueError):
            return ""

    def run_ep_init(self, timeout: int = 120) -> dict[int, str]:
        """Run Themida EP init to resolve .rdata API slots.

        Uses a lightweight Unicorn emulator with only 8 core DLLs
        in PEB/LDR (faster than the full 60-DLL setup used for
        function devirtualization).

        Returns {slot_va: 'dll!func'} for every resolved slot.
        """
        ep_va = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.ib
        print(f"[*] EP init: emulating from 0x{ep_va:x} "
              f"(timeout {timeout}s)")

        rdata_dark: dict[int, int] = {}
        sec = self.sections.get(".rdata")
        if sec:
            rva = sec["obj"].VirtualAddress
            mid_rva = rva + sec["vsize"] // 4
            data = sec["obj"].get_data()
            for off in range(0, min(len(data), sec["vsize"]) - 7, 8):
                val = struct.unpack_from("<Q", data, off)[0]
                if mid_rva <= val < rva + sec["vsize"] + 0x1000:
                    rdata_dark[sec["va"] + off] = val

        self._ep_missing_dlls: set[str] = set()

        self._reset_func_state()
        mu = self._create_emu()
        self._fill_iat(mu)

        self._dll_bases = dict(getattr(self, "_fake_pe_bases", {}))

        ep_heap_base = self._alloc(0x400000)
        mu.mem_map(ep_heap_base, 0x400000)
        self._ep_heap_base = ep_heap_base
        self._ep_heap_cursor = ep_heap_base + 0x1000

        def _on_cpuid(uc):
            leaf = uc.reg_read(UC_X86_REG_EAX)
            if leaf == 0:
                uc.reg_write(UC_X86_REG_EAX, 0x16)
                uc.reg_write(UC_X86_REG_EBX, 0x756E6547)
                uc.reg_write(UC_X86_REG_EDX, 0x49656E69)
                uc.reg_write(UC_X86_REG_ECX, 0x6C65746E)
            elif leaf == 1:
                uc.reg_write(UC_X86_REG_EAX, 0x000906EA)
                uc.reg_write(UC_X86_REG_EBX, 0x00100800)
                uc.reg_write(UC_X86_REG_ECX, 0xFEDA3203)
                uc.reg_write(UC_X86_REG_EDX, 0x178BFBFF)
            else:
                for r in (UC_X86_REG_EAX, UC_X86_REG_EBX,
                          UC_X86_REG_ECX, UC_X86_REG_EDX):
                    uc.reg_write(r, 0)
        try:
            mu.hook_add(UC_HOOK_INSN, _on_cpuid, arg1=UC_X86_INS_CPUID)
        except Exception:
            pass
        try:
            mu.hook_add(UC_HOOK_INSN,
                        lambda uc: uc.reg_write(UC_X86_REG_RAX, 0),
                        arg1=UC_X86_INS_SYSCALL)
        except Exception:
            pass

        sp = self._stack_base + EMU_STACK_SIZE - 0x10000
        mu.reg_write(UC_X86_REG_RSP, sp)
        mu.reg_write(UC_X86_REG_RFLAGS, 0x246)
        mu.mem_write(sp, struct.pack("<Q", 0xDEAD_DEAD_DEAD_DEAD))

        rdata_va = sec["va"] if sec else 0
        rdata_end = sec["va"] + sec["vsize"] if sec else 0
        rdata_writes = []

        def on_rdata_write(uc, _access, addr, _sz, val, _data):
            if addr in rdata_dark:
                rdata_writes.append(addr)
                if len(rdata_writes) == 1:
                    print(f"[*] EP init: first .rdata write at "
                          f"{time.time() - t0:.1f}s")
                if len(rdata_writes) >= len(rdata_dark):
                    uc.emu_stop()

        if rdata_va:
            mu.hook_add(UC_HOOK_MEM_WRITE, on_rdata_write,
                        begin=rdata_va, end=rdata_end)

        t0 = time.time()
        ip = self.ib + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        api_count = 0
        CHUNK = 2_000_000_000

        def _hm_name(addr):
            v = self.hook_map.get(addr)
            if v is None:
                return None
            if isinstance(v, str):
                return v
            if isinstance(v, dict):
                return f"{v.get('dll', '?')}!{v.get('func', '?')}"
            return None

        last_err_rip = 0
        err_repeat = 0

        while time.time() - t0 < timeout:
            try:
                mu.emu_start(ip, 0, timeout=0, count=CHUNK)
                break
            except UcError:
                rip = mu.reg_read(UC_X86_REG_RIP)
                rsp = mu.reg_read(UC_X86_REG_RSP)
                rcx = mu.reg_read(UC_X86_REG_RCX)
                rdx = mu.reg_read(UC_X86_REG_RDX)
                r8 = mu.reg_read(UC_X86_REG_R8)
                r9 = mu.reg_read(UC_X86_REG_R9)

                name = _hm_name(rip) or _hm_name(rip - 1)
                if name:
                    fn = name.split("!")[-1]
                    ret = self._ep_smart_ret(mu, fn, rcx, rdx, r8, r9)
                    api_count += 1
                    last_err_rip = 0
                    try:
                        ra = struct.unpack(
                            "<Q", bytes(mu.mem_read(rsp, 8)))[0]
                        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
                        mu.reg_write(UC_X86_REG_RAX, ret)
                        ip = ra
                    except UcError:
                        break
                    continue

                if self._sec_of(rip):
                    if rip == last_err_rip:
                        err_repeat += 1
                        if err_repeat > 2:
                            try:
                                ra = struct.unpack(
                                    "<Q", bytes(mu.mem_read(rsp, 8)))[0]
                                if ra >= 0x1000:
                                    mu.reg_write(UC_X86_REG_RSP, rsp + 8)
                                    mu.reg_write(UC_X86_REG_RAX, 0)
                                    ip = ra
                                    last_err_rip = 0
                                    err_repeat = 0
                                    continue
                            except UcError:
                                pass
                            break
                    else:
                        last_err_rip = rip
                        err_repeat = 0
                    ip = rip
                    continue

                try:
                    ra = struct.unpack(
                        "<Q", bytes(mu.mem_read(rsp, 8)))[0]
                except UcError:
                    break
                if ra < 0x1000:
                    break
                mu.reg_write(UC_X86_REG_RSP, rsp + 8)
                mu.reg_write(UC_X86_REG_RAX, 0)
                ip = ra
                api_count += 1
                last_err_rip = 0

            if rdata_writes and len(rdata_writes) >= len(rdata_dark):
                break

        elapsed = time.time() - t0
        resolved: dict[int, str] = {}
        for slot_va, orig_val in rdata_dark.items():
            try:
                new_val = struct.unpack(
                    "<Q", bytes(mu.mem_read(slot_va, 8)))[0]
            except UcError:
                continue
            if new_val == orig_val:
                continue
            hm_name = self.hook_map.get(new_val)
            if hm_name is None:
                hm_name = self.hook_map.get(new_val - 1)
            if isinstance(hm_name, str):
                resolved[slot_va] = hm_name
            elif isinstance(hm_name, dict) and hm_name.get("dll") != "?":
                resolved[slot_va] = f"{hm_name['dll']}!{hm_name['func']}"

        by_val: dict[int, list[int]] = {}
        for va, val in rdata_dark.items():
            by_val.setdefault(val, []).append(va)
        propagated = 0
        for val, slots in by_val.items():
            names = [resolved[s] for s in slots if s in resolved]
            if names:
                for s in slots:
                    if s not in resolved:
                        resolved[s] = names[0]
                        propagated += 1

        n_unique = len({resolved[s] for s in resolved})
        print(f"[*] EP init: {elapsed:.1f}s, {api_count} API calls, "
              f"{len(resolved)}/{len(rdata_dark)} .rdata slots resolved "
              f"({n_unique} unique APIs, {propagated} from ILT)")
        if resolved:
            seen = set()
            for va, name in sorted(resolved.items()):
                if name not in seen:
                    seen.add(name)
                    if len(seen) <= 10:
                        print(f"    [0x{va:x}] = {name}")
            if n_unique > 10:
                print(f"    ... +{n_unique - 10} more")

        if self._ep_missing_dlls:
            print(f"[!] EP init: {len(self._ep_missing_dlls)} module(s) "
                  f"NOT in win_exports.json — need manual export dump:")
            for dll in sorted(self._ep_missing_dlls):
                print(f"    {dll}  →  run: dumpbin /exports {dll}")
        return resolved

    # ─────── auto driver (scan + devirt all) ───────

    def run_auto(self, output: str, max_iter: int = 100,
                 ep_timeout: int = 120) -> bool:
        """Auto-scan all VM-protected functions and devirtualize them."""
        if not self._is_pe32plus:
            print("[!] PE32 (32-bit) not supported yet, only PE32+ (x64)")
            return False
        self.vm_sec_name = self._detect_vm_section()
        if not self.vm_sec_name:
            print("[!] No VM section detected"); return False
        print(f"[*] VM section: {self.vm_sec_name}")

        if ep_timeout > 0:
            ep_resolved = self.run_ep_init(timeout=ep_timeout)
        else:
            ep_resolved = {}
            print("[*] EP init: skipped (--no-ep)")
        self._ep_resolved = ep_resolved

        results: list[dict] = []
        done: set[int] = set()

        for iteration in range(1, max_iter + 1):
            candidates = self._scan_vm_functions()
            new = [f for f in candidates if f not in done]
            if not new:
                break
            print(f"\n{'═'*60}")
            print(f"  ITERATION {iteration}: {len(new)} new VM function(s)")
            print(f"{'═'*60}")

            for func_va in new:
                done.add(func_va)
                r = self._devirt_one(func_va)
                if r:
                    results.append(r)

        if not results:
            print("[!] No VM-protected functions found or decoded")
            return False

        print(f"\n{'═'*60}")
        print(f"  TOTAL: {len(results)} function(s) devirtualized")
        print(f"{'═'*60}")
        for r in results:
            nc = len(r["events"])
            print(f"  0x{r['func_va']:x}: {nc} calls, "
                  f"exit→0x{r['vm_exit']:x}")

        ok = self._generate_multi_pe(results, output)
        if ok:
            print(f"\n[OK] Patched PE -> {output}")
        return ok

    # ─────── trace ───────

    def _print_trace(self):
        print(f"\n{'─'*60}\n  CALL TRACE\n{'─'*60}")
        for ev in self.events:
            via = f"  via {ev['via']}" if ev["via"] else ""
            marker = ("  [MARKER]"
                      if self._is_marker_dll(ev["dll"]) else "")
            args = ", ".join(f"{r}=0x{ev['regs'][r]:x}"
                            for r in ("rcx", "rdx", "r8", "r9"))
            print(f"  #{ev['i']:2d} {ev['dll']}!{ev['func']}{via}{marker}")
            print(f"      {args}")

    # ─────── Phase 2: reconstruct ───────

    def _classify_delta(self, prev: dict, cur: dict, last_ev):
        ops = []
        prax = prev.get("rax")
        for rn in GP_REGS:
            if rn == "rsp":
                continue
            old, new = prev.get(rn, 0), cur[rn]
            if new == old:
                continue
            if Sentinel.is_clobber(new):
                continue
            if last_ev and prax is not None and new == prax:
                ops.append(("ret", rn, last_ev)); continue
            src = self._find_reg_src(rn, new, prev)
            if src:
                ops.append(("reg", rn, src)); continue
            if new in self.hook_map:
                ops.append(("iat", rn, self.hook_map[new])); continue
            if self.frame_rsp and 0 <= (new - self.frame_rsp) < self.frame_size:
                ops.append(("lea_rsp", rn, new - self.frame_rsp)); continue
            if self._is_data_addr(new):
                ops.append(("lea_data", rn, new)); continue
            ops.append(("imm", rn, new))
        return ops

    def _frame_delta(self, pf: dict, cf: dict) -> list[tuple]:
        shadow = 0x20
        cookie_off = self.frame_size - 8 if self.frame_size > 8 else 0
        scan = min(cookie_off, 0x200)
        writes, done = [], set()
        for o in range(shadow, scan, 8):
            k = ("q", o)
            cv, pv = cf.get(k), pf.get(k)
            if cv is not None and cv != pv:
                writes.append(("sq", o, cv & 0xFFFFFFFF))
                done.add(o); done.add(o + 4)
        for o in range(shadow, scan, 4):
            if o in done:
                continue
            k = ("d", o)
            cv, pv = cf.get(k), pf.get(k)
            if cv is not None and cv != pv:
                writes.append(("sd", o, cv))
        return writes

    def _reconstruct(self) -> list[str]:
        lines: list[str] = []
        prev = dict(self.pre_vm_regs) if self.pre_vm_regs else {}
        sentinel = 0xCCCCCCCC
        scan = min(self.frame_size, 0x200)
        pf = {("d", o): sentinel for o in range(0, scan, 4)}
        pf.update({("q", o): sentinel | (sentinel << 32) for o in range(0, scan, 8)})
        last_ev = None

        for ev in self.events:
            cur = ev["regs"]
            if self._is_marker_dll(ev["dll"]):
                prev = dict(cur); prev["rax"] = ev["ret"]
                pf = dict(ev["frame"]); last_ev = ev
                continue

            ops = self._classify_delta(prev, cur, last_ev)
            fwrites = self._frame_delta(pf, ev["frame"])

            for tag, rn, *rest in ops:
                if tag == "ret":
                    lines.append(f"mov {rn}, rax")
                elif tag == "reg":
                    lines.append(f"mov {rn}, {rest[0]}")
                elif tag == "iat":
                    info = rest[0]
                    lines.append(
                        f"mov {rn}, qword ptr [__iat_{info['sym']}__]")
                elif tag == "lea_rsp":
                    lines.append(f"lea {rn}, [rsp + 0x{rest[0]:x}]")
                elif tag == "lea_data":
                    lines.append(f"lea {rn}, [__data_0x{rest[0]:x}__]")
                elif tag == "imm":
                    val = rest[0]
                    if val >= 0xFFFFFFFF80000000:
                        lines.append(f"mov {R32[rn]}, 0x{val & 0xFFFFFFFF:x}")
                    elif val <= 0xFFFFFFFF:
                        lines.append(f"mov {R32[rn]}, 0x{val:x}")
                    else:
                        lines.append(f"mov {rn}, 0x{val:x}")

            for tag, off, val in fwrites:
                if tag == "sq" and val >= 0x80000000:
                    lines.append(f"mov dword ptr [rsp + 0x{off:x}], 0x{val:x}")
                else:
                    sz = "qword" if tag == "sq" else "dword"
                    lines.append(f"mov {sz} ptr [rsp + 0x{off:x}], 0x{val:x}")

            if ev["via"]:
                lines.append(f"call {ev['via']}")
            else:
                info = self.hook_map.get(ev["hook"])
                sym = info["sym"] if info else f"dark_{ev['i']}"
                lines.append(f"call qword ptr [__iat_{sym}__]")

            prev = dict(cur)
            prev["rax"] = ev["ret"]
            for rn in WIN64_VOLATILE:
                prev[rn] = Sentinel.clobber(rn, ev["i"])
            pf = dict(ev["frame"])
            last_ev = ev

        lines.append(f"jmp 0x{self.vm_exit_addr:x}")
        return lines

    def _resolve_asm(self, lines: list[str], base_va: int,
                     extra_iat: Optional[dict[str, int]] = None) -> list[str]:
        """Replace __iat_*__ / __data_*__ with [rip ± disp]."""
        iat_by_sym: dict[str, int] = {}
        for info in self.hook_map.values():
            if info["iat"]:
                iat_by_sym[f"__iat_{info['sym']}__"] = info["iat"]
        if extra_iat:
            for sym, va in extra_iat.items():
                iat_by_sym[f"__iat_{sym}__"] = va

        def _strip(ln: str) -> str:
            out = re.sub(r"__iat_[a-zA-Z0-9_]+__", "rip", ln)
            return re.sub(r"__data_0x[0-9a-fA-F]+__", "rip", out)

        sizes: list[int] = []
        for ln in lines:
            try:
                enc, _ = self.asm.ks.asm(_strip(ln), base_va + sum(sizes))
                sizes.append(len(enc))
            except KsError:
                sizes.append(7)

        def _rip(target: int, va: int, sz: int) -> str:
            d = target - (va + sz)
            return f"rip - 0x{-d:x}" if d < 0 else f"rip + 0x{d:x}"

        resolved: list[str] = []
        va = base_va
        for ln, sz in zip(lines, sizes):
            out = ln
            for sym, tgt in iat_by_sym.items():
                if sym in out:
                    out = out.replace(sym, _rip(tgt, va, sz))
            m = re.search(r"__data_(0x[0-9a-fA-F]+)__", out)
            if m:
                tgt = int(m.group(1), 16)
                out = out.replace(m.group(0), _rip(tgt, va, sz))
            resolved.append(out)
            va += sz
        return resolved

    # ─────── text output ───────

    def _print_asm(self, lines: list[str]):
        print(f"\n{'═'*60}\n  DEVIRTUALIZED CODE\n{'═'*60}")

        cs = self._code_section()
        ts = cs["va"]
        raw = cs["obj"].get_data()
        off = self.func_va - ts

        print("\n; --- prologue (native) ---")
        for insn in self.asm.disasm(raw[off:off + 256], self.func_va):
            print(f"  {insn.mnemonic:8s} {insn.op_str}")
            if insn.mnemonic == "jmp":
                break

        print("\n; --- devirtualized body ---")
        iat_by_sym = {v["sym"]: v for v in self.hook_map.values()}
        for ln in lines:
            display, comment = ln, ""
            def _ri(m):
                nonlocal comment
                sym = m.group(1)
                info = iat_by_sym.get(sym)
                if info:
                    comment = f"  ; {info['dll']}!{info['func']}"
                    if info["iat"]:
                        return f"0x{info['iat']:x}"
                    return f"[{info['func']}]"
                return m.group(0)
            display = re.sub(r"__iat_(.+?)__", _ri, display)
            display = re.sub(r"__data_(0x[0-9a-fA-F]+)__", r"\1", display)
            print(f"  {display}{comment}")
            comment = ""

        if self.vm_exit_addr:
            print("\n; --- epilogue (native) ---")
            eoff = self.vm_exit_addr - ts
            for insn in self.asm.disasm(raw[eoff:], self.vm_exit_addr):
                print(f"  {insn.mnemonic:8s} {insn.op_str}")
                if insn.mnemonic == "ret":
                    break

    # ─────── PE generation ───────

    def _build_new_imports(self, section_rva: int, code_size: int
                           ) -> tuple[bytes, dict[str, int], int]:
        """Build import data for dark APIs to embed in .devrt section.

        Returns (area_bytes, iat_va_map, new_import_dir_rva).
        """
        by_dll: OrderedDict[str, list] = OrderedDict()
        for imp in self._new_imports:
            by_dll.setdefault(imp["dll"], []).append(imp)

        area_start = (code_size + 0xF) & ~0xF
        buf = bytearray()

        iat_dll_off: dict[str, int] = {}
        iat_va_map: dict[str, int] = {}
        for dll, funcs in by_dll.items():
            iat_dll_off[dll] = len(buf)
            for imp in funcs:
                va = self.ib + section_rva + area_start + len(buf)
                iat_va_map[imp["sym"]] = va
                buf.extend(b"\x00" * 8)
            buf.extend(b"\x00" * 8)

        ilt_dll_off: dict[str, int] = {}
        for dll, funcs in by_dll.items():
            ilt_dll_off[dll] = len(buf)
            buf.extend(b"\x00" * (len(funcs) + 1) * 8)

        dll_name_rvas: dict[str, int] = {}
        hn_rvas: dict[tuple, int] = {}
        for dll, funcs in by_dll.items():
            dll_name_rvas[dll] = section_rva + area_start + len(buf)
            buf.extend(dll.encode("ascii") + b"\x00")
            if len(buf) % 2:
                buf.append(0)
            for imp in funcs:
                hn_rvas[(dll, imp["func"])] = section_rva + area_start + len(buf)
                buf.extend(struct.pack("<H", 0))
                buf.extend(imp["func"].encode("ascii") + b"\x00")
                if len(buf) % 2:
                    buf.append(0)

        for dll, funcs in by_dll.items():
            for i, imp in enumerate(funcs):
                rva = hn_rvas[(dll, imp["func"])]
                struct.pack_into("<Q", buf, iat_dll_off[dll] + i * 8, rva)
                struct.pack_into("<Q", buf, ilt_dll_off[dll] + i * 8, rva)

        desc_off = len(buf)
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for de in self.pe.DIRECTORY_ENTRY_IMPORT:
                buf.extend(struct.pack("<IIIII",
                                       de.struct.OriginalFirstThunk,
                                       de.struct.TimeDateStamp,
                                       de.struct.ForwarderChain,
                                       de.struct.Name,
                                       de.struct.FirstThunk))
        for dll in by_dll:
            buf.extend(struct.pack(
                "<IIIII",
                section_rva + area_start + ilt_dll_off[dll],
                0, 0,
                dll_name_rvas[dll],
                section_rva + area_start + iat_dll_off[dll]))
        buf.extend(b"\x00" * 20)

        return bytes(buf), iat_va_map, section_rva + area_start + desc_off

    def _generate_multi_pe(self, results: list[dict],
                           out_path: str) -> bool:
        """Generate patched PE with all devirtualized functions in .devrt.

        Key: devirtualized code calls through NEW IAT entries in .devrt
        (resolved by the Windows loader at startup), NOT through the old
        dark .rdata slots.  This lets IDA see proper import references.
        """
        fa = self.pe.OPTIONAL_HEADER.FileAlignment
        sa = self.pe.OPTIONAL_HEADER.SectionAlignment

        last_sec = self.pe.sections[-1]
        new_rva = last_sec.VirtualAddress + \
                  ((last_sec.Misc_VirtualSize + sa - 1) & ~(sa - 1))
        new_va = self.ib + new_rva

        merged_hook: dict[int, dict] = {}
        for r in results:
            merged_hook.update(r["hook_map_snapshot"])
        self.hook_map = merged_hook

        all_apis: OrderedDict[str, dict] = OrderedDict()
        for r in results:
            hm = r["hook_map_snapshot"]
            for ev in r["events"]:
                info = hm.get(ev["hook"])
                if not info:
                    continue
                sym = info["sym"]
                if sym in all_apis:
                    continue
                dll = info["dll"] if info["dll"] != "?" else "unknown.dll"
                all_apis[sym] = {
                    "dll": dll, "func": info["func"], "sym": sym}
        self._new_imports = list(all_apis.values())

        est_code = sum(len(r["asm_lines"]) * 10 for r in results)
        import_area, extra_iat, import_dir_rva = \
            self._build_new_imports(new_rva, est_code)

        func_code_list: list[tuple[dict, bytes, int]] = []
        cursor = 0
        for r in results:
            fva = new_va + cursor
            resolved = self._resolve_asm(r["asm_lines"], fva, extra_iat)
            try:
                code = self.asm.asm_lines(resolved, fva)
            except RuntimeError as e:
                print(f"[!] Assembly failed for 0x{r['func_va']:x}: {e}")
                continue
            func_code_list.append((r, code, cursor))
            cursor += (len(code) + 0xF) & ~0xF

        if not func_code_list:
            print("[!] No functions assembled")
            return False

        actual_code = cursor
        if actual_code != est_code:
            import_area, extra_iat, import_dir_rva = \
                self._build_new_imports(new_rva, actual_code)
            func_code_list = []
            cursor = 0
            for r in results:
                fva = new_va + cursor
                resolved = self._resolve_asm(
                    r["asm_lines"], fva, extra_iat)
                code = self.asm.asm_lines(resolved, fva)
                func_code_list.append((r, code, cursor))
                cursor += (len(code) + 0xF) & ~0xF

        section_data = bytearray()
        for _, code, offset in func_code_list:
            pad = offset - len(section_data)
            if pad > 0:
                section_data.extend(b"\x00" * pad)
            section_data.extend(code)

        code_aligned = (len(section_data) + 0xF) & ~0xF
        section_data.extend(b"\x00" * (code_aligned - len(section_data)))
        section_data.extend(import_area)
        vsize = len(section_data)

        n_imp = len(self._new_imports)
        print(f"\n[*] .devrt: {len(func_code_list)} function(s), "
              f"{vsize} bytes at VA 0x{new_va:x}, "
              f"{n_imp} new imports")
        for r, code, offset in func_code_list:
            fva = new_va + offset
            print(f"    0x{r['func_va']:x} → 0x{fva:x} ({len(code)} bytes)")

        with open(self.pe_path, "rb") as f:
            data = bytearray(f.read())

        raw_off = (len(data) + fa - 1) & ~(fa - 1)
        data.extend(b"\x00" * (raw_off - len(data)))
        raw_sz = (vsize + fa - 1) & ~(fa - 1)

        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        fh_off = pe_off + 4
        num_s = struct.unpack_from("<H", data, fh_off + 2)[0]
        opt_sz = struct.unpack_from("<H", data, fh_off + 16)[0]
        st_off = fh_off + 20 + opt_sz
        new_hdr = st_off + num_s * 40
        first_raw = min(s.PointerToRawData
                        for s in self.pe.sections if s.PointerToRawData)
        if new_hdr + 40 > first_raw:
            print("[!] No header space for new section")
            return False

        chars = DEVRT_CHARACTERISTICS | IMAGE_SCN_MEM_WRITE

        hdr = bytearray(40)
        hdr[0:7] = b".devrt\x00"
        struct.pack_into("<I", hdr, 8, vsize)
        struct.pack_into("<I", hdr, 12, new_rva)
        struct.pack_into("<I", hdr, 16, raw_sz)
        struct.pack_into("<I", hdr, 20, raw_off)
        struct.pack_into("<I", hdr, 36, chars)
        data[new_hdr:new_hdr + 40] = hdr

        struct.pack_into("<H", data, fh_off + 2, num_s + 1)
        new_img = new_rva + ((vsize + sa - 1) & ~(sa - 1))
        opt_off = fh_off + 20
        struct.pack_into("<I", data, opt_off + 56, new_img)
        struct.pack_into("<I", data, opt_off + 64, 0)

        cur_soh = struct.unpack_from("<I", data, opt_off + 60)[0]
        need_soh = ((new_hdr + 40 + fa - 1) & ~(fa - 1))
        if need_soh > cur_soh:
            struct.pack_into("<I", data, opt_off + 60, need_soh)

        if import_dir_rva is not None:
            n_old = len(self.pe.DIRECTORY_ENTRY_IMPORT) \
                if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT") else 0
            n_new = len(set(imp["dll"] for imp in self._new_imports))
            struct.pack_into("<I", data, opt_off + 120, import_dir_rva)
            struct.pack_into("<I", data, opt_off + 124,
                             (n_old + n_new + 1) * 20)

        patched = 0
        for r, code, offset in func_code_list:
            devrt_va = new_va + offset
            vm_info = r["vm_entry"]
            jmp_raw = self._va_to_raw(vm_info["jmp"])
            if jmp_raw is None:
                continue
            jmp_rel = devrt_va - (vm_info["jmp"] + 5)
            if not (-0x8000_0000 <= jmp_rel <= 0x7FFF_FFFF):
                print(f"[!] JMP rel32 overflow for 0x{r['func_va']:x}")
                continue
            data[jmp_raw] = 0xE9
            struct.pack_into("<i", data, jmp_raw + 1, jmp_rel)
            patched += 1

        n_rdata_fixed = self._patch_rdata_dark_slots(
            data, extra_iat, new_rva, section_data)

        if n_rdata_fixed:
            for s in self.pe.sections:
                nm = s.Name.decode("utf-8", "replace").rstrip("\x00")
                if nm == ".rdata":
                    rdata_hdr = st_off
                    for j in range(num_s):
                        sn = data[st_off + j * 40: st_off + j * 40 + 8]
                        if sn.rstrip(b"\x00") == b".rdata":
                            rdata_hdr = st_off + j * 40
                            old_ch = struct.unpack_from("<I", data,
                                                        rdata_hdr + 36)[0]
                            struct.pack_into("<I", data, rdata_hdr + 36,
                                             old_ch | IMAGE_SCN_MEM_WRITE)
                            break
                    break

        data.extend(bytearray(section_data) + bytearray(raw_sz - vsize))

        with open(out_path, "wb") as f:
            f.write(data)
        print(f"[*] Patched {patched} VM entry point(s), "
              f"{n_rdata_fixed} .rdata slots fixed")
        return True

    def _patch_rdata_dark_slots(self, data: bytearray,
                                extra_iat: dict[str, int],
                                devrt_rva: int,
                                section_data: bytearray) -> int:
        """Overwrite dark .rdata function pointers in the output PE.

        For identified APIs → write the new IAT slot address so that
        thunks/CRT code reads the correct import at runtime.
        For unidentified → zero out (IDA shows 0 instead of MEMORY[0xXXX]).
        """
        if not hasattr(self, "_rdata_dark_slots"):
            return 0
        iat_by_slot: dict[int, int] = {}
        for r_info in self.hook_map.values():
            if r_info["iat"] and r_info["dll"] != "?":
                iat_by_slot[r_info["iat"]] = r_info["iat"]
        for sym, iat_va in extra_iat.items():
            for info in self.hook_map.values():
                if info["sym"] == sym and info.get("iat"):
                    iat_by_slot[info["iat"]] = iat_va

        fixed = 0
        for slot_va, dark_val in self._rdata_dark_slots.items():
            raw = self._va_to_raw(slot_va)
            if raw is None or raw + 8 > len(data):
                continue
            if slot_va in iat_by_slot:
                new_iat_va = iat_by_slot[slot_va]
                new_iat_rva = new_iat_va - self.ib
                struct.pack_into("<Q", data, raw, new_iat_rva)
            else:
                struct.pack_into("<Q", data, raw, 0)
            fixed += 1
        return fixed

    def _generate_pe(self, asm_lines: list[str], out_path: str) -> bool:
        fa = self.pe.OPTIONAL_HEADER.FileAlignment
        sa = self.pe.OPTIONAL_HEADER.SectionAlignment

        last_sec = self.pe.sections[-1]
        new_rva = last_sec.VirtualAddress + \
                  ((last_sec.Misc_VirtualSize + sa - 1) & ~(sa - 1))
        new_va = self.ib + new_rva

        extra_iat: dict[str, int] = {}
        import_area = b""
        import_dir_rva: Optional[int] = None

        if self._new_imports:
            est_resolved = self._resolve_asm(asm_lines, new_va)
            try:
                est_code = self.asm.asm_lines(est_resolved, new_va)
            except Exception:
                est_code = b"\x00" * (len(asm_lines) * 8)
            import_area, extra_iat, import_dir_rva = \
                self._build_new_imports(new_rva, len(est_code))

        resolved = self._resolve_asm(asm_lines, new_va, extra_iat)
        try:
            code = self.asm.asm_lines(resolved, new_va)
        except RuntimeError as e:
            print(f"[!] Assembly failed: {e}")
            return False

        if self._new_imports and len(code) != len(est_code):
            import_area, extra_iat, import_dir_rva = \
                self._build_new_imports(new_rva, len(code))
            resolved = self._resolve_asm(asm_lines, new_va, extra_iat)
            code = self.asm.asm_lines(resolved, new_va)

        code_aligned = (len(code) + 0xF) & ~0xF
        section_data = bytearray(code)
        section_data.extend(b"\x00" * (code_aligned - len(code)))
        section_data.extend(import_area)
        vsize = len(section_data)

        print(f"\n[*] Assembled {len(code)} bytes at VA 0x{new_va:x}")
        print("[*] .devrt disassembly:")
        for insn in self.asm.disasm(code, new_va):
            print(f"    0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}")

        with open(self.pe_path, "rb") as f:
            data = bytearray(f.read())

        raw_off = (len(data) + fa - 1) & ~(fa - 1)
        data.extend(b"\x00" * (raw_off - len(data)))
        raw_sz = (vsize + fa - 1) & ~(fa - 1)

        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        fh_off = pe_off + 4
        num_s = struct.unpack_from("<H", data, fh_off + 2)[0]
        opt_sz = struct.unpack_from("<H", data, fh_off + 16)[0]
        st_off = fh_off + 20 + opt_sz
        new_hdr = st_off + num_s * 40
        first_raw = min(s.PointerToRawData
                        for s in self.pe.sections if s.PointerToRawData)
        if new_hdr + 40 > first_raw:
            print("[!] No header space for new section")
            return False

        chars = DEVRT_CHARACTERISTICS
        if self._new_imports:
            chars |= IMAGE_SCN_MEM_WRITE

        hdr = bytearray(40)
        hdr[0:7] = b".devrt\x00"
        struct.pack_into("<I", hdr, 8, vsize)
        struct.pack_into("<I", hdr, 12, new_rva)
        struct.pack_into("<I", hdr, 16, raw_sz)
        struct.pack_into("<I", hdr, 20, raw_off)
        struct.pack_into("<I", hdr, 36, chars)
        data[new_hdr:new_hdr + 40] = hdr

        struct.pack_into("<H", data, fh_off + 2, num_s + 1)
        new_img = new_rva + ((vsize + sa - 1) & ~(sa - 1))
        opt_off = fh_off + 20
        struct.pack_into("<I", data, opt_off + 56, new_img)
        struct.pack_into("<I", data, opt_off + 64, 0)

        cur_soh = struct.unpack_from("<I", data, opt_off + 60)[0]
        need_soh = ((new_hdr + 40 + fa - 1) & ~(fa - 1))
        if need_soh > cur_soh:
            struct.pack_into("<I", data, opt_off + 60, need_soh)

        if import_dir_rva is not None:
            n_old = len(self.pe.DIRECTORY_ENTRY_IMPORT) \
                if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT") else 0
            n_new = len(set(imp["dll"] for imp in self._new_imports))
            imp_dir_size = (n_old + n_new + 1) * 20
            struct.pack_into("<I", data, opt_off + 120, import_dir_rva)
            struct.pack_into("<I", data, opt_off + 124, imp_dir_size)

        vm_info = self._find_vm_entry(self.func_va)
        jmp_raw = self._va_to_raw(vm_info["jmp"])
        jmp_rel = new_va - (vm_info["jmp"] + 5)
        if not (-0x8000_0000 <= jmp_rel <= 0x7FFF_FFFF):
            print(f"[!] JMP rel32 overflow: offset 0x{jmp_rel:x} doesn't fit")
            return False
        data[jmp_raw] = 0xE9
        struct.pack_into("<i", data, jmp_raw + 1, jmp_rel)

        exit_raw = self._va_to_raw(self.vm_exit_addr)
        if exit_raw:
            nop_end = self._find_epilogue_start()
            nop_len = max(0, (nop_end - self.vm_exit_addr)
                          if nop_end and nop_end > self.vm_exit_addr else 0)
            for i in range(nop_len):
                if exit_raw + i < len(data):
                    data[exit_raw + i] = 0x90

        data.extend(bytearray(section_data) + bytearray(raw_sz - vsize))

        with open(out_path, "wb") as f:
            f.write(data)
        return True

    def _find_epilogue_start(self) -> Optional[int]:
        """Find where the real epilogue begins after vm_exit_addr
        (skip any leftover garbage / marker bytes)."""
        cs = self._code_section()
        ts, sec = cs["va"], cs["obj"]
        off = self.vm_exit_addr - ts
        raw = sec.get_data()[off:off + 32]
        for insn in self.asm.disasm(raw, self.vm_exit_addr):
            if insn.mnemonic in ("mov", "xor", "cmp", "add", "sub",
                                 "pop", "push", "ret", "lea"):
                if "rsp" in insn.op_str or insn.mnemonic in ("pop", "ret"):
                    return insn.address
        return None


# ═══════════════════════════ CLI ═══════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        prog="vm_devirt",
        description=(
            "Generic x86-64 PE VM devirtualizer. Works against Themida, "
            "VMProtect, Code Virtualizer, WinLicense and similar protectors "
            "by emulating the VM with Unicorn and diffing register / stack "
            "state across call boundaries to reconstruct native code."
        ),
    )
    ap.add_argument("pe", help="VM-protected PE file (PE32+, x86-64)")
    ap.add_argument("func_va", nargs="?", default=None,
                    help="Function VA (hex). Omit to scan everything with --auto.")
    ap.add_argument("-o", "--output",
                    help="Output patched PE path (defaults to <pe>-devirt.bin)")
    ap.add_argument("--auto", action="store_true",
                    help="Auto-scan and devirtualize every VM-protected function")
    ap.add_argument("--max-iter", type=int, default=100,
                    help="Max scan iterations for --auto (default 100)")
    ap.add_argument("--ep-timeout", type=int, default=120,
                    help="EP init emulation timeout in seconds (default 120)")
    ap.add_argument("--no-ep", action="store_true",
                    help="Skip EP init emulation (faster, loses API names)")
    args = ap.parse_args()

    d = VMDevirtualizer(args.pe)

    if args.auto or args.func_va is None:
        out = args.output or args.pe.replace(".bin", "-devirt.bin")
        if out == args.pe:
            out = args.pe + ".devirt"
        d.run_auto(out, max_iter=args.max_iter,
                   ep_timeout=0 if args.no_ep else args.ep_timeout)
    else:
        d.run(int(args.func_va, 16), output=args.output)


if __name__ == "__main__":
    main()
