r"""[AUDIT: read-only] elf_checksec — enumerasi mitigasi binary ELF
(Linux) dari header + tabel dinamis: NX (PT_GNU_STACK), PIE (e_type/
PT_INTERP/DF_1_PIE), RELRO (PT_GNU_RELRO + BIND_NOW), stack canary
(simbol __stack_chk_* di dynsym) — analog tools/pe_mitigation_scan.py
utk PE.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/performing-binary-exploitation-analysis' (antrean
SKILL-PORT-QUEUE #0780; atribusi konsep, lisensi sumber Apache-2.0).
Skill sumber = alur eksploitasi live (pwntools/ROPgadget/GDB — TIDAK
di-port; target hanya lab berizin); INTI DETERMINISTIK-nya adalah
tahap "checksec" (langkah 2 skill): fakta header yang bisa dibaca
OFFLINE tanpa mengeksekusi binary. Dibangun FROM SCRATCH TANPA kode
sumber itu — parser ELF ditulis dari spesifikasi publik (System V
ABI: refspecs.linuxfoundation.org/ELF/x86_64-abi-0.99.pdf, "man 5
elf").

Ranah tool tetangga ditulis eksplisit:
  - pe_mitigation_scan : mitigasi binary WINDOWS (PE: DEP/ASLR/CFG);
    tool ini sisi ELF-nya — vocab verdict disamakan (MITIGATED/
    PARTIAL/WEAK/INCONCLUSIVE) supaya gate CI sama;
  - binary_strings_surface : provenance/section ELF, bukan mitigasi;
  - packer_scan : entropi PE (bukan ELF).

Mitigasi yang dinilai (fakta header, bukan klaim kerentanan):
  - NX     : PT_GNU_STACK ada dan TANPA bit PF_X; GNU_STACK absen =
             NX mati (kernel lama mengeksekusi stack — perilaku
             checksec standar); dicatat sbg catatan nx-absent.
  - PIE    : ET_DYN + (PT_INTERP ATAU DF_1_PIE di DT_FLAGS_1);
             ET_EXEC = no-PIE; ET_DYN tanpa interp/tanpa DF_1_PIE =
             shared object -> INCONCLUSIVE (PIE tidak berlaku).
  - RELRO  : PT_GNU_RELRO absen = none; ada tanpa BIND_NOW
             (DT_FLAGS 0x8 / DT_FLAGS_1 0x1 / DT_BIND_NOW) = partial;
             keduanya = full. RELRO_FULL = mitigasi inti.
  - CANARY : simbol __stack_chk_fail/__stack_chk_guard/
             __stack_chk_copy/__intel_security_cookie di dynsym
             (dinamis) ATAU string simbol di file (statis — metode
             dicatat). PENENTUAN "absen" hanya dilakukan bila
             enumerasi simbol sukses — tanpa DT_HASH/DT_GNU_HASH =>
             canary None + INCONCLUSIVE (fail-closed: tak bisa
             enumerate BUKAN "tidak ada").

Lapisan info TIDAK memengaruhi verdict (anti-FP, cf. catatan NO_SEH
di pe_mitigation_scan): fortify_hint (simbol *_chk glibc),
rpath/runpath (DT_RPATH/DT_RUNPATH — permukaan hijack library).

Input -> mekanisme -> output:
  - Input   : path file ELF (satu atau banyak) + --require (gate,
              opsional) + --out.
  - Mekanisme: parse e_ident/ehdr -> program headers -> PT_DYNAMIC
              -> dynamic entries -> enumerasi nama dynsym (count
              dari nchain DT_HASH atau walk chain DT_GNU_HASH);
              vaddr->offset via PT_LOAD.
  - Output  : JSON {schema, require, files: [...], summary}.

Fail-closed:
  - bukan ELF / header terpangkas / ei_class-ei_data tak dikenal /
    e_phentsize salah / overrun tabel -> verdict INCONCLUSIVE +
    reason; exit 2 (pola pe_mitigation_scan);
  - --require dgn mitigasi tak dikenal -> exit 2;
  - gate: file terurai dgn mitigasi inti hilang -> exit 1.

Pemakaian:
  python tools/elf_checksec.py ./app.bin
  python tools/elf_checksec.py ./app.bin --require NX,PIE,RELRO_FULL,CANARY
Exit: 0 semua lolos; 1 gate gagal; 2 input error / file tak terurai.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

SCHEMA = "cyphron.elf-checksec/1"
MAX_FILE_BYTES = 512 * 1024 * 1024  # 512 MB — biner besar tetap diurai

# Mitigasi inti (vocab disamakan dgn pe_mitigation_scan).
CORE_MITIGATIONS = ("NX", "PIE", "RELRO_FULL", "CANARY")

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1

ET_EXEC = 2
ET_DYN = 3

DT_NULL = 0
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RPATH = 15
DT_BIND_NOW = 24
DT_RUNPATH = 29
DT_FLAGS = 30
DT_GNU_HASH = 0x6FFFFEF5
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000

CANARY_SYMBOLS = (b"__stack_chk_fail", b"__stack_chk_guard",
                  b"__stack_chk_copy", b"__intel_security_cookie")
FORTIFY_SUFFIX = b"_chk"

MACHINE_NAMES = {0x03: "x86", 0x08: "mips", 0x28: "arm",
                 0x3E: "x86-64", 0xB7: "aarch64", 0xF3: "riscv"}

MAX_SYMBOLS = 10_000_000  # pelindung tabel patologis
MAX_NAME_LEN = 512

ELF64_HEADER = "HHIQQQIHHHHHH"   # setelah e_ident[16]
ELF32_HEADER = "HHIIIIIHHHHHH"
ELF64_PHDR = "IIQQQQQQ"          # type, flags, offset, vaddr, paddr,
ELF32_PHDR = "IIIIIIII"          # filesz, memsz, align (flags idx 6)
ELF64_SYM = 24                   # I st_name + B B H + Q Q
ELF32_SYM = 16                   # I st_name + I I + B B H


class ELFFail(ValueError):
    """Binary tidak terurai -> INCONCLUSIVE."""


def _name(machine: int) -> str:
    return MACHINE_NAMES.get(machine, f"0x{machine:x}")


def _vaddr_to_off(segments: list[dict], vaddr: int) -> int | None:
    """Translasi vaddr -> offset file via PT_LOAD (bound p_filesz)."""
    for seg in segments:
        if seg["type"] != PT_LOAD:
            continue
        if seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
            return seg["offset"] + (vaddr - seg["vaddr"])
    return None


def _read_cstr(data: bytes, off: int) -> bytes:
    """C-string di offset; pangkas di MAX_NAME_LEN (fail-closed)."""
    if off < 0 or off >= len(data):
        return b""
    end = data.find(b"\x00", off, off + MAX_NAME_LEN)
    if end < 0:
        return data[off:off + MAX_NAME_LEN]
    return data[off:end]


def _parse_dynamic(data: bytes, seg: dict, prefix: str, is64: bool
                   ) -> dict[int, int]:
    """Dynamic entries -> {tag: value} (nilai pertama per tag menang)."""
    ent_fmt = prefix + ("QQ" if is64 else "II")
    ent_size = struct.calcsize(ent_fmt)
    mask = (1 << 64) - 1 if is64 else 0xFFFFFFFF
    entries: dict[int, int] = {}
    base = seg["offset"]
    limit = seg["offset"] + seg["filesz"]
    if limit > len(data):
        limit = len(data)
    while base + ent_size <= limit:
        tag, val = struct.unpack_from(ent_fmt, data, base)
        tag &= mask
        if tag == DT_NULL:
            break
        entries.setdefault(tag, val & mask)
        base += ent_size
    return entries


def _symbol_count(data: bytes, segments: list[dict],
                  entries: dict[int, int], prefix: str, is64: bool
                  ) -> int | None:
    """Jumlah simbol dynsym: DT_HASH.nchain ATAU walk DT_GNU_HASH."""
    if DT_HASH in entries:
        off = _vaddr_to_off(segments, entries[DT_HASH])
        if off is None or off + 8 > len(data):
            raise ELFFail("DT_HASH tidak bisa dialamatkan / terpangkas")
        _nbucket, nchain = struct.unpack(prefix + "II",
                                         data[off:off + 8])
        if nchain > MAX_SYMBOLS:
            raise ELFFail(f"nchain DT_HASH tak wajar: {nchain}")
        return nchain
    if DT_GNU_HASH in entries:
        off = _vaddr_to_off(segments, entries[DT_GNU_HASH])
        if off is None or off + 16 > len(data):
            raise ELFFail("DT_GNU_HASH tidak bisa dialamatkan")
        nbucket, symoffset, bloom_size, _shift = struct.unpack(
            prefix + "IIII", data[off:off + 16])
        buckets_off = off + 16 + bloom_size * (8 if is64 else 4)
        buckets_end = buckets_off + nbucket * 4
        if nbucket == 0 or buckets_end > len(data):
            raise ELFFail("tabel bucket DT_GNU_HASH tak wajar")
        buckets = struct.unpack(prefix + f"{nbucket}I",
                                data[buckets_off:buckets_end])
        max_idx = max(buckets)
        if max_idx < symoffset:
            return symoffset  # semua bucket kosong
        sym_off = _vaddr_to_off(segments, entries[DT_SYMTAB])
        if sym_off is None:
            raise ELFFail("DT_SYMTAB tidak bisa dialamatkan")
        sym_entsize = ELF64_SYM if is64 else ELF32_SYM
        chain_base = sym_off + symoffset * sym_entsize
        idx = max_idx
        while idx < MAX_SYMBOLS:
            c_off = chain_base + (idx - symoffset) * 4
            if c_off + 4 > len(data):
                raise ELFFail("chain DT_GNU_HASH overrun")
            (chain,) = struct.unpack(prefix + "I", data[c_off:c_off + 4])
            if chain & 1:
                return idx + 1
            idx += 1
        raise ELFFail("chain DT_GNU_HASH tanpa terminator")
    return None


def _dynsym_names(data: bytes, segments: list[dict],
                  entries: dict[int, int], prefix: str, is64: bool
                  ) -> list[bytes] | None:
    """Daftar nama simbol dinamis — None bila TIDAK BISA dienumerate
    (fail-closed; berbeda dari daftar kosong)."""
    if DT_SYMTAB not in entries or DT_STRTAB not in entries:
        return None
    count = _symbol_count(data, segments, entries, prefix, is64)
    if count is None:
        return None
    sym_off = _vaddr_to_off(segments, entries[DT_SYMTAB])
    str_off = _vaddr_to_off(segments, entries[DT_STRTAB])
    if sym_off is None or str_off is None:
        raise ELFFail("DT_SYMTAB/DT_STRTAB tidak bisa dialamatkan")
    sym_entsize = ELF64_SYM if is64 else ELF32_SYM
    names: list[bytes] = []
    for i in range(count):
        base = sym_off + i * sym_entsize
        if base + 4 > len(data):
            break  # tabel terpangkas — pakai yang terbaca saja
        (st_name,) = struct.unpack_from(prefix + "I", data, base)
        if st_name == 0:
            continue
        names.append(_read_cstr(data, str_off + st_name))
    return names


def assess_elf(data: bytes) -> dict:
    """Fakta mitigasi dari byte ELF (murni deterministik)."""
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ELFFail("bukan file ELF (magic \\x7fELF tidak ada)")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise ELFFail(f"ei_class tak dikenal: {ei_class}")
    if ei_data not in (1, 2):
        raise ELFFail(f"ei_data tak dikenal: {ei_data}")
    is64 = ei_class == 2
    prefix = "<" if ei_data == 1 else ">"

    hdr_fmt = prefix + (ELF64_HEADER if is64 else ELF32_HEADER)
    if len(data) < 16 + struct.calcsize(hdr_fmt):
        raise ELFFail("ELF header terpangkas")
    (e_type, e_machine, _ver, _entry, e_phoff, _shoff, _flags, _ehsize,
     e_phentsize, e_phnum, *_rest) = struct.unpack_from(hdr_fmt, data, 16)

    ph_fmt = prefix + (ELF64_PHDR if is64 else ELF32_PHDR)
    if e_phentsize != struct.calcsize(ph_fmt):
        raise ELFFail(f"e_phentsize {e_phentsize} != ukuran format kelas "
                      f"{struct.calcsize(ph_fmt)}")
    segments: list[dict] = []
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        if base + e_phentsize > len(data):
            raise ELFFail("tabel program header overrun")
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, _mem, _al \
                = struct.unpack_from(ph_fmt, data, base)
        else:
            (p_type, p_offset, p_vaddr, _pa, p_filesz, _mem, p_flags,
             _al) = struct.unpack_from(ph_fmt, data, base)
        segments.append({"type": p_type, "flags": p_flags,
                         "offset": p_offset, "vaddr": p_vaddr,
                         "filesz": p_filesz})

    notes: list[str] = []

    # --- NX -----------------------------------------------------------
    gnu_stack = [s for s in segments if s["type"] == PT_GNU_STACK]
    if gnu_stack:
        nx = not (gnu_stack[0]["flags"] & PF_X)
    else:
        nx = False
        notes.append("PT_GNU_STACK absen — stack executable pada "
                     "kernel lama (NX dianggap mati, perilaku checksec "
                     "standar)")

    # --- dynamic entries -----------------------------------------------
    dyn = next((s for s in segments if s["type"] == PT_DYNAMIC), None)
    entries: dict[int, int] = {}
    if dyn is not None:
        entries = _parse_dynamic(data, dyn, prefix, is64)
    flags = entries.get(DT_FLAGS, 0)
    flags1 = entries.get(DT_FLAGS_1, 0)

    # --- PIE / shared object -------------------------------------------
    has_interp = any(s["type"] == PT_INTERP for s in segments)
    if e_type == ET_DYN and (has_interp or (flags1 & DF_1_PIE)):
        pie = True
    else:
        pie = False
    dso = e_type == ET_DYN and not pie

    # --- RELRO -----------------------------------------------------------
    relro_present = any(s["type"] == PT_GNU_RELRO for s in segments)
    bind_now = bool(flags & DF_BIND_NOW) or bool(flags1 & DF_1_NOW) \
        or DT_BIND_NOW in entries
    if not relro_present:
        relro = "none"
    elif bind_now:
        relro = "full"
    else:
        relro = "partial"

    # --- CANARY ------------------------------------------------------------
    canary: bool | None = None
    fortify = False
    if dyn is not None:
        names = _dynsym_names(data, segments, entries, prefix, is64)
        if names is None:
            canary = None
            notes.append("dynsym tidak bisa dienumerate (tanpa "
                         "DT_HASH/DT_GNU_HASH) — status canary tidak "
                         "bisa dipastikan (fail-closed)")
        else:
            canary = any(n in CANARY_SYMBOLS for n in names)
            fortify = any(n.endswith(FORTIFY_SUFFIX)
                          and not n.startswith(b"__stack_chk")
                          for n in names)
    else:
        notes.append("tanpa PT_DYNAMIC (binari statis) — canary dinilai "
                     "dari pencarian string simbol di seluruh file")
        hit = any(sig in data for sig in CANARY_SYMBOLS)
        canary = hit
        fortify = b"__printf_chk" in data or b"__sprintf_chk" in data
        if not hit:
            notes.append("string simbol canary tidak ditemukan di file "
                         "statis — canary dianggap absen (metode: "
                         "pencarian byte, bukan enumerasi simbol)")

    mitigations: dict[str, bool | None] = {
        "NX": nx, "PIE": pie, "RELRO_FULL": relro == "full",
        "CANARY": canary}
    core_missing = [m for m in CORE_MITIGATIONS if not mitigations.get(m)]

    if dso:
        verdict = "INCONCLUSIVE"
        reason = ("shared object (ET_DYN tanpa PT_INTERP/DF_1_PIE) — "
                  "PIE tidak berlaku; nilai mitigasi tetap dilaporkan "
                  "sebagai fakta")
    elif canary is None:
        verdict = "INCONCLUSIVE"
        reason = "status canary tak bisa dipastikan (fail-closed)"
    elif not core_missing:
        verdict = "MITIGATED"
        reason = None
    elif not nx or not pie:
        verdict = "WEAK"
        reason = None
    else:
        verdict = "PARTIAL"
        reason = None

    for tag_val, label in ((DT_RPATH, "DT_RPATH"),
                           (DT_RUNPATH, "DT_RUNPATH")):
        if tag_val in entries:
            notes.append(f"{label} ter-set — jalur pencarian library "
                         "disematkan di binary (permukaan hijack "
                         "library, info bukan mitigasi)")

    return {
        "etype": e_type, "machine": _name(e_machine),
        "elf_class": 64 if is64 else 32,
        "endian": "le" if ei_data == 1 else "be",
        "relro_level": relro,
        "mitigations": mitigations,
        "fortify_hint": fortify,
        "notes": notes,
        "core_missing": core_missing,
        "verdict": verdict,
        "reason": reason,
    }


def scan_file(path: Path) -> dict:
    """Scan satu file -> hasil JSON (INCONCLUSIVE bila tak terurai)."""
    result: dict = {"file": str(path), "verdict": "INCONCLUSIVE",
                    "reason": None}
    try:
        data = path.read_bytes()
    except OSError as exc:
        result["reason"] = f"tidak bisa dibaca: {exc}"
        return result
    result["size"] = len(data)
    result["sha256"] = hashlib.sha256(data).hexdigest()
    if len(data) > MAX_FILE_BYTES:
        result["reason"] = (f"file melebihi batas {MAX_FILE_BYTES} "
                            "byte — tidak diurai")
        return result
    try:
        result.update(assess_elf(data))
    except ELFFail as exc:
        result["reason"] = str(exc)
        result["verdict"] = "INCONCLUSIVE"
    return result


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Enumerasi mitigasi binary ELF (NX/PIE/RELRO/"
                    "canary) dari header — read-only, nol jaringan. "
                    "Analog pe_mitigation_scan utk PE.")
    ap.add_argument("files", nargs="+", help="path binary ELF")
    ap.add_argument("--require", default="",
                    help="gate: daftar mitigasi wajib, pisah koma "
                         "(NX,PIE,RELRO_FULL,CANARY) — exit 1 bila "
                         "ada yang hilang pada file yang terurai")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)

    required = [r.strip().upper() for r in args.require.split(",")
                if r.strip()]
    unknown = [r for r in required if r not in CORE_MITIGATIONS]
    if unknown:
        print(f"ERROR: mitigasi tidak dikenal di --require: "
              f"{','.join(unknown)} (pilihan: "
              f"{','.join(CORE_MITIGATIONS)})", file=sys.stderr)
        return 2

    results = [scan_file(Path(f)) for f in args.files]
    inconclusive = [r for r in results if r["verdict"] == "INCONCLUSIVE"]
    gate_fail = [
        {"file": r["file"],
         "missing": [m for m in required if not r["mitigations"].get(m)]}
        for r in results
        if r["verdict"] != "INCONCLUSIVE" and required
        and [m for m in required if not r["mitigations"].get(m)]
    ]
    summary = {
        "total": len(results),
        "mitigated": sum(1 for r in results
                         if r["verdict"] == "MITIGATED"),
        "partial": sum(1 for r in results
                       if r["verdict"] == "PARTIAL"),
        "weak": sum(1 for r in results if r["verdict"] == "WEAK"),
        "inconclusive": len(inconclusive),
    }
    out = {"schema": SCHEMA, "require": required, "files": results,
           "summary": summary}

    text = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)

    if inconclusive:
        for r in inconclusive:
            print(f"ERROR: {r['file']}: {r.get('reason')}",
                  file=sys.stderr)
        return 2
    if gate_fail:
        for g in gate_fail:
            print(f"GATE GAGAL: {g['file']}: hilang "
                  f"{','.join(g['missing'])}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
