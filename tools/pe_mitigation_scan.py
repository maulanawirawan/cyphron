"""[SAFETY: read-only] pe_mitigation_scan — verifikasi mitigasi biner
Windows (DEP/ASLR/CFG/SEH) dari header PE.

Mengisi antrean port SKILL-PORT-QUEUE #0131 (sumber SnailSploit/
Claude-Red skill 'offensive-windows-mitigations'; atribusi ide). Skill
sumber mengajarkan: SEBELUM uji eksploitasi, verifikasi dulu mitigasi
per-biner (padanan dumpbin: "NX compatible", "Dynamic base", "High
Entropy Virtual Addresses", "Guard: CF"). Tool ini menyediakan
sisi defensifnya: memeriksa apakah biner memang dikompilasi dengan
mitigasi yang diklaim — berguna untuk (a) memastikan target lab
benar-benar menguji jalur bypass, (b) inventaris perangkat lunak yang
belum di-hardening. Ditulis from scratch dari spesifikasi publik
PE/COFF Microsoft (PE Format, winnt.h IMAGE_OPTIONAL_HEADER) — TANPA
menyalin kode dari repo sumber. Lisensi cyphron: PolyForm NC.

Yang dicek (bit DllCharacteristics, offset 70 optional header — sama
untuk PE32 dan PE32+):
  - DEP   : 0x0100 IMAGE_DLLCHARACTERISTICS_NX_COMPAT
  - ASLR  : 0x0040 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
  - HEVA  : 0x0020 IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            (hanya bermakna bersama ASLR)
  - CFG   : 0x4000 IMAGE_DLLCHARACTERISTICS_GUARD_CF
            (dukungan: entri data-directory index 10 / Load Config)
  - NO_SEH: 0x0400 IMAGE_DLLCHARACTERISTICS_NO_SEH (opt-in; tidak ada
            bit ini NORMAL, bukan kelemahan — dilaporkan sebagai info)

Verdict per file (fail-closed):
  - INCONCLUSIVE : file tak ada / bukan PE / header terpotong — TIDAK
    boleh dihitung lemah maupun aman.
  - MITIGATED    : DEP + ASLR + CFG semua ada.
  - PARTIAL      : ada sebagian mitigasi inti.
  - WEAK         : DEP atau ASLR tidak ada (dasar hardening hilang).

Exit: 0 = semua file terurai & (bila --require) lolos; 1 = gagal gate
--require; 2 = input error / ada file INCONCLUSIVE.

Pemakaian:
  python tools/pe_mitigation_scan.py biner.exe dll.dll --out pe.json
  python tools/pe_mitigation_scan.py target.exe --require DEP,ASLR,CFG
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

SCHEMA = "cyphron.pe-mitigation-scan/1"
MAX_FILE_BYTES = 512 * 1024 * 1024  # 512 MB — biner besar tetap diurai

# bit DllCharacteristics -> (id mitigasi, deskripsi)
BIT_DEP = 0x0100
BIT_ASLR = 0x0040
BIT_HEVA = 0x0020
BIT_CFG = 0x4000
BIT_NO_SEH = 0x0400

CORE_MITIGATIONS = ("DEP", "ASLR", "CFG")
MITIGATION_BITS = {
    "DEP": BIT_DEP,
    "ASLR": BIT_ASLR,
    "HEVA": BIT_HEVA,
    "CFG": BIT_CFG,
    "NO_SEH": BIT_NO_SEH,
}


class PEFail(Exception):
    """Header PE tidak bisa diurai — fail-closed."""


def parse_dll_characteristics(data: bytes) -> dict:
    """Ambil field minimum untuk mitigasi: magic optional header,
    DllCharacteristics (offset 70), dan data-directory index 10
    (Load Config, bukti pendukung CFG). Error eksplisit (fail-closed).

    Layout dirujuk dari spesifikasi PE/COFF Microsoft — offset
    DllCharacteristics sama (70) untuk PE32 dan PE32+ karena PE32+
    menghapus BaseOfData (4B) tapi memperbesar ImageBase (+4B).
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFail("bukan DOS/PE (magic MZ tidak ada)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data) \
            or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEFail("signature PE tidak valid")
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    if opt_size < 72 or opt + opt_size > len(data):
        raise PEFail("optional header terlalu pendek (tanpa "
                     "DllCharacteristics)")
    opt_magic = struct.unpack_from("<H", data, opt)[0]
    if opt_magic not in (0x10B, 0x20B):
        raise PEFail(f"optional header magic tak dikenal: {opt_magic:#x}")

    dll_chars = struct.unpack_from("<H", data, opt + 70)[0]

    # data directory: PE32 count@opt+92 base@opt+96; PE32+ count@opt+108
    # base@opt+112. Load Config = index 10.
    load_config_present = None  # None = tidak bisa dipastikan
    dd_count_off, dd_base_off = (108, 112) if opt_magic == 0x20B \
        else (92, 96)
    if dd_base_off + 8 * 11 <= opt + opt_size and dd_count_off + 4 <= \
            len(data):
        dd_count = struct.unpack_from("<I", data, opt + dd_count_off)[0]
        if dd_count > 10:
            rva, size = struct.unpack_from(
                "<II", data, opt + dd_base_off + 8 * 10)
            load_config_present = rva != 0 and size != 0

    return {
        "machine": machine,
        "opt_magic": opt_magic,
        "pe32plus": opt_magic == 0x20B,
        "dll_characteristics": dll_chars,
        "load_config_present": load_config_present,
    }


def assess(pe: dict) -> dict:
    """Dari field PE -> status mitigasi + verdict (fail-closed)."""
    bits = pe["dll_characteristics"]
    mitigations = {mid: bool(bits & bit)
                   for mid, bit in MITIGATION_BITS.items()}
    core_missing = [m for m in CORE_MITIGATIONS if not mitigations[m]]

    if core_missing == []:
        verdict = "MITIGATED"
    elif not mitigations["DEP"] or not mitigations["ASLR"]:
        verdict = "WEAK"
    else:
        verdict = "PARTIAL"

    notes: list[str] = []
    if mitigations["HEVA"] and not mitigations["ASLR"]:
        notes.append("HEVA ter-set tanpa ASLR — tidak bermakna")
    if mitigations["CFG"]:
        lcp = pe.get("load_config_present")
        if lcp is False:
            notes.append("bit CFG ter-set tapi Load Config directory "
                         "tidak ada — klaim CFG meragukan")
        elif lcp is None:
            notes.append("Load Config tidak bisa dipastikan dari "
                         "header — klaim CFG hanya dari bit")
    # NO_SEH tidak ada = normal; hanya dicatat bila ada (hardening
    # tambahan) supaya laporan tidak jadi bom false-positive.
    return {"mitigations": mitigations, "core_missing": core_missing,
            "verdict": verdict, "notes": notes}


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
        pe = parse_dll_characteristics(data)
    except PEFail as exc:
        result["reason"] = str(exc)
        return result
    result["machine"] = f"0x{pe['machine']:04x}"
    result["pe32plus"] = pe["pe32plus"]
    result["dll_characteristics"] = f"0x{pe['dll_characteristics']:04x}"
    result.update(assess(pe))
    return result


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Verifikasi mitigasi biner Windows dari header PE "
                    "(DEP/ASLR/CFG) — read-only, nol jaringan.")
    ap.add_argument("files", nargs="+", help="path biner PE (.exe/.dll)")
    ap.add_argument("--require", default="",
                    help="gate: daftar mitigasi wajib, pisah koma "
                         "(contoh: DEP,ASLR,CFG) — exit 1 bila ada "
                         "yang hilang pada file yang terurai")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)

    required = [r.strip().upper() for r in args.require.split(",")
                if r.strip()]
    unknown = [r for r in required if r not in MITIGATION_BITS]
    if unknown:
        print(f"ERROR: mitigasi tidak dikenal di --require: "
              f"{','.join(unknown)} (pilihan: "
              f"{','.join(MITIGATION_BITS)})", file=sys.stderr)
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
