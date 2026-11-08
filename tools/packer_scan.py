r"""[SAFETY: read-only] packer_scan — deteksi packer/binary-packed pada
file PE (Windows .exe/.dll).

Port konsep dari antrean SKILL-PORT-QUEUE #0229 (mukul975/
Anthropic-Cybersecurity-Skills 'analyzing-packed-malware-with-upx-
unpacker' — langkah "Identify the Packer": nama section UPX, entropi
tinggi, import minimal LoadLibrary/GetProcAddress). Dibangun from
scratch dari spesifikasi PE/COFF Microsoft yang dipublikasikan
terbuka, stdlib-only, NOL jaringan, read-only — TIDAK melakukan
unpacking (upx -d / debugger di luar cakupan; alat ini hanya TRIASE
mengapa sebuah binary dicurigai packed).

Mekanisme:
  - header DOS/PE/COFF/Optional (PE32 & PE32+), tabel section
  - entropi Shannon per section (>= 7.0 di section eksekusi = indikator)
  - nama section packer dikenal: UPX0/UPX1/UPX2/.upx, .aspack, .adata,
    .themida, .vmp0/.vmp1, .MPRESS1/.MPRESS2, .petite, .pec1
  - magic b"UPX!" di dalam file
  - tabel import diurai (IMAGE_IMPORT_DESCRIPTOR) — jumlah import &
    daftar DLL; packed khasnya <= 10 import
  - entry point menunjuk section dengan raw 0 byte (UPX0 pattern)
  - overlay (data setelah section terakhir) — ukuran dicatat

Verdict fail-closed:
  - PACKED-LIKELY  : nama section packer, ATAU EP di section raw-0 +
                     entropi exec >= 7.0, ATAU entropi exec >= 7.0 +
                     import <= 10
  - SUSPICIOUS     : entropi exec >= 7.0 tanpa indikator lain, ATAU
                     magic UPX! tanpa nama section UPX
  - INCONCLUSIVE   : header rusak / import tak terurai / file > batas
                     — TIDAK PERNAH mengklaim bersih
  - CLEAN          : semua pemeriksaan selesai tanpa indikator
  - Bukan PE -> exit 2.

Pemakaian:
  python tools/packer_scan.py --pe sampel.exe --out scan.json
  python tools/packer_scan.py --pe sampel.exe --fail-on SUSPICIOUS
Exit: 0 verdict < fail-on; 1 verdict >= fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "secai.packer-scan/1"

VERDICTS = ("CLEAN", "INCONCLUSIVE", "SUSPICIOUS", "PACKED-LIKELY")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_IMPORTS = 10_000
ENTROPY_EXEC_THRESHOLD = 7.0
FEW_IMPORTS = 10

PACKER_SECTIONS = (
    "upx0", "upx1", "upx2", ".upx",
    ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
    ".mpress1", ".mpress2", ".petite", ".pec1",
)

SCN_MEM_EXECUTE = 0x20000000


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _add(findings: list[dict], fid: str, severity: str, detail: str,
         evidence: dict | str = "") -> None:
    findings.append({"id": fid, "severity": severity, "detail": detail,
                     "evidence": evidence})


class PEFail(Exception):
    """Header/anatomi PE tidak bisa diurai — fail-closed."""


def _rva_to_off(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        span = max(s["vsize"], s["rawsize"])
        if s["vaddr"] <= rva < s["vaddr"] + span:
            delta = rva - s["vaddr"]
            if delta < s["rawsize"]:
                return s["rawptr"] + delta
            return None
    return None


def _read_cstr(data: bytes, off: int, limit: int = 256) -> str | None:
    if off is None or off < 0 or off >= len(data):
        return None
    end = data.find(b"\x00", off, off + limit)
    if end == -1:
        return None
    try:
        return data[off:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def parse_pe(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFail("bukan DOS/PE (magic MZ tidak ada)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data) \
            or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEFail("signature PE tidak valid")

    machine, nsec, _ts, _sym, _nsym, opt_size, _chars = \
        struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    if opt_size < 2 or opt + opt_size > len(data):
        raise PEFail("optional header tidak lengkap")
    opt_magic = struct.unpack_from("<H", data, opt)[0]
    if opt_magic == 0x10B:      # PE32
        ep, dd_base = struct.unpack_from("<I", data, opt + 16)[0], opt + 96
    elif opt_magic == 0x20B:    # PE32+
        ep, dd_base = struct.unpack_from("<I", data, opt + 16)[0], opt + 112
    else:
        raise PEFail(f"optional header magic tak dikenal: {opt_magic:#x}")

    dd_count = struct.unpack_from("<I", data, opt + 92)[0]
    import_rva = import_size = 0
    if dd_count > 1 and dd_base + 8 * 2 <= len(data):
        import_rva, import_size = struct.unpack_from("<II", data,
                                                     dd_base + 8)

    sec_table = opt + opt_size
    sections: list[dict] = []
    if sec_table + 40 * nsec > len(data):
        raise PEFail("tabel section tidak lengkap")
    for i in range(nsec):
        base = sec_table + i * 40
        name = data[base:base + 8].rstrip(b"\x00").decode(
            "latin-1", errors="replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII",
                                                           data, base + 8)
        chars = struct.unpack_from("<I", data, base + 36)[0]
        raw = data[rawptr:rawptr + min(rawsize, MAX_FILE_BYTES)]
        sections.append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "rawsize": rawsize, "rawptr": rawptr, "chars": chars,
            "entropy": round(_entropy(raw), 3),
            "is_exec": bool(chars & SCN_MEM_EXECUTE),
        })
    return {
        "machine": machine, "nsec": nsec, "entry_point": ep,
        "opt_magic": opt_magic,
        "sections": sections,
        "import_rva": import_rva, "import_size": import_size,
    }


def parse_imports(data: bytes, pe: dict,
                  sections: list[dict]) -> tuple[int, list[str], bool]:
    """Kembalikan (jumlah import, daftar DLL, ok). ok=False = gagal
    diurai (fail-closed — verdict tak boleh CLEAN)."""
    if pe["import_rva"] == 0:
        return 0, [], True
    off = _rva_to_off(pe["import_rva"], sections)
    if off is None:
        return 0, [], False
    entry_size = 8 if pe.get("opt_magic") == 0x20B else 4
    top_bit = 1 << (entry_size * 8 - 1)
    dlls: list[str] = []
    total = 0
    for i in range(MAX_IMPORTS):
        desc = off + i * 20
        if desc + 20 > len(data):
            return total, dlls, False
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII",
                                                         data, desc)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        dll = _read_cstr(data, _rva_to_off(name_rva, sections))
        if dll:
            dlls.append(dll)
        thunk_rva = oft or ft
        t_off = _rva_to_off(thunk_rva, sections)
        if t_off is None:
            continue
        for j in range(MAX_IMPORTS):
            t = t_off + j * entry_size
            if t + entry_size > len(data):
                return total, dlls, False
            val = (struct.unpack_from("<Q", data, t)[0] if entry_size == 8
                   else struct.unpack_from("<I", data, t)[0])
            if val == 0:
                break
            if val & top_bit:  # import per-ordinal, bukan nama
                total += 1
                continue
            hint_off = _rva_to_off(val, sections)
            if hint_off is not None:
                total += 1
    return total, dlls, True


def scan(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        # fail-closed: file besar tidak boleh dilaporkan bersih
        return {
            "schema": SCHEMA, "file": str(path), "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "verdict": "INCONCLUSIVE",
            "findings": [{"id": "limits", "severity": "info",
                          "detail": f"file {len(data)}B > batas pindai "
                                    f"{MAX_FILE_BYTES}B", "evidence": ""}],
            "read_only": True,
        }
    findings: list[dict] = []
    pe = parse_pe(data)
    n_imp, dlls, imp_ok = parse_imports(data, pe, pe["sections"])

    exec_secs = [s for s in pe["sections"] if s["is_exec"]]
    max_exec_entropy = max((s["entropy"] for s in exec_secs), default=0.0)
    raw0_exec = [s["name"] for s in exec_secs
                 if s["rawsize"] == 0 and s["vsize"] > 0]
    ep_sec = next((s for s in pe["sections"]
                   if s["vaddr"] <= pe["entry_point"]
                   < s["vaddr"] + max(s["vsize"], s["rawsize"])), None)
    ep_raw0 = bool(ep_sec and ep_sec["rawsize"] == 0
                   and ep_sec["vsize"] > 0)
    packer_secs = [s["name"] for s in pe["sections"]
                   if s["name"].lower() in PACKER_SECTIONS]
    upx_magic = data.count(b"UPX!")
    end_raw = max((s["rawptr"] + s["rawsize"] for s in pe["sections"]),
                  default=0)
    overlay = max(0, len(data) - end_raw)

    if packer_secs:
        _add(findings, "pe.packer-section-names", "high",
             f"nama section packer dikenal: {', '.join(packer_secs)}",
             {"sections": packer_secs, "upx_magic_count": upx_magic})
    if ep_raw0 and max_exec_entropy >= ENTROPY_EXEC_THRESHOLD:
        _add(findings, "pe.ep-zero-raw-entropy", "high",
             "entry point di section raw-0 + entropi eksekusi tinggi "
             "(pola stub unpacker)", {
                 "entry_point": pe["entry_point"],
                 "entropy": max_exec_entropy})
    if (max_exec_entropy >= ENTROPY_EXEC_THRESHOLD
            and n_imp <= FEW_IMPORTS):
        _add(findings, "pe.high-entropy-few-imports", "high",
             f"entropi exec {max_exec_entropy} >= 7.0 dengan hanya "
             f"{n_imp} import (pola packed)", {
                 "entropy": max_exec_entropy, "imports": n_imp,
                 "dlls": dlls})
    if (max_exec_entropy >= ENTROPY_EXEC_THRESHOLD
            and n_imp > FEW_IMPORTS and not packer_secs and not ep_raw0):
        _add(findings, "pe.high-entropy-exec", "medium",
             f"entropi exec {max_exec_entropy} >= 7.0 (bisa kompresi/"
             f"enkripsi section)", {"entropy": max_exec_entropy})
    if upx_magic and not packer_secs:
        _add(findings, "pe.upx-magic-no-name", "medium",
             f"magic UPX! x{upx_magic} tanpa nama section UPX "
             "(header mungkin diubah)", {"upx_magic_count": upx_magic})
    if not imp_ok:
        _add(findings, "pe.import-unreadable", "info",
             "tabel import tak terurai penuh (fail-closed)")
    if overlay:
        _add(findings, "pe.overlay", "info",
             f"{overlay} byte overlay setelah section terakhir",
             {"overlay_bytes": overlay})

    hard = [f for f in findings if f["severity"] == "high"]
    if hard:
        verdict = "PACKED-LIKELY"
    elif not imp_ok or not pe["sections"]:
        verdict = "INCONCLUSIVE"
    elif any(f["id"] in ("pe.high-entropy-exec", "pe.upx-magic-no-name")
             for f in findings):
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
    return {
        "schema": SCHEMA,
        "file": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "machine": hex(pe["machine"]),
        "entry_point": pe["entry_point"],
        "sections": [{k: s[k] for k in ("name", "vsize", "rawsize",
                                        "entropy", "is_exec")}
                     for s in pe["sections"]],
        "imports_total": n_imp,
        "import_dlls": dlls,
        "upx_magic_count": upx_magic,
        "overlay_bytes": overlay,
        "verdict": verdict,
        "findings": findings,
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deteksi packer pada file PE (read-only, NOL "
                    "jaringan, tanpa unpacking)")
    ap.add_argument("--pe", required=True, help="path file PE (.exe/.dll)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=VERDICTS, default="PACKED-LIKELY",
                    help="gate exit 1 bila verdict >= pilihan ini")
    args = ap.parse_args(argv)

    path = Path(args.pe)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = scan(path)
    except PEFail as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)

    if VERDICTS.index(result["verdict"]) >= VERDICTS.index(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
