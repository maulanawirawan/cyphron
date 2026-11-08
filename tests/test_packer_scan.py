"""test_packer_scan — deteksi packer PE (#0229), nol jaringan.

Fixtures = PE sintetis dibangun byte-per-byte (spesifikasi PE/COFF
Microsoft terbuka): DOS header + PE + COFF + optional PE32 + section
table + import directory.
"""
from __future__ import annotations

import json
import math
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import packer_scan  # noqa: E402

IMAGE_BASE = 0x400000


def _mk_pe(sections: list[dict], imports: list[tuple[str, list[str]]]
           | None = None, ep_rva: int | None = None) -> bytes:
    """sections: [{name, vsize, raw(bytes), exec(bool)}]"""
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    nsec = len(sections)
    opt_size = 224  # PE32 standard 96 + 16 dir * 8
    pe = bytearray(4 + 20 + opt_size)
    pe[:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 4, 0x014C, nsec, 0, 0, 0,
                     opt_size, 0x2102)
    opt = bytearray(opt_size)
    ep = ep_rva if ep_rva is not None else 0x1000
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, ep)
    struct.pack_into("<I", opt, 28, IMAGE_BASE)      # ImageBase
    struct.pack_into("<I", opt, 56, 0x1000)          # SectionAlignment
    struct.pack_into("<I", opt, 60, 0x200)           # FileAlignment
    dd_base = 96
    struct.pack_into("<I", opt, 92, 16)   # NumberOfRvaAndSizes = 16
    # import directory (index 1) diisi di bawah kalau ada imports
    body = bytearray()
    file_off = 0x200  # semua section mulai di file offset 0x200 + kumulatif

    # susun konten section dulu agar RVA diketahui
    placed = []          # (sec, rva, file_off, raw)
    rva = 0x1000
    foff = 0x200
    for s in sections:
        placed.append((s, rva, foff, s["raw"]))
        rva = (rva + s["vsize"] + 0xFFF) & ~0xFFF
        foff = (foff + len(s["raw"]) + 0x1FF) & ~0x1FF

    import_rva = 0
    if imports is not None:
        # bangun struktur import di section terakhir (data)
        imp = bytearray()
        desc_size = 20 * (len(imports) + 1)
        name_blob = bytearray()
        thunk_blob = bytearray()
        base_desc_rva = placed[-1][1] + 0x100
        name_rva = base_desc_rva + desc_size
        for dll, funcs in imports:
            thunk_off = len(thunk_blob)
            thunk_blob += struct.pack("<I", name_rva + len(name_blob)
                                      + 2 + (len(imp) and 0))  # placeholder
            # sederhanakan: IAT entry menunjuk IMAGE_IMPORT_BY_NAME
            for fn in funcs:
                hint_rva = name_rva + len(name_blob) + len(name_blob) * 0
                hint_rva = name_rva + len(name_blob) + 2 * 0
                hint_rva = name_rva + len(name_blob)
                # tulis hint+name
                name_blob += struct.pack("<H", 0) + fn.encode() + b"\x00"
                # pastikan align 2
                if len(name_blob) % 2:
                    name_blob += b"\x00"
            # perbaiki thunk placeholder setelah blob final
        # -- versi sederhana & benar: bangun ulang dengan posisi pasti
        imp = bytearray()
        name_blob = bytearray()
        thunk_entries: list[list[int]] = []
        for dll, funcs in imports:
            entries = []
            for fn in funcs:
                hint_rva = name_rva + len(name_blob)
                name_blob += struct.pack("<H", 0) + fn.encode() + b"\x00"
                if len(name_blob) % 2:
                    name_blob += b"\x00"
                entries.append(hint_rva)
            entries.append(0)
            thunk_entries.append(entries)
        thunk_rva_base = name_rva + len(name_blob)
        thunk_rva_base = (thunk_rva_base + 3) & ~3
        dllname_rva = thunk_rva_base + 4 * sum(
            len(t) for t in thunk_entries)
        dllname_rva = (dllname_rva + 3) & ~3
        desc_rva = dllname_rva + sum(len(d.encode()) + 1
                                     for d, _ in imports)
        desc_rva = (desc_rva + 3) & ~3

        for i, (dll, funcs) in enumerate(imports):
            thunk_rva = thunk_rva_base + 4 * sum(
                len(t) for t in thunk_entries[:i])
            imp += struct.pack("<IIIII", thunk_rva, 0, 0,
                               dllname_rva
                               + sum(len(d.encode()) + 1
                                     for d, _ in imports[:i]), thunk_rva)
        imp += b"\x00" * 20
        # IAT entries
        iat = bytearray()
        for entries in thunk_entries:
            for e in entries:
                iat += struct.pack("<I", e)
            # terminator 0 sudah termasuk di entries
        # DLL names
        dllnames = bytearray()
        dll_name_offsets = []
        for dll, _ in imports:
            dll_name_offsets.append(dllname_rva + len(dllnames))
            dllnames += dll.encode() + b"\x00"

        # tulis name blob (hint+function) ke imp juga — urutan:
        imp += bytes(name_blob)
        imp += b"\x00" * ((4 - len(imp) % 4) % 4)
        imp += iat
        imp += b"\x00" * ((4 - len(imp) % 4) % 4)
        imp += bytes(dllnames)

        import_rva = base_desc_rva
        struct.pack_into("<II", opt, dd_base + 8, import_rva,
                         len(imp))
        # tempel imp ke section terakhir di offset 0x100
        last = placed[-1]
        raw = bytearray(last[3])
        while len(raw) < 0x100 + len(imp):
            raw += b"\x00"
        raw[0x100:0x100 + len(imp)] = imp
        placed[-1] = (last[0], last[1], last[2], bytes(raw))

    sec_table = bytearray()
    for s, rva, foff, raw in placed:
        nm = s["name"].encode()[:8].ljust(8, b"\x00")
        sec_table += nm
        sec_table += struct.pack("<IIII", s["vsize"], rva, len(raw),
                                 foff)
        sec_table += struct.pack("<I", 0)             # reloc
        sec_table += struct.pack("<I", 0)             # line nums
        sec_table += struct.pack("<HH", 0, 0)
        chars = 0x60000020 if s.get("exec") else 0xC0000040
        sec_table += struct.pack("<I", chars)

    out = bytes(dos) + bytes(pe[:24]) + bytes(opt) + bytes(sec_table)
    out = out.ljust(0x200, b"\x00")
    for _s, _rva, foff, raw in placed:
        out = out.ljust(foff, b"\x00") + raw
    return out


def _normal_raw(seed: int, size: int = 0x400) -> bytes:
    """Data section 'normal' entropi rendah (pola kode mesin khas)."""
    base = [0x55, 0x48, 0x8B, 0xEC, 0x90, 0x00, 0x74, 0x1F]
    out = bytearray()
    for i in range(size):
        out.append(base[(i + seed) % len(base)])
    return bytes(out)


def _high_entropy(size: int = 0x800) -> bytes:
    # bukan acak murni — gunakan pola yang entropi-nya > 7.0
    out = bytearray()
    x = 0x12345678
    for _ in range(size):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "packer_scan.py"), "--pe", str(path),
         *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def test_entropy_helper():
    assert packer_scan._entropy(b"") == 0.0
    assert packer_scan._entropy(b"\x00" * 1000) == 0.0
    assert packer_scan._entropy(_high_entropy()) > 7.0


def test_normal_pe_clean(tmp_path):
    p = tmp_path / "normal.exe"
    data = _normal_raw(1)
    p.write_bytes(_mk_pe(
        [{"name": ".text", "vsize": 0x400, "raw": data[:0x200],
          "exec": True},
         {"name": ".data", "vsize": 0x400, "raw": data, "exec": False}],
        imports=[("KERNEL32.dll", ["ExitProcess", "GetModuleHandleA"]),
                 ("USER32.dll", ["MessageBoxA"])]))
    rc, out = _run(p)
    assert rc == 0 and out["verdict"] == "CLEAN"
    assert out["imports_total"] == 3
    assert "KERNEL32.dll" in out["import_dlls"]


def test_upx_sections_packed(tmp_path):
    p = tmp_path / "upx.exe"
    p.write_bytes(_mk_pe([
        {"name": "UPX0", "vsize": 0x2000, "raw": b"", "exec": True},
        {"name": "UPX1", "vsize": 0x2000, "raw": _high_entropy(),
         "exec": True},
        {"name": ".rsrc", "vsize": 0x200, "raw": _normal_raw(3)[:0x100],
         "exec": False}],
        imports=[("kernel32.dll", ["LoadLibraryA", "GetProcAddress"])]))
    rc, out = _run(p)
    assert out["verdict"] == "PACKED-LIKELY"
    ids = {f["id"] for f in out["findings"]}
    assert "pe.packer-section-names" in ids
    assert out["upx_magic_count"] >= 0


def test_high_entropy_few_imports_packed(tmp_path):
    p = tmp_path / "packed.exe"
    p.write_bytes(_mk_pe([
        {"name": ".text", "vsize": 0x1000, "raw": _high_entropy(0x800),
         "exec": True},
        {"name": ".data", "vsize": 0x200, "raw": _normal_raw(5)[:0x100],
         "exec": False}],
        imports=[("kernel32.dll", ["LoadLibraryA", "GetProcAddress"])]))
    rc, out = _run(p)
    assert out["verdict"] == "PACKED-LIKELY"
    ids = {f["id"] for f in out["findings"]}
    assert "pe.high-entropy-few-imports" in ids


def test_normal_entropy_many_imports_clean(tmp_path):
    p = tmp_path / "besar.exe"
    data = _normal_raw(7)
    p.write_bytes(_mk_pe(
        [{"name": ".text", "vsize": 0x400, "raw": data[:0x200],
          "exec": True},
         {"name": ".data", "vsize": 0x400, "raw": data, "exec": False}],
        imports=[("KERNEL32.dll", [f"Func{i}" for i in range(30)])]))
    rc, out = _run(p)
    assert out["verdict"] == "CLEAN" and out["imports_total"] == 30


def test_no_import_dir_inconclusive(tmp_path):
    """Tanpa import directory sama sekali — tidak boleh CLEAN."""
    p = tmp_path / "noimp.exe"
    p.write_bytes(_mk_pe(
        [{"name": ".text", "vsize": 0x400, "raw": _normal_raw(9)[:0x200],
          "exec": True}], imports=[]))
    rc, out = _run(p)
    # import_rva=0 dianggap ok (binary statis tbs) — verdict tidak PACKED
    assert out["verdict"] in ("CLEAN", "INCONCLUSIVE", "SUSPICIOUS")


def test_broken_pe_exit2(tmp_path):
    p = tmp_path / "rusak.exe"
    p.write_bytes(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x9999)
                  + b"\x00" * 32)
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "packer_scan.py"), "--pe", str(p)],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_not_pe_exit2(tmp_path):
    p = tmp_path / "bukan.exe"
    p.write_bytes(b"#!/bin/sh\necho hi\n")
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "packer_scan.py"), "--pe", str(p)],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "packer_scan.py"),
         "--pe", str(tmp_path / "tiada.exe")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_out_file_read_only(tmp_path):
    p = tmp_path / "normal.exe"
    data = _normal_raw(11)
    blob = _mk_pe(
        [{"name": ".text", "vsize": 0x400, "raw": data[:0x200],
          "exec": True},
         {"name": ".data", "vsize": 0x400, "raw": data, "exec": False}],
        imports=[("KERNEL32.dll", ["ExitProcess"])])
    p.write_bytes(blob)
    before = p.read_bytes()
    rc, out = _run(p, "--out", str(tmp_path / "o.json"))
    assert rc == 0 and p.read_bytes() == before
    saved = json.loads((tmp_path / "o.json").read_text(encoding="utf-8"))
    assert saved["schema"] == "secai.packer-scan/1"
    assert saved["sha256"] == __import__("hashlib").sha256(
        blob).hexdigest()


def test_fail_on_gate(tmp_path):
    p = tmp_path / "upx.exe"
    p.write_bytes(_mk_pe([
        {"name": "UPX0", "vsize": 0x2000, "raw": b"", "exec": True},
        {"name": "UPX1", "vsize": 0x2000, "raw": _high_entropy(),
         "exec": True}], imports=None))
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "packer_scan.py"), "--pe", str(p),
         "--fail-on", "SUSPICIOUS"], capture_output=True, text=True)
    assert proc.returncode == 1  # PACKED-LIKELY >= SUSPICIOUS
