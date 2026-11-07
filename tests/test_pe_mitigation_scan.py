"""Nol jaringan — test pe_mitigation_scan (verifikasi mitigasi PE).

Biner PE sintetis dibangun di memori dari layout spesifikasi PE/COFF:
MZ -> e_lfanew -> PE\\0\\0 -> COFF (20B) -> optional header.
"""
from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import pe_mitigation_scan as pms  # noqa: E402


def build_pe(dll_chars: int, pe32plus: bool = False,
             load_config: "int | None" = None) -> bytes:
    """PE minimal: optional header 72B (tanpa dd) atau 224B (dd 16
    entri); load_config = None -> dd index 10 nol, int -> RVA/size."""
    machine = 0x8664 if pe32plus else 0x014C
    magic = 0x20B if pe32plus else 0x10B
    with_dd = load_config is not None
    opt_size = 224 if with_dd else 72
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    struct.pack_into("<H", opt, 70, dll_chars)
    if with_dd:
        # count @opt+92 (PE32) / @opt+108 (PE32+); base @opt+96/@opt+112
        n_count = 108 if pe32plus else 92
        n_dd = 112 if pe32plus else 96
        struct.pack_into("<I", opt, n_count, 16)   # NumberOfRvaAndSizes
        if load_config:
            struct.pack_into("<II", opt, n_dd + 80, load_config, 0x100)
    coff = struct.pack("<HHIIIHH", machine, 3, 0, 0, 0, opt_size, 0x2100)
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt)


DEP_ASLR_HEVA_CFG = pms.BIT_DEP | pms.BIT_ASLR | pms.BIT_HEVA | pms.BIT_CFG
DEP_ASLR = pms.BIT_DEP | pms.BIT_ASLR


class TestAssess(unittest.TestCase):
    """Nol jaringan — semantik verdict fail-closed."""

    def test_semua_mitigasi_mitigated(self):
        pe = pms.parse_dll_characteristics(build_pe(DEP_ASLR_HEVA_CFG,
                                                    load_config=0x2000))
        a = pms.assess(pe)
        self.assertEqual(a["verdict"], "MITIGATED")
        self.assertEqual(a["core_missing"], [])

    def test_tanpa_dep_aslr_weak(self):
        pe = pms.parse_dll_characteristics(build_pe(0))
        a = pms.assess(pe)
        self.assertEqual(a["verdict"], "WEAK")

    def test_dep_aslr_tanpa_cfg_partial(self):
        pe = pms.parse_dll_characteristics(build_pe(DEP_ASLR))
        a = pms.assess(pe)
        self.assertEqual(a["verdict"], "PARTIAL")
        self.assertEqual(a["core_missing"], ["CFG"])

    def test_heva_tanpa_aslr_note(self):
        pe = pms.parse_dll_characteristics(build_pe(pms.BIT_HEVA))
        a = pms.assess(pe)
        self.assertTrue(any("HEVA" in n for n in a["notes"]))

    def test_cfg_bit_tanpa_load_config_note(self):
        pe = pms.parse_dll_characteristics(build_pe(DEP_ASLR_HEVA_CFG,
                                                    load_config=0))
        a = pms.assess(pe)
        self.assertTrue(any("meragukan" in n for n in a["notes"]))

    def test_cfg_bit_dengan_load_config_bersih(self):
        pe = pms.parse_dll_characteristics(build_pe(DEP_ASLR_HEVA_CFG,
                                                    load_config=0x2000))
        a = pms.assess(pe)
        self.assertFalse([n for n in a["notes"] if "CFG" in n])

    def test_pe32_dan_pe32plus_sama_offset_dllchars(self):
        for plus in (False, True):
            pe = pms.parse_dll_characteristics(
                build_pe(DEP_ASLR, pe32plus=plus))
            self.assertEqual(pe["dll_characteristics"], DEP_ASLR)
            self.assertEqual(pe["pe32plus"], plus)


class TestParseFailClosed(unittest.TestCase):
    """Nol jaringan — input rusak TIDAK boleh jadi verdict aman."""

    def test_bukan_pe(self):
        with self.assertRaises(pms.PEFail):
            pms.parse_dll_characteristics(b"ini bukan binary MZ" * 4)

    def test_optional_header_terpotong(self):
        data = build_pe(DEP_ASLR)[:0x40 + 4 + 20 + 30]
        with self.assertRaises(pms.PEFail):
            pms.parse_dll_characteristics(data)

    def test_magic_asing(self):
        data = bytearray(build_pe(DEP_ASLR))
        off = struct.unpack_from("<I", data, 0x3C)[0] + 24
        struct.pack_into("<H", data, off, 0x999)
        with self.assertRaises(pms.PEFail):
            pms.parse_dll_characteristics(bytes(data))

    def test_scan_file_hilang_inconclusive(self):
        r = pms.scan_file(Path("Z:/tidak/ada/biner.exe"))
        self.assertEqual(r["verdict"], "INCONCLUSIVE")
        self.assertIn("tidak bisa dibaca", r["reason"])


class TestMain(unittest.TestCase):
    """Nol jaringan — CLI, gate --require, exit code."""

    def _write(self, d, name, data):
        p = d / name
        p.write_bytes(data)
        return p

    def test_exit0_json_schema(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            exe = self._write(d, "good.exe", build_pe(DEP_ASLR_HEVA_CFG,
                                                      load_config=0x2000))
            out = d / "out.json"
            rc = pms.main([str(exe), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], pms.SCHEMA)
            self.assertEqual(doc["files"][0]["verdict"], "MITIGATED")
            self.assertEqual(doc["summary"]["mitigated"], 1)

    def test_gate_require_gagal_exit1(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            exe = self._write(d, "weak.exe", build_pe(DEP_ASLR))
            rc = pms.main([str(exe), "--require", "DEP,ASLR,CFG"])
            self.assertEqual(rc, 1)

    def test_gate_require_lolos_exit0(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            exe = self._write(d, "good.exe", build_pe(DEP_ASLR_HEVA_CFG,
                                                      load_config=0x2000))
            rc = pms.main([str(exe), "--require", "DEP,ASLR,CFG"])
            self.assertEqual(rc, 0)

    def test_inconclusive_exit2(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            exe = self._write(d, "bad.exe", b"bukan pe sama sekali")
            rc = pms.main([str(exe)])
            self.assertEqual(rc, 2)

    def test_require_tak_kenal_exit2(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            exe = self._write(d, "good.exe", build_pe(DEP_ASLR))
            rc = pms.main([str(exe), "--require", "DEP,MAGIC"])
            self.assertEqual(rc, 2)

    def test_blok_campur_inconclusive_dominan(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            good = self._write(d, "good.exe",
                               build_pe(DEP_ASLR_HEVA_CFG,
                                        load_config=0x2000))
            bad = self._write(d, "bad.exe", b"ZZ")
            rc = pms.main([str(good), str(bad)])
            self.assertEqual(rc, 2)  # fail-closed: satu tak terurai = 2


if __name__ == "__main__":
    unittest.main()
