"""Nol jaringan — test yara_rule_lint (linter kualitas aturan YARA).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import yara_rule_lint as yl  # noqa: E402

CLEAN = r'''
import "pe"

rule Mal_LockBit_config_extract
{
    meta:
        author = "lab"
        family = "lockbit"
        reference = "internal-lab-2026"
    strings:
        $mut = "8F4A9C2E1B7D63A5" ascii
        $cfg = { 4C 6F 63 6B 42 69 74 33 }
    condition:
        uint32(0) == 0x464C457F and $mut at pe.rva_to_offset(0) and $cfg
}
'''


def checks(fs):
    return {f["check"] for f in fs}


class TestParse(unittest.TestCase):
    """Nol jaringan — parser fail-closed + komentar."""

    def test_bersih_tanpa_temuan(self):
        fs, meta = yl.lint_source(CLEAN, "clean.yar")
        self.assertEqual(fs, [], msg=str(fs))
        self.assertEqual(meta["rules"], 1)

    def test_kutip_tak_tertutup(self):
        with self.assertRaises(yl.ParseError):
            yl.lint_source('rule A { strings: $a = "abc condition: $a }', "x.yar")

    def test_kurung_tak_seimbang(self):
        with self.assertRaises(yl.ParseError):
            yl.lint_source("rule A { strings: $a = \"abcd\" condition: $a", "x.yar")

    def test_komentar_dilewati(self):
        src = ('// rule Palsu_Di_Komentar { strings: $x = "ab" condition: $x }\n'
               "rule B_Komentar_Ok {\n"
               "    meta: note = \"x\"\n"
               "    /* VirtualAlloc di komentar bukan string rule */\n"
               '    strings: $a = "un1qu3" ascii\n'
               "    condition: $a\n}\n")
        fs, meta = yl.lint_source(src, "c.yar")
        self.assertEqual(checks(fs), set(), msg=str(fs))
        self.assertEqual(meta["rules"], 1)

    def test_komentar_di_dalam_kondisi(self):
        src = ('rule C_Kondisi_Komentar {\n'
               '    meta: note = "x"\n'
               '    strings: $a = "un1qu3"\n'
               "    condition: /* } */ filesize < 1MB and $a\n}\n")
        fs, _ = yl.lint_source(src, "c.yar")
        self.assertEqual(checks(fs), set(), msg=str(fs))

    def test_multi_rule_dan_tag(self):
        src = CLEAN + '\nprivate rule Mal_Internal_helper : fam1 fam2 {\n' \
            '    meta: note = "x"\n    strings: $s = "ab3d" fullword\n' \
            "    condition: any of them\n}\n"
        _, meta = yl.lint_source(src, "m.yar")
        self.assertEqual(meta["rules"], 2)


class TestCek(unittest.TestCase):
    """Nol jaringan — tiap cek deterministik."""

    def lint1(self, body: str, header: str = "rule T_uji") -> list[dict]:
        return yl.lint_source(f"{header} {{\n{body}\n}}\n", "t.yar")[0]

    def test_nama_sintaks(self):
        fs = self.lint1('strings: $a = "abcd" condition: $a', header="rule 2bad")
        self.assertIn("nama-sintaks", checks(fs))
        self.assertEqual([f["severity"] for f in fs if f["check"] == "nama-sintaks"],
                         ["high"])

    def test_nama_tanpa_underscore(self):
        fs = self.lint1('meta: x = "y"\nstrings: $a = "abcd"\ncondition: $a',
                        header="rule TanpaGaris")
        self.assertIn("nama-konvensi", checks(fs))

    def test_metadata_hampa(self):
        fs = self.lint1('strings: $a = "abcd"\ncondition: $a')
        self.assertIn("metadata-hampa", checks(fs))

    def test_string_pendek_teks(self):
        fs = self.lint1('strings: $a = "ab"\ncondition: $a')
        self.assertIn("string-pendek", checks(fs))

    def test_string_pendek_hex(self):
        fs = self.lint1("strings: $a = { AA BB }\ncondition: $a")
        self.assertIn("string-pendek", checks(fs))

    def test_hex_berulang(self):
        fs = self.lint1("strings: $a = { DE AD BE EF } \ncondition: $a")
        self.assertNotIn("hex-berulang", checks(fs))
        fs = self.lint1("strings: $a = { DE DE DE DE }\ncondition: $a")
        self.assertIn("hex-berulang", checks(fs))

    def test_string_umum(self):
        fs = self.lint1('meta: note = "x"\n'
                        'strings: $a = "VirtualAlloc" ascii\ncondition: $a')
        self.assertIn("string-umum", checks(fs))

    def test_overfit_string(self):
        ss = "\n".join(f'$s{i} = "uniq{i}x"' for i in range(7))
        fs = self.lint1(f"strings:\n{ss}\ncondition: 3 of them")
        self.assertIn("overfit-string", checks(fs))
        ss6 = "\n".join(f'$s{i} = "uniq{i}x"' for i in range(6))
        fs = self.lint1(f"strings:\n{ss6}\ncondition: 3 of them")
        self.assertNotIn("overfit-string", checks(fs))

    def test_urutan_kondisi(self):
        fs = self.lint1('strings: $a = "abcd"\ncondition: $a and filesize < 1MB')
        self.assertIn("urutan-kondisi", checks(fs))
        fs = self.lint1('strings: $a = "abcd"\ncondition: filesize < 1MB and $a')
        self.assertNotIn("urutan-kondisi", checks(fs))

    def test_baca_past_eof(self):
        fs = self.lint1("strings: $a = \"abcd\"\ncondition: uint32(4) == 0x1 and $a")
        self.assertIn("baca-past-eof", checks(fs))
        # dengan guard filesize -> aman
        fs = self.lint1(
            'strings: $a = "abcd"\n'
            "condition: filesize > 100 and uint32(4) == 0x1 and $a")
        self.assertNotIn("baca-past-eof", checks(fs))
        # offset 0 tidak perlu guard
        fs = self.lint1('strings: $a = "abcd"\ncondition: uint16(0) == 0x5A4D and $a')
        self.assertNotIn("baca-past-eof", checks(fs))

    def test_ref_string_hampa(self):
        fs = self.lint1('strings: $a = "abcd"\ncondition: $a and $hilang')
        self.assertIn("ref-string-hampa", checks(fs))
        self.assertEqual([f["severity"] for f in fs if f["check"] == "ref-string-hampa"],
                         ["high"])

    def test_wildcard_any_of_tidak_diflag(self):
        fs = self.lint1('strings: $a = "abcd"\ncondition: any of them')
        self.assertNotIn("ref-string-hampa", checks(fs))


class TestMain(unittest.TestCase):
    """Nol jaringan — CLI, exit codes, direktori, fail-closed."""

    def write(self, td: Path, name: str, text: str) -> str:
        p = td / name
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            clean = self.write(td, "c.yar", CLEAN)
            self.assertEqual(yl.main(["--source", clean]), 0)
            # medium: string pendek
            bad = self.write(td, "b.yar",
                             'rule T_x { meta: n = "x" strings: $a = "ab" '
                             'condition: $a }\n')
            self.assertEqual(yl.main(["--source", bad]), 1)
            self.assertEqual(
                yl.main(["--source", bad, "--fail-on", "high"]), 0)
            # info saja: nama tanpa underscore
            info = self.write(td, "i.yar",
                              'rule TanpaGaris { meta: n = "x" '
                              'strings: $a = "abcd" condition: $a }\n')
            self.assertEqual(yl.main(["--source", info]), 1)
            self.assertEqual(
                yl.main(["--source", info, "--fail-on", "medium"]), 0)
            rusak = self.write(td, "r.yar", "rule X_x { strings: $a = ")
            self.assertEqual(yl.main(["--source", rusak]), 1)  # unparsed lead
            self.assertEqual(yl.main(["--source", str(td / "tak-ada.yar")]), 2)

    def test_rule_satu_baris(self):
        """Rule inline satu baris tetap terparse utuh (bukan unparsed)."""
        fs, meta = yl.lint_source(
            'rule T_inline { meta: n = "x" strings: $a = "abcd" '
            'condition: $a }\n', "one.yar")
        self.assertEqual(checks(fs), set(), msg=str(fs))
        self.assertEqual(meta["rules"], 1)

    def test_direktori_unparsed_bukan_bersih(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self.write(td, "a.yar", CLEAN)
            self.write(td, "z.yar", "rule Z_z { strings: $a = \"ab\"")
            self.assertEqual(yl.main(["--source", str(td)]), 1)  # unparsed = lead

    def test_hanya_ambil_yar(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self.write(td, "a.txt", "rule A_x { strings: $a = \"ab\" condition: $a }")
            r = yl.main(["--source", str(td)])
            self.assertEqual(r, 2)  # tidak ada file .yar -> error

    def test_json_out(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bad = self.write(td, "b.yar",
                             'rule T_x { strings: $a = "ab" condition: $a }\n')
            out = td / "o.json"
            self.assertEqual(yl.main(["--source", bad, "--json", str(out)]), 1)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], yl.SCHEMA)
            self.assertTrue(any(f["check"] == "string-pendek"
                                for f in data["findings"]))


if __name__ == "__main__":
    unittest.main()
