"""B8-SLOP: linter laporan (reportslop) + rule pack slop di sast.py.

Kontrak yang diuji:
- deterministik, tanpa LLM, tanpa jaringan;
- PASS utk laporan rapi (zero-FP), FAIL per pelanggaran;
- tiap rule punya test positif & negatif;
- slop score sast 0-100.
"""

import unittest
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.reportslop import lint_report, format_result
from cyphron.sast import scan_path, scan_file, slop_score, SLOP_RULES


LAPORAN_RAPI = """# Hasil Uji Ketahanan Lab

## Ringkasan
Server lab single-thread bertahan sampai 50 VU (diukur dari ladder run 19 Sep).
Latency p95 naik 3x saat 50 VU, throughput turun 40% dari baseline
(dihitung dari log akses server). Verdict: DEGRADE.

## Temuan
Tidak ada temuan terkonfirmasi. Satu LEAD: error rate melonjak di menit ke-8
(dari log error server).
"""

LAPORAN_SLOP = """# Laporan

## Ringkasan
It is worth noting bahwa sistem kami cutting-edge dan pasti berhasil.
Kami memberikan ketenangan pikiran dengan zero false positive.
Sistem aman 100% secure untuk semua ancaman.

## Angka
Akurasi sistem 98.5%.
Dalam era digital, keamanan sangat penting untuk diingat.

## Pengulangan
Segera lakukan patching sebelum hari minggu. Segera lakukan patching sebelum
hari minggu. Segera lakukan patching sebelum hari minggu.
"""


class TestReportSlop(unittest.TestCase):
    def test_rapi_pass_full_score(self):
        res = lint_report(LAPORAN_RAPI)
        self.assertEqual(res["verdict"], "PASS")
        self.assertEqual(res["score"], 100)
        self.assertTrue(all(b["verdict"] == "PASS" for b in res["blocks"]))

    def test_statistik_dengan_sumber_tidak_bermasalah(self):
        res = lint_report(LAPORAN_RAPI)
        for b in res["blocks"]:
            rules = [i["rule"] for i in b["issues"]]
            self.assertNotIn("SL-STAT-TANPA-SUMBER", rules,
                             "angka dengan konteks pengukuran harus lolos")

    def test_slop_fail(self):
        res = lint_report(LAPORAN_SLOP)
        self.assertEqual(res["verdict"], "FAIL")
        rules = {i["rule"] for b in res["blocks"] for i in b["issues"]}
        self.assertIn("SL-FRASE-GENERIK", rules)
        self.assertIn("SL-KLAIM-ABSOLUT", rules)
        self.assertIn("SL-STAT-TANPA-SUMBER", rules)
        self.assertIn("SL-PENGULANGAN", rules)
        self.assertLess(res["score"], 100)

    def test_frase_id_dan_en_terdeteksi(self):
        id_report = "## X\nSeiring berkembangnya teknologi, sistem ini unggul.\n"
        en_report = "## X\nWe delve into the results below.\n"
        self.assertEqual(lint_report(id_report)["verdict"], "FAIL")
        self.assertEqual(lint_report(en_report)["verdict"], "FAIL")

    def test_percent_sourced_vs_bare(self):
        bare = "## A\nUptime 99.9%.\n"
        sourced = "## A\nUptime 99.9% (diukur dari monitoring 30 hari).\n"
        self.assertEqual(lint_report(bare)["verdict"], "FAIL")
        self.assertEqual(lint_report(sourced)["verdict"], "PASS")

    def test_blok_dan_format(self):
        res = lint_report(LAPORAN_SLOP)
        headings = [b["heading"] for b in res["blocks"]]
        self.assertIn("Ringkasan", headings)
        out = format_result(res)
        self.assertIn("FAIL", out)
        self.assertIn("SL-KLAIM-ABSOLUT", out)


def _ids(findings):
    return {f.rule_id for f in findings}


class TestSastSlop(unittest.TestCase):
    def _scan(self, files: dict, slop=True):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, content in files.items():
                (root / name).write_text(content, encoding="utf-8")
            return scan_path(root, slop=slop)

    def test_todo_stub_positive_negative(self):
        pos = self._scan({"a.py": "# TODO: benerin nanti\nx = 1\n"})
        self.assertIn("SL-TODO-STUB", _ids(pos))
        neg = self._scan({"a.py": "x = 1\n"})
        self.assertNotIn("SL-TODO-STUB", _ids(neg))
        pos_js = self._scan({"a.js": "let x = 1; // FIXME nanti\n"})
        self.assertIn("SL-TODO-STUB", _ids(pos_js))

    def test_console_log(self):
        pos = self._scan({"a.js": "console.log('masuk sini');\n"})
        self.assertIn("SL-CONSOLE-LOG", _ids(pos))

    def test_print_leftover_positive_negative(self):
        pos = self._scan({"a.py": "print('mencapai sini')\n"})
        self.assertIn("SL-PRINT-LEFTOVER", _ids(pos))
        neg = self._scan({"a.py": "import sys\nprint(sys.argv)\n"})
        self.assertNotIn("SL-PRINT-LEFTOVER", _ids(neg))

    def test_func_long(self):
        long_body = "def proses_transaksi():\n" + \
                    "\n".join(f"    step_{i} = {i}" for i in range(70))
        pos = self._scan({"a.py": long_body + "\n"})
        self.assertIn("SL-FUNC-LONG", _ids(pos))
        ok_body = "def proses_transaksi():\n" + \
                  "\n".join(f"    step_{i} = {i}" for i in range(40))
        neg = self._scan({"a.py": ok_body + "\n"})
        self.assertNotIn("SL-FUNC-LONG", _ids(neg))

    def test_nama_generik(self):
        pos = self._scan({"a.py": "def do_stuff(a):\n    return a * 2\n"})
        self.assertIn("SL-NAMA-GENERIK", _ids(pos))
        neg = self._scan({"a.py": "def hitung_bunga(a):\n    return a * 2\n"})
        self.assertNotIn("SL-NAMA-GENERIK", _ids(neg))

    def test_komentar_trivial_dan_naratif(self):
        pos = self._scan({"a.py": "# increment\nx = x + 1\n"})
        self.assertIn("SL-KOMENTAR-TRIVIAL", _ids(pos))
        pos2 = self._scan({"a.py": "# x = x + 1\nx = x + 1\n"})
        self.assertIn("SL-KOMENTAR-NARATIF", _ids(pos2))
        neg = self._scan({"a.py": "# batas 30 VU mengikuti cap resilience\n"
                                  "x = 30\n"})
        self.assertNotIn("SL-KOMENTAR-TRIVIAL", _ids(neg))
        self.assertNotIn("SL-KOMENTAR-NARATIF", _ids(neg))

    def test_dup_helper(self):
        fn = ("def hitung_total(items):\n"
              "    total = 0\n"
              "    for it in items:\n"
              "        total += it.harga\n"
              "    return total\n")
        pos = self._scan({"a.py": fn, "b.py": fn.replace(
            "hitung_total", "kalkulasi_total")})
        self.assertIn("SL-DUP-HELPER", _ids(pos))
        fn_beda = fn.replace("total += it.harga", "total += it.qty")
        neg = self._scan({"a.py": fn, "b.py": fn_beda.replace(
            "hitung_total", "kalkulasi_total")})
        self.assertNotIn("SL-DUP-HELPER", _ids(neg))

    def test_slop_score_bounds(self):
        self.assertEqual(slop_score([]), 100)
        f = self._scan({"a.py": "print('debug')\n# TODO: x\n"})
        score = slop_score([x for x in f if x.rule_id.startswith("SL-")])
        self.assertTrue(0 <= score < 100)

    def test_slop_off_by_default(self):
        f = self._scan({"a.py": "print('debug')\n"}, slop=False)
        self.assertEqual([x for x in f if x.rule_id.startswith("SL-")], [])

    def test_run_ci_slop_score_in_json(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src").mkdir()
            (root / "src" / "a.py").write_text("print('debug')\n",
                                               encoding="utf-8")
            out = root / "out"
            from cyphron.sast import run_ci
            rc = run_ci(root / "src", out_dir=out, slop=True)
            data = json.loads((out / "sast.json").read_text(encoding="utf-8"))
            self.assertIn("slop_score", data)
            self.assertLess(data["slop_score"], 100)
            self.assertEqual(rc, 0)  # slop low/info tidak memicu exit 2


if __name__ == "__main__":
    unittest.main()
