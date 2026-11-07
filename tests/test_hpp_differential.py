"""Nol jaringan — test hpp_differential (diagnostik HPP fail-closed).

Klasifikasi murni dites dengan objek Resp sintetis; fail-closed URL
dites tanpa request jaringan. Kasus live-verify nyata terhadap lab
(dijalankan manual, bukan di sini): python tools/lab_target.py.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import hpp_differential as hp  # noqa: E402


def R(status: int, body: str) -> hp.Resp:
    return hp.Resp(status=status, body=body)


class TestValidateUrl(unittest.TestCase):
    """Nol jaringan — validasi URL fail-closed."""

    def test_valid(self):
        self.assertEqual(hp.validate_url("http://127.0.0.1:8000/api/products"),
                         "http://127.0.0.1:8000/api/products")

    def test_bukan_http_ditolak(self):
        for bad in ("ftp://x/y", "file:///etc/passwd", "//host", "", "   "):
            with self.assertRaises(ValueError):
                hp.validate_url(bad)

    def test_query_ditolak(self):
        # query dikelola alat; URL dengan query ditolak agar urutan duplikat
        # terkendali (integritas pengukuran)
        with self.assertRaises(ValueError):
            hp.validate_url("http://127.0.0.1/api?q=1")


class TestClassify(unittest.TestCase):
    """Nol jaringan — matriks klasifikasi refleksi (anti-FP)."""

    A, B = "cafe" + "a" * 12, "beef" + "b" * 12

    def test_first(self):
        # server (mis. qs.get(p)[0]) hanya melihat nilai pertama
        v = hp.classify(R(200, f"hasil {self.A}"), R(200, f"hasil {self.B}"),
                        R(200, f"hasil {self.A}"), R(200, "ok"),
                        self.A, self.B)
        self.assertEqual(v["winner"], "FIRST")
        self.assertFalse(v["generic"])

    def test_last(self):
        v = hp.classify(R(200, f"hasil {self.A}"), R(200, f"hasil {self.B}"),
                        R(200, f"hasil {self.B}"), R(200, "ok"),
                        self.A, self.B)
        self.assertEqual(v["winner"], "LAST")

    def test_both(self):
        body = f"hasil {self.A} dan {self.B}"
        v = hp.classify(R(200, f"hasil {self.A}"), R(200, f"hasil {self.B}"),
                        R(200, body), R(200, "ok"), self.A, self.B)
        self.assertEqual(v["winner"], "BOTH")

    def test_indifferent_tanpa_refleksi(self):
        v = hp.classify(R(200, "ok"), R(200, "ok"), R(200, "ok"),
                        R(200, "ok2"), self.A, self.B)
        self.assertEqual(v["winner"], "INDIFFERENT")

    def test_generic_bukan_klaim(self):
        # semua respons sama persis -> tidak ada sinyal, BUKAN FIRST/LAST
        same = "selamat datang"
        v = hp.classify(R(200, same), R(200, same), R(200, same),
                        R(200, same), self.A, self.B)
        self.assertEqual(v["winner"], "GENERIC")
        self.assertTrue(v["generic"])

    def test_kontrol_canary_menangkap_mirror(self):
        # kontrol (tanpa A/B) ternyata memantulkan nama-param canary —
        # tanda server menyalin query mentah -> refleksi tak bisa dipercaya
        v = hp.classify(R(200, f"x {self.A}"), R(200, f"x {self.B}"),
                        R(200, f"x {self.A}{self.B}"),
                        R(200, "echo hppc-dead=0123 & hppd-dead=4567"),
                        self.A, self.B,
                        control_markers=("hppc-dead", "hppd-dead"))
        self.assertEqual(v["winner"], "UNTRUSTWORTHY")


class TestFailClosedCli(unittest.TestCase):
    """Nol jaringan — exit code CLI tanpa menyentuh jaringan."""

    def test_url_invalid_exit2(self):
        self.assertEqual(hp.main(["--url", "notaurl"]), 2)

    def test_url_dengan_query_exit2(self):
        self.assertEqual(
            hp.main(["--url", "http://127.0.0.1/x?a=1"]), 2)

    def test_values_invalid_exit2(self):
        self.assertEqual(
            hp.main(["--url", "http://127.0.0.1/x", "--values", "hanya1"]), 2)

    def test_probe_gagal_jaringan_exit3(self):
        # port yang pasti tidak ada di 127.0.0.1 (RFC: reserved, bukan jaringan
        # eksternal) -> URLError -> exit 3 tanpa klaim
        rc = hp.main(["--url", "http://127.0.0.1:1/x", "--timeout", "2"])
        self.assertEqual(rc, 3)


class TestOutput(unittest.TestCase):
    """Nol jaringan — struktur hasil JSON."""

    def test_probe_bounded_metadata(self):
        # probe() tak dipanggil (jaringan); hanya cek konstanta & schema
        self.assertEqual(hp.MAX_REQUESTS, 5)
        self.assertEqual(hp.SCHEMA, "cyphron.hpp-differential/1")

    def test_result_json_serializable(self):
        # simulate hasil classify penuh seperti probe() kembalikan
        A, B = "aa11", "bb22"
        v = hp.classify(R(200, f"r {A}"), R(200, f"r {B}"), R(200, f"r {A}"),
                        R(200, "ok"), A, B)
        result = {"schema": hp.SCHEMA, "winner": v["winner"],
                  "detail": v}
        json.dumps(result)  # tidak boleh raise
        self.assertEqual(result["winner"], "FIRST")


if __name__ == "__main__":
    unittest.main()
