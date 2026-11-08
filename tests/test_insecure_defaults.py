"""Nol jaringan — test insecure_defaults (scanner konfigurasi statis)."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import insecure_defaults as idf  # noqa: E402
from findings import validate_finding  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _write(self, name: str, content: str) -> Path:
        p = self.tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def _scan_dir(self) -> dict:
        return idf.scan_source(str(self.tmp))

    @staticmethod
    def _cats(res: dict) -> dict:
        return res["by_category"]


class TestKategori(Base):
    """Nol jaringan — empat kategori terdeteksi di config aktif."""

    def test_default_credentials(self):
        self._write("app.env", "DB_USERNAME=admin\nDB_PASSWORD=admin\n")
        res = self._scan_dir()
        # username default (medium) + password default (high) = 2 temuan
        self.assertEqual(self._cats(res).get("default-credentials"), 2)
        f_pass = [f for f in res["findings"] if f["key"] == "DB_PASSWORD"][0]
        self.assertEqual(f_pass["severity"], "high")
        self.assertEqual(f_pass["cwe"], "CWE-798")
        self.assertIn("***", f_pass["value_masked"])
        self.assertNotIn("admin\n", f_pass["poc"])

    def test_password_bukan_default_tidak_kena(self):
        self._write("app.env",
                    "DB_PASSWORD=xT9$vQ2#mLp!8zRw\nDB_USERNAME=svc-api-7\n")
        res = self._scan_dir()
        self.assertEqual(res["findings_total"], 0)

    def test_fail_open(self):
        self._write("settings.yml",
                    "ssl_verify: false\nrejectUnauthorized: false\n")
        res = self._scan_dir()
        self.assertEqual(self._cats(res).get("fail-open"), 2)
        for f in res["findings"]:
            self.assertEqual(f["severity"], "high")

    def test_fail_open_aman_tidak_kena(self):
        self._write("settings.yml",
                    "ssl_verify: true\nrejectUnauthorized: true\n")
        res = self._scan_dir()
        self.assertEqual(res["findings_total"], 0)

    def test_debug_features(self):
        self._write("prod.ini", "DEBUG = true\nFLASK_ENV=development\n")
        res = self._scan_dir()
        self.assertEqual(self._cats(res).get("debug-features"), 2)

    def test_weak_crypto_hash(self):
        self._write("conf.yml", "hash_algorithm: md5\ncipher: rc4\n")
        res = self._scan_dir()
        self.assertEqual(self._cats(res).get("weak-crypto"), 2)

    def test_weak_secret_bawaan(self):
        self._write("app.py", "JWT_SECRET = 'changeme'\nsecret_key = 'secret'\n")
        res = self._scan_dir()
        self.assertEqual(self._cats(res).get("weak-crypto"), 2)

    def test_jwt_io_sample_placeholder_tidak_kena(self):
        # sample jwt.io = placeholder (zero-FP): tidak dihitung temuan
        self._write("auth.json", '{"jwt_secret": "your-256-bit-secret"}\n')
        res = self._scan_dir()
        self.assertEqual(res["findings_total"], 0)


class TestZeroFP(Base):
    """Nol jaringan — penekan komentar, placeholder, dan file non-config."""

    def test_komentar_tidak_kena(self):
        self._write("app.env",
                    "# DB_PASSWORD=admin (contoh)\n"
                    "// ssl_verify: false\n"
                    "; DEBUG=true\n")
        res = self._scan_dir()
        self.assertEqual(res["findings_total"], 0)

    def test_placeholder_tidak_kena(self):
        self._write("config.yml",
                    "secret_key: YOUR_SECRET_HERE\n"
                    "jwt_secret: <isi-disini>\n"
                    "password: REPLACE_ME\n")
        res = self._scan_dir()
        self.assertEqual(res["findings_total"], 0)

    def test_nilai_kosong_tidak_kena(self):
        self._write("config.yml", "password:\nsecret_key: ''\n")
        res = self._scan_dir()
        self.assertEqual(res["findings_total"], 0)

    def test_dir_skip_dan_biner(self):
        (self.tmp / "node_modules" / "x").mkdir(parents=True)
        (self.tmp / "node_modules" / "x" / "c.env").write_text(
            "DB_PASSWORD=admin\n", encoding="utf-8")
        (self.tmp / ".git").mkdir()
        (self.tmp / ".git" / "c.env").write_text("DB_PASSWORD=admin\n",
                                                 encoding="utf-8")
        self._write("binary.env", "DB_PASSWORD=admin\n\x00\x00\x00\n")
        res = self._scan_dir()
        # node_modules & .git di-skip; binary.env (NUL) di-skip juga
        self.assertEqual(res["files_scanned"], 0)
        self.assertEqual(res["findings_total"], 0)


class TestKontrak(Base):
    """Nol jaringan — temuan lulus kontrak findings + masking."""

    def test_semua_lulus_validate(self):
        self._write("mix.env",
                    "DB_PASSWORD=admin\nssl_verify=false\nDEBUG=true\n"
                    "hash_algorithm: sha1\njwt_secret: changeme\n")
        res = self._scan_dir()
        self.assertGreaterEqual(res["findings_total"], 5)
        self.assertEqual(res["invalid_contract"], [])
        for f in res["findings"]:
            self.assertEqual(validate_finding(f), [])
            self.assertEqual(f["verdict"], 2)
            self.assertEqual(f["status"], "confirmed")

    def test_masking_tanpa_nilai_penuh(self):
        self._write("app.env", "JWT_SECRET=supersecret\n")
        res = self._scan_dir()
        self.assertEqual(self._cats(res).get("weak-crypto"), 1)
        blob = json.dumps(res)
        self.assertNotIn("supersecret", blob)


class TestCli(Base):
    """Nol jaringan — CLI fail-closed."""

    def test_source_tak_ada_exit2(self):
        rc = idf.main(["--source", str(self.tmp / "tidak-ada"), "--out",
                       str(self.tmp / "o.json")])
        self.assertEqual(rc, 2)

    def test_out_json_valid(self):
        self._write("app.env", "DB_PASSWORD=admin\n")
        out = self.tmp / "res.json"
        rc = idf.main(["--source", str(self.tmp), "--out", str(out)])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "secai.insecure-defaults/1")
        self.assertGreaterEqual(data["findings_total"], 1)


if __name__ == "__main__":
    unittest.main()
