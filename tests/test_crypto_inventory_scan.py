"""Test crypto_inventory_scan (#0746) — nol jaringan, fixture inline."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import crypto_inventory_scan as cis


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def _run(self, *extra, scan=None):
        scan = scan or [str(self.root)]
        out = self.root / "_out.json"
        rc = cis.main(["--scan", *scan, "--out", str(out), *extra])
        rep = json.loads(out.read_text(encoding="utf-8"))
        return rc, rep


class TestClassification(Base):
    def test_rsa_medium_asym_shor(self):
        self._write("srv.py", "context = ssl.SSLContext()\n"
                              "key = rsa.generate_private_key()\n")
        rc, rep = self._run()
        f = [x for x in rep["findings"] if x["field"] == "RSA"]
        self.assertEqual(rc, 1)
        self.assertEqual(f[0]["check"], "asym-shor-token")
        self.assertEqual(f[0]["severity"], "medium")
        self.assertEqual(f[0]["line"], 2)

    def test_sufiks_angka_dan_mode_kena(self):
        self._write("t.conf",
                    "groups = ML-KEM-768\n"
                    "cipher = aes-128-gcm\n"
                    "dhparam = rsa-2048\n")
        rc, rep = self._run()
        fields = {x["field"] for x in rep["findings"]}
        self.assertIn("RSA", fields)  # rsa-2048 -> RSA
        self.assertIn("ML-KEM (FIPS 203)", rep["inventory"])
        self.assertEqual(rep["inventory"]["AES-128"]["class"],
                         "grover-note")

    def test_dedup_per_file_dan_algoritma(self):
        self._write("a.py", "rsa = 1\nrsa = 2\nrsa = 3\n")
        rc, rep = self._run()
        rsa = [x for x in rep["findings"] if x["field"] == "RSA"]
        self.assertEqual(len(rsa), 1, "dedup per (file, algoritma)")
        self.assertEqual(rep["summary"]["algorithms"], 1)

    def test_jws_alg_names_dipetakan(self):
        self._write("auth.py", 'alg = "RS256"\nalg2 = "ES256"\n'
                               'mac = "HS256"\n')
        rc, rep = self._run()
        fields = {x["field"] for x in rep["findings"]}
        self.assertIn("JWS RS256 (RSA)", fields)
        self.assertIn("JWS ES256 (EC)", fields)
        # HS256 = HMAC (symmetric) -> grover-note, bukan temuan
        self.assertNotIn("JWS HS256 (HMAC-SHA256)", fields)
        self.assertIn("JWS HS256 (HMAC-SHA256)", rep["inventory"])

    def test_weak_legacy_medium(self):
        self._write("hash.py", "digest = md5(data)\n"
                               "cipher = DES.new(k)\n")
        rc, rep = self._run()
        checks = {x["check"] for x in rep["findings"]}
        self.assertEqual(checks, {"weak-legacy-token"})
        self.assertEqual(rep["summary"]["by_severity"]["medium"], 2)

    def test_sufiks_mode_lemah(self):
        self._write("old.conf", "cipher = rc4-md5\ndigest = sha1\n")
        rc, rep = self._run()
        checks = {x["check"] for x in rep["findings"]}
        self.assertEqual(checks, {"weak-legacy-token"})
        self.assertEqual(rep["summary"]["by_severity"]["medium"], 3)
        fields = {x["field"] for x in rep["findings"]}
        self.assertEqual(fields, {"RC4", "MD5", "SHA-1"})

    def test_sha1_dan_sha_dash_1_keduanya(self):
        self._write("h.go", "a := sha1.Sum(b)\n")
        rc, rep = self._run()
        self.assertEqual([x["field"] for x in rep["findings"]],
                         ["SHA-1"])

    def test_pqc_tidak_menjadi_temuan(self):
        self._write("new.py", "kem = ML-KEM-768\nsig = ML-DSA-65\n"
                              "group = X25519MLKEM768\n")
        rc, rep = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(rep["findings"], [])
        self.assertIn("ML-KEM (FIPS 203)", rep["inventory"])
        self.assertIn("hybrid X25519MLKEM768", rep["inventory"])
        self.assertEqual(rep["inventory"]["ML-KEM (FIPS 203)"]["class"],
                         "pqc")

    def test_grover_dicatat_bukan_temuan(self):
        self._write("c.py", "cipher = AES-128-GCM\nsum = sha256(x)\n"
                            "h = sha384(y)\naes256 = True\n")
        rc, rep = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(rep["findings"], [])
        self.assertEqual(rep["inventory"]["AES-128"]["class"],
                         "grover-note")
        # sha384 TIDAK boleh salah kemas sbg SHA-3 (digit-boundary)
        self.assertNotIn("SHA-3", rep["inventory"])
        self.assertIn("SHA-384", rep["inventory"])
        self.assertIn("AES-256", rep["inventory"])

    def test_hybrid_tidak_salah_kemas_x25519(self):
        # token hybrid utuh dikenali sbg pqc; x25519 telanjang tetap shor
        self._write("n.conf",
                    "ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;\n")
        rc, rep = self._run()
        fields = {x["field"] for x in rep["findings"]}
        self.assertNotIn("hybrid X25519MLKEM768", fields)
        self.assertIn("X25519 (klasik, non-hybrid)", fields)
        self.assertIn("secp256r1/P-256", fields)


class TestAntiFP(Base):
    def test_kata_bertempel_tidak_kena(self):
        self._write("w.py", "rsaparam = 1\necdhx = 2\nsha1hash = 3\n"
                            "md5sum_tool = 4\nbuckets = 5\n")
        rc, rep = self._run()
        self.assertEqual(rc, 0, "token harus kata-utuh")

    def test_variabel_umum_tidak_kena(self):
        self._write("clean.py", "diff = a - b\ncache = {}\n"
                                "des_list = []\n"
                                "idea_text = 'gagasan'\n"
                                "falcon_app = True\nlms_id = 3\n")
        rc, rep = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(rep["findings"], [])

    def test_ukuran_kunci_aes_dengan_digit(self):
        self._write("c.conf", "cipher = AES256-GCM\n")
        rc, rep = self._run()
        # "AES256" bukan token tabel (aes-128/aes/aes128) — tak kena
        self.assertEqual(rep["findings"], [])


class TestMosca(Base):
    def test_prioritas_bila_lewat_garis(self):
        self._write("a.py", "rsa = 1\n")
        rc, rep = self._run("--data-lifetime-years", "15",
                            "--crqc-years", "10",
                            "--migration-years", "2")
        self.assertTrue(rep["mosca"]["hndl_priority"])
        self.assertIn("HNDL", rep["notes"][0])

    def test_tanpa_prioritas_tetap_dicatat(self):
        self._write("a.py", "rsa = 1\n")
        rc, rep = self._run("--data-lifetime-years", "5")
        self.assertFalse(rep["mosca"]["hndl_priority"])
        self.assertIn("jangan diabaikan", rep["notes"][0])

    def test_tanpa_argumen_catatan(self):
        self._write("a.py", "rsa = 1\n")
        rc, rep = self._run()
        self.assertIsNone(rep["mosca"])
        self.assertTrue(any("Mosca tidak dihitung" in n
                            for n in rep["notes"]))


class TestFileHandling(Base):
    def test_biner_dilewati_dan_dihitung(self):
        self._write("bin.dat", "ok")
        (self.root / "bin.dat").write_bytes(b"\x00\x01\x02" + b"x" * 100)
        rc, rep = self._run()
        self.assertEqual(rep["summary"]["skipped_binary"], 1)
        self.assertTrue(any("biner" in n for n in rep["notes"]))

    def test_max_bytes(self):
        self._write("big.txt", "rsa = 1\n" * 400000)  # ~2.8MB
        rc, rep = self._run("--max-bytes", "1000")
        self.assertEqual(rep["summary"]["skipped_size"], 1)
        self.assertEqual(rep["summary"]["files_scanned"], 0)
        self.assertTrue(any("BUKAN kebersihan" in n for n in rep["notes"]))

    def test_subdirektori_dijalankan(self):
        self._write("sub/a.py", "sig = ecdsa.sign(msg)\n")
        self._write("sub/deep/b.py", "data = rc4(key, x)\n")
        rc, rep = self._run()
        self.assertEqual(rep["summary"]["files_scanned"], 2)
        self.assertEqual(rep["summary"]["findings"], 2)

    def test_pem_key_diarahkan_bukan_temuan(self):
        self._write("key.pem",
                    "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n"
                    "-----END RSA PRIVATE KEY-----\n")
        rc, rep = self._run()
        self.assertEqual([x for x in rep["findings"] if "PEM" in
                          x["check"]], [])
        self.assertTrue(any("repo_secret_scan" in n
                            for n in rep["notes"]))

    def test_path_hilang_exit_2(self):
        rc = cis.main(["--scan", str(self.root / "nope")])
        self.assertEqual(rc, 2)

    def test_tanpa_scan_exit_2(self):
        rc = cis.main([])
        self.assertEqual(rc, 2)


class TestAllow(Base):
    def test_allow_alg(self):
        self._write("a.py", "rsa = 1\nmd5 = 2\n")
        out = self.root / "_out.json"
        rc = cis.main(["--scan", str(self.root), "--allow-alg", "rsa",
                       "--out", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual([x["field"] for x in rep["findings"]], ["MD5"])
        self.assertTrue(any("rsa" in n for n in rep["notes"]))

    def test_allow_check(self):
        self._write("a.py", "rsa = 1\n")
        out = self.root / "_out.json"
        rc = cis.main(["--scan", str(self.root),
                       "--allow-check", "asym-shor-token",
                       "--out", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertEqual(rep["findings"], [])
        self.assertIn("asym-shor-token", " ".join(rep["notes"]))


if __name__ == "__main__":
    unittest.main()
