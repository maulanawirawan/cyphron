"""Nol jaringan — test cert_chain_audit (auditor rantai sertifikat X.509 offline).

Fixture = sertifikat lab statis di tests/fixtures/b12/ (dibuat sekali via
lib cryptography + openssl saat dev; tool-nya sendiri stdlib murni dan
hanya membaca file). --now dipatok agar deterministik.
"""
from __future__ import annotations

import datetime
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import cert_chain_audit as cca  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "b12"
NOW = "2026-11-08T13:00:00Z"  # setelah notBefore semua fixture


def _iso_now(iso: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))


def pem(*names: str) -> bytes:
    return b"".join((FIX / n).read_bytes() for n in names)


def lint_bytes(data: bytes, now=NOW):
    return cca.lint_source(data, "test.pem", _iso_now(now))


def checks(fnds):
    return {f["check"] for f in fnds}


class TestChain(unittest.TestCase):
    """Nol jaringan — cek level rantai."""

    def test_bersih_hanya_info_wajar(self):
        fnds, meta = lint_bytes(pem("leaf.pem", "inter.pem", "root.pem"))
        self.assertFalse([f for f in fnds if f["severity"] in ("high", "medium")],
                         msg=str(fnds))
        self.assertEqual(meta["certs"], 3)
        self.assertNotIn("tanpa-revokasi", checks(fnds))

    def test_pathlen_langgar(self):
        fnds, _ = lint_bytes(pem("leaf_p0.pem", "inter_p0.pem", "root_p0.pem"))
        self.assertIn("pathlen-langgar", checks(fnds))
        self.assertTrue(any(f["severity"] == "high" and f["check"] == "pathlen-langgar"
                            for f in fnds))

    def test_chain_order_putus(self):
        # leaf diikuti root langsung (intermediate hilang)
        fnds, _ = lint_bytes(pem("leaf.pem", "root.pem"))
        self.assertIn("chain-order", checks(fnds))

    def test_leaf_ca_true(self):
        fnds, _ = lint_bytes(pem("cata.pem", "inter.pem", "root.pem"))
        self.assertIn("leaf-ca-true", checks(fnds))

    def test_single_cert_tanpa_cek_rantai(self):
        fnds, meta = lint_bytes(pem("leaf.pem"))
        self.assertEqual(meta["certs"], 1)
        for chain_check in ("chain-order", "leaf-ca-true", "tanpa-revokasi",
                            "ca-tanpa-bc", "self-signed-tengah"):
            self.assertNotIn(chain_check, checks(fnds), msg=fnds)


class TestPerCert(unittest.TestCase):
    """Nol jaringan — cek per sertifikat."""

    def test_kedaluwarsa(self):
        fnds, _ = lint_bytes(pem("expired.pem", "inter.pem", "root.pem"))
        self.assertIn("kedaluwarsa", checks(fnds))

    def test_belum_berlaku(self):
        fnds, _ = lint_bytes(pem("future.pem", "inter.pem", "root.pem"),
                             now="2026-11-08T13:00:00Z")
        self.assertIn("belum-berlaku", checks(fnds))

    def test_sig_lemah_sha1(self):
        fnds, _ = lint_bytes(pem("sha1_leaf.pem", "inter.pem", "root.pem"))
        self.assertIn("sig-lemah", checks(fnds))
        self.assertTrue(any("sha1" in f["message"].lower() for f in fnds))

    def test_sig_lemah_self_signed_info(self):
        # SHA-1 pada self-signature root: tidak divalidasi dalam jalur chain
        fnds, _ = lint_bytes(pem("sha1_self.pem"))
        self.assertIn("sig-lemah", checks(fnds))
        self.assertTrue(all(f["severity"] == "info"
                            for f in fnds if f["check"] == "sig-lemah"))

    def test_rsa_pendek(self):
        fnds, _ = lint_bytes(pem("rsa1024.pem", "inter.pem", "root.pem"))
        self.assertIn("rsa-pendek", checks(fnds))
        self.assertTrue(any("1024" in f["message"] for f in fnds))

    def test_ec_kecil(self):
        fnds, _ = lint_bytes(pem("ec224.pem", "inter.pem", "root.pem"))
        self.assertIn("ec-kecil", checks(fnds))

    def test_masa_panjang_info(self):
        fnds, _ = lint_bytes(pem("long_leaf.pem", "inter.pem", "root.pem"))
        self.assertIn("masa-berlaku-panjang", checks(fnds))
        self.assertTrue(all(f["severity"] == "info"
                            for f in fnds if f["check"] == "masa-berlaku-panjang"))

    def test_tanpa_revokasi_info(self):
        fnds, _ = lint_bytes(pem("leaf_nocrl.pem", "inter.pem", "root.pem"))
        self.assertIn("tanpa-revokasi", checks(fnds))
        # leaf dengan CRL DP + OCSP tidak di-flag
        fnds2, _ = lint_bytes(pem("leaf.pem", "inter.pem", "root.pem"))
        self.assertNotIn("tanpa-revokasi", checks(fnds2))

    def test_serial_lemah(self):
        fnds, _ = lint_bytes(pem("short_serial.pem", "inter.pem", "root.pem"))
        self.assertIn("serial-lemah", checks(fnds))
        self.assertTrue(any(f["severity"] == "medium" for f in fnds))

    def test_serial_negatif_via_der_patch(self):
        # patch serial INTEGER 12345 (0x3039) -> nilai negatif (high bit set)
        der_text = (FIX / "short_serial.pem").read_text()
        import base64
        body = "".join(l for l in der_text.splitlines() if "-----" not in l)
        der = bytearray(base64.b64decode(body))
        cert = cca.Cert(bytes(der), "s")
        self.assertFalse(cert.serial_neg)
        # cari TLV serial: anak kedua TBS (setelah [0] version)
        tag, vpos, vlen = cca._read_tlv(der, 0)
        kids = cca._children(der, vpos, vpos + vlen)
        tbs = kids[0]
        tkids = cca._children(der, tbs[1], tbs[1] + tbs[2])
        stag, spos, slen = tkids[1]
        self.assertEqual(stag, 0x02)
        der[spos] |= 0x80  # set bit tanda -> negatif
        pem_txt = ("-----BEGIN CERTIFICATE-----\n"
                   + base64.encodebytes(bytes(der)).decode()
                   + "-----END CERTIFICATE-----")
        fnds, _ = lint_bytes(pem_txt.encode())
        self.assertIn("serial-lemah", checks(fnds))
        self.assertTrue(any("negatif" in f["message"] for f in fnds))


class TestFailClosed(unittest.TestCase):
    """Nol jaringan — parse gagal tidak pernah dihitung bersih."""

    def test_pem_terpotong(self):
        fnds, meta = lint_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB\n")
        self.assertEqual(checks(fnds), {"file-unparsed"})
        self.assertEqual(fnds[0]["severity"], "high")
        self.assertTrue(meta["unparsed"])

    def test_der_rusak(self):
        fnds, _ = lint_bytes(b"\x30\x10\xff\xff\xff\xff")
        self.assertIn("file-unparsed", checks(fnds))

    def test_garbage_bytes(self):
        fnds, _ = lint_bytes(b"garbage-not-pem-not-der")
        self.assertIn("file-unparsed", checks(fnds))

    def test_kunci_tak_dikenal_info(self):
        # DSA (di luar peta RSA/EC) -> info kunci-tak-dikenal, bukan temuan pasti
        fnds, _ = lint_bytes(pem("dsa.pem"))
        self.assertIn("kunci-tak-dikenal", checks(fnds))
        self.assertTrue(all(f["severity"] == "info"
                            for f in fnds if f["check"] == "kunci-tak-dikenal"))


class TestCLI(unittest.TestCase):
    """Nol jaringan — exit codes + JSON out + direktori."""

    def _run(self, argv):
        return cca.main(argv)

    def test_exit_bersih(self):
        chain = self._tmp_chain("leaf.pem", "inter.pem", "root.pem")
        self.assertEqual(self._run(["--source", str(chain), "--now", NOW]), 0)

    def test_exit_fail_on_medium(self):
        chain = self._tmp_chain("leaf.pem", "inter.pem", "root.pem")
        # rantai bersih hanya info -> fail-on medium tetap 0
        self.assertEqual(self._run(["--source", str(chain), "--now", NOW,
                                    "--fail-on", "medium"]), 0)
        broken = self._tmp_chain("leaf.pem", "root.pem")
        self.assertEqual(self._run(["--source", str(broken), "--now", NOW]), 1)

    def test_exit_input_error(self):
        self.assertEqual(self._run(["--source", str(FIX / "tidak-ada.pem")]), 2)
        self.assertEqual(self._run(["--source", str(FIX / "tidak-ada.pem"),
                                    "--now", "bukan-iso"]), 2)

    def test_json_out_dan_direktori(self):
        import tempfile
        out = Path(tempfile.mkdtemp())
        jf = out / "hasil.json"
        self.assertEqual(self._run(["--source", str(FIX), "--json", str(jf),
                                    "--now", NOW]), 1)
        data = json.loads(jf.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "secai.cert-chain-audit/1")
        self.assertGreater(data["summary"]["files"], 5)
        self.assertGreater(data["summary"]["high"], 0)

    def _tmp_chain(self, *names: str) -> Path:
        import tempfile
        d = Path(tempfile.mkdtemp())
        f = d / "chain.pem"
        f.write_bytes(pem(*names))
        return f


if __name__ == "__main__":
    unittest.main()
