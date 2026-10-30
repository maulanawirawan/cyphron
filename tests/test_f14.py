"""Test F14 — payload lab + deep decode + security.txt (logika, nol jaringan).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import payload_lab as pl  # noqa: E402
import deep_decode as dd  # noqa: E402
import security_txt as st  # noqa: E402


class PayloadLabTest(unittest.TestCase):
    def test_pack_deterministic_by_seed(self):
        a = pl.build_pack(["sqli"], ["url"], "seed-1")
        b = pl.build_pack(["sqli"], ["url"], "seed-1")
        self.assertEqual(a["sqli"][0]["id"], b["sqli"][0]["id"])
        c = pl.build_pack(["sqli"], ["url"], "seed-2")
        self.assertNotEqual(a["sqli"][0]["id"], c["sqli"][0]["id"])

    def test_encoder_chains(self):
        self.assertEqual(pl.encode_chain("<x>", ["url"]), "%3Cx%3E")
        self.assertEqual(pl.encode_chain("a b", ["url", "url"]), "a%2520b")
        import base64
        self.assertEqual(pl.encode_chain("hi", ["base64"]),
                         base64.b64encode(b"hi").decode())

    def test_all_classes_have_payloads(self):
        pack = pl.build_pack(list(pl.PAYLOADS.keys()), ["url"], "s")
        for cls in pl.PAYLOADS:
            self.assertGreater(len(pack[cls]), 0)


class DeepDecodeTest(unittest.TestCase):
    def test_base64_single_layer(self):
        import base64
        r = dd.deep_decode(base64.b64encode(b"secret text 123").decode())
        self.assertEqual(r["layers"][0]["method"], "base64")
        self.assertEqual(r["final"], "secret text 123")

    def test_nested_base64_two_layers(self):
        import base64
        inner = base64.b64encode(b"inner payload").decode()
        outer = base64.b64encode(inner.encode()).decode()
        r = dd.deep_decode(outer)
        self.assertEqual(r["final"], "inner payload")
        self.assertEqual(r["depth_reached"], 2)

    def test_gzip_base64(self):
        import base64, gzip
        gz = gzip.compress(b"deep hidden data")
        r = dd.deep_decode(base64.b64encode(gz).decode())
        self.assertEqual(r["layers"][0]["method"], "gzip+base64")
        self.assertEqual(r["final"], "deep hidden data")

    def test_url_encoded(self):
        r = dd.deep_decode("admin%40mail.com%3Fdebug%3D1")
        self.assertEqual(r["final"], "admin@mail.com?debug=1")

    def test_unicode_and_charcode(self):
        r1 = dd.deep_decode(r"\u0041\u0042")
        self.assertEqual(r1["final"], "AB")
        r2 = dd.deep_decode("String.fromCharCode(72,73)")
        self.assertEqual(r2["final"], "HI")

    def test_jwt_decoded_unverified(self):
        import base64
        h = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
        p = base64.urlsafe_b64encode(b'{"user":"x"}').decode().rstrip("=")
        r = dd.deep_decode(f"{h}.{p}.sig")
        self.assertEqual(r["layers"][-1]["method"], "jwt")
        self.assertIn("payload", r["final"])
        self.assertIn("TIDAK diverifikasi", r["final"])

    def test_plain_text_stops_immediately(self):
        r = dd.deep_decode("hanya teks biasa tanpa enkode apapun")
        self.assertEqual(r["depth_reached"], 0)


class SecurityTxtTest(unittest.TestCase):
    def test_parse_rfc9116_fields(self):
        body = ("Contact: mailto:security@example.id\n"
                "Contact: https://example.id/report\n"
                "Policy: https://example.id/policy\n"
                "Preferred-Languages: id, en\n")
        f = st.parse(body)
        self.assertEqual(len(f["contact"]), 2)
        self.assertIn("policy", f)
        self.assertEqual(f["preferred-languages"], ["id, en"])

    def test_audit_found(self):
        body = "Contact: mailto:security@example.id\nPolicy: https://x/p\n"
        with patch.object(st, "fetch", side_effect=[body, None]):
            rows, meta = st.audit("example.id")
        self.assertTrue(meta["found"])
        self.assertEqual(meta["path"], "/.well-known/security.txt")
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertIn("security@example.id", str(rows[0]["contact"]))

    def test_audit_not_found_lead(self):
        with patch.object(st, "fetch", return_value=None):
            rows, meta = st.audit("example.id")
        self.assertFalse(meta["found"])
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertEqual(meta["requests"], 2)  # dua path standar saja


if __name__ == "__main__":
    unittest.main(verbosity=2)
