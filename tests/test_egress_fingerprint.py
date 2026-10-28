"""Test skill egress-fingerprint-check — NOL jaringan (echo di-mock).

Pola yang diuji (dari review bridge): konsistensi lintas lapisan UA vs
OS host, proxy env vs kemampuan stack, redaksi kredensial sebelum
output, dan echo differential (dikirim vs dilihat server) — zero-FP.
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
sys.path.insert(0, str(ROOT / "tools"))

import egress_fingerprint_check as efc  # noqa: E402
import ua as ua_mod  # noqa: E402
from findings import validate_finding  # noqa: E402


def all_valid(rows):
    return all(validate_finding(r) == [] for r in rows)


class ConfigAuditTest(unittest.TestCase):
    def test_returns_two_tuple_and_valid_rows(self):
        with patch.dict("os.environ", {}, clear=False):
            for k in ("CYPHRON_UA", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
                __import__("os").environ.pop(k, None)
            rows, meta = efc.audit(None, None)
        self.assertIsInstance(rows, list)
        self.assertIsInstance(meta, dict)
        self.assertTrue(all_valid(rows))
        self.assertEqual(meta["requests"], 0)

    def test_ua_inventory_is_l0(self):
        rows, meta = efc.audit(None, None)
        inv = [r for r in rows if "Egress UA aktif" in r["title"]]
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0]["verdict"], 0)
        self.assertEqual(inv[0]["category"], "EGRESS")

    def test_browser_ua_on_mismatched_os_is_lead(self):
        # lesi lintas-lapisan dari review: UA Chrome Windows di host lain
        with patch.dict("os.environ", {"CYPHRON_UA": "browser"}), \
                patch.object(efc.platform, "system", return_value="Linux"):
            rows, _ = efc.audit(None, None)
        hits = [r for r in rows if "tidak cocok OS host" in r["title"]]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["verdict"], 1, "lead, bukan klaim")
        self.assertTrue(all_valid(rows))

    def test_browser_ua_on_windows_is_aman(self):
        with patch.dict("os.environ", {"CYPHRON_UA": "browser"}), \
                patch.object(efc.platform, "system",
                             return_value="Windows"):
            rows, _ = efc.audit(None, None)
        self.assertFalse([r for r in rows if "tidak cocok OS host"
                          in r["title"]])

    def test_proxy_url_redacted_in_rows_and_meta(self):
        with patch.dict("os.environ",
                        {"HTTPS_PROXY": "http://user:rahasia@10.9.9.9:8128"}):
            rows, meta = efc.audit(None, None)
        blob = json.dumps([rows, meta])
        self.assertNotIn("rahasia", blob, "kredensial tidak boleh bocor")
        self.assertIn("***@10.9.9.9:8128", blob)
        self.assertEqual(meta["proxies"]["HTTPS_PROXY"],
                         "http://***@10.9.9.9:8128")

    def test_invalid_proxy_scheme_is_lead(self):
        with patch.dict("os.environ", {"ALL_PROXY": "ftp://10.0.0.1:21"}):
            rows, _ = efc.audit(None, None)
        hits = [r for r in rows if "scheme tidak didukung" in r["title"]]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["verdict"], 1)

    def test_socks5_without_pysocks_is_lead(self):
        # ua.py fail-loud (stderr); skill ini mengangkatnya jadi temuan
        builtins = __import__("builtins")
        real_import = builtins.__import__

        def no_socks(name, *a, **kw):
            if name == "socks":
                raise ImportError("no socks")
            return real_import(name, *a, **kw)

        with patch.dict("os.environ", {"ALL_PROXY": "socks5://10.1.1.1:1080"}), \
                patch("builtins.__import__", side_effect=no_socks):
            rows, meta = efc.audit(None, None)
        hits = [r for r in rows if "tanpa PySocks" in r["title"]]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "medium")
        self.assertFalse(meta["pysocks"])
        self.assertTrue(all_valid(rows))


class EchoTest(unittest.TestCase):
    def test_echo_match_is_aman(self):
        res = {"status": 200, "headers": {"user-agent": ua_mod.DEFAULT_UA},
               "seen_ua": ua_mod.DEFAULT_UA}
        rows, meta = efc.audit("http://lab.local/headers", res)
        hit = [r for r in rows if "sama dengan yang dikirim" in r["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["verdict"], 0)
        self.assertEqual(meta["requests"], 1)

    def test_echo_mismatch_is_reproduced(self):
        res = {"status": 200, "headers": {"user-agent": "Other/1.0"},
               "seen_ua": "Other/1.0"}
        rows, _ = efc.audit("http://lab.local/headers", res)
        hit = [r for r in rows if "BERBEDA" in r["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["verdict"], 2, "differential = reproduced")
        self.assertEqual(hit[0]["severity"], "medium")

    def test_non_echo_target_no_claim(self):
        # respons tidak memuat UA -> info unconfirmed, bukan klaim
        res = {"status": 200, "headers": {"content-type": "text/html"},
               "seen_ua": None}
        rows, _ = efc.audit("http://lab.local/", res)
        hit = [r for r in rows if "tidak memuat echo" in r["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["verdict"], 1)
        self.assertEqual(hit[0]["status"], "unconfirmed")

    def test_echo_error_no_claim(self):
        res = {"status": None, "headers": {},
               "error": "__error__ URLError: refused"}
        rows, meta = efc.audit("http://lab.local/headers", res)
        hit = [r for r in rows if "tidak bisa diverifikasi" in r["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["status"], "unconfirmed")
        # header respons echo ikut ter-redaksi di meta
        self.assertEqual(meta["echo"]["headers"], {})


class RedactIntegrationTest(unittest.TestCase):
    def test_sensitive_headers_hashed(self):
        from redact import redact_headers
        h = redact_headers({"cookie": "SID=abc", "accept": "*/*"})
        self.assertTrue(h["cookie"].startswith("[REDACTED sha256:"))
        self.assertEqual(h["accept"], "*/*")
        # deterministik: nilai sama -> penanda sama
        self.assertEqual(h["cookie"], redact_headers(
            {"cookie": "SID=abc"})["cookie"])

    def test_redact_url_userinfo_and_query(self):
        from redact import redact_url
        out = redact_url("http://u:p@host:9/x?token=abc&q=1")
        self.assertIn("***@host:9", out)
        self.assertNotIn("abc", out)
        self.assertIn("q=1", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
