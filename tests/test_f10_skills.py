"""Test F10 — skill breadth baru: ssl_tls, cors, redirect, rdap, js_endpoints.

Logika dites dengan fakta di-mock (nol jaringan); parser & verdict
ladder yang diuji, bukan konektivitas.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import ssl_tls_analyzer as ssla  # noqa: E402
import cors_checker as cors  # noqa: E402
import redirect_chain as rch  # noqa: E402
import rdap_whois as rd  # noqa: E402
import js_endpoints as jsx  # noqa: E402
import banner_posture as bp  # noqa: E402


class SslTlsTest(unittest.TestCase):
    def _facts(self, proto="TLSv1.3", info=None):
        return {"ok": True, "protocol": proto, "cipher": "TLS_AES_256_GCM",
                "pem": "", "cert_info": info or {}}

    def test_weak_protocol_is_lead(self):
        rows, _ = ssla.audit("lab.id", self._facts(proto="TLSv1.1"))
        weak = [r for r in rows if "Weak TLS" in r["title"]]
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0]["verdict"], 1)
        self.assertEqual(weak[0]["cwe"], "CWE-327")

    def test_modern_protocol_aman(self):
        rows, _ = ssla.audit("lab.id", self._facts())
        aman = [r for r in rows if r.get("category") == "AMAN"]
        self.assertTrue(any("TLS protocol OK" in r["title"] for r in aman))

    def test_expired_cert_high(self):
        import time
        info = {"not_after_s": time.time() - 86400 * 5, "subject": {"CN": "x"},
                "issuer": {"CN": "ca"}, "san_count": 2}
        rows, _ = ssla.audit("lab.id", self._facts(info=info))
        exp = [r for r in rows if "EXPIRED" in r["title"]]
        self.assertEqual(len(exp), 1)
        self.assertEqual(exp[0]["severity"], "high")

    def test_self_signed_lead(self):
        info = {"not_after_s": 0, "subject": {"CN": "same"},
                "issuer": {"CN": "same"}, "san_count": 0}
        rows, _ = ssla.audit("lab.id", self._facts(info=info))
        self.assertTrue(any("Self-signed" in r["title"] for r in rows))

    def test_handshake_failure_fail_closed(self):
        rows, meta = ssla.audit("lab.id", {"ok": False, "error": "refused"})
        self.assertTrue(meta["error"])
        self.assertEqual(rows[0]["status"], "unconfirmed")


class CorsTest(unittest.TestCase):
    def test_reflect_origin_with_credentials_high(self):
        res = {"status": 200, "headers": {
            "access-control-allow-origin": "https://evil-probe.example",
            "access-control-allow-credentials": "true"}}
        rows, _ = cors.audit("https://lab.id/api", res)
        bad = [r for r in rows if "WITH credentials" in r["title"]]
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0]["severity"], "high")
        self.assertEqual(bad[0]["cwe"], "CWE-942")
        self.assertEqual(bad[0]["verdict"], 1)

    def test_reflect_without_credentials_low(self):
        res = {"status": 200, "headers": {
            "access-control-allow-origin": "https://evil-probe.example",
            "access-control-allow-credentials": "false"}}
        rows, _ = cors.audit("https://lab.id/api", res)
        self.assertTrue(any("no credentials" in r["title"] for r in rows))

    def test_no_cors_aman(self):
        rows, _ = cors.audit("https://lab.id/", {"status": 200, "headers": {}})
        self.assertEqual(rows[0]["category"], "AMAN")

    def test_wildcard_info_not_lead(self):
        res = {"status": 200, "headers": {"access-control-allow-origin": "*"}}
        rows, _ = cors.audit("https://lab.id/", res)
        self.assertEqual(rows[0]["verdict"], 0)


class RedirectTest(unittest.TestCase):
    def test_https_downgrade_detected(self):
        res = {"hops": [
            {"hop": 0, "url": "https://lab.id/", "status": 301,
             "location": "http://lab.id/login"},
            {"hop": 1, "url": "http://lab.id/login", "status": 200,
             "location": None}],
            "final": "http://lab.id/login", "loop": False, "truncated": False}
        rows, _ = rch.audit("https://lab.id/", res)
        down = [r for r in rows if "downgrade" in r["title"]]
        self.assertEqual(len(down), 1)
        self.assertEqual(down[0]["verdict"], 1)
        self.assertEqual(down[0]["cwe"], "CWE-319")

    def test_loop_detected(self):
        res = {"hops": [
            {"hop": 0, "url": "http://lab.id/a", "status": 302,
             "location": "http://lab.id/b"},
            {"hop": 1, "url": "http://lab.id/b", "status": 302,
             "location": "http://lab.id/a"}],
            "final": "http://lab.id/a", "loop": True, "truncated": False}
        rows, _ = rch.audit("http://lab.id/a", res)
        self.assertTrue(any("LOOP" in r["title"] for r in rows))


class RdapTest(unittest.TestCase):
    def _doc(self, expired=False):
        import time
        exp = time.time() - 86400 if expired else time.time() + 86400 * 90
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp))
        return {"events": [{"eventAction": "expiration",
                            "eventDate": iso}],
                "status": ["client transferProhibited"],
                "nameservers": [{"ldhName": "ns1.example.id"}]}

    def test_expired_domain_high(self):
        rows, _ = rd.audit("lab.id", self._doc(expired=True))
        exp = [r for r in rows if "EXPIRED" in r["title"]]
        self.assertEqual(len(exp), 1)
        self.assertEqual(exp[0]["severity"], "high")

    def test_transfer_locked_aman(self):
        rows, _ = rd.audit("lab.id", self._doc())
        aman = [r for r in rows if r.get("category") == "AMAN"]
        self.assertTrue(any("transfer-locked" in r["title"] for r in aman))


class JsEndpointsTest(unittest.TestCase):
    HTML = """
    <script src="/static/app.js"></script>
    <script>fetch("/api/v1/users", {headers:{"Authorization":"Bearer abcdef12345"}})</script>
    <form action="/api/v1/login"></form>
    <script>var pk_live_1234567890 = "pk_live_abcdefgh12";</script>
    """

    def test_surface_extracted_zero_requests(self):
        rows, meta = jsx.audit("https://lab.id/", self.HTML)
        self.assertEqual(meta["requests"], 0)
        surf = rows[0]
        self.assertEqual(surf["verdict"], 0)
        self.assertEqual(surf["scripts"], ["https://lab.id/static/app.js"])
        self.assertIn("/api/v1/users", surf["api_paths"])

    def test_secret_like_is_lead_not_claim(self):
        rows, _ = jsx.audit("https://lab.id/", self.HTML)
        secrets = [r for r in rows if "Secret-like" in r["title"]]
        self.assertEqual(len(secrets), 1)  # regex konservatif: Bearer+spasi tidak dipicu (anti-FP)
        for r in secrets:
            self.assertEqual(r["status"], "unconfirmed")  # LEAD, bukan klaim
            self.assertEqual(r["verdict"], 1)
            self.assertEqual(r["cwe"], "CWE-798")


class BannerCookieTest(unittest.TestCase):
    def test_cookie_missing_flags_lead(self):
        res = {"status": 200, "headers": {},
               "set_cookies": ["SID=abc123; Path=/; HttpOnly"],
               "body": "ok"}
        rows, _ = bp.audit("https://lab.id/", res)
        cookies = [r for r in rows if "Cookie without security flags" in r["title"]]
        self.assertEqual(len(cookies), 1)
        self.assertIn("SECURE", cookies[0]["title"])
        self.assertIn("SAMESITE", cookies[0]["title"])
        self.assertEqual(cookies[0]["verdict"], 1)
        self.assertEqual(cookies[0]["cwe"], "CWE-614")

    def test_cookie_all_flags_aman(self):
        res = {"status": 200, "headers": {},
               "set_cookies": ["SID=abc123; Secure; HttpOnly; SameSite=Strict"],
               "body": "ok"}
        rows, _ = bp.audit("https://lab.id/", res)
        ok = [r for r in rows if "Cookie flags OK" in r["title"]]
        self.assertEqual(len(ok), 1)
        self.assertEqual(ok[0]["category"], "AMAN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
