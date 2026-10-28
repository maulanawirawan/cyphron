"""Test kanonik F18 — golden marker + fail-closed, 2 test per skill.

Aturan main:
  - NOL jaringan: semua input di-mock (headers dict, html string,
    dokumen DoH/fetch hasil injeksi).
  - GOLDEN: marker klasik yang WAJIB terdeteksi (temuan tepat dengan
    verdict/severity/cwe yang diharapkan).
  - FAIL-CLOSED: input kosong/gagal TIDAK boleh menghasilkan klaim
    palsu — hanya AMAN L0 (inventaris) atau info unconfirmed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import clickjacking_protection_checker as cj      # noqa: E402
import cache_control_posture as cc                 # noqa: E402
import xss_protection_header_checker as xssprot    # noqa: E402
import cdn_detector as cdn                         # noqa: E402
import waf_fingerprint as waf                      # noqa: E402
import http2_support_checker as h2c                # noqa: E402
import http_method_allow_checker as hma            # noqa: E402
import port_banner_consistency_checker as pbc      # noqa: E402
import cookie_flags_aggregate as ckf               # noqa: E402
import hsts_preload_checker as hsts                # noqa: E402
import server_version_disclosure as svd            # noqa: E402
import http_security_headers as hsh                # noqa: E402
import csp_analyzer as cspa                        # noqa: E402
import sri_checker as sri                          # noqa: E402
import mixed_content_detector as mxd               # noqa: E402
import sourcemap_exposure_checker as smap          # noqa: E402
import directory_listing_detector as dld           # noqa: E402
import form_csrf_checker as fcsrf                  # noqa: E402
import password_autocomplete_checker as pwac       # noqa: E402
import tech_fingerprint as tfp                     # noqa: E402
import graphql_surface_detector as gql             # noqa: E402
import open_redirect_surface as ored               # noqa: E402
import js_library_version_checker as jlv           # noqa: E402
import ct_inventory as cti                         # noqa: E402
import takeover_cname_hygiene as tch               # noqa: E402
import subdomain_enum_surface as ses               # noqa: E402
import robots_txt_surface as rbt                   # noqa: E402
import tls_cipher_suites_checker as tcs            # noqa: E402
import security_txt as stx                         # noqa: E402

URL = "https://lab.local/"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


# ---------------------------------------------------------------------------
# Keluarga header — evidence headers (audit(url, headers))
# ---------------------------------------------------------------------------

class ClickjackingTest(unittest.TestCase):
    def test_golden_absent_is_lead_cwe1021(self):
        rows, _ = cj.audit(URL, {})
        f = one(rows, "Clickjacking protection absent")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-1021")

    def test_fail_closed_present_is_aman(self):
        rows, _ = cj.audit(URL, {"X-Frame-Options": "DENY"})
        f = one(rows, "Clickjacking protection present")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(f["category"], "AMAN")


class CacheControlTest(unittest.TestCase):
    def test_golden_absent_is_lead(self):
        rows, _ = cc.audit(URL, {})
        f = one(rows, "Cache-Control absent")
        self.assertEqual(f["verdict"], 1)

    def test_fail_closed_present_is_aman(self):
        rows, _ = cc.audit(URL, {"Cache-Control": "no-store"})
        f = one(rows, "Cache-Control present")
        self.assertEqual(f["verdict"], 0)


class XssProtectionHeaderTest(unittest.TestCase):
    def test_golden_absent_is_lead(self):
        rows, _ = xssprot.audit(URL, {})
        self.assertEqual(one(rows, "X-XSS-Protection absent")["verdict"], 1)

    def test_fail_closed_present_is_aman(self):
        rows, _ = xssprot.audit(URL, {"X-XSS-Protection": "1; mode=block"})
        self.assertEqual(one(rows, "X-XSS-Protection present")["verdict"], 0)


class CdnDetectorTest(unittest.TestCase):
    def test_golden_cfray_present_is_surface(self):
        rows, meta = cdn.audit(URL, {"CF-Ray": "abc123-SIN"})
        f = one(rows, "CDN header present")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(meta["checked"], "cf-ray")

    def test_fail_closed_absent_is_not_lead(self):
        rows, _ = cdn.audit(URL, {})
        f = one(rows, "CDN header absent")
        self.assertEqual(f["verdict"], 0, "tanpa CDN bukan kelemahan")
        self.assertEqual(f["category"], "SURFACE")


class WafFingerprintTest(unittest.TestCase):
    def test_golden_sucuri_present_is_surface(self):
        rows, _ = waf.audit(URL, {"X-Sucuri-ID": "15008"})
        self.assertEqual(one(rows, "WAF header present")["verdict"], 0)

    def test_fail_closed_absent_is_not_lead(self):
        rows, _ = waf.audit(URL, {})
        f = one(rows, "WAF header absent")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(f["category"], "SURFACE")


class Http2SupportTest(unittest.TestCase):
    def test_golden_altsvc_present(self):
        rows, _ = h2c.audit(URL, {"alt-svc": 'h2=":443"; ma=86400'})
        self.assertEqual(one(rows, "HTTP/2 hint present")["verdict"], 0)

    def test_fail_closed_absent_is_not_lead(self):
        rows, _ = h2c.audit(URL, {})
        self.assertEqual(one(rows, "HTTP/2 hint absent")["verdict"], 0)


class HttpMethodAllowTest(unittest.TestCase):
    def test_golden_allow_present(self):
        rows, meta = hma.audit(URL, {"Allow": "GET, POST"})
        self.assertEqual(one(rows, "Allow header present")["verdict"], 0)
        self.assertEqual(meta["checked"], "allow")

    def test_fail_closed_absent_is_not_lead(self):
        rows, _ = hma.audit(URL, {})
        self.assertEqual(one(rows, "Allow header absent")["verdict"], 0)


class PortBannerConsistencyTest(unittest.TestCase):
    def test_golden_server_banner_present(self):
        rows, _ = pbc.audit(URL, {"Server": "cloudflare"})
        self.assertEqual(one(rows, "Server banner present")["verdict"], 0)

    def test_fail_closed_absent_is_not_lead(self):
        rows, _ = pbc.audit(URL, {})
        self.assertEqual(one(rows, "Server banner absent")["verdict"], 0)


class CookieFlagsTest(unittest.TestCase):
    def test_golden_missing_flags_is_lead_cwe614(self):
        rows, _ = ckf.audit(URL, {"Set-Cookie": "sid=abc123; Path=/"})
        f = one(rows, "Cookie flags missing")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-614")
        self.assertIn("secure", f["missing"])

    def test_fail_closed_no_cookie_is_aman(self):
        rows, _ = ckf.audit(URL, {})
        f = one(rows, "No Set-Cookie")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(f["category"], "AMAN")


class HstsPreloadTest(unittest.TestCase):
    def test_golden_ready_is_aman(self):
        h = {"Strict-Transport-Security":
             "max-age=31536000; includeSubDomains; preload"}
        rows, _ = hsts.audit(URL, h)
        f = one(rows, "HSTS preload ready")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(f["category"], "AMAN")

    def test_fail_closed_not_ready_is_lead_only(self):
        rows, _ = hsts.audit(URL, {"Strict-Transport-Security": "max-age=300"})
        f = one(rows, "HSTS preload not ready")
        self.assertEqual(f["verdict"], 1)
        self.assertFalse(f["reportable"])


class ServerVersionDisclosureTest(unittest.TestCase):
    def test_golden_version_is_lead_cwe200(self):
        rows, _ = svd.audit(URL, {"Server": "nginx/1.24.0"})
        f = one(rows, "Version leak via header")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-200")

    def test_fail_closed_no_version_is_aman(self):
        rows, _ = svd.audit(URL, {"Server": "nginx"})
        self.assertEqual(one(rows, "No version leak")["verdict"], 0)


class HttpSecurityHeadersCanonicalTest(unittest.TestCase):
    def test_golden_missing_hsts_is_medium_and_summary_lead(self):
        rows, meta = hsh.audit(URL, {"Content-Security-Policy": "default-src 'self'"})
        absent = one(rows, "Security header absent on " + URL + ": Strict-Transport-Security")
        self.assertEqual(absent["severity"], "medium")
        summary = one(rows, "Security headers posture")
        self.assertEqual(summary["verdict"], 1)
        self.assertIn("missing", meta)

    def test_fail_closed_version_leak_subcheck_and_complete(self):
        # sub-check bocor versi (dulu x-powered-by-leak) + keadaan lengkap
        rows, _ = hsh.audit(URL, {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "X-Powered-By": "PHP/7.4.3",
        })
        leak = one(rows, "Version leak via X-Powered-By")
        self.assertEqual(leak["verdict"], 1)
        self.assertEqual(leak["cwe"], "CWE-200")
        complete = one(rows, "Security headers complete")
        self.assertEqual(complete["verdict"], 0)


class CspAnalyzerTest(unittest.TestCase):
    def test_golden_missing_csp_is_lead(self):
        rows, meta = cspa.audit(URL, {})
        f = one(rows, "CSP missing")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-693")
        self.assertFalse(meta["csp_present"])

    def test_fail_closed_restrictive_csp_is_aman(self):
        rows, _ = cspa.audit(URL, {"Content-Security-Policy":
                                   "default-src 'self'; object-src 'none'"})
        f = one(rows, "CSP present and restrictive")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(f["category"], "AMAN")


class SriCheckerTest(unittest.TestCase):
    def test_golden_unsafe_script_is_lead_cwe829(self):
        html = '<script src="https://cdn.example/lib.js"></script>'
        rows, meta = sri.audit(URL, html)
        f = one(rows, "SRI missing")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-829")
        self.assertEqual(meta["unsafe"], 1)

    def test_fail_closed_integrity_present_is_aman(self):
        html = ('<script src="https://cdn.example/lib.js" '
                'integrity="sha384-abc" crossorigin="anonymous"></script>')
        rows, _ = sri.audit(URL, html)
        self.assertEqual(one(rows, "SRI posture OK")["verdict"], 0)


# ---------------------------------------------------------------------------
# HTML evidence skills — audit(url, html)
# ---------------------------------------------------------------------------

class MixedContentTest(unittest.TestCase):
    def test_golden_http_resource_is_lead(self):
        html = '<img src="http://lab.local/x.png">'
        rows, _ = mxd.audit(URL, html)
        f = one(rows, "Mixed-content http found")
        self.assertEqual(f["verdict"], 1)

    def test_fail_closed_https_only_is_aman(self):
        rows, _ = mxd.audit(URL, '<img src="https://lab.local/x.png">')
        self.assertEqual(one(rows, "No mixed-content")["verdict"], 0)


class SourcemapTest(unittest.TestCase):
    def test_golden_map_reference_is_lead(self):
        rows, _ = smap.audit(URL, '//# sourceMappingURL=app.min.js.map"')
        self.assertEqual(one(rows, "Sourcemap exposure found")["verdict"], 1)

    def test_fail_closed_clean_is_aman(self):
        rows, _ = smap.audit(URL, "<html><body>ok</body></html>")
        self.assertEqual(one(rows, "No sourcemap exposure")["verdict"], 0)


class DirectoryListingTest(unittest.TestCase):
    def test_golden_index_of_is_lead_cwe548(self):
        rows, _ = dld.audit(URL, "<html><title>Index of /backup</title></html>")
        f = one(rows, "Directory listing signature found")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-548")

    def test_fail_closed_clean_is_aman(self):
        rows, _ = dld.audit(URL, "<html>halaman biasa</html>")
        self.assertEqual(one(rows, "No directory listing")["verdict"], 0)


class FormCsrfTest(unittest.TestCase):
    def test_golden_form_without_csrf_is_lead(self):
        html = '<form action="/login" method="post"><input name="u"></form>'
        rows, _ = fcsrf.audit(URL, html)
        f = one(rows, "Form without CSRF token")
        self.assertEqual(f["verdict"], 1)

    def test_fail_closed_no_form_is_info(self):
        rows, _ = fcsrf.audit(URL, "<html>teks saja</html>")
        f = one(rows, "No form")
        self.assertEqual(f["verdict"], 0)


class PasswordAutocompleteTest(unittest.TestCase):
    def test_golden_risky_field_is_lead(self):
        html = '<form><input type="password" name="pw"></form>'
        rows, _ = pwac.audit(URL, html)
        f = one(rows, "Password autocomplete risk")
        self.assertEqual(f["verdict"], 1)

    def test_fail_closed_ok_is_aman(self):
        html = '<form><input type="password" autocomplete="new-password"></form>'
        rows, _ = pwac.audit(URL, html)
        self.assertEqual(one(rows, "Password autocomplete posture OK")["verdict"], 0)


class TechFingerprintTest(unittest.TestCase):
    def test_golden_wordpress_detected_is_surface(self):
        html = ('<meta name="generator" content="WordPress 6.4">'
                '<script src="/wp-includes/js/jquery.min.js"></script>')
        rows, _ = tfp.audit(URL, html)
        f = one(rows, "Tech fingerprint on")
        self.assertEqual(f["verdict"], 0)
        self.assertIn("WordPress", f["title"])

    def test_fail_closed_clean_html_no_claim(self):
        rows, _ = tfp.audit(URL, "<html><body>halaman kosong</body></html>")
        f = one(rows, "No tech fingerprint")
        self.assertEqual(f["verdict"], 0)


class GraphQLSurfaceTest(unittest.TestCase):
    def test_golden_graphql_endpoint_is_lead(self):
        rows, _ = gql.audit(URL, 'fetch("/graphql", {query: "{__schema}"})')
        f = one(rows, "GraphQL surface found")
        self.assertEqual(f["verdict"], 1)  # endpoint GraphQL terekspos = lead

    def test_fail_closed_clean_is_no_surface(self):
        rows, _ = gql.audit(URL, "<html>halaman</html>")
        self.assertEqual(one(rows, "No GraphQL surface")["verdict"], 0)


class OpenRedirectSurfaceTest(unittest.TestCase):
    def test_golden_redirect_param_is_lead(self):
        html = '<a href="/login?next=https://evil.example">masuk</a>'
        rows, _ = ored.audit(URL, html)
        f = one(rows, "Open-redirect surface found")
        self.assertEqual(f["verdict"], 1)

    def test_fail_closed_clean_is_aman(self):
        rows, _ = ored.audit(URL, '<a href="/about">tentang</a>')
        self.assertEqual(one(rows, "No open-redirect surface")["verdict"], 0)


class JsLibraryVersionTest(unittest.TestCase):
    def test_golden_jquery_version_is_lead(self):
        rows, _ = jlv.audit(URL, '<script src="jquery-3.5.1.min.js"></script>')
        f = one(rows, "JS library version found")
        self.assertEqual(f["verdict"], 1)  # versi tua = lead, bukan AMAN
        self.assertEqual(f["severity"], "low")

    def test_fail_closed_clean_is_no_claim(self):
        rows, _ = jlv.audit(URL, "<html>tanpa library</html>")
        self.assertEqual(one(rows, "No JS library version")["verdict"], 0)


# ---------------------------------------------------------------------------
# Jaringan di-mock — DoH / HTTP / probe
# ---------------------------------------------------------------------------

class CtInventoryTest(unittest.TestCase):
    def test_golden_inventory_and_interesting_lead(self):
        data = [{"dns_names": ["lab.local", "admin.lab.local"]}]
        with patch.object(cti, "fetch_ct", lambda d: (data, None)):
            rows, meta = cti.audit("lab.local")
        inv = one(rows, "CT inventory on")
        self.assertEqual(inv["verdict"], 0)
        self.assertEqual(inv["category"], "SURFACE")
        lead = one(rows, "Interesting CT hostname")
        self.assertEqual(lead["verdict"], 1)
        self.assertIn("admin", lead["title"])

    def test_fail_closed_source_unreachable_unconfirmed(self):
        with patch.object(cti, "fetch_ct",
                          lambda d: (None, "TimeoutError: boom")):
            rows, _ = cti.audit("lab.local")
        f = one(rows, "CT source unreachable")
        self.assertEqual(f["status"], "unconfirmed")
        self.assertFalse(f["reportable"])


class TakeoverCnameTest(unittest.TestCase):
    def test_golden_dangling_marker_is_lead(self):
        doc = {"Status": 0, "Answer": [{"data": "x.azurewebsites.net."}]}
        rows, _ = tch.audit("lab.local", doh_result=doc)
        f = one(rows, "CNAME dangling hygiene")
        self.assertEqual(f["verdict"], 1)
        self.assertIn("hygiene saja", f["description"])  # bukan claim takeover

    def test_fail_closed_nxdomain_is_surface_only(self):
        doc = {"Status": 3, "Answer": []}
        rows, _ = tch.audit("lab.local", doh_result=doc)
        f = one(rows, "CNAME NXDOMAIN hygiene")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(f["category"], "SURFACE")


class SubdomainEnumTest(unittest.TestCase):
    def test_golden_ct_names_is_surface(self):
        rows, _ = ses.audit("lab.local", data=["a.lab.local", "b.lab.local"])
        f = one(rows, "CT surface on")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(f["count"], 2)

    def test_fail_closed_error_unconfirmed(self):
        rows, _ = ses.audit("lab.local", data={"__error__": "boom"})
        f = one(rows, "CT fetch failed")
        self.assertEqual(f["status"], "unconfirmed")


class RobotsTxtTest(unittest.TestCase):
    def test_golden_200_is_lead(self):
        rows, meta = rbt.audit(URL + "robots.txt", {"status": 200,
                                                    "body": "User-agent: *\nDisallow: /admin"})
        f = one(rows, "exposes resource")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(meta["requests"], 1)

    def test_fail_closed_404_is_aman(self):
        rows, _ = rbt.audit(URL + "robots.txt", {"status": 404, "body": ""})
        f = one(rows, "No resource on")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(f["category"], "AMAN")


class TlsCipherSuitesTest(unittest.TestCase):
    def test_golden_weak_proto_is_lead_cwe326(self):
        rows, _ = tcs.audit("lab.local", {"ok": True, "proto": "TLSv1.1"})
        f = one(rows, "Weak TLS on")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-326")

    def test_fail_closed_probe_failed_unconfirmed(self):
        rows, _ = tcs.audit("lab.local", {"ok": False, "err": "refused"})
        f = one(rows, "TLS probe failed")
        self.assertEqual(f["status"], "unconfirmed")
        self.assertEqual(f["severity"], "info")


class SecurityTxtTest(unittest.TestCase):
    def test_golden_found_complete_is_surface(self):
        body = "Contact: mailto:security@lab.local\nExpires: 2027-01-01T00:00:00Z\n"
        with patch.object(stx, "fetch", lambda u: body):
            rows, meta = stx.audit("lab.local")
        f = one(rows, "security.txt found")
        self.assertEqual(f["verdict"], 0)
        self.assertTrue(meta["found"])
        self.assertEqual(meta["requests"], 1)  # path pertama langsung kena -> break

    def test_fail_closed_no_contact_is_lead(self):
        body = "Expires: 2027-01-01T00:00:00Z\n"
        with patch.object(stx, "fetch", lambda u: body):
            rows, _ = stx.audit("lab.local")
        f = one(rows, "has no Contact field")
        self.assertEqual(f["verdict"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=1)
