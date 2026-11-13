"""Test suite skill banner-oracle-ebs — body di-mock, NOL jaringan.

Kontrak yang dikunci:
  - token produk ketat: frasa "Oracle E-Business Suite" ATAU
    ("e-business suite" + penanda aplikasi) — bukan "Oracle" polos;
  - maks 2 GET (AppsLogin -> root fallback hanya bila perlu);
  - versi tidak terekspos => CVE mapping TIDAK diklaim (fail-closed);
  - fetch gagal => finding unconfirmed, bukan dibungkam.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import banner_oracle_ebs as be  # noqa: E402

EBS_LOGIN = """
<html><head><title>Oracle E-Business Suite Login</title></head>
<body>
<div id="OAerror">Oracle Applications login</div>
<form action="/OA_HTML/OA.jsp?page=/oracle/apps/fnd/framework/webui/LoginPG">
</form>
</body></html>
"""

EBS_LOGIN_WITH_VERSION = """
<html><head><title>Oracle E-Business Suite Home</title></head>
<body>
<div class="x1l">E-Business Suite 12.2.9</div>
<span>Oracle Applications Release 12.2.9</span>
</body></html>
"""

ROOT_EBS = """
<html><head><title>Oracle E-Business Suite Home Page Redirect</title>
<meta name="application-name" content="Oracle E-Business Suite">
</head><body>appslogin redirect</body></html>
"""

NON_EBS_BLOG = """
<html><head><title>Oracle database tuning blog</title></head>
<body><p>We compared Oracle ERP stacks and the e-business suite landscape
in general (no product installed here).</p></body></html>
"""


def _res(url, body, status=200, headers=None):
    return {"url": url, "status": status, "headers": headers or {},
            "body": body}


class ProductDetectionTest(unittest.TestCase):
    def test_login_page_detected(self):
        rows, meta = be.audit(
            "https://erp.example.go.id/",
            [_res("https://erp.example.go.id/OA_HTML/AppsLogin", EBS_LOGIN)])
        self.assertEqual(meta["products"], ["Oracle E-Business Suite"])
        self.assertEqual(meta["requests"], 1)
        self.assertIn("banner observed", rows[0]["title"])

    def test_loose_phrase_without_app_marker_is_not_enough(self):
        # frasa terpotong + tanpa appslogin/oa_html = tidak cukup (anti-FP)
        rows, meta = be.audit(
            "https://blog.example.com/",
            [_res("https://blog.example.com/OA_HTML/AppsLogin",
                  NON_EBS_BLOG)])
        self.assertEqual(meta["products"], [])
        self.assertIn("No Oracle EBS banner", rows[0]["title"])

    def test_full_phrase_alone_is_enough(self):
        rows, meta = be.audit(
            "https://erp.example.go.id/",
            [_res("https://erp.example.go.id/OA_HTML/AppsLogin",
                  "<html><title>Oracle E-Business Suite</title></html>")])
        self.assertEqual(meta["products"], ["Oracle E-Business Suite"])


class VersionClaimTest(unittest.TestCase):
    def test_version_exposed_is_claimed(self):
        rows, meta = be.audit(
            "https://erp.example.go.id/",
            [_res("https://erp.example.go.id/OA_HTML/AppsLogin",
                  EBS_LOGIN_WITH_VERSION)])
        self.assertEqual(meta["version_markers"], ["12.2.9"])
        titles = [r["title"] for r in rows]
        self.assertTrue(any("version marker exposed" in t for t in titles))

    def test_version_not_exposed_means_no_cve_claim(self):
        rows, meta = be.audit(
            "https://erp.example.go.id/",
            [_res("https://erp.example.go.id/OA_HTML/AppsLogin", EBS_LOGIN)])
        self.assertEqual(meta["version_markers"], [])
        titles = [r["title"] for r in rows]
        self.assertTrue(any("CVE mapping NOT claimed" in t for t in titles))

    def test_version_on_root_fallback_page(self):
        # login tanpa marker -> fallback root yang berisi frasa + versi
        rows, meta = be.audit(
            "https://erp.example.go.id/",
            [_res("https://erp.example.go.id/OA_HTML/AppsLogin",
                  "<html><body>not found</body></html>", status=404),
             _res("https://erp.example.go.id/", ROOT_EBS)])
        self.assertEqual(meta["requests"], 2)
        self.assertEqual(meta["version_markers"], [])
        self.assertEqual(meta["products"], ["Oracle E-Business Suite"])
        self.assertEqual(meta["probed"],
                         ["https://erp.example.go.id/OA_HTML/AppsLogin",
                          "https://erp.example.go.id/"])


class FailClosedTest(unittest.TestCase):
    def test_fetch_failed_is_unconfirmed_not_silent(self):
        rows, meta = be.audit(
            "https://erp.example.go.id/",
            [_res("https://erp.example.go.id/OA_HTML/AppsLogin",
                  "__fetch_error__ URLError: conn refused", status=None)])
        self.assertTrue(meta["error"])
        self.assertEqual(rows[0]["status"], "unconfirmed")

    def test_meta_shape_has_requests_and_probed(self):
        _, meta = be.audit(
            "https://erp.example.go.id/",
            [_res("https://erp.example.go.id/OA_HTML/AppsLogin", EBS_LOGIN)])
        self.assertIn("requests", meta)
        self.assertIn("probed", meta)


if __name__ == "__main__":
    unittest.main()
