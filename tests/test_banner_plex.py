"""Test suite skill banner-plex — body/header di-mock, NOL jaringan.

Kontrak yang dikunci:
  - token produk ketat: header X-Plex-Protocol ATAU frasa
    "plex media server" — "plex"/"multiplex" polos TIDAK cukup;
  - maks 2 GET (root -> /web/ fallback hanya bila perlu);
  - versi tidak terekspos => CVE mapping TIDAK diklaim (fail-closed);
  - fetch gagal => finding unconfirmed, bukan dibungkam.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import banner_plex as bp  # noqa: E402

PLEX_HEADERS = {
    "X-Plex-Protocol": "1.0",
    "X-Plex-Version": "1.41.2.9054-af2e3c049",
    "Content-Type": "text/html",
}

PLEX_WEB_BODY = """
<html><head><title>Plex</title></head>
<body><div id="plex-root">Plex Media Server</div></body></html>
"""


def _res(url, body, status=200, headers=None):
    return {"url": url, "status": status, "headers": headers or {},
            "body": body}


class ProductDetectionTest(unittest.TestCase):
    def test_header_marker_detected_on_root(self):
        rows, meta = bp.audit(
            "http://media.example.lan:32400/",
            [_res("http://media.example.lan:32400/", "<html></html>",
                  headers=PLEX_HEADERS)])
        self.assertEqual(meta["products"], ["Plex Media Server"])
        self.assertEqual(meta["requests"], 1)

    def test_body_phrase_detected_via_web_fallback(self):
        # root tanpa header (reverse proxy menyaring) -> /web/ berfrasa
        rows, meta = bp.audit(
            "http://media.example.lan/",
            [_res("http://media.example.lan/", "<html>hello</html>",
                  status=200),
             _res("http://media.example.lan/web/", PLEX_WEB_BODY)])
        self.assertEqual(meta["requests"], 2)
        self.assertEqual(meta["products"], ["Plex Media Server"])
        self.assertEqual(meta["probed"],
                         ["http://media.example.lan/",
                          "http://media.example.lan/web/"])

    def test_plex_word_alone_is_not_enough(self):
        rows, meta = bp.audit(
            "http://shop.example.com/",
            [_res("http://shop.example.com/", "<body>multiplex display "
                  "and plexiglass frames</body>"),
             _res("http://shop.example.com/web/", "<html>shop</html>")])
        self.assertEqual(meta["products"], [])
        self.assertIn("No Plex banner", rows[0]["title"])


class VersionClaimTest(unittest.TestCase):
    def test_header_version_is_claimed(self):
        rows, meta = bp.audit(
            "http://media.example.lan:32400/",
            [_res("http://media.example.lan:32400/", "<html></html>",
                  headers=PLEX_HEADERS)])
        self.assertEqual(meta["version_marker"], "1.41.2.9054-af2e3c049")
        titles = [r["title"] for r in rows]
        self.assertTrue(any("version exposed" in t for t in titles))

    def test_body_version_fallback(self):
        hdrs = {"X-Plex-Protocol": "1.0"}  # tanpa X-Plex-Version
        rows, meta = bp.audit(
            "http://media.example.lan:32400/",
            [_res("http://media.example.lan:32400/",
                  "<html>Plex Media Server 1.32.8.7751-90c9b7bb4</html>",
                  headers=hdrs)])
        self.assertEqual(meta["version_marker"], "1.32.8.7751-90c9b7bb4")
        self.assertTrue(any("version exposed" in r["title"] for r in rows))

    def test_version_not_exposed_means_no_cve_claim(self):
        hdrs = {"X-Plex-Protocol": "1.0"}  # tanpa versi, body polos
        rows, meta = bp.audit(
            "http://media.example.lan:32400/",
            [_res("http://media.example.lan:32400/",
                  "<html>Plex Media Server</html>", headers=hdrs)])
        self.assertIsNone(meta["version_marker"])
        titles = [r["title"] for r in rows]
        self.assertTrue(any("CVE mapping NOT claimed" in t for t in titles))


class FailClosedTest(unittest.TestCase):
    def test_fetch_failed_is_unconfirmed_not_silent(self):
        rows, meta = bp.audit(
            "http://media.example.lan:32400/",
            [_res("http://media.example.lan:32400/",
                  "__fetch_error__ URLError: conn refused", status=None)])
        self.assertTrue(meta["error"])
        self.assertEqual(rows[0]["status"], "unconfirmed")

    def test_meta_shape_has_requests_and_probed(self):
        _, meta = bp.audit(
            "http://media.example.lan:32400/",
            [_res("http://media.example.lan:32400/", "<html></html>",
                  headers=PLEX_HEADERS)])
        self.assertIn("requests", meta)
        self.assertIn("probed", meta)


if __name__ == "__main__":
    unittest.main()
