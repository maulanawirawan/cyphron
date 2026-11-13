"""Test capture_triage — NOL jaringan, HAR di-mock in-memory.

Kontrak yang dikunci:
  - rantai redirect >= 3 hop = sinyal;
  - POST lintas domain + kredensial di URL = high;
  - zero-FP: capture satu halaman same-host https = clean;
  - fail-closed: bukan HAR -> error (exit 2 via main).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import capture_triage as ct  # noqa: E402


def _entry(url: str, method: str = "GET", status: int = 200,
           mime: str = "text/html", size: int = 5000,
           redirect: str = "") -> dict:
    return {
        "request": {"method": method, "url": url},
        "response": {"status": status,
                     "redirectURL": redirect,
                     "content": {"mimeType": mime, "size": size}},
    }


HAR_CLEAN = {
    "log": {"entries": [
        _entry("https://toko.example.id/"),
        _entry("https://toko.example.id/app.js", mime="application/javascript"),
        _entry("https://toko.example.id/api/cart"),
    ]}
}

HAR_RISKY = {
    "log": {"entries": [
        _entry("http://iklan.example.net/ad",
               redirect="https://bit.ly/next"),
        _entry("https://bit.ly/next", redirect="https://login.toko.example.id/x"),
        _entry("https://login.toko.example.id/x",
               redirect="https://toko.example.id/"),
        _entry("http://phish.example.org/collect?email=a@b.c&password=x",
               method="POST"),
        _entry("https://tracker.example.com/px.gif", mime="image/gif", size=44),
        _entry("https://tracker.example.com/px2.gif", mime="image/gif", size=44),
        _entry("https://tracker.example.com/px3.gif", mime="image/gif", size=44),
        _entry("https://cdn.thirdparty.example/js/track.js",
               mime="application/javascript"),
        _entry("https://cdn2.thirdparty.example/js/ad.js",
               mime="application/javascript"),
        _entry("https://cdn3.thirdparty.example/js/metrics.js",
               mime="application/javascript"),
        _entry("https://cdn4.thirdparty.example/js/beacon.js",
               mime="application/javascript"),
        _entry("https://cdn5.thirdparty.example/js/profile.js",
               mime="application/javascript"),
    ]}
}


class ScoringTest(unittest.TestCase):
    def test_clean_capture_is_clean(self):
        res = ct.triage_har(HAR_CLEAN, "clean.har")
        self.assertEqual(res["severity"], "info")
        self.assertTrue(res["clean"])
        self.assertEqual(res["first_party"], "toko.example.id")

    def test_risky_capture_flags_all_expected_signals(self):
        res = ct.triage_har(HAR_RISKY, "risk.har")
        for s in ("redirect-chain", "credentials-in-url", "cross-domain-post",
                  "shortener", "http-not-https", "third-party-script",
                  "tracking-pixel"):
            self.assertIn(s, res["signals"], s)
        self.assertEqual(res["severity"], "high")
        kinds = [f["type"] for f in res["findings"]]
        self.assertIn("risky-entry", kinds)
        self.assertIn("tracking-pixel", kinds)
        self.assertIn("third-party-script", kinds)
        post_f = [f for f in res["findings"]
                  if "cross-domain-post" in f["evidence"]][0]
        self.assertEqual(post_f["severity"], "high")

    def test_schema_and_read_only(self):
        res = ct.triage_har(HAR_CLEAN, "clean.har")
        self.assertEqual(res["schema"], "secai.capture-triage/1")
        self.assertTrue(res["read_only"])


class FailClosedTest(unittest.TestCase):
    def test_not_har_raises(self):
        with self.assertRaises(ValueError):
            ct.triage_har({"entries": []}, "x.har")

    def test_empty_entries_raises(self):
        with self.assertRaises(ValueError):
            ct.triage_har({"log": {"entries": []}}, "x.har")

    def test_main_exit_2_on_bad_har(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.har"
            p.write_text('{"nope": true}', encoding="utf-8")
            rc = ct.main(["--file", str(p)])
            self.assertEqual(rc, 2)

    def test_main_exit_2_on_missing_file(self):
        rc = ct.main(["--file", str(ROOT / ".tmp" / "nope.har")])
        self.assertEqual(rc, 2)

    def test_main_writes_single_json_line(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.har"
            p.write_text(json.dumps(HAR_CLEAN), encoding="utf-8")
            out = Path(td) / "o.json"
            rc = ct.main(["--file", str(p), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], "secai.capture-triage/1")
            self.assertTrue(doc["read_only"])


if __name__ == "__main__":
    unittest.main()
