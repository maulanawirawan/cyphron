"""Test F75d — canary differensial soft-404 (robots/sitemap/well-known).

Strategi A (differensial kontrol): 1 canary GET path sengaja-tak-ada
HANYA bila resource menjawab 200. Yang dikunci (pola sama utk 3 skill):
  - canary 200 + body identik = wildcard-200 TERBUKTI:
      * resource HTML -> tetap unconfirmed (bukti deterministik di desc);
      * resource non-HTML -> lead DITOLAK L-x (status false-positive,
        verdict -1, kategori FP-ELIMINATED) — kontrak validate lolos;
  - canary 4xx -> lead dipertahankan + catatan "SPESIFIK";
  - canary 4xx pada HTML -> tetap unconfirmed + catatan spesifik;
  - canary gagal jaringan / beda konten -> tanpa kesimpulan;
  - tanpa canary (result tanpa kunci) -> perilaku lama utuh
    (backward compat, meta.requests = 1);
  - meta.requests = 2 saat canary jalan;
  - canary path beda per skill (kontrol independen, tanpa cache bentrok).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import robots_txt_surface as rbt       # noqa: E402
import sitemap_disclosure_checker as smc  # noqa: E402
import well_known_exposure_checker as wkc  # noqa: E402
from findings import validate_finding  # noqa: E402

URL = "https://contoh.example/robots.txt"
HTML = "<!doctype html><html><body>halaman</body></html>"
ROBOTS = "User-agent: *\nDisallow: /admin/\n"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


class CanaryRobotsTest(unittest.TestCase):
    def test_html_plus_wildcard_proven_bukti_deterministik(self):
        res = {"status": 200, "headers": {"content-type": "text/html"},
               "body": HTML, "canary": {"status": 200, "body": HTML}}
        rows, meta = rbt.audit(URL, res)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))
        f = one(rows, "soft-404 suspicion")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["status"], "unconfirmed")
        self.assertIn("wildcard-200 TERBUKTI", f["description"])
        self.assertIn(".cx-canary-robots-7f3a.txt", f["description"])
        self.assertEqual(meta["canary"], "wildcard-proven")
        self.assertEqual(meta["requests"], 2)

    def test_nonhtml_plus_wildcard_proven_ditolak_lx(self):
        res = {"status": 200, "headers": {"content-type": "text/plain"},
               "body": ROBOTS, "canary": {"status": 200, "body": ROBOTS}}
        rows, meta = rbt.audit(URL, res)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))
        f = one(rows, "DITOLAK")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], -1)
        self.assertEqual(f["status"], "false-positive")
        self.assertEqual(f["category"], "FP-ELIMINATED")
        self.assertIn("body IDENTIK", f["description"])
        self.assertEqual(meta["canary"], "wildcard-proven")
        # tidak ada lead yang tersisa dari skill ini
        self.assertIsNone(one(rows, "exposes resource — 1 GET"))

    def test_nonhtml_plus_canary_404_lead_diperkuat(self):
        res = {"status": 200, "headers": {"content-type": "text/plain"},
               "body": ROBOTS, "canary": {"status": 404, "body": ""}}
        rows, meta = rbt.audit(URL, res)
        f = one(rows, "exposes resource — 1 GET")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["status"], "confirmed")
        self.assertIn("SPESIFIK", f["description"])
        self.assertEqual(meta["canary"], "specific-404")

    def test_html_plus_canary_404_tetap_unconfirmed(self):
        res = {"status": 200, "headers": {"content-type": "text/html"},
               "body": HTML, "canary": {"status": 404, "body": ""}}
        rows, meta = rbt.audit(URL, res)
        f = one(rows, "soft-404 suspicion")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["status"], "unconfirmed")
        self.assertIn("SPESIFIK, bukan", f["description"])

    def test_canary_error_tanpa_kesimpulan(self):
        res = {"status": 200, "headers": {"content-type": "text/plain"},
               "body": ROBOTS, "canary": {"status": None, "body": "__error__"}}
        rows, meta = rbt.audit(URL, res)
        f = one(rows, "exposes resource — 1 GET")
        self.assertEqual(f["verdict"], 1)
        self.assertIn("tanpa kesimpulan", f["description"])
        self.assertEqual(meta["canary"], "error")

    def test_canary_beda_konten_inkonklusif(self):
        res = {"status": 200, "headers": {"content-type": "text/plain"},
               "body": ROBOTS, "canary": {"status": 200,
                                          "body": "<html>beda</html>"}}
        rows, meta = rbt.audit(URL, res)
        f = one(rows, "exposes resource — 1 GET")
        self.assertEqual(f["verdict"], 1)
        self.assertIn("inkonklusif", f["description"])
        self.assertEqual(meta["canary"], "inconclusive")

    def test_tanpa_canary_backward_compat(self):
        res = {"status": 200, "headers": {"content-type": "text/plain"},
               "body": ROBOTS}
        rows, meta = rbt.audit(URL, res)
        f = one(rows, "exposes resource — 1 GET")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["status"], "confirmed")
        self.assertEqual(meta["requests"], 1)
        self.assertEqual(meta["canary"], "none")

    def test_404_tanpa_canary_aman(self):
        rows, meta = rbt.audit(URL, {"status": 404, "body": ""})
        self.assertEqual(one(rows, "No resource")["verdict"], 0)
        self.assertEqual(meta["requests"], 1)


class CanaryFamilyTest(unittest.TestCase):
    """Pola sama di sitemap + well-known; canary path beda per skill."""

    def _skills(self):
        return ((smc, "sitemap"), (wkc, "wellknown"))

    def test_reject_lx_pola_sama(self):
        for mod, tag in self._skills():
            res = {"status": 200,
                   "headers": {"content-type": "text/plain"},
                   "body": "data", "canary": {"status": 200,
                                              "body": "data"}}
            rows, meta = mod.audit(f"https://contoh.example/{tag}", res)
            f = one(rows, "DITOLAK")
            self.assertIsNotNone(f, tag)
            self.assertEqual(f["verdict"], -1, tag)
            self.assertEqual(f["status"], "false-positive", tag)
            self.assertTrue(validate_finding(f) == [], tag)
            self.assertEqual(meta["requests"], 2, tag)

    def test_canary_path_unik_per_skill(self):
        paths = {rbt.CANARY_PATH, smc.CANARY_PATH, wkc.CANARY_PATH}
        self.assertEqual(len(paths), 3,
                         "canary path wajib unik per skill (kontrol "
                         "independen)")
        for pth in paths:
            self.assertTrue(pth.startswith("/.cx-canary-"))
            self.assertTrue(pth.endswith(".txt"))

    def test_safety_class_bounded(self):
        # kelas = kontrak registry (bukan meta audit — itu diisi main())
        import json
        reg = json.loads((ROOT / "skills" / "registry.json")
                         .read_text(encoding="utf-8"))
        by_name = {s["name"]: s for s in reg["skills"]}
        for name in ("robots-txt-surface", "sitemap-disclosure-checker",
                     "well-known-exposure-checker"):
            self.assertEqual(by_name[name]["safety_class"],
                             "bounded-requests", name)


if __name__ == "__main__":
    unittest.main()
