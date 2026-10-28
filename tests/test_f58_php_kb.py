"""Test F58 — KB php2shell (CVE-2026-109618/109619) + alias php.

NOL jaringan. Yang dikunci:
  - banner "PHP/8.2.34" -> 2 lead KB terikat versi (8.2.0 <= v < 8.2.35);
  - PHP/8.2.35 (patched) = TIDAK ADA klaim KB (zero-FP);
  - legacy <8.2 (7.4/8.0/8.1) = lead via entri legacy;
  - 8.3.x < 8.3.36 = lead (multi-branch);
  - alias php -> KEV product-level (PHP :: PHP).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import cve_matcher as cm  # noqa: E402
from findings import validate_finding  # noqa: E402

KB = json.load(open(ROOT / "assets/intel/cve-kb.json",
                    encoding="utf-8"))["entries"]
VALID = []
for e in KB:
    fixed = cm.parse_version(str(e["fixed"]))
    intro = (cm.parse_version(str(e["introduced"]))
             if e.get("introduced") else None)
    if fixed is None:
        continue
    VALID.append({**e, "_product": cm.norm_text(e["product"]),
                  "_fixed": fixed, "_introduced": intro})


def _banner(banner: str):
    row = {"tool": "banner-posture",
           "response": f"Server: Apache {banner}",
           "title": f"banner {banner}", "status": "confirmed",
           "target_url": "http://t.local", "extra": {}}
    return cm.match_cves([row], [], VALID)


class Php2ShellKbTest(unittest.TestCase):
    def test_8_2_34_in_range_two_cve_leads(self):
        rows, meta = _banner("PHP/8.2.34")
        kb = [r for r in rows if r.get("via") == "operator-kb"]
        self.assertEqual(sorted(r["cve"] for r in kb),
                         ["CVE-2026-109618", "CVE-2026-109619"])
        self.assertEqual(kb[0]["version_detected"], "8.2.34")
        self.assertEqual(kb[0]["verdict"], 1)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_patched_8_2_35_no_claim(self):
        rows, meta = _banner("PHP/8.2.35")
        self.assertEqual(
            [r for r in rows if r.get("via") == "operator-kb"], [])

    def test_other_branches_flagged(self):
        for banner, in [("PHP/8.3.30",), ("PHP/7.4.33",),
                        ("PHP/8.4.20",), ("PHP/8.5.5",)]:
            rows, meta = _banner(banner)
            kb = [r for r in rows if r.get("via") == "operator-kb"]
            self.assertEqual(len(kb), 2, banner)

    def test_patched_other_branches_no_claim(self):
        for banner, in [("PHP/8.3.36",), ("PHP/8.4.27",),
                        ("PHP/8.5.12",)]:
            rows, meta = _banner(banner)
            self.assertEqual(
                [r for r in rows if r.get("via") == "operator-kb"], [],
                banner)

    def test_php_alias_kev_product_level(self):
        kev = [{"cveID": "CVE-2026-00001", "vendorProject": "PHP Group",
                "product": "PHP", "vulnerabilityName": "x",
                "knownRansomwareCampaignUse": "Unknown", "cwes": []}]
        rows, meta = _banner("PHP/8.2.34")
        rows2, meta2 = cm.match_cves(
            [{"tool": "banner-posture",
              "response": "Server: Apache PHP/8.2.34",
              "title": "t", "status": "confirmed",
              "target_url": "http://t.local", "extra": {}}],
            kev, VALID)
        self.assertTrue(any(r.get("cve") == "CVE-2026-00001"
                            for r in rows2))


if __name__ == "__main__":
    unittest.main()
