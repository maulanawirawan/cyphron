"""Test F40 — detection freshness (jangan sampai jadul).

NOL jaringan (manifest dummy, waktu dibekukan). Yang dikunci:
  - komponen segar (<= TTL) + count cocok = AMAN L0;
  - stale (> TTL) = L1 dengan saran perintah refresh;
  - komponen hilang dari manifest = lead "belum pernah di-sync";
  - drift jumlah nyata vs manifest = lead tersendiri.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import detection_freshness as df  # noqa: E402
import intel_sync  # noqa: E402

NOW = 1_800_000_000.0
H = 3600


def manifest_with(**ages) -> dict:
    comps = {}
    for name, age_h in ages.items():
        comps[name] = {"synced_at": NOW - age_h * H,
                       "template_count": 100, "entry_count": 100}
    return {"components": comps}


class FreshnessTest(unittest.TestCase):
    """verify_counts di-patch: jumlah nyata TIDAK boleh memengaruhi test
    yang menguji logika umur (di export, folder intel tidak dibawa)."""

    def setUp(self):
        p0 = patch.object(intel_sync, "verify_counts", return_value=0)
        p0.start()
        self.addCleanup(p0.stop)

    def test_all_fresh_is_aman(self):
        rows, meta = df.freshness_report(
            manifest_with(**{"nuclei-templates": 2, "kev": 2, "cwe": 2,
                             "watchlist": 2, "nvd-ranges": 2}),
            now_epoch=NOW)
        self.assertEqual(meta["stale"], [])
        self.assertEqual(rows[0]["verdict"], 0)

    def test_stale_component_is_l1_with_refresh_hint(self):
        rows, meta = df.freshness_report(
            manifest_with(**{"nuclei-templates": 72, "kev": 2, "cwe": 2,
                             "watchlist": 2, "nvd-ranges": 2}),
            now_epoch=NOW)
        self.assertIn("nuclei-templates", meta["stale"])
        f = [r for r in rows if "stale" in r["title"]]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["verdict"], 1)
        self.assertIn("intel_sync", f[0]["recommendation"])

    def test_missing_component_is_lead(self):
        m = {"components": {"nuclei-templates": {"synced_at": NOW - H}}}
        rows, meta = df.freshness_report(m, now_epoch=NOW)
        f = [r for r in rows if "belum pernah di-sync" in r["title"]]
        # komponen hilang: kev + cwe + watchlist + nvd-ranges
        self.assertEqual(len(f), 4)
        self.assertIn("kev", meta["stale"])
        self.assertIn("cwe", meta["stale"])
        self.assertIn("watchlist", meta["stale"])
        self.assertIn("nvd-ranges", meta["stale"])

    def test_drift_reported(self):
        with patch.object(intel_sync, "verify_counts",
                          return_value=1):
            rows, meta = df.freshness_report(
                manifest_with(**{"nuclei-templates": 1, "kev": 1, "cwe": 1,
                                 "watchlist": 1, "nvd-ranges": 1}),
                now_epoch=NOW)
        self.assertEqual(meta["drift"], 1)
        self.assertTrue(any("tidak cocok" in r["title"] for r in rows))

    def test_custom_max_age(self):
        rows, meta = df.freshness_report(
            manifest_with(**{"nuclei-templates": 30, "kev": 30, "cwe": 30,
                             "watchlist": 30, "nvd-ranges": 30}),
            now_epoch=NOW, max_age_hours=12)
        self.assertEqual(sorted(meta["stale"]),
                         ["cwe", "kev", "nuclei-templates", "nvd-ranges",
                          "watchlist"])


if __name__ == "__main__":
    unittest.main()
