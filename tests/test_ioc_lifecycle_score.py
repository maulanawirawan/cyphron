"""Nol jaringan — test ioc_lifecycle_score (decay + disposisi IOC).

--now dipatok deterministik; nilai decay diverifikasi eksak (rumus
0.5^(umur/half-life)). Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import math
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import ioc_lifecycle_score as ils  # noqa: E402
from findings import validate_finding  # noqa: E402

NOW = "2026-11-08T00:00:00Z"


def write(tmp: Path, entries: list[dict], name: str = "ioc.json") -> Path:
    p = tmp / name
    p.write_text(json.dumps(entries), encoding="utf-8")
    return p


class IocLifecycleScoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ils_t"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, entries: list[dict], **kw) -> tuple[int, dict]:
        out = self.tmp / kw.pop("out_name", "f.json")
        argv = ["--indicators", str(write(self.tmp, entries)),
                "--now", NOW, "--out", str(out)]
        rc = ils.main(argv + [str(x) for pair in kw.items()
                              for x in ("--" + pair[0].replace("_", "-"),
                                        str(pair[1]))])
        if not out.exists():
            return rc, {}
        return rc, json.loads(out.read_text(encoding="utf-8"))

    def test_decay_exact_ip_30d(self) -> None:
        # IP, umur tepat 30 hari, half-life 30 -> conf 80 -> 40.0
        entries = [{"type": "ip", "value": "198.51.100.7",
                    "confidence": 80, "last_seen": "2026-10-09T00:00:00Z"}]
        rc, doc = self._run(entries)
        self.assertEqual(rc, 0)
        scored = doc  # meta dibaca via data? (findings.json contract)
        self.assertEqual(doc["findings"], [])

    def test_decay_math_via_score_indicator(self) -> None:
        from datetime import datetime, timezone
        now = datetime(2026, 11, 8, tzinfo=timezone.utc)
        res, flag = ils.score_indicator(
            {"type": "ip", "value": "1.2.3.4", "confidence": 80,
             "last_seen": "2026-10-09T00:00:00Z"}, now, 30, 10)
        self.assertIsNone(flag)
        self.assertAlmostEqual(res["confidence_decayed"], 40.0, places=2)
        self.assertEqual(res["state"], "MONITORING")  # 40 >= 30
        self.assertEqual(res["disposition"], "monitor")

        # hash umur 365 hari, half-life 365: 50 -> 25 = UNDER-REVIEW
        res2, _ = ils.score_indicator(
            {"type": "sha256", "value": "ab" * 32, "confidence": 50,
             "last_seen": "2025-11-08T00:00:00Z"}, now, 30, 10)
        self.assertAlmostEqual(res2["confidence_decayed"], 25.0, places=2)
        self.assertEqual(res2["state"], "UNDER-REVIEW")

        # IP umur 90 hari: 80 -> 10 (tepat expire ambang = 10 TIDAK < 10,
        # jadi bukan retire-by-threshold; 10 < 30 -> UNDER-REVIEW)
        res3, _ = ils.score_indicator(
            {"type": "ip", "value": "5.6.7.8", "confidence": 80,
             "last_seen": "2026-08-10T00:00:00Z"}, now, 30, 10)
        self.assertAlmostEqual(res3["confidence_decayed"], 10.0, places=2)
        self.assertEqual(res3["state"], "UNDER-REVIEW")

    def test_fp_heavy_retire(self) -> None:
        from datetime import datetime, timezone
        now = datetime(2026, 11, 8, tzinfo=timezone.utc)
        res, _ = ils.score_indicator(
            {"type": "domain", "value": "cdn.example.net", "confidence": 90,
             "last_seen": "2026-11-07T00:00:00Z",
             "hit_count": 3, "false_positive_count": 9}, now, 30, 10)
        self.assertAlmostEqual(res["fp_rate"], 0.75, places=3)
        self.assertEqual(res["state"], "RETIRE-CANDIDATE")
        # gabungan = 90 * 0.5^(1/90) * (1-0.75) ≈ 22.33 (1 hari decay)
        expected = 90 * 0.5 ** (1 / 90) * (1 - 0.75)
        self.assertAlmostEqual(res["combined_factor"], expected, places=2)

    def test_flags_unknown_type_and_future(self) -> None:
        rc, doc = self._run([
            {"type": "blorptoken", "value": "x", "confidence": 50,
             "last_seen": "2026-11-01T00:00:00Z"},
            {"type": "ip", "value": "9.9.9.9", "confidence": 50,
             "last_seen": "2027-01-01T00:00:00Z"},
            {"type": "url", "value": "https://ok.example/a",
             "confidence": 70, "last_seen": "2026-11-01T00:00:00Z"},
        ])
        self.assertEqual(rc, 0)
        reasons = {fl.get("reason", "").split(":")[0] for fl in
                   doc["data"]["flags"]}
        self.assertIn("type-unknown", reasons)
        self.assertIn("last_seen/created di masa depan (data-error)",
                      {fl["reason"] for fl in doc["data"]["flags"]})
        self.assertEqual(doc["data"]["scored"], 1)

    def test_fail_closed(self) -> None:
        out = self.tmp / "x.json"
        # file tidak ada
        self.assertEqual(ils.main(["--indicators",
                                   str(self.tmp / "no.json"), "--now", NOW,
                                   "--out", str(out)]), 2)
        # bukan list / kosong
        p = self.tmp / "empty.json"
        p.write_text("[]", encoding="utf-8")
        self.assertEqual(ils.main(["--indicators", str(p), "--now", NOW,
                                   "--out", str(out)]), 2)
        # 0 valid (semua rusak)
        rc, _ = self._run([{"nope": 1}], out_name="y.json")
        self.assertEqual(rc, 2)
        # threshold terbalik
        p2 = write(self.tmp, [{"type": "ip", "value": "1.1.1.1",
                               "confidence": 50,
                               "last_seen": "2026-11-01T00:00:00Z"}],
                   name="t.json")
        self.assertEqual(ils.main(["--indicators", str(p2), "--now", NOW,
                                   "--review-threshold", "10",
                                   "--expire-threshold", "20",
                                   "--out", str(out)]), 2)
        self.assertFalse(out.exists())

    def test_cli_retire_finding_contract(self) -> None:
        entries = [
            {"type": "ip", "value": "203.0.113.66", "confidence": 70,
             "last_seen": "2026-01-01T00:00:00Z"},  # ~311 hari, hl 30
            {"type": "domain", "value": "fresh.example.com",
             "confidence": 90, "last_seen": "2026-11-07T00:00:00Z",
             "hit_count": 10, "false_positive_count": 0},
        ]
        out = self.tmp / "cli.json"
        rc = ils.main(["--indicators", str(write(self.tmp, entries,
                                                 name="cli.json")),
                       "--now", NOW, "--out", str(out)])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(doc["findings"]), 1)
        for f in doc["findings"]:
            self.assertEqual(validate_finding(f), [])
        self.assertEqual(doc["data"]["states"].get("RETIRE-CANDIDATE"), 1)
        self.assertEqual(doc["data"]["states"].get("MONITORING"), 1)


if __name__ == "__main__":
    unittest.main()
