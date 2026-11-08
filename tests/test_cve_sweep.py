"""Test tools/cve_sweep.py — triage pipeline kontribusi.

Nol jaringan: semua fungsi murni (encoding window, ekstraksi CVSS,
klasifikasi flag, filter, state file) diuji dengan payload NVD sintetis.
Jaringan hanya dijalankan manual via CLI (`--help`) dan live-verify.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import cve_sweep  # noqa: E402


def make_cve(cid, score, vector, desc, refs=()):
    """Payload NVD minimalis yang meniru struktur API 2.0."""
    metrics = {"cvssMetricV31": [{"cvssData": {
        "baseScore": score, "vectorString": vector}}]}
    return {
        "id": cid,
        "metrics": metrics,
        "descriptions": [{"lang": "en", "value": desc}],
        "references": [{"url": u} for u in refs],
    }


class WindowEncodingTest(unittest.TestCase):
    def test_offset_utc_explicit(self):
        dt = datetime(2026, 11, 6, 17, 10, 0, tzinfo=timezone.utc)
        self.assertEqual(cve_sweep.iso_utc(dt),
                         "2026-11-06T17:10:00.000+00:00")

    def test_naive_treated_as_utc(self):
        dt = cve_sweep.parse_since("2026-11-06T17:10:00")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(cve_sweep.iso_utc(dt),
                         "2026-11-06T17:10:00.000+00:00")

    def test_build_params_shapes(self):
        params = cve_sweep.build_params(
            datetime(2026, 11, 6, tzinfo=timezone.utc),
            datetime(2026, 11, 7, tzinfo=timezone.utc), keyword="wordpress")
        self.assertIn("+00:00", params["pubStartDate"])
        self.assertIn("+00:00", params["pubEndDate"])
        self.assertEqual(params["resultsPerPage"], "200")
        self.assertEqual(params["keywordSearch"], "wordpress")
        # tanggal polos tanpa offset = sumber bug 404 NVD; harus tak terjadi
        self.assertNotRegex(params["pubStartDate"], r"T\d{2}:\d{2}:\d{2}$")

    def test_urlencode_encodes_offset(self):
        import urllib.parse
        params = cve_sweep.build_params(
            datetime(2026, 11, 6, tzinfo=timezone.utc),
            datetime(2026, 11, 7, tzinfo=timezone.utc))
        encoded = urllib.parse.urlencode(params)
        self.assertIn("%2B00%3A00", encoded)


class CvssExtractionTest(unittest.TestCase):
    def test_v31_priority(self):
        cve = make_cve("CVE-1", 7.5,
                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "x")
        score, vector = cve_sweep.extract_cvss(cve)
        self.assertEqual(score, 7.5)
        self.assertIn("AV:N", vector)

    def test_v40_takes_priority_over_v31(self):
        cve = make_cve("CVE-1", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "x")
        cve["metrics"]["cvssMetricV40"] = [{"cvssData": {
            "baseScore": 8.7,
            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N"}}]
        score, _ = cve_sweep.extract_cvss(cve)
        self.assertEqual(score, 8.7)

    def test_no_metrics(self):
        score, vector = cve_sweep.extract_cvss({"id": "CVE-2", "metrics": {}})
        self.assertIsNone(score)
        self.assertEqual(vector, "")


class ClassifyTest(unittest.TestCase):
    def test_has_patch_from_commit_ref(self):
        cve = make_cve("CVE-1", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                       "unauthenticated info disclosure",
                       refs=["https://github.com/a/b/commit/abc123",
                             "https://github.com/a/b/releases/tag/v2"])
        flags = cve_sweep.classify(cve, 7.5, "CVSS:3.1/AV:N")
        self.assertTrue(flags["has_patch"])
        self.assertTrue(flags["auth_free"])
        self.assertFalse(flags["denied"])

    def test_denied_xss(self):
        cve = make_cve("CVE-1", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                       "Cross-Site Scripting in the widget renderer")
        flags = cve_sweep.classify(cve, 6.1, "CVSS:3.1/AV:N")
        self.assertTrue(flags["denied"])
        self.assertEqual(flags["denied_reason"], "xss")

    def test_denied_dos_variants(self):
        for desc in ("causes denial of service via crafted frame",
                     "results in resource consumption",
                     "application hangs when parsing"):
            cve = make_cve("CVE-1", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", desc)
            flags = cve_sweep.classify(cve, 5.3, "CVSS:3.1/AV:N")
            self.assertTrue(flags["denied"], desc)
            self.assertEqual(flags["denied_reason"], "dos", desc)

    def test_auth_required_by_vector(self):
        cve = make_cve("CVE-1", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                       "restricted user reads other user records")
        flags = cve_sweep.classify(cve, 6.5, cve["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"])
        self.assertFalse(flags["auth_free"])

    def test_auth_required_by_description(self):
        cve = make_cve("CVE-1", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                       "An authenticated attacker can enumerate records")
        flags = cve_sweep.classify(cve, 6.5, "CVSS:3.1/AV:N")
        self.assertFalse(flags["auth_free"])

    def test_auth_free_clean_disclosure(self):
        cve = make_cve("CVE-1", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                       "unauthenticated endpoint returns private records "
                       "without applying collection rules")
        flags = cve_sweep.classify(cve, 7.5, "CVSS:3.1/AV:N")
        self.assertTrue(flags["auth_free"])
        self.assertTrue(flags["has_patch"] is False)  # refs kosong


class FilterCandidatesTest(unittest.TestCase):
    def test_filters_and_sorts(self):
        cves = [
            make_cve("CVE-B", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                     "unauth disclosure, low score"),
            make_cve("CVE-A", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                     "unauth disclosure high", refs=["https://github.com/a/b/commit/x"]),
            make_cve("CVE-C", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     "Cross-Site Scripting everywhere"),
            make_cve("CVE-D", 8.1, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     "local only, ignore"),
        ]
        candidates, new_count = cve_sweep.filter_candidates(cves, 5.0, set())
        self.assertEqual(new_count, 4)
        self.assertEqual([c["id"] for c in candidates], ["CVE-A", "CVE-B"])
        self.assertEqual(candidates[0]["flags"]["has_patch"], True)

    def test_seen_skipped_but_counted_new_false(self):
        cves = [make_cve("CVE-A", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "x")]
        candidates, new_count = cve_sweep.filter_candidates(
            cves, 5.0, {"CVE-A"})
        self.assertEqual(candidates, [])
        self.assertEqual(new_count, 0)

    def test_below_min_score_dropped(self):
        cves = [make_cve("CVE-A", 4.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "x")]
        self.assertEqual(cve_sweep.filter_candidates(cves, 5.0, set())[0], [])

    def test_missing_en_desc_dropped(self):
        cve = make_cve("CVE-A", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "")
        cve["descriptions"] = [{"lang": "es", "value": "otro"}]
        self.assertEqual(cve_sweep.filter_candidates(cves := [cve], 5.0, set())[0], [])


class StateFileTest(unittest.TestCase):
    def test_roundtrip_and_append(self):
        with tempfile.TemporaryDirectory(prefix="secai_sweep_") as tmp:
            state = Path(tmp) / "nested" / "state.txt"
            self.assertEqual(cve_sweep.load_state(state), set())
            cve_sweep.update_state(state, ["CVE-B", "CVE-A", "CVE-B"])
            self.assertEqual(cve_sweep.load_state(state),
                             {"CVE-A", "CVE-B"})
            cve_sweep.update_state(state, ["CVE-C"])
            self.assertEqual(cve_sweep.load_state(state),
                             {"CVE-A", "CVE-B", "CVE-C"})

    def test_load_ignores_blank_lines(self):
        with tempfile.TemporaryDirectory(prefix="secai_sweep_") as tmp:
            state = Path(tmp) / "state.txt"
            state.write_text("CVE-A\n\n  \nCVE-B\n", encoding="utf-8")
            self.assertEqual(cve_sweep.load_state(state), {"CVE-A", "CVE-B"})


class FetchNvdUnwrapTest(unittest.TestCase):
    def test_vulnerabilities_wrapper_unwrapped(self):
        # API NVD membalut tiap CVE dalam {"cve": {...}} — fetch_nvd harus
        # mengembalikan objek CVE-nya (bug nyata tertangkap live-test).
        calls = []

        def fake_fetch(url):
            calls.append(url)
            return {"totalResults": 1, "resultsPerPage": 1,
                    "vulnerabilities": [{"cve": make_cve(
                        "CVE-W", 7.5,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "unauth disclosure")}]}

        orig = cve_sweep._fetch_json
        cve_sweep._fetch_json = fake_fetch
        try:
            out = cve_sweep.fetch_nvd(
                cve_sweep.build_params(
                    datetime(2026, 11, 6, tzinfo=timezone.utc),
                    datetime(2026, 11, 7, tzinfo=timezone.utc)))
        finally:
            cve_sweep._fetch_json = orig
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "CVE-W")
        self.assertTrue(calls[0].startswith(cve_sweep.NVD_URL))


class ReportJsonSerializableTest(unittest.TestCase):
    def test_run_report_shape(self):
        # run() butuh jaringan; shape laporan diuji lewat filter saja:
        cves = [make_cve("CVE-A", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                         "unauth disclosure", refs=["https://github.com/a/b/commit/x"])]
        candidates, _ = cve_sweep.filter_candidates(cves, 5.0, set())
        payload = json.dumps(candidates)  # harus tanpa TypeError
        self.assertIn("CVE-A", payload)
        self.assertIn("has_patch", payload)


if __name__ == "__main__":
    unittest.main()
