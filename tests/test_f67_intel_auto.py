"""Test F67 — mesin auto-update intel + audit dependensi.

NOL jaringan (fetch/urlopen di-mock). Yang dikunci:
  - parser NVD cpeMatch: range start/end + exact; wildcard murni dilewati;
  - sync_nvd_ranges: bootstrap vs delta, merge, manifest, TTL skip;
  - verify_counts nvd-ranges: mismatch -> exit 2;
  - dependency: parser requirements/package-lock + in/out-of-range,
    exact, unmapped, versi tak terurai dilewati;
  - OSV: interval introduced/fixed/last_affected, cache, fail-closed;
  - auto_update: satu komponen gagal tidak menggagalkan yang lain;
  - freshness: nvd-ranges termasuk komponen TTL.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import auto_update  # noqa: E402
import dependency_cve as dc  # noqa: E402
import detection_freshness  # noqa: E402
import intel_sync  # noqa: E402
from findings import make_finding, validate_finding  # noqa: E402

NVD_DOC = {"totalResults": 3, "vulnerabilities": [
    {"cve": {"id": "CVE-2026-11111",
             "published": "2026-10-20T00:00:00.000",
             "metrics": {"cvssMetricV31": [
                 {"cvssData": {"baseScore": 9.8}}]},
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"vulnerable": True,
                  "criteria": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
                  "versionStartIncluding": "0",
                  "versionEndExcluding": "4.17.21"}]}]}]}},
    {"cve": {"id": "CVE-2026-22222",
             "published": "2026-10-15T00:00:00.000",
             "metrics": {"cvssMetricV31": [
                 {"cvssData": {"baseScore": 8.1}}]},
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"vulnerable": True,
                  "criteria": "cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*",
                  "versionEndIncluding": "4.18.0"}]}]}]}},
    {"cve": {"id": "CVE-2026-33333",
             "published": "2026-10-10T00:00:00.000",
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"vulnerable": True,
                  "criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}]}]}]}},
]}

OSV_DOC = {"vulns": [{
    "id": "GHSA-test-0001",
    "aliases": ["CVE-2026-99999"],
    "summary": "Prototype pollution di lodash",
    "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [
                      {"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    "references": [{"url": "https://osv.dev/vulnerability/GHSA-test-0001"}],
    "database_specific": {"severity": "HIGH"},
}]}


class _FakeResp:
    def __init__(self, body: str):
        self._b = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self._b if n is None or n < 0 else self._b[:n]


def _ok_row(title="Tidak ada match"):
    return make_finding(tool="detection-freshness", title=title,
                        severity="info", description="x",
                        evidence_kind="file-manifest",
                        finding_class="posture", confidence=1.0,
                        status="confirmed", verdict=0,
                        extra={"category": "AMAN"})


class NvdParseTest(unittest.TestCase):
    def test_ranges_parsed_and_wildcard_skipped(self):
        entries = intel_sync._parse_nvd_ranges(NVD_DOC)
        self.assertEqual(len(entries), 2)
        lodash = next(e for e in entries if e["cve"] == "CVE-2026-11111")
        self.assertEqual(lodash["product_norm"], "lodash")
        self.assertEqual(lodash["start_incl"], "0")
        self.assertEqual(lodash["end_excl"], "4.17.21")
        self.assertEqual(lodash["cvss"], 9.8)
        express = next(e for e in entries if e["cve"] == "CVE-2026-22222")
        self.assertEqual(express["end_incl"], "4.18.0")
        self.assertEqual(express["product_norm"], "express")

    def test_dedup_by_key(self):
        doc = {"vulnerabilities": [NVD_DOC["vulnerabilities"][0],
                                   NVD_DOC["vulnerabilities"][0]]}
        self.assertEqual(len(intel_sync._parse_nvd_ranges(doc)), 1)


class NvdSyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron-f67-"))
        self._old = {k: getattr(intel_sync, k) for k in
                     ("INTEL", "MANIFEST", "NVD_RANGES_OUT",
                      "NVD_POLITE_DELAY")}
        intel_sync.INTEL = self.tmp
        intel_sync.MANIFEST = self.tmp / "manifest.json"
        intel_sync.NVD_RANGES_OUT = self.tmp / "nvd-ranges.json"
        intel_sync.NVD_POLITE_DELAY = 0

    def tearDown(self):
        for k, v in self._old.items():
            setattr(intel_sync, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fake_fetch(self, calls):
        def fetch(url, timeout=60.0, headers=None):
            calls.append(url)
            return json.dumps(NVD_DOC).encode()
        return fetch

    def test_bootstrap_delta_merge_and_ttl(self):
        calls: list[str] = []
        with patch.object(intel_sync, "fetch", self._fake_fetch(calls)):
            first = intel_sync.sync_nvd_ranges(force=True)
        self.assertTrue(first["synced"])
        self.assertEqual(first["entry_count"], 2)
        self.assertEqual(first["window_days"],
                         intel_sync.NVD_RANGES_WINDOW_DAYS)
        store = json.loads(
            intel_sync.NVD_RANGES_OUT.read_text(encoding="utf-8"))
        self.assertEqual(len(store["entries"]), 2)
        man = json.loads(
            intel_sync.MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(man["components"]["nvd-ranges"]["entry_count"], 2)

        with patch.object(intel_sync, "fetch", self._fake_fetch(calls)):
            skipped = intel_sync.sync_nvd_ranges(False)
        self.assertTrue(skipped.get("skipped"))

        with patch.object(intel_sync, "fetch", self._fake_fetch(calls)):
            second = intel_sync.sync_nvd_ranges(force=True)
        self.assertEqual(second["entry_count"], 2)
        self.assertEqual(second["window_days"],
                         intel_sync.NVD_RANGES_DELTA_DAYS)
        self.assertEqual(second["delta_from_prev"], 0)

    def test_verify_counts_mismatch(self):
        calls: list[str] = []
        with patch.object(intel_sync, "fetch", self._fake_fetch(calls)):
            intel_sync.sync_nvd_ranges(force=True)
        self.assertEqual(intel_sync.verify_counts({"nvd-ranges"}), 0)
        store = json.loads(
            intel_sync.NVD_RANGES_OUT.read_text(encoding="utf-8"))
        store["entries"] = store["entries"][:1]
        intel_sync.NVD_RANGES_OUT.write_text(
            json.dumps(store), encoding="utf-8")
        self.assertEqual(intel_sync.verify_counts({"nvd-ranges"}), 2)

    def test_parse_versions_exact(self):
        e = {"product_norm": "thing", "exact": "1.2.3"}
        self.assertTrue(dc._in_range("1.2.3", e))
        self.assertFalse(dc._in_range("1.2.4", e))


class DependencyParseTest(unittest.TestCase):
    def test_requirements_hashes_and_markers(self):
        text = ("Django==3.2.0\n"
                "requests==2.31.0 --hash=sha256:abc\n"
                "flask==2.0.1 ; python_version >= '3.8'\n"
                "-r other.txt\n")
        deps = dc.parse_requirements(text)
        self.assertEqual([(d["name"], d["version"]) for d in deps],
                         [("Django", "3.2.0"),
                          ("requests", "2.31.0"),
                          ("flask", "2.0.1")])

    def test_package_lock_v3_and_scoped(self):
        doc = {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/@scope/pkg": {"version": "0.9.1"},
        }}
        deps = dc.parse_package_lock(doc)
        self.assertEqual({(d["name"], d["version"]) for d in deps},
                         {("lodash", "4.17.20"), ("@scope/pkg", "0.9.1")})


class DependencyMatchTest(unittest.TestCase):
    INDEX = {
        "lodash": [{"cve": "CVE-2026-11111", "vendor": "lodash",
                    "product": "lodash", "cvss": 9.8,
                    "start_incl": "0", "end_excl": "4.17.21",
                    "source_url": "https://nvd.nist.gov/vuln/detail/"
                                  "CVE-2026-11111"}],
        "express": [{"cve": "CVE-2026-22222", "vendor": "expressjs",
                     "product": "express", "cvss": 8.1,
                     "end_incl": "4.18.0",
                     "source_url": "https://nvd.nist.gov/vuln/detail/"
                                   "CVE-2026-22222"}],
    }

    def _deps(self):
        return [
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
            {"ecosystem": "npm", "name": "express", "version": "4.18.0"},
            {"ecosystem": "npm", "name": "express", "version": "4.18.1"},
            {"ecosystem": "npm", "name": "unknown-pkg", "version": "1.0.0"},
            {"ecosystem": "npm", "name": "bad-pkg", "version": "1.0.0-rc1"},
        ]

    def test_in_range_exact_and_unmapped(self):
        rows, meta = dc.check_deps(self._deps(), self.INDEX)
        hits = {r["cve"] for r in rows if r.get("cve")}
        self.assertEqual(hits, {"CVE-2026-11111", "CVE-2026-22222"})
        self.assertEqual(meta["matches"], 2)
        self.assertEqual(meta["unmapped"], 1)
        self.assertEqual(meta["skipped_unparsed"], 1)
        lod = next(r for r in rows if r.get("cve") == "CVE-2026-11111")
        self.assertEqual(lod["verdict"], 1)
        self.assertEqual(lod["severity"], "critical")
        self.assertEqual(lod["fixed"], "4.17.21")
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_no_match_single_aman_row(self):
        rows, meta = dc.check_deps(
            [{"ecosystem": "npm", "name": "clean", "version": "1.0.0"}],
            {})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(rows[0]["category"], "AMAN")


class OsvTest(unittest.TestCase):
    def test_interval_hit_fixed(self):
        aff = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
        self.assertEqual(dc._osv_interval_hit("4.17.20", aff),
                         {"fixed": "4.17.21"})
        self.assertIsNone(dc._osv_interval_hit("4.17.21", aff))

    def test_interval_hit_last_affected(self):
        aff = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "1.0.0"},
            {"last_affected": "1.2.3"}]}]}]
        self.assertEqual(dc._osv_interval_hit("1.2.3", aff),
                         {"fixed": None, "last_affected": "1.2.3"})
        self.assertIsNone(dc._osv_interval_hit("1.2.4", aff))

    def test_lookup_cache_and_fail_closed(self):
        calls = []

        def fake_urlopen(req, timeout=None):
            calls.append(req.full_url)
            return _FakeResp(json.dumps(OSV_DOC))

        with tempfile.TemporaryDirectory() as td:
            dep = {"ecosystem": "npm", "name": "lodash",
                   "version": "4.17.20"}
            with patch.object(dc.urllib.request, "urlopen", fake_urlopen):
                doc1, cached1, err1 = dc._osv_lookup(
                    dep, Path(td), 24.0)
                doc2, cached2, err2 = dc._osv_lookup(
                    dep, Path(td), 24.0)
            self.assertIsNone(err1)
            self.assertFalse(cached1)
            self.assertTrue(cached2)
            self.assertEqual(len(calls), 1)
            self.assertEqual(doc2["vulns"][0]["id"], "GHSA-test-0001")

        def boom(req, timeout=None):
            raise OSError("network down")

        with tempfile.TemporaryDirectory() as td:
            with patch.object(dc.urllib.request, "urlopen", boom):
                doc, cached, err = dc._osv_lookup(
                    {"ecosystem": "npm", "name": "x",
                     "version": "1.0.0"}, Path(td), 24.0)
        self.assertIsNone(doc)
        self.assertIn("network down", err)

    def test_check_deps_osv_rows(self):
        deps = [{"ecosystem": "npm", "name": "lodash",
                 "version": "4.17.20"}]
        rows, meta = dc.check_deps(
            deps, {}, osv=True,
            osv_lookup=lambda dep, cache, ttl: (OSV_DOC, False, None))
        osv_rows = [r for r in rows if r.get("via") == "osv"]
        self.assertEqual(len(osv_rows), 1)
        self.assertEqual(osv_rows[0]["cve"], "CVE-2026-99999")
        self.assertEqual(osv_rows[0]["severity"], "high")
        self.assertTrue(all(validate_finding(r) == [] for r in rows))


class AutoUpdateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron-f67b-"))
        p = patch.object(detection_freshness, "freshness_report",
                         return_value=([_ok_row()],
                                       {"stale": [], "drift": 0,
                                        "components": {}}))
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_error_isolated_and_findings_written(self):
        def ok(force):
            return {"synced": True, "entry_count": 2}

        def bad(force):
            raise RuntimeError("fetch down")

        comps = {"kev": ok, "nvd-ranges": bad}
        with patch.dict(auto_update.COMPONENTS, comps, clear=True):
            results, rows, meta, out = auto_update.run_once(
                ["kev", "nvd-ranges"], force=True,
                out=self.tmp / "status.json")
        self.assertTrue(results["kev"]["synced"])
        self.assertIn("fetch down", results["nvd-ranges"]["error"])
        self.assertTrue((self.tmp / "status.json").is_file())
        err_rows = [r for r in rows
                    if r.get("category") == "INTEL-AUTOUPDATE"]
        self.assertEqual(len(err_rows), 1)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_freshness_has_nvd_component(self):
        self.assertIn("nvd-ranges", intel_sync.TTL_HOURS)


if __name__ == "__main__":
    unittest.main(verbosity=1)
