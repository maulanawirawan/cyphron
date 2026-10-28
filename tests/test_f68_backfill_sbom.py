"""Test F68 — backfill NVD historis + SBOM + config/alias dependensi.

NOL jaringan (fetch di-mock). Yang dikunci:
  - backfill: chunk <=120 hari, merge, state resumable, manifest;
  - purl: pypi / npm scoped (%40) / golang / invalid;
  - SBOM: CycloneDX components, SPDX packages+externalRefs purl;
  - detect_format: ekstensi + JSON sniffing;
  - config: default lokal-first (OSV off) + override;
  - alias: mapping terverifikasi membuka pencocokan tanpa klaim baru;
  - OSV: ekosistem tak didukung dilewati (bukan error).
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

import dependency_cve as dc  # noqa: E402
import intel_sync  # noqa: E402
from findings import validate_finding  # noqa: E402

NVD_DOC = {"totalResults": 2, "vulnerabilities": [
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
]}


class BackfillTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron-f68-"))
        self._old = {k: getattr(intel_sync, k) for k in
                     ("INTEL", "MANIFEST", "NVD_RANGES_OUT",
                      "NVD_BACKFILL_STATE", "NVD_POLITE_DELAY")}
        intel_sync.INTEL = self.tmp
        intel_sync.MANIFEST = self.tmp / "manifest.json"
        intel_sync.NVD_RANGES_OUT = self.tmp / "nvd-ranges.json"
        intel_sync.NVD_BACKFILL_STATE = self.tmp / "backfill-state.json"
        intel_sync.NVD_POLITE_DELAY = 0

    def tearDown(self):
        for k, v in self._old.items():
            setattr(intel_sync, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fake_fetch(self):
        def fetch(url, timeout=60.0, headers=None):
            return json.dumps(NVD_DOC).encode()
        return fetch

    def test_backfill_chunks_merge_and_resume(self):
        with patch.object(intel_sync, "fetch", self._fake_fetch()):
            res = intel_sync.backfill_nvd_ranges(10, chunk_days=5,
                                                 force=True)
        self.assertTrue(res["synced"])
        self.assertEqual(res["chunks"], 2)
        self.assertEqual(res["entry_count"], 2)
        store = json.loads(
            intel_sync.NVD_RANGES_OUT.read_text(encoding="utf-8"))
        self.assertEqual(len(store["entries"]), 2)
        self.assertIsNone(store["window_days"])
        state = json.loads(
            intel_sync.NVD_BACKFILL_STATE.read_text(encoding="utf-8"))
        self.assertIn("oldest_covered", state)
        man = json.loads(
            intel_sync.MANIFEST.read_text(encoding="utf-8"))
        comp = man["components"]["nvd-ranges"]
        self.assertEqual(comp["entry_count"], 2)
        self.assertEqual(comp["backfill_days"], 10)

        with patch.object(intel_sync, "fetch", self._fake_fetch()):
            again = intel_sync.backfill_nvd_ranges(10, chunk_days=5)
        self.assertTrue(again.get("skipped"))
        self.assertIn("tercakup", again.get("reason", ""))

    def test_backfill_zero_days_noop(self):
        res = intel_sync.backfill_nvd_ranges(0)
        self.assertTrue(res.get("skipped"))

    def test_backfill_partial_failure_resumes(self):
        calls = {"n": 0}

        def flaky_fetch(url, timeout=60.0, headers=None):
            calls["n"] += 1
            if calls["n"] == 3:  # chunk ke-2, request pertama
                raise TimeoutError("read timed out")
            return json.dumps(NVD_DOC).encode()

        with patch.object(intel_sync, "fetch", flaky_fetch):
            first = intel_sync.backfill_nvd_ranges(10, chunk_days=5,
                                                   force=True)
        self.assertFalse(first["synced"])
        self.assertEqual(first["chunks_done"], 1)
        self.assertIn("TimeoutError", first["error"])
        man = json.loads(
            intel_sync.MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(man["components"]["nvd-ranges"]["entry_count"], 2)
        state = json.loads(
            intel_sync.NVD_BACKFILL_STATE.read_text(encoding="utf-8"))
        self.assertIn("oldest_covered", state)

        with patch.object(intel_sync, "fetch", self._fake_fetch()):
            resumed = intel_sync.backfill_nvd_ranges(10, chunk_days=5)
        self.assertTrue(resumed["synced"])
        self.assertEqual(resumed["chunks"], 1)
        self.assertEqual(resumed["entry_count"], 2)

    def test_fetch_retries_transient_timeout(self):
        calls = {"n": 0}

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"ok"

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise TimeoutError("slow")
            return _Resp()

        with patch.object(intel_sync.urllib.request, "urlopen",
                          fake_urlopen), \
                patch.object(intel_sync.time, "sleep", lambda s: None):
            self.assertEqual(intel_sync.fetch("http://x"), b"ok")
        self.assertEqual(calls["n"], 2)


class PurlTest(unittest.TestCase):
    def test_pypi(self):
        self.assertEqual(dc.parse_purl("pkg:pypi/django@4.2.0"),
                         ("pypi", "django", "4.2.0"))

    def test_npm_scoped_encoded(self):
        self.assertEqual(
            dc.parse_purl("pkg:npm/%40angular/core@16.0.0"),
            ("npm", "@angular/core", "16.0.0"))

    def test_golang(self):
        self.assertEqual(
            dc.parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
            ("golang", "gin", "v1.9.1"))

    def test_invalid(self):
        self.assertIsNone(dc.parse_purl("bukan-purl"))


class SbomParseTest(unittest.TestCase):
    def test_cyclonedx_components(self):
        doc = {"bomFormat": "CycloneDX", "components": [
            {"name": "pillow", "version": "12.9.0",
             "purl": "pkg:pypi/pillow@12.9.0"},
            {"name": "undici", "version": "8.12.1",
             "purl": "pkg:npm/undici@8.12.1"},
        ]}
        deps = dc.parse_cyclonedx(doc)
        self.assertEqual(
            {(d["ecosystem"], d["name"], d["version"]) for d in deps},
            {("pypi", "pillow", "12.9.0"),
             ("npm", "undici", "8.12.1")})

    def test_spdx_packages(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [
            {"name": "django", "versionInfo": "4.2.0",
             "externalRefs": [{"referenceLocator":
                               "pkg:pypi/django@4.2.0"}]},
            {"name": "no-purl", "versionInfo": "1.0.0"},
        ]}
        deps = dc.parse_spdx(doc)
        self.assertEqual(len(deps), 2)
        dj = next(d for d in deps if d["name"] == "django")
        self.assertEqual(dj["ecosystem"], "pypi")
        self.assertEqual(dj["version"], "4.2.0")
        np = next(d for d in deps if d["name"] == "no-purl")
        self.assertEqual(np["ecosystem"], "unknown")

    def test_detect_format(self):
        self.assertEqual(dc.detect_format(Path("bom.cdx.json"), "{}"),
                         "cyclonedx")
        self.assertEqual(dc.detect_format(Path("x.spdx.json"), "{}"),
                         "spdx")
        self.assertEqual(dc.detect_format(Path("package-lock.json"), "{}"),
                         "package-lock")
        self.assertEqual(dc.detect_format(Path("requirements.txt"), ""),
                         "requirements")
        self.assertEqual(
            dc.detect_format(Path("bom.json"),
                             json.dumps({"bomFormat": "CycloneDX"})),
            "cyclonedx")
        self.assertEqual(
            dc.detect_format(Path("doc.json"),
                             json.dumps({"spdxVersion": "SPDX-2.3"})),
            "spdx")


class ConfigAliasTest(unittest.TestCase):
    def test_config_default_off_and_override(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.json"
            self.assertFalse(dc.load_config(p)["osv_default"])
            p.write_text(json.dumps({"osv_default": True,
                                     "osv_cache_ttl_hours": 8}),
                         encoding="utf-8")
            cfg = dc.load_config(p)
            self.assertTrue(cfg["osv_default"])
            self.assertEqual(cfg["osv_cache_ttl_hours"], 8.0)

    def test_load_aliases_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "aliases.json"
            p.write_text(json.dumps({"entries": [
                {"ecosystem": "pypi", "package": "beautiful-soup",
                 "product": "beautifulsoup"},
                {"rusak": True},
            ]}), encoding="utf-8")
            al = dc.load_aliases(p)
            self.assertEqual(al[("pypi", "beautiful soup")],
                             {"beautifulsoup"})

    def test_alias_matching_is_lead_only(self):
        index = {"beautifulsoup": [{
            "cve": "CVE-2026-77777", "vendor": "crummy",
            "product": "beautifulsoup", "cvss": 7.5,
            "start_incl": "0", "end_excl": "4.13.0",
            "source_url": "https://nvd.nist.gov/vuln/detail/"
                          "CVE-2026-77777"}]}
        aliases = {("pypi", "beautiful soup"): {"beautifulsoup"}}
        deps = [{"ecosystem": "pypi", "name": "beautiful-soup",
                 "version": "4.12.0"}]
        rows, meta = dc.check_deps(deps, index, aliases=aliases)
        self.assertEqual(meta["matches"], 1)
        self.assertEqual(meta["alias_mapped"], 1)
        hit = next(r for r in rows if r.get("cve"))
        self.assertEqual(hit["verdict"], 1)
        self.assertFalse(hit["reportable"])
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_osv_skips_unsupported_ecosystem(self):
        called = []

        def lookup(*a, **k):
            called.append(1)
            return {}, False, None

        rows, meta = dc.check_deps(
            [{"ecosystem": "golang", "name": "x", "version": "1.0.0"}],
            {}, osv=True, osv_lookup=lookup)
        self.assertEqual(meta["osv_skipped_ecosystem"], 1)
        self.assertEqual(called, [])


class ReconcileTest(unittest.TestCase):
    """Lapis verifikasi dependensi: cross-confirm / eliminasi / L1."""

    INDEX = {"lodash": [{
        "cve": "CVE-2026-11111", "vendor": "lodash",
        "product": "lodash", "cvss": 9.8, "start_incl": "0",
        "end_excl": "4.17.21",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-11111"}]}
    DEP = [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}]

    @staticmethod
    def _osv_doc(cve: str, fixed: str | None, withdrawn: str | None = None):
        events = [{"introduced": "0"}]
        if fixed:
            events.append({"fixed": fixed})
        v = {"id": "GHSA-test-1", "aliases": [cve], "summary": "s",
             "affected": [{"package": {"name": "lodash",
                                       "ecosystem": "npm"},
                           "ranges": [{"type": "ECOSYSTEM",
                                       "events": events}]}],
             "database_specific": {"severity": "HIGH"}}
        if withdrawn:
            v["withdrawn"] = withdrawn
        return {"vulns": [v]}

    def test_agree_is_cross_confirmed_l2(self):
        doc = self._osv_doc("CVE-2026-11111", "4.17.21")
        rows, meta = dc.check_deps(
            self.DEP, self.INDEX, osv=True,
            osv_lookup=lambda d, c, t: (doc, False, None))
        row = next(r for r in rows if r.get("cve") == "CVE-2026-11111")
        self.assertEqual(row["verdict"], 2)
        self.assertTrue(row["cross_confirmed"])
        self.assertEqual(row["via"], "nvd+osv")
        self.assertEqual(row["fixed"], "4.17.21")
        self.assertEqual(meta["cross_confirmed"], 1)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_disagree_is_eliminated_lx(self):
        doc = self._osv_doc("CVE-2026-88888", "1.0.0")
        rows, meta = dc.check_deps(
            self.DEP, self.INDEX, osv=True,
            osv_lookup=lambda d, c, t: (doc, False, None))
        rej = next(r for r in rows
                   if r.get("category") == "FP-ELIMINATED")
        self.assertEqual(rej["verdict"], -1)
        self.assertEqual(rej["status"], "false-positive")
        self.assertFalse(rej["reportable"])
        self.assertEqual(rej["reason"], "osv-disagree")
        self.assertEqual(meta["eliminated"], 1)
        self.assertEqual(meta["cross_confirmed"], 0)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_osv_error_keeps_single_source_l1(self):
        rows, meta = dc.check_deps(
            self.DEP, self.INDEX, osv=True,
            osv_lookup=lambda d, c, t: (None, False, "boom"))
        row = next(r for r in rows if r.get("cve") == "CVE-2026-11111")
        self.assertEqual(row["verdict"], 1)
        self.assertEqual(row["via"], "nvd-range")
        self.assertEqual(meta["osv_errors"], 1)
        self.assertEqual(meta["eliminated"], 0)

    def test_osv_empty_keeps_single_source_l1(self):
        rows, meta = dc.check_deps(
            self.DEP, self.INDEX, osv=True,
            osv_lookup=lambda d, c, t: ({"vulns": []}, False, None))
        row = next(r for r in rows if r.get("cve") == "CVE-2026-11111")
        self.assertEqual(row["verdict"], 1)
        self.assertEqual(meta["eliminated"], 0)

    def test_withdrawn_osv_not_cross_confirm(self):
        doc = self._osv_doc("CVE-2026-11111", "4.17.21",
                            withdrawn="2026-10-01")
        rows, meta = dc.check_deps(
            self.DEP, self.INDEX, osv=True,
            osv_lookup=lambda d, c, t: (doc, False, None))
        row = next(r for r in rows if r.get("cve") == "CVE-2026-11111")
        self.assertEqual(row["verdict"], 1)
        self.assertEqual(meta["cross_confirmed"], 0)

    def test_offline_is_single_source_l1(self):
        rows, meta = dc.check_deps(self.DEP, self.INDEX, osv=False)
        row = next(r for r in rows if r.get("cve") == "CVE-2026-11111")
        self.assertEqual(row["verdict"], 1)
        self.assertIn("Single-source", row["description"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
