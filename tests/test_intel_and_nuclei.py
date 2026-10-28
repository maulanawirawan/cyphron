"""Test F7 — intel sync (manifest/delta/TTL) + adapter nuclei.

Semua jaringan di-mock; fokus pada logika keputusan segar, delta,
pemetaan JSONL -> kontrak, dan fail-closed tanpa --lab.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import intel_sync as isl  # noqa: E402
import nuclei_runner as nr  # noqa: E402


class IntelSyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_intel = isl.INTEL
        self.old_manifest = isl.MANIFEST
        isl.INTEL = Path(self.tmp.name)
        isl.MANIFEST = isl.INTEL / "manifest.json"

    def tearDown(self):
        isl.INTEL = self.old_intel
        isl.MANIFEST = self.old_manifest
        self.tmp.cleanup()

    def test_should_sync_fresh_by_ttl(self):
        import time
        now = time.time()
        self.assertTrue(isl.should_sync(None, 24))               # belum pernah
        self.assertFalse(isl.should_sync({"synced_at": now}, 24))  # segar
        self.assertTrue(isl.should_sync({"synced_at": now - 25 * 3600}, 24))  # basi

    def test_kev_sync_writes_manifest_with_delta(self):
        fake = {"dateReleased": "2026-10-01", "catalogVersion": "12.0",
                "vulnerabilities": [{"cveID": "CVE-1"}, {"cveID": "CVE-2"}]}
        with patch.object(isl, "fetch", return_value=json.dumps(fake).encode()):
            r = isl.sync_kev(force=True)
        self.assertTrue(r["synced"])
        self.assertEqual(r["entry_count"], 2)
        self.assertIsNone(r["delta_from_prev"])  # sync pertama
        # sync kedua: entri bertambah -> delta terukur
        fake2 = {**fake, "vulnerabilities": [{"cveID": f"CVE-{i}"} for i in range(5)]}
        with patch.object(isl, "fetch", return_value=json.dumps(fake2).encode()):
            r2 = isl.sync_kev(force=True)
        self.assertEqual(r2["delta_from_prev"], 3)
        m = json.loads(isl.MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(len(m["history"]), 2)

    def test_nuclei_templates_version_unchanged_skips_download(self):
        api = {"sha": "abc123def456", "commit": {"committer": {"date": "2026-10-01"}}}
        prev_entry = {"version": "abc123def456", "template_count": 9000,
                      "synced_at": 0.0}  # basi (TTL lewat) tapi versi sama
        isl.INTEL.mkdir(parents=True, exist_ok=True)
        isl.MANIFEST.write_text(json.dumps(
            {"components": {"nuclei-templates": prev_entry}, "history": []}),
            encoding="utf-8")
        calls = []

        def fake_fetch(url, timeout=60.0):
            calls.append(url)
            return json.dumps(api).encode()

        with patch.object(isl, "fetch", side_effect=fake_fetch):
            r = isl.sync_nuclei_templates()
        self.assertTrue(r.get("skipped"))
        self.assertEqual(r.get("reason"), "versi sama")
        # hanya API commit yang diakses — tarball TIDAK diunduh
        self.assertEqual(len([u for u in calls if "codeload" in u]), 0)


class NucleiRunnerTest(unittest.TestCase):
    FIXTURE = (
        '{"template-id":"CVE-2024-1234","info":{"name":"Broken Access",'
        '"severity":"critical","description":"desc","tags":["cve"],'
        '"classification":{"cve-id":["CVE-2024-1234"]}},"host":"http://lab/",'
        '"matched-at":"http://lab/api/v1","matcher-status":true,'
        '"curl-command":"curl -i http://lab/api/v1","type":"http"}\n'
        '{"template-id":"panel-x","info":{"name":"Login Panel","severity":"info",'
        '"tags":["panel"]},"host":"http://lab/","matcher-status":true}\n'
        '{"template-id":"no-match","info":{"name":"Gagal","severity":"high"},'
        '"host":"http://lab/","matcher-status":false}\n'
        'bukan-json\n'
    )

    def test_parse_jsonl_skips_bad_lines(self):
        rows = nr.parse_jsonl(self.FIXTURE)
        self.assertEqual(len(rows), 3)  # 3 json valid, 1 sampah dilewati

    def test_matcher_false_not_finding(self):
        rows = nr.parse_jsonl(self.FIXTURE)
        findings = nr.to_findings(rows)
        self.assertEqual(len(findings), 2)  # baris no-match tidak jadi temuan
        by_id = {f["template_id"]: f for f in findings}
        self.assertNotIn("no-match", by_id)
        # L3 deterministik + reportable
        self.assertEqual(by_id["CVE-2024-1234"]["verdict"], 3)
        self.assertTrue(by_id["CVE-2024-1234"]["reportable"])
        self.assertEqual(by_id["CVE-2024-1234"]["severity"], "critical")
        self.assertEqual(by_id["CVE-2024-1234"]["evidence_kind"],
                         "request-response")
        self.assertEqual(by_id["panel-x"]["severity"], "info")
        self.assertEqual(by_id["panel-x"]["verdict"], 3)  # tetap L3, tapi info

    def test_write_findings_contract_shape(self):
        rows = nr.parse_jsonl(self.FIXTURE)
        findings = nr.to_findings(rows)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.json"
            nr.write_findings(p, findings, {"target": "http://lab/"})
            doc = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(set(doc.keys()), {"ok", "data", "findings", "requests"})
        self.assertTrue(all(f["lab_only"] for f in doc["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
