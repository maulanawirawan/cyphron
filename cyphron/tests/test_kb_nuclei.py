"""Unit tests — nuclei_loader: subset aman template Nuclei via yamlite.

Fokus guardrail (fail-closed):
- whitelist tag + blacklist tag (dos/bruteforce/fuzz = buang),
- severity gate (default info/low),
- GET + satu path {{BaseURL}} literal; raw/body/payloads/DSL/interactsh
  = skip,
- matcher wajib memeriksa ISI respons — status-only ditolak (anti
  catch-all 200, pelajaran SIPAS),
- template tak bisa diparse = SKIP tercatat, bukan error.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "kb" / "nuclei"

from cyphron.kb import nuclei_loader
from cyphron.kb.nuclei_loader import (
    LoadStats, NucleiTemplate, is_safe, iter_safe_templates, iter_templates,
    parse_template)

SAFE_TPL = """id: example-exposure

info:
  name: Example Exposure
  author: t
  severity: low
  description: |
    Cek: isi respons wajib.
  classification:
    cve-id: CVE-2026-0001
    cwe-id: CWE-200
    cvss-score: 5.3
  tags: exposure,cve

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
        condition: and
      - type: status
        status:
          - 200
"""


class TestParseTemplate(unittest.TestCase):
    def test_safe_template_parsed(self):
        t, why = parse_template(SAFE_TPL, "inline")
        self.assertIsNone(why)
        self.assertEqual(t.tid, "example-exposure")
        self.assertEqual(t.severity, "low")
        self.assertEqual(t.cve_ids, ["CVE-2026-0001"])
        self.assertEqual(t.cwe, "CWE-200")
        self.assertEqual(t.cvss_score, 5.3)
        self.assertIn("exposure", t.tags)
        self.assertEqual(len(t.requests), 1)
        self.assertEqual(t.requests[0].path, "{{BaseURL}}/.env")
        self.assertIsNone(is_safe(t))

    def test_interactsh_rejected(self):
        t, why = parse_template(
            "id: x\ninfo:\n  name: X\n  severity: info\n  tags: cve\n"
            "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/{{interactsh-url}}'\n"
            "    matchers:\n      - type: word\n        words: ['a']\n")
        self.assertIsNone(t)
        self.assertIn("interactsh", why)

    def test_non_http_workload_rejected(self):
        t, why = parse_template(
            "id: x\ninfo:\n  name: X\n  severity: info\n  tags: cve\n"
            "javascript:\n  - code: alert(1)\n")
        self.assertIsNone(t)
        self.assertIn("javascript", why)

    def test_broken_yaml_reports_reason(self):
        t, why = parse_template(
            "id: x\ninfo:\n  name: X\n    oops-indent: true\n", "broken.yaml")
        self.assertIsNone(t)
        self.assertIn("yamlite", why)


class TestSafetyGate(unittest.TestCase):
    def _tpl(self, **kw):
        base = dict(tid="t", name="n", severity="low",
                    tags={"exposure"}, requests=[
                        nuclei_loader.NucleiRequest(
                            path="{{BaseURL}}/x",
                            matchers=[{"type": "word", "words": ["ok"]}])])
        base.update(kw)
        return NucleiTemplate(**base)

    def test_severity_gate(self):
        self.assertIn("di luar izin", is_safe(self._tpl(severity="high")))
        self.assertIsNone(is_safe(self._tpl(severity="low"),
                                  allow_severity=("info", "low", "medium")))

    def test_whitelist_required(self):
        self.assertIn("whitelist", is_safe(self._tpl(tags={"random"})))

    def test_blacklist_rejects(self):
        # whitelist tetap harus lolos dulu, jadi gabungkan tag cve + dos
        self.assertIn("blacklist", is_safe(self._tpl(tags={"cve", "dos"})))
        self.assertIn("blacklist", is_safe(self._tpl(tags={"cve", "fuzz"})))

    def test_get_only(self):
        t = self._tpl()
        t.requests[0].method = "POST"
        self.assertIn("POST", is_safe(t))

    def test_path_constraints(self):
        self.assertIn("berisiko", is_safe(
            self._tpl(requests=[nuclei_loader.NucleiRequest(
                path="{{BaseURL}}/../x",
                matchers=[{"type": "word", "words": ["ok"]}])])))
        self.assertIn("placeholder", is_safe(
            self._tpl(requests=[nuclei_loader.NucleiRequest(
                path="{{BaseURL}}/{{randstr}}",
                matchers=[{"type": "word", "words": ["ok"]}])])))

    def test_status_only_rejected_anti_catchall(self):
        self.assertIn("status-only", is_safe(
            self._tpl(requests=[nuclei_loader.NucleiRequest(
                path="{{BaseURL}}/admin",
                matchers=[{"type": "status", "status": [200]}])])))
        self.assertIn("tanpa matcher", is_safe(
            self._tpl(requests=[nuclei_loader.NucleiRequest(
                path="{{BaseURL}}/admin", matchers=[])])))

    def test_status_with_or_condition_rejected(self):
        # status + word TAPI matchers-condition 'or' = jalur status-only
        self.assertIn("'or'", is_safe(
            self._tpl(requests=[nuclei_loader.NucleiRequest(
                path="{{BaseURL}}/admin", matchers_condition="or",
                matchers=[{"type": "status", "status": [200]},
                          {"type": "word", "words": ["x"]}])])))


class TestIterFixtures(unittest.TestCase):
    def test_fixture_directory_gates(self):
        stats = LoadStats()
        safe = list(iter_safe_templates(FIXTURES, stats=stats))
        ids = {t.tid for t in safe}
        self.assertEqual(ids, {"git-config-exposure"})
        self.assertEqual(stats.total, 6)
        self.assertEqual(stats.safe, 1)
        self.assertGreaterEqual(stats.skipped_parse, 2)   # broken + dsl/body/POST
        self.assertGreaterEqual(stats.skipped_unsafe, 2)  # dos tag + status-only

    def test_every_parsed_template_has_reason_when_unsafe(self):
        reasons = set()
        for t, why in iter_templates(FIXTURES, LoadStats()):
            if t is None:
                reasons.add(why)
        self.assertTrue(any("yamlite" in r for r in reasons))
        self.assertTrue(any("matcher di luar kelas aman" in r
                            for r in reasons))


if __name__ == "__main__":
    unittest.main()
