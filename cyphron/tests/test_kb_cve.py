"""Unit tests — GOD-TIER batch 2: fingerprint_to_cpe + nvd_sqlite + cve_matcher.

Semua offline: feed NVD mini (fixture) -> cpe.sqlite di folder sementara;
tool dijalankan langsung dengan ToolContext + WorldModel berisi fingerprint
ala BIM nyata (nginx, PHP, OJS, Leconfe). Zero-FP diverifikasi eksplisit:
- rentang menutup = tidak diklaim (CVE-2026-1111 vs 3.4.0.7),
- bound ambigu (7.x) = dibuang + dihitung,
- versi tak diketahui = note, bukan temuan.
"""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FIXTURE_FEED = (Path(__file__).resolve().parent / "fixtures" / "kb" / "nvd" /
                "nvdcve-1.1-mini-2026.json")

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.kb import fingerprint, nvd_sqlite
from cyphron.kb.paths import load_manifest
from cyphron.tools.base import ToolContext
from cyphron.world.model import WorldModel


def _ctx(world: WorldModel | None = None) -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=world or WorldModel(), rate_limit_s=0.0,
                       timeout_s=5.0, max_requests=50)


class KbEnv:
    """KB sementara: feed fixture -> cpe.sqlite."""

    def __init__(self):
        tmp = tempfile.TemporaryDirectory()
        self.addon_cleanup = tmp.cleanup
        self.kb_dir = Path(tmp.name) / "kb"
        nvd = self.kb_dir / "nvd"
        nvd.mkdir(parents=True)
        raw = FIXTURE_FEED.read_bytes()
        (nvd / "nvdcve-1.1-2026.json.gz").write_bytes(gzip.compress(raw))
        self.build = nvd_sqlite.build_sqlite(self.kb_dir)

    def cleanup(self):
        self.addon_cleanup()


class TestCpe23AndBounds(unittest.TestCase):
    def test_parse_cpe23(self):
        parsed = nvd_sqlite.parse_cpe23(
            "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
        self.assertEqual(parsed, ("a", "f5", "nginx", "1.24.0", "*"))
        self.assertIsNone(nvd_sqlite.parse_cpe23("bukan-cpe"))

    def test_version_in_bounds(self):
        f = nvd_sqlite.version_in_bounds
        self.assertTrue(f("3.4.0.7", None, None, None, None))
        self.assertFalse(f("3.4.0.7", None, "3.4.0.6", None, None))
        self.assertTrue(f("3.4.0.7", "3.4.0.7", None, None, None))
        self.assertFalse(f("3.4.0.7", None, None, "3.4.0.7", None))
        self.assertTrue(f("8.1.34", "8.1.0", None, None, "8.2.0"))
        self.assertFalse(f("8.2.0", "8.1.0", None, None, "8.2.0"))
        self.assertIsNone(f("3.4", "3.x", None, None, None))  # ambigu
        self.assertTrue(f("2.3", "2.3.0", None, None, None))  # padding nol

    def test_build_and_query(self):
        env = KbEnv()
        self.addCleanup(env.cleanup)
        self.assertEqual(env.build["cves"], 8)
        self.assertGreaterEqual(env.build["cpe_rows"], 6)
        rows, ambiguous = nvd_sqlite.query_cves_for_product(
            env.build["db"], "public_knowledge_project",
            "open_journal_systems", "3.4.0.7")
        self.assertEqual([r["id"] for r in rows], ["CVE-2026-2222"])
        self.assertEqual(ambiguous, 0)
        # PHP 8.1.34: rentang <8.1.30 tertutup, rentang 8.1.0-<8.2.0 cocok
        rows, _ = nvd_sqlite.query_cves_for_product(
            env.build["db"], "php", "php", "8.1.34")
        self.assertEqual([r["id"] for r in rows], ["CVE-2026-4444"])
        # nginx eksak 1.23.4 tidak boleh menimpa 1.24.0; wildcard tetap cocok
        rows, _ = nvd_sqlite.query_cves_for_product(
            env.build["db"], "f5", "nginx", "1.24.0")
        self.assertEqual([r["id"] for r in rows], ["CVE-2026-6666"])
        # wordpress + bound ambigu -> dibuang total
        rows, ambiguous = nvd_sqlite.query_cves_for_product(
            env.build["db"], "wordpress", "wordpress", "7.1")
        self.assertEqual(rows, [])
        self.assertEqual(ambiguous, 1)


class TestFingerprint(unittest.TestCase):
    def test_bim_like_strings_to_cpe(self):
        texts = ["Server: nginx/1.24.0",
                 "X-Powered-By: PHP/8.1.34",
                 "generator: Open Journal Systems 3.4.0.7",
                 "generator: Leconfe 1.4.0",
                 "generator: WordPress 7.1"]
        matches = fingerprint.to_cpe(texts)
        by_product = {m.product: m for m in matches}
        self.assertEqual(by_product["nginx"].cpe23,
                         "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
        self.assertEqual(by_product["php"].version, "8.1.34")
        self.assertEqual(by_product["open_journal_systems"].version, "3.4.0.7")
        self.assertEqual(by_product["leconfe"].version, "1.4.0")
        self.assertEqual(by_product["wordpress"].version, "7.1")
        self.assertTrue(all(m.versioned for m in matches))

    def test_no_version_is_star_not_claim(self):
        matches = fingerprint.to_cpe(["Server: nginx"])
        self.assertEqual(len(matches), 1)
        self.assertFalse(matches[0].versioned)
        self.assertEqual(matches[0].version, "*")

    def test_neo_feeder_note_only(self):
        matches = fingerprint.to_cpe(["banner: NEO Feeder PDDIKTI"])
        self.assertEqual(len(matches), 1)
        self.assertTrue(matches[0].note_only)

    def test_fingerprint_from_world(self):
        world = WorldModel()
        world.technologies = {"Server: nginx/1.24.0": "header on /"}
        texts = fingerprint.fingerprints_from_world(world)
        self.assertTrue(any("nginx/1.24.0" in t for t in texts))


class TestFingerprintToCpeTool(unittest.TestCase):
    def test_tool_outputs_cpe_and_note(self):
        world = WorldModel()
        world.technologies = {
            "generator: Open Journal Systems 3.4.0.7": "meta tag on /"}
        ctx = _ctx(world)
        from cyphron.tools.fingerprint_to_cpe import FingerprintToCpeTool
        tr = FingerprintToCpeTool().run({}, ctx)
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["total"], 1)
        self.assertEqual(tr.data["cpe"][0]["cpe23"],
                         "cpe:2.3:a:public_knowledge_project:"
                         "open_journal_systems:3.4.0.7:*:*:*:*:*:*:*")
        self.assertTrue(any("open_journal_systems" in n for n in world.notes))

    def test_tool_without_signals_skips(self):
        ctx = _ctx()
        from cyphron.tools.fingerprint_to_cpe import FingerprintToCpeTool
        tr = FingerprintToCpeTool().run({}, ctx)
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["skipped"], "tidak ada fingerprint")


class TestCveMatcherTool(unittest.TestCase):
    def _env_ctx(self, technologies: dict | None = None):
        env = KbEnv()
        self.addCleanup(env.cleanup)
        world = WorldModel()
        world.target = "https://bim.example.ac.id"
        world.technologies = technologies or {}
        ctx = _ctx(world)
        return env, ctx

    def test_kb_missing_is_note_not_error(self):
        ctx = _ctx()
        import tempfile as _tf
        with _tf.TemporaryDirectory() as empty:
            from cyphron.tools.cve_matcher import CveMatcherTool
            tr = CveMatcherTool().run({"kb_dir": empty}, ctx)
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["skipped"], "kb-belum-tersedia")

    def test_bim_like_world_yields_leads(self):
        env, ctx = self._env_ctx({
            "Server: nginx/1.24.0": "header on /",
            "X-Powered-By: PHP/8.1.34": "header on /",
            "generator: Open Journal Systems 3.4.0.7": "meta tag on /",
            "generator: Leconfe 1.4.0": "meta tag on /"})
        from cyphron.tools.cve_matcher import CveMatcherTool
        tr = CveMatcherTool().run({"kb_dir": str(env.kb_dir)}, ctx)
        self.assertTrue(tr.ok)
        titles = {f.title for f in tr.findings}
        # 4 produk berversi -> 4 lead; masing-masing tepat sesuai rentang
        self.assertEqual(len(tr.findings), 4)
        self.assertTrue(any("open_journal_systems 3.4.0.7" in t
                            and "CVE-2026-2222" in t for t in titles))
        self.assertTrue(any("php 8.1.34" in t and "CVE-2026-4444" in t
                            for t in titles))
        self.assertTrue(any("nginx 1.24.0" in t and "CVE-2026-6666" in t
                            for t in titles))
        self.assertTrue(any("leconfe 1.4.0" in t and "CVE-2026-8888" in t
                            for t in titles))
        for f in tr.findings:
            self.assertEqual(f.severity, "info")
            self.assertEqual(f.status, "unconfirmed")
            self.assertEqual(f.finding_class, "surface")
            self.assertIn("bukan klaim kerentanan", f.description)
            kinds = [e["kind"] for e in f.evidence_chain]
            self.assertIn("kb", kinds)

    def test_unversioned_product_note_only(self):
        env, ctx = self._env_ctx({"Server: nginx": "header on /"})
        from cyphron.tools.cve_matcher import CveMatcherTool
        tr = CveMatcherTool().run({"kb_dir": str(env.kb_dir)}, ctx)
        self.assertTrue(tr.ok)
        self.assertEqual(tr.findings, [])
        self.assertTrue(any("tanpa versi eksplisit" in n
                            for n in ctx.world.notes))

    def test_manual_cpe23_arg(self):
        env, ctx = self._env_ctx()
        from cyphron.tools.cve_matcher import CveMatcherTool
        tr = CveMatcherTool().run(
            {"kb_dir": str(env.kb_dir),
             "cpe23": ["cpe:2.3:a:php:php:8.1.34:*:*:*:*:*:*:*"]}, ctx)
        self.assertEqual(len(tr.findings), 1)
        self.assertIn("CVE-2026-4444", tr.findings[0].title)

    def test_ambiguous_bound_never_claims(self):
        env, ctx = self._env_ctx({"generator: WordPress 7.1": "meta tag on /"})
        from cyphron.tools.cve_matcher import CveMatcherTool
        tr = CveMatcherTool().run({"kb_dir": str(env.kb_dir)}, ctx)
        self.assertTrue(tr.ok)
        # satu-satunya CVE wordpress di KB ambigu (7.x) -> NOL temuan
        self.assertEqual(tr.findings, [])
        self.assertEqual(tr.data["products"][0]["matched"], 0)


if __name__ == "__main__":
    unittest.main()
