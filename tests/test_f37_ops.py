"""Test F37 — tooling operasional: egress preflight + report pack.

NOL jaringan: probe difungsi lewat mock; program difilter dari config
dummy. Yang dikunci:
  - preflight: semua OK -> all_ok + impact kosong; satu jalur blok ->
    dampak capability tercantum;
  - report_pack.load_programs: hanya accepted=true yang lolos, filter
    --only berdasarkan domain, non-accepted = baris audit (fail-closed).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))

import egress_preflight as ep  # noqa: E402
import report_pack  # noqa: E402


class PreflightTest(unittest.TestCase):
    def test_all_ok(self):
        with unittest_mock_patch_all_ok():
            st = ep.run_preflight()
        self.assertTrue(st["all_ok"])
        self.assertEqual(st["impact"], [])
        self.assertEqual(len(st["checks"]), 3)

    def test_udp_blocked_impacts_dns(self):
        original = ep.check_udp53
        try:
            ep.check_udp53 = (lambda *a, **k:
                              {"check": "udp-53", "ok": False,
                               "detail": "timeout/blok", "elapsed_s": 0.0})
            st = ep.run_preflight()
        finally:
            ep.check_udp53 = original
        self.assertFalse(st["all_ok"])
        self.assertIn("udp-53", st["blocked"])
        self.assertTrue(any("DNS" in i for i in st["impact"]))

    def test_render_text_marks_blocked(self):
        txt = ep.render_text({"checks": [
            {"check": "udp-53", "ok": False, "detail": "blok",
             "elapsed_s": 0.0}],
            "all_ok": False, "blocked": ["udp-53"], "impact": []})
        self.assertIn("BLOK", txt)


def unittest_mock_patch_all_ok():
    import unittest.mock
    return unittest.mock.patch.multiple(
        ep, check_doh=lambda *a, **k: {"check": "doh-443", "ok": True,
                                       "detail": "status=0", "elapsed_s": 0.1},
        check_udp53=lambda *a, **k: {"check": "udp-53", "ok": True,
                                     "detail": "rcode=0", "elapsed_s": 0.1},
        check_tcp53=lambda *a, **k: {"check": "tcp-53", "ok": True,
                                     "detail": "jawaban diterima",
                                     "elapsed_s": 0.1})


class ReportPackProgramsTest(unittest.TestCase):
    def test_only_accepted_and_domain_filter(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "programs.json"
            cfg.write_text(json.dumps({"programs": [
                {"id": "a", "domain": "a.example", "accepted": True},
                {"id": "b", "domain": "b.example", "accepted": False},
                {"id": "c", "domain": "c.example", "accepted": True},
            ]}), encoding="utf-8")
            progs = report_pack.load_programs(cfg, None)
            self.assertEqual([p["id"] for p in progs], ["a", "c"])
            progs2 = report_pack.load_programs(cfg, ["c.example"])
            self.assertEqual([p["id"] for p in progs2], ["c"])

    def test_empty_selection_exit(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "programs.json"
            cfg.write_text(json.dumps({"programs": [
                {"id": "b", "domain": "b.example", "accepted": False}]}),
                encoding="utf-8")
            with self.assertRaises(SystemExit):
                # argv tanpa program lolos -> exit 2 (fail-closed)
                report_pack.main()


if __name__ == "__main__":
    unittest.main()


class MetaConsistencyRegressionTest(unittest.TestCase):
    """F47 regresi live-target (meta tanpa 'hits' membuat main() crash
    via KeyError — fail-closed orchestrator menangkapnya): SEMUA jalur
    audit() harus mengembalikan meta yang bisa dipakai main() tanpa
    KeyError."""

    def test_internal_info_leak_error_meta_has_no_crash_key(self):
        import internal_info_leak_checker as iil
        rows, meta = iil.audit(
            "https://example.com/x",
            {"status": None, "error": "URLError: timeout",
             "content_type": "", "body": ""})
        # main() memakai meta.get('hits', 0) — kunci: audit jalan + meta
        # ada; baris fetch-failed = unconfirmed
        self.assertTrue(any("Fetch failed" in r["title"] for r in rows))
        self.assertIn("error", meta)


class Soft404GuardTest(unittest.TestCase):
    """Regresi live-target 2026-10-20 (microsoft /sitemap.xml -> HTML):
    200 dengan konten HTML pada resource non-HTML = soft-404 suspicion,
    BUKAN lead 'exposes resource'."""

    def test_sitemap_html_is_soft404_not_lead(self):
        import sitemap_disclosure_checker as sm
        rows, _ = sm.audit(
            "https://microsoft.com/sitemap.xml",
            {"status": 200, "headers": {"content-type": "text/html"},
             "body": "<!DOCTYPE html><html><head>"})
        self.assertFalse([r for r in rows if "exposes resource" in r["title"]])
        soft = [r for r in rows if "soft-404" in r["title"]]
        self.assertEqual(len(soft), 1)
        self.assertEqual(soft[0]["status"], "unconfirmed")

    def test_sitemap_xml_still_lead(self):
        import sitemap_disclosure_checker as sm
        rows, _ = sm.audit(
            "https://example.com/sitemap.xml",
            {"status": 200, "headers": {"content-type": "application/xml"},
             "body": '<?xml version="1.0"?><urlset>'})
        self.assertEqual(len([r for r in rows
                              if "exposes resource" in r["title"]]), 1)

    def test_robots_html_is_soft404(self):
        import robots_txt_surface as rb
        rows, _ = rb.audit(
            "https://example.com/robots.txt",
            {"status": 200, "headers": {"content-type": "text/html"},
             "body": "<!doctype html><html>not found</html>"})
        self.assertFalse([r for r in rows if "exposes resource" in r["title"]])

    def test_wellknown_html_is_soft404(self):
        import well_known_exposure_checker as wk
        rows, _ = wk.audit(
            "https://example.com/.well-known/security.txt",
            {"status": 200, "headers": {"content-type": "text/html"},
             "body": "<!doctype html><html>error</html>"})
        self.assertFalse([r for r in rows if "exposes resource" in r["title"]])
