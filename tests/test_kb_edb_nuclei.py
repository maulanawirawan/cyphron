"""Unit tests — GOD-TIER batch 3: edb_reference + nuclei_bridge.

edb_reference : katalog EDB (fixture CSV) -> referensi EDB-ID pasif,
                nama produk saja TIDAK dianggap klaim versi, PHPMyAdmin
                tidak boleh tertelan pola 'PHP' (word-boundary).
nuclei_bridge : template aman dieksekusi 1x dan match wajib ISI respons
                (catch-all 200 tidak boleh lolos); template dos/DSL tidak
                pernah dijalankan; dry_run = nol request.
Semua offline (HTTPServer dipatch ala test engine lain).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

EDB_CSV = (Path(__file__).resolve().parent / "fixtures" / "kb" / "edb" /
           "files_exploits.csv")
# tools menerima ROOT KB (berisi nuclei/, edb/, nvd/) — mirror struktur kb/data
KB_ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.kb import edb_index
from cyphron.tools import http_engine
from cyphron.tools.base import ToolContext
from cyphron.world.model import WorldModel


def _ctx(world: WorldModel | None = None) -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=world or WorldModel(), rate_limit_s=0.0,
                       timeout_s=5.0, max_requests=50)


def _tmp_edb_kb() -> Path:
    tmp = tempfile.TemporaryDirectory()
    kb = Path(tmp.name) / "kb" / "edb"
    kb.mkdir(parents=True)
    (kb / "files_exploits.csv").write_bytes(EDB_CSV.read_bytes())
    # simpan referensi cleanup lewat penutupan tmp oleh pemanggil addCleanup
    _tmp_edb_kb._last = tmp
    return Path(tmp.name) / "kb"


class TestEdbIndex(unittest.TestCase):
    def test_find_versioned_and_name_only(self):
        rows = edb_index.load_index(EDB_CSV)
        self.assertEqual(len(rows), 7)
        versioned, name_only = edb_index.find_exploits(
            rows, ["WordPress"], "7.1")
        self.assertEqual([r["id"] for r in versioned], ["10001"])
        self.assertEqual(name_only, 1)  # "WordPress Core - ..." tanpa versi

    def test_word_boundary_no_phpmyadmin(self):
        rows = edb_index.load_index(EDB_CSV)
        versioned, _ = edb_index.find_exploits(rows, ["PHP"], "8.1.34")
        ids = [r["id"] for r in versioned]
        self.assertEqual(ids, ["10006"])
        self.assertNotIn("10007", ids)  # PHPMyAdmin != PHP

    def test_multi_alias_ojs(self):
        rows = edb_index.load_index(EDB_CSV)
        versioned, _ = edb_index.find_exploits(
            rows, ["Open Journal Systems", "OJS"], "3.4.0.7")
        self.assertEqual([r["id"] for r in versioned], ["10003"])
        # alias "OJS" saja tidak menemukan deskripsi yang menulis nama penuh
        versioned, _ = edb_index.find_exploits(rows, ["OJS"], "3.4.0.7")
        self.assertEqual(versioned, [])


class TestEdbReferenceTool(unittest.TestCase):
    def test_missing_kb_is_note(self):
        ctx = _ctx()
        with tempfile.TemporaryDirectory() as empty:
            from cyphron.tools.edb_reference import EdbReferenceTool
            tr = EdbReferenceTool().run({"kb_dir": empty}, ctx)
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["skipped"], "kb-belum-tersedia")

    def test_bim_world_yields_public_exploit_leads(self):
        kb_dir = _tmp_edb_kb()
        self.addCleanup(_tmp_edb_kb._last.cleanup)
        world = WorldModel()
        world.technologies = {
            "generator: WordPress 7.1": "meta tag on /",
            "X-Powered-By: PHP/8.1.34": "header on /",
            "generator: Leconfe 1.4.0": "meta tag on /"}
        ctx = _ctx(world)
        from cyphron.tools.edb_reference import EdbReferenceTool
        tr = EdbReferenceTool().run({"kb_dir": str(kb_dir)}, ctx)
        self.assertTrue(tr.ok)
        titles = {f.title for f in tr.findings}
        self.assertTrue(any("WordPress 7.1" in t and "EDB-10001" in t
                            for t in titles))
        self.assertTrue(any("Leconfe 1.4.0" in t and "EDB-10005" in t
                            for t in titles))
        self.assertTrue(any("PHP 8.1.34" in t and "EDB-10006" in t
                            for t in titles))
        for f in tr.findings:
            self.assertEqual(f.severity, "info")
            self.assertIn("tidak pernah", f.description.lower() + f.description)
            self.assertIn("edb", [e["kind"] for e in f.evidence_chain])


class _RouterServer:
    """Patch http_engine.http_get dengan responder sederhana."""

    def __init__(self, test, responder):
        self._orig = http_engine.http_get

        def fake_get(url, **kw):
            return responder(url, kw)

        http_engine.http_get = fake_get
        test.addCleanup(setattr, http_engine, "http_get", self._orig)


class TestNucleiBridgeTool(unittest.TestCase):
    def _bridge(self, responder, args: dict):
        _RouterServer(self, responder)
        from cyphron.tools.nuclei_bridge import NucleiBridgeTool
        world = WorldModel()
        world.target = "http://t.test"
        return NucleiBridgeTool().run(args, _ctx(world))

    def _responder(self, config_body: str, status: int = 200):
        def resp(url, kw):
            if url.endswith("/.git/config"):
                return status, {}, config_body, 1
            return status, {}, "<html>halaman default apa pun</html>", 1
        return resp

    def test_missing_kb_is_note(self):
        ctx = _ctx()
        with tempfile.TemporaryDirectory() as empty:
            from cyphron.tools.nuclei_bridge import NucleiBridgeTool
            tr = NucleiBridgeTool().run({"kb_dir": empty}, ctx)
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["skipped"], "kb-belum-tersedia")

    def test_safe_template_match_and_single_request(self):
        calls = []

        def resp(url, kw):
            calls.append(url)
            return self._responder("[core]\nrepositoryformatversion = 0"
                                   )(url, kw)

        _RouterServer(self, resp)
        from cyphron.tools.nuclei_bridge import NucleiBridgeTool
        world = WorldModel()
        world.target = "http://t.test"
        tr = NucleiBridgeTool().run(
            {"kb_dir": str(KB_ROOT), "template_ids":
             ["git-config-exposure"]}, _ctx(world))
        self.assertTrue(tr.ok)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith("/.git/config"))
        self.assertEqual(len(tr.findings), 1)
        f = tr.findings[0]
        self.assertEqual(f.title, "[nuclei:git-config-exposure] Git "
                                  "Configuration File Exposure")
        self.assertEqual(f.status, "confirmed")
        self.assertEqual(f.severity, "low")
        self.assertEqual(tr.data["requests_sent"], 1)

    def test_catchall_200_never_matches(self):
        # kata kunci "[core]" TIDAK ada di body catch-all -> nol temuan
        tr = self._bridge(self._responder("halaman kosong"), {
            "kb_dir": str(KB_ROOT),
            "template_ids": ["git-config-exposure"]})
        self.assertEqual(tr.findings, [])
        self.assertEqual(tr.data["requests_sent"], 1)

    def test_dry_run_sends_nothing(self):
        calls = []

        def resp(url, kw):
            calls.append(url)
            return 200, {}, "x", 1
        _RouterServer(self, resp)
        from cyphron.tools.nuclei_bridge import NucleiBridgeTool
        world = WorldModel()
        world.target = "http://t.test"
        tr = NucleiBridgeTool().run(
            {"kb_dir": str(KB_ROOT), "dry_run": True}, _ctx(world))
        self.assertEqual(calls, [])
        self.assertEqual(tr.data["requests_sent"], 0)
        self.assertGreaterEqual(len(tr.data["checked"]), 1)
        self.assertTrue(all(r.get("would_send")
                            for r in tr.data["checked"]))

    def test_unsafe_templates_never_run(self):
        # fixture berisi template dos/DSL/body-POST -> hanya 1 aman
        tr = self._bridge(self._responder("x"), {
            "kb_dir": str(KB_ROOT), "dry_run": True})
        would = {r["id"] for r in tr.data["checked"]}
        self.assertEqual(would, {"git-config-exposure"})
        stats = tr.data["stats"]
        self.assertEqual(stats["total"], 6)
        self.assertEqual(stats["safe"], 1)


if __name__ == "__main__":
    unittest.main()
