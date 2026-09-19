"""B1: Engine Adapter Layer polyglot — manifest + auto-detect runtime +
jalankan engine non-Python via satu pintu guardrail. C++ pilot entropy_audit
diliputi (skip bila compiler absen); jalur eksekusi dibuktikan via fixture
node yang pasti ada di mesin dev."""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import adapter
from cyphron.adapter import AdapterEngine, detect_runtimes, load_manifests
from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.base import ToolContext
from cyphron.world.model import WorldModel

_REPO = Path(__file__).resolve().parents[1]
_FIXTURE = _REPO / "tests" / "fixtures" / "adapter" / "echo_node"


def _ctx(world: WorldModel | None = None) -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=world or WorldModel(), rate_limit_s=0.0,
                       timeout_s=5.0, max_requests=50)


class TestManifests(unittest.TestCase):
    def test_pilot_cpp_manifest_sah(self):
        manifests, errors = load_manifests()
        self.assertEqual(errors, [], errors)
        names = {m["name"] for m in manifests}
        self.assertIn("entropy_audit", names)

    def test_manifest_rusak_terdeteksi_sebagai_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "broken"
            bad.mkdir()
            (bad / "manifest.json").write_text('{"name": "x"}',
                                               encoding="utf-8")
            _m, errors = load_manifests(root=Path(td))
            self.assertEqual(len(errors), 1)
            self.assertIn("broken", errors[0])


class TestRegistryIntegration(unittest.TestCase):
    def test_adapter_terdaftar_di_registry(self):
        ctx = _ctx()
        reg = build_default_registry(ctx)
        self.assertIsNotNone(reg.get("entropy_audit"))
        self.assertIn("entropy_audit", {t.name for t in reg.all()})


class TestRuntimeDetectAndSkip(unittest.TestCase):
    def test_detect_mengembalikan_semua_runtime_key(self):
        r = detect_runtimes()
        self.assertEqual(set(r), set(adapter.RUNTIME_BINARIES))
        # node pasti ada di mesin dev/test (dipakai browser_scout juga)
        if shutil.which("node"):
            self.assertIsNotNone(r["node"])

    def test_runtime_absen_dilewati_anggun(self):
        manifests, _ = load_manifests()
        mf = next(m for m in manifests if m["name"] == "entropy_audit")
        w = WorldModel()
        eng = AdapterEngine(mf)
        _orig = adapter.detect_runtimes
        adapter.detect_runtimes = lambda: {"cpp": None}
        self.addCleanup(setattr, adapter, "detect_runtimes", _orig)
        res = eng.run({"values": ["x"]}, _ctx(w))
        self.assertTrue(res.ok)
        self.assertEqual(res.data.get("skipped"), "runtime-unavailable")
        self.assertTrue(any("runtime" in n for n in w.notes))


class TestExecutionPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("node"):
            raise unittest.SkipTest("node tidak tersedia")
        manifests, errors = load_manifests(root=_FIXTURE.parent)
        assert not errors, errors
        cls.mf = next(m for m in manifests if m["name"] == "echo_node")

    def test_echo_roundtrip(self):
        eng = AdapterEngine(self.mf)
        res = eng.run({"hello": "dunia", "n": 21}, _ctx())
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.data["echo"], "dunia")
        self.assertEqual(res.data["double"], 42)

    def test_findings_tidak_sah_dibuang(self):
        eng = AdapterEngine(self.mf)
        res = eng.run({"emit_finding": True}, _ctx())
        self.assertEqual(len(res.findings), 1,
                         "hanya temuan severity sah yang lolos")
        self.assertEqual(res.findings[0].tool, "echo_node")
        self.assertEqual(res.findings[0].status, "unconfirmed")
        kinds = [e["kind"] for e in res.findings[0].evidence_chain]
        self.assertIn("adapter", kinds)

    def test_request_accounting_jujur(self):
        w = WorldModel()
        eng = AdapterEngine(self.mf)
        eng.run({"requests": 7}, _ctx(w))
        self.assertEqual(w.request_count, 7)


@unittest.skipUnless(shutil.which("g++") or shutil.which("clang++"),
                     "compiler C++ tidak terpasang di mesin ini")
class TestCppPilot(unittest.TestCase):
    def test_entropy_audit_menemukan_token_lemah(self):
        manifests, errors = load_manifests()
        self.assertEqual(errors, [])
        mf = next(m for m in manifests if m["name"] == "entropy_audit")
        eng = AdapterEngine(mf)
        res = eng.run({"values": ["aaaaaaaaaaaaaaaa",
                                  "Dh3jK9pQzXvL2mNq8WzR"]}, _ctx())
        self.assertTrue(res.ok, res.error)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].cwe, "CWE-330")
        self.assertEqual(res.findings[0].severity, "low")
        self.assertEqual(res.findings[0].finding_class, "posture")


if __name__ == "__main__":
    unittest.main()
