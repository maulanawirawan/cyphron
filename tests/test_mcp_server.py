"""Guard MCP server — allowlist, gerbang tier0, validasi kontrak fail-closed.

Nol jaringan: end-to-end memakai registry sementara dengan skill python
inline yang menulis findings.json (pola sama dengan test orchestrator).
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import mcp_server as ms  # noqa: E402

# output run_skill diarahkan ke direktori sementara — repo tetap bersih
_ms_tmp = pathlib.Path(tempfile.mkdtemp(prefix="cyphron_mcp_out_"))
ms.OUT_DIR = _ms_tmp

# skrip skill inline: tulis findings.json valid (pola sama test Rust)
GOOD_SCRIPT = r"""import json,sys,hashlib
h=hashlib.sha256(f"t|ok|lab.local||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{"requests":0},"requests":0,"findings":[
 {"tool":"t","title":"ok","severity":"low","description":"d",
  "target_url":"lab.local","evidence_kind":"dns","finding_class":"posture",
  "confidence":1.0,"status":"confirmed","verdict":1,
  "verdict_tag":"L1 SUSPECTED - LEAD","id":h,"reportable":False}]},
  open(sys.argv[1],"w"))
"""
# varian yang melanggar kontrak (severity ngawur) — harus ditolak server
BAD_SCRIPT = r"""import json,sys,hashlib
h=hashlib.sha256(f"t|ok|lab.local||".encode()).hexdigest()[:16]
json.dump({"ok":True,"data":{"requests":0},"requests":0,"findings":[
 {"tool":"t","title":"ok","severity":"gila","description":"d",
  "target_url":"lab.local","evidence_kind":"dns","finding_class":"posture",
  "confidence":1.0,"status":"confirmed","verdict":1,
  "verdict_tag":"L1 SUSPECTED - LEAD","id":h,"reportable":False}]},
  open(sys.argv[1],"w"))
"""


def fake_registry(script: str) -> pathlib.Path:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cyphron_mcp_"))
    reg = {"version": 1, "skills": [
        {"name": "fake-read", "cmd": ["python", "-c", script, "@OUT@"],
         "safety_class": "read-only", "needs": "none"},
        {"name": "fake-evidence",
         "cmd": ["python", "-c", script, "@OUT@"],
         "safety_class": "read-only", "needs": "none",
         "requires_evidence": True},
        {"name": "fake-probe", "cmd": ["python", "-c", script, "@OUT@"],
         "safety_class": "active-probe", "needs": "none"},
        {"name": "fake-needs-target",
         "cmd": ["python", "-c", script, "@OUT@"],
         "safety_class": "1-request", "needs": "target"},
    ]}
    p = tmp / "registry.json"
    p.write_text(json.dumps(reg), encoding="utf-8")
    return p


class AllowlistTest(unittest.TestCase):
    def test_registry_real_loads_and_tier0_selectable(self):
        reg = ms.load_registry()
        sel = ms.selectable_skills(reg)
        self.assertEqual(reg["version"], 1)
        expected = sum(1 for s in reg["skills"]
                       if s.get("safety_class") in ms.TIER0_CLASSES
                       and not s.get("lab_only"))
        self.assertEqual(len(sel), expected,
                         "selectable = kelas tier0, tanpa lab_only")
        self.assertGreater(len(sel), 40, "registry utama mayoritas tier0")
        names = {s["name"] for s in sel}
        self.assertIn("banner-posture", names)

    def test_lab_classes_never_selectable(self):
        reg = ms.load_registry()
        for s in ms.selectable_skills(reg):
            self.assertNotIn(s["safety_class"], ms.LAB_CLASSES)


class GateTest(unittest.TestCase):
    def setUp(self):
        self.reg = json.loads(fake_registry(GOOD_SCRIPT).read_text())

    def test_unknown_skill_fails_closed(self):
        with self.assertRaises(LookupError):
            ms.resolve_skill(self.reg, "perintah-ngawur")

    def test_lab_class_gate(self):
        s = ms.resolve_skill(self.reg, "fake-probe")
        with self.assertRaises(ValueError):
            ms.gate_skill(s, None, None, None)

    def test_requires_evidence_gate(self):
        s = ms.resolve_skill(self.reg, "fake-evidence")
        with self.assertRaises(ValueError):
            ms.gate_skill(s, None, None, None)
        ms.gate_skill(s, None, None, "ev.json")  # lolos bila bukti ada

    def test_needs_target_gate(self):
        s = ms.resolve_skill(self.reg, "fake-needs-target")
        with self.assertRaises(ValueError):
            ms.gate_skill(s, None, None, None)
        ms.gate_skill(s, "https://lab.local", None, None)

    def test_build_argv_placeholders(self):
        s = ms.resolve_skill(self.reg, "fake-read")
        argv = ms.build_argv(s, "https://t.example", None, "ev.json",
                             pathlib.Path("o.json"), python_exe="py.exe")
        self.assertEqual(argv[0], "py.exe", "python diganti interpreter")
        self.assertIn("o.json", argv)
        # placeholder @EVIDENCE@ diekspansi (spec sintetis ber-placeholder)
        spec = {"cmd": ["python", "-c", "x", "--evidence", "@EVIDENCE@",
                        "--target", "@TARGET@", "--out", "@OUT@"]}
        argv2 = ms.build_argv(spec, "https://t.example", None, "ev.json",
                              pathlib.Path("o.json"), python_exe="py.exe")
        self.assertEqual(argv2[4:],
                         ["ev.json", "--target", "https://t.example",
                          "--out", "o.json"])


class RunSkillTest(unittest.TestCase):
    def test_run_valid_skill_end_to_end(self):
        rp = fake_registry(GOOD_SCRIPT)
        out = json.loads(ms.run_skill("fake-read", registry_path=rp))
        self.assertTrue(out["ok"], out.get("error"))
        self.assertEqual(out["total_findings"], 1)
        self.assertEqual(out["reportable"], 0)
        self.assertEqual(out["findings"][0]["verdict_tag"],
                         "L1 SUSPECTED - LEAD")

    def test_contract_violation_never_reaches_client(self):
        rp = fake_registry(BAD_SCRIPT)
        out = json.loads(ms.run_skill("fake-read", registry_path=rp))
        self.assertFalse(out["ok"])
        self.assertIn("fail-closed", out["error"])
        self.assertNotIn("findings", out, "baris invalid tidak boleh bocor")

    def test_evidence_gate_blocks_execution(self):
        rp = fake_registry(GOOD_SCRIPT)
        out = json.loads(ms.run_skill("fake-evidence", registry_path=rp))
        self.assertFalse(out["ok"])
        self.assertIn("bukti", out["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
