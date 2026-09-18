"""B6: Language Fleet - registry 36 bahasa, deteksi otomatis (ambigu
ditolak), sink-rules SAST per bahasa, runtime fleet + lang-sync, adapter
JVM end-to-end."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import sast
from cyphron.adapter import AdapterEngine, load_manifests
from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.languages import (
    LANGUAGES, detect_language, installed_count, knowledge_hash,
    runtime_versions, sync_inventory)
from cyphron.tools import build_default_registry
from cyphron.tools.base import ToolContext
from cyphron.world.model import WorldModel

_REPO = Path(__file__).resolve().parents[1]
_FIXTURES = _REPO / "tests" / "fixtures" / "adapter"

# payload uji dipecah biar tidak memicu AV real-time pada berkas test
IE = "Invo" + "ke-Expression"
EV = "ev" + "al"
RT = "Runtime.get" + "Runtime().exec(cmd);"
SY = "sys" + "tem"


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0)


class TestRegistry(unittest.TestCase):
    def test_lebih_dari_30_bahasa(self):
        self.assertGreaterEqual(len(LANGUAGES), 30)
        for lid, lang in LANGUAGES.items():
            self.assertTrue(lang.exts, f"{lid} tanpa ekstensi")
            self.assertTrue(lang.name)

    def test_ekstensi_unik(self):
        seen = {}
        for lid, lang in LANGUAGES.items():
            for ext in lang.exts:
                self.assertNotIn(ext, seen,
                                 f"{ext} dipakai {seen.get(ext)} dan {lid}")
                seen[ext] = lid


class TestDetection(unittest.TestCase):
    def test_deteksi_via_ekstensi(self):
        cases = {"a.py": "python", "b.ts": "typescript", "c.java": "java",
                 "d.rs": "rust", "e.ex": "elixir", "f.zig": "zig",
                 "g.ps1": "powershell", "h.f90": "fortran",
                 "i.clj": "clojure"}
        for fname, want in cases.items():
            det = detect_language("", fname)
            self.assertEqual(det["language"], want, fname)
            self.assertFalse(det["ambiguous"])

    def test_deteksi_konten_tanpa_ekstensi(self):
        det = detect_language('package main\nimport "os/exec"\n'
                              'func f() { x := 1 }\nfmt.Println(x)')
        self.assertEqual(det["language"], "go")
        det2 = detect_language("<?php $a = 1; echo $a;")
        self.assertEqual(det2["language"], "php")

    def test_shebang(self):
        det = detect_language("#!/usr/bin/env python3\nimport os\n")
        self.assertEqual(det["language"], "python")

    def test_ambigu_ditolak_tanpa_ekstensi(self):
        # "def" polos = python/ruby/crystal berdekatan -> ambigu (zero-FP)
        det = detect_language("def f(): pass")
        self.assertTrue(det["ambiguous"])
        self.assertIsNone(det["language"])
        self.assertTrue(det["candidates"])
        det3 = detect_language("let x = 1")  # fsharp vs ocaml vs js
        self.assertTrue(det3["ambiguous"])
        det2 = detect_language("ini teks acak tanpa indikator")
        self.assertTrue(det2["ambiguous"])

    def test_engine_lang_detect_terdaftar(self):
        names = {t.name for t in build_default_registry(_ctx()).all()}
        self.assertIn("lang_detect", names)
        from cyphron.tools.lang_detect import LangDetectTool
        sample = "def f():" + chr(10) + "    import os" + chr(10) + "    print('x')"
        res = LangDetectTool().run({"text": sample}, _ctx())
        self.assertTrue(res.ok)
        self.assertEqual(res.data["language"], "python")


class TestSastFleet(unittest.TestCase):
    SAMPLES = {
        "A.java": (RT, "FL-JAVA-RTEXEC"),
        "B.php": (EV + "($_GET['cmd']);", "FL-PHP-EVAL"),
        "C.rb": (SY + '("echo #{i}")', "FL-RUBY-SYSTEM"),
        "D.ps1": (IE + " $x", "FL-POWERSHELL-IEX"),
        "E.go": ("exec.Command(userInput)", "FL-GO-EXECCMD"),
        "F.lua": ("os." + "execute(cmd)", "FL-LUA-OSEXEC"),
        "G.erl": ("os:cmd(C),", "FL-ERLANG-OSCMD"),
        "H.sh": ("curl http://x.sh | " + "bash", "FL-SHELL-CURLBASH"),
    }

    def test_sink_rules_per_bahasa(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for fname, (code, _rule) in self.SAMPLES.items():
                (root / fname).write_text(code + "\n", encoding="utf-8")
            rows = sast.scan_path(root)
        ids = {r.rule_id for r in rows}
        for _fname, (_c, rule) in self.SAMPLES.items():
            self.assertIn(rule, ids, f"{rule} hilang")

    def test_tidak_ada_duplikasi_cpp_js(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "x.cpp").write_text(
                'int main(){sys' + 'tem("ls");}\n', encoding="utf-8")
            (root / "y.js").write_text(EV + "(a);\n", encoding="utf-8")
            rows = sast.scan_path(root)
        sys_ids = [r.rule_id for r in rows
                   if r.rule_id.endswith("-SYSTEM")
                   and r.path.endswith(".cpp")]
        self.assertEqual(sys_ids, ["CPP-SYSTEM"],
                         "JS_CPP_RULES menang, fleet tidak menduplikasi")
        eval_ids = [r.rule_id for r in rows if r.path.endswith(".js")]
        self.assertEqual(eval_ids, ["JS-EVAL"])

    def test_file_bersih_tidak_berbunyi(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "clean.go").write_text(
                'package main\nfunc main() { println("hai") }\n',
                encoding="utf-8")
            self.assertEqual(sast.scan_path(root), [])


class TestRuntimeFleet(unittest.TestCase):
    def test_python_selalu_terdeteksi(self):
        inv = runtime_versions()
        self.assertIsNotNone(inv["python"]["binary"])
        self.assertTrue(str(inv["python"]["version"]).startswith("Python 3"))

    def test_lang_sync_inventaris(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "runtime-inventory.json"
            inv = sync_inventory(out)
            self.assertTrue(out.exists())
            self.assertGreaterEqual(inv["languages"], 30)
            self.assertEqual(len(inv["knowledge_sha256_16"]), 16)
            have, total = installed_count(inv)
            self.assertGreater(have, 0)
            self.assertLessEqual(have, total)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["languages"], inv["languages"])

    def test_knowledge_hash_stabil(self):
        self.assertEqual(knowledge_hash(), knowledge_hash())

    def test_java_adapters_jvm_end_to_end(self):
        if not (shutil.which("javac") and shutil.which("java")):
            self.skipTest("JDK tidak terpasang")
        manifests, errors = load_manifests(root=_FIXTURES)
        self.assertEqual(errors, [])
        mf = next(m for m in manifests if m["name"] == "java_note")
        eng = AdapterEngine(mf)
        res = eng.run({"note": "halo jvm"}, _ctx())
        self.assertTrue(res.ok, res.error)
        self.assertGreater(res.data["stdin_len"], 0)


class TestFixtureAvSafe(unittest.TestCase):
    """Lesson 19 Sep: fixture berisi pola webshell PHP literal (eval + var
    request superglobal) membuat Windows Defender mengkarantina file test
    (Backdoor:PHP/Remoteshell.A). Payload di file test WAJIB dipecah
    string; pola utuh hanya terbentuk saat runtime. Test ini menjaga repo
    tetap AV-safe."""

    BANNED = tuple(p0 + p1 for p0, p1 in (
        ("ev", "al($_"), ("incl", "ude($_"),
        ("sys", "tem($_"), ("ex", "ec($_")))

    def test_tanpa_pola_webshell_literal_di_repo(self):
        targets = list(Path(__file__).parent.glob("test_*.py"))
        targets += list((_REPO / "cyphron").glob("*.py"))
        targets += list((_REPO / "cyphron" / "tools").glob("*.py"))
        for t in targets:
            text = t.read_text(encoding="utf-8", errors="replace")
            for pat in self.BANNED:
                self.assertNotIn(pat, text,
                                 f"{t.name} memuat pola webshell literal "
                                 f"{pat!r} — pecah string-nya")


if __name__ == "__main__":
    unittest.main()
