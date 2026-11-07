"""Nol jaringan — test dep_confusion_check (risiko dependency
confusion). Jaringan di-patch: http_get_status diganti stub; tidak ada
request nyata."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import dep_confusion_check as dcc  # noqa: E402


def leads_of(rc):
    return [l.lead for l in rc] if rc else []


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = Path(self._td.name)
        self.addCleanup(self._td.cleanup)

    def write(self, name, content):
        p = self.d / name
        p.write_text(content, encoding="utf-8")
        return p


class TestNpm(Base):
    def test_scope_tanpa_pemetaan_high(self):
        pkg = self.write("package.json", json.dumps({
            "dependencies": {"@corp/util": "^1.0", "lodash": "^4"}}))
        rc = self.write(".npmrc", "registry=https://registry.npmjs.org/\n")
        leads, _ = dcc.run_checks([pkg, rc], None, False)
        ls = leads_of(leads)
        self.assertTrue(any(l["severity"] == "HIGH" and
                            l["package"] == "@corp" for l in ls))

    def test_scope_dengan_pemetaan_bersih(self):
        pkg = self.write("package.json", json.dumps({
            "dependencies": {"@corp/util": "^1.0"}}))
        rc = self.write(".npmrc",
                        "@corp:registry=https://npm.corp.internal/\n"
                        "always-auth=true\n")
        leads, _ = dcc.run_checks([pkg, rc], None, False)
        self.assertEqual(leads_of(leads), [])

    def test_internal_unscoped_high(self):
        pkg = self.write("package.json", json.dumps({
            "dependencies": {"corp-utils": "^0.1.0"}}))
        internal = self.write("internal.txt", "npm:corp-utils\n")
        leads, _ = dcc.run_checks([pkg], internal, False)
        ls = leads_of(leads)
        self.assertTrue(any(l["severity"] == "HIGH" and
                            l["package"] == "corp-utils" for l in ls))

    def test_lockfile_campur_maju_medium(self):
        lock = self.write("package-lock.json", json.dumps({
            "packages": {
                "node_modules/lodash": {
                    "resolved": "https://registry.npmjs.org/lodash/"},
                "node_modules/corp-util": {
                    "resolved": "https://npm.corp.internal/corp-util/"},
            }}))
        leads, _ = dcc.run_checks([lock], None, False)
        ls = leads_of(leads)
        self.assertTrue(any(l["severity"] == "MEDIUM" for l in ls))

    def test_lockfile_publik_saja_bersih(self):
        lock = self.write("package-lock.json", json.dumps({
            "packages": {
                "node_modules/lodash": {
                    "resolved": "https://registry.npmjs.org/lodash/"}}}))
        leads, _ = dcc.run_checks([lock], None, False)
        self.assertEqual(leads_of(leads), [])

    def test_yarn_lock_campur_medium(self):
        y = self.write("yarn.lock",
                       'lodash@^4:\n  resolved "https://registry.npmjs.org/lodash/-/lodash-4.0.0.tgz"\n'
                       'corp@^1:\n  resolved "https://npm.corp.internal/corp-1.0.0.tgz"\n')
        leads, _ = dcc.run_checks([y], None, False)
        self.assertTrue(any(l["severity"] == "MEDIUM"
                            for l in leads_of(leads)))


class TestPip(Base):
    def test_multi_index_medium(self):
        req = self.write("requirements.txt",
                         "--index-url https://pypi.org/simple\n"
                         "--extra-index-url https://pypi.corp.internal/simple\n"
                         "requests==2.31.0\n")
        leads, _ = dcc.run_checks([req], None, False)
        ls = leads_of(leads)
        self.assertTrue(any(l["severity"] == "MEDIUM" and
                            l["ecosystem"] == "pypi" for l in ls))

    def test_internal_unpinned_di_multi_index_high(self):
        req = self.write("requirements.txt",
                         "--index-url https://pypi.org/simple\n"
                         "--extra-index-url https://pypi.corp.internal/simple\n"
                         "corp-tool\n")
        internal = self.write("internal.txt", "pypi:corp-tool\n")
        leads, _ = dcc.run_checks([req], internal, False)
        ls = leads_of(leads)
        self.assertTrue(any(l["severity"] == "HIGH" and
                            l["package"] == "corp-tool" for l in ls))

    def test_internal_terpin_di_multi_index_tidak_high(self):
        req = self.write("requirements.txt",
                         "--index-url https://pypi.org/simple\n"
                         "--extra-index-url https://pypi.corp.internal/simple\n"
                         "corp-tool==1.2.3\n")
        internal = self.write("internal.txt", "pypi:corp-tool\n")
        leads, _ = dcc.run_checks([req], internal, False)
        self.assertFalse([l for l in leads_of(leads)
                          if l["package"] == "corp-tool" and
                          l["severity"] == "HIGH"])


class TestNuget(Base):
    def test_multi_feed_tanpa_mapping_high(self):
        cfg = self.write(
            "NuGet.config",
            "<configuration><packageSources>"
            '<add key="corp" value="https://nuget.corp.internal/v3/index.json" />'
            '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />'
            "</packageSources></configuration>")
        leads, _ = dcc.run_checks([cfg], None, False)
        self.assertTrue(any(l["severity"] == "HIGH" and
                            l["ecosystem"] == "nuget"
                            for l in leads_of(leads)))

    def test_dengan_source_mapping_bersih(self):
        cfg = self.write(
            "NuGet.config",
            "<configuration><packageSources>"
            '<add key="corp" value="https://nuget.corp.internal/v3/index.json" />'
            '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />'
            "</packageSources>"
            "<packageSourceMapping>"
            '<packageSource key="corp"><package pattern="Corp.*" /></packageSource>'
            "</packageSourceMapping></configuration>")
        leads, _ = dcc.run_checks([cfg], None, False)
        self.assertEqual(leads_of(leads), [])


class TestFailClosed(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = Path(self._td.name)
        self.addCleanup(self._td.cleanup)

    def test_json_rusak_input_error(self):
        p = self.d / "package.json"
        p.write_text("{bukan json", encoding="utf-8")
        with self.assertRaises(dcc.InputError):
            dcc.run_checks([p], None, False)

    def test_xml_rusak_input_error(self):
        p = self.d / "NuGet.config"
        p.write_text("<configuration><unclosed>", encoding="utf-8")
        with self.assertRaises(dcc.InputError):
            dcc.run_checks([p], None, False)

    def test_main_file_hilang_exit2(self):
        rc = dcc.main(["--file", str(self.d / "nope.json")])
        self.assertEqual(rc, 2)

    def test_main_tanpa_file_exit2(self):
        self.assertEqual(dcc.main([]), 2)

    def test_format_tak_kenal_dicatat_lewat(self):
        p = self.d / "readme.md"
        p.write_text("halo", encoding="utf-8")
        leads, notes = dcc.run_checks([p], None, False)
        self.assertEqual(leads_of(leads), [])
        self.assertIn("format tidak dikenal", notes[0]["note"])


class TestVerifyRegistry(Base):
    """Stub jaringan — tidak ada request nyata."""

    def test_unclaimed_naik_high_dengan_detail(self):
        pkg = self.write("package.json", json.dumps({
            "dependencies": {"corp-utils": "^0.1.0"}}))
        internal = self.write("internal.txt", "npm:corp-utils\n")
        orig = dcc.http_get_status
        dcc.http_get_status = lambda url, timeout=10: 404
        try:
            leads, notes = dcc.run_checks([pkg], internal, True)
        finally:
            dcc.http_get_status = orig
        ls = leads_of(leads)
        target = [l for l in ls if l["package"] == "corp-utils"][0]
        self.assertEqual(target["severity"], "HIGH")
        self.assertIn("TIDAK terklaim", target["detail"])

    def test_unverified_tidak_diartikan_aman(self):
        pkg = self.write("package.json", json.dumps({
            "dependencies": {"corp-utils": "^0.1.0"}}))
        internal = self.write("internal.txt", "npm:corp-utils\n")
        orig = dcc.http_get_status
        dcc.http_get_status = lambda url, timeout=10: None
        try:
            leads, notes = dcc.run_checks([pkg], internal, True)
        finally:
            dcc.http_get_status = orig
        self.assertTrue(any("fail-closed" in n["note"]
                            for n in notes if "package" in n
                            and n.get("package") == "corp-utils"))

    def test_url_builder_npm_dan_pypi(self):
        self.assertIn("registry.npmjs.org/corp-utils",
                      "https://registry.npmjs.org/corp-utils")
        # via verify_registry_claim dengan stub
        orig = dcc.http_get_status
        seen = {}
        def fake(url, timeout=10):
            seen["url"] = url
            return 200
        dcc.http_get_status = fake
        try:
            self.assertEqual(dcc.verify_registry_claim("x", "pypi"),
                             "claimed")
            self.assertTrue(seen["url"].startswith(
                "https://pypi.org/pypi/x/"))
        finally:
            dcc.http_get_status = orig
        # ekosistem tak dikenal -> unverified (fail-closed)
        self.assertEqual(dcc.verify_registry_claim("x", "maven"),
                         "unverified")


class TestMainGate(Base):
    def test_exit0_tanpa_lead(self):
        pkg = self.write("package.json", json.dumps({
            "dependencies": {"@corp/u": "^1"}}))
        rc = self.write(".npmrc", "@corp:registry=https://npm.corp.internal/\n")
        out = self.d / "out.json"
        self.assertEqual(dcc.main(["--file", str(pkg), "--file", str(rc),
                                   "--out", str(out)]), 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], dcc.SCHEMA)

    def test_gate_high_exit1_dan_none_exit0(self):
        pkg = self.write("package.json", json.dumps({
            "dependencies": {"@corp/u": "^1"}}))
        # .npmrc ada tapi mapping scope hilang -> HIGH -> exit 1
        rc = self.write(".npmrc", "registry=https://registry.npmjs.org/\n")
        self.assertEqual(dcc.main(["--file", str(pkg),
                                   "--file", str(rc)]), 1)
        self.assertEqual(dcc.main(["--file", str(pkg), "--file", str(rc),
                                   "--fail-on", "NONE"]), 0)

    def test_scope_tanpa_npmrc_medium_bukan_high(self):
        pkg = self.write("package.json", json.dumps({
            "dependencies": {"@corp/u": "^1"}}))
        leads, _ = dcc.run_checks([pkg], None, False)
        ls = leads_of(leads)
        self.assertTrue(any(l["severity"] == "MEDIUM" and
                            l["package"] == "@corp" for l in ls))
        self.assertFalse([l for l in ls if l["severity"] == "HIGH"])
        # default gate HIGH -> exit 0
        self.assertEqual(dcc.main(["--file", str(pkg)]), 0)

    def test_gate_medium_exit1_bila_diminta(self):
        lock = self.write("package-lock.json", json.dumps({
            "packages": {
                "node_modules/a": {
                    "resolved": "https://registry.npmjs.org/a/"},
                "node_modules/b": {
                    "resolved": "https://npm.corp.internal/b/"}}}))
        self.assertEqual(dcc.main(["--file", str(lock),
                                   "--fail-on", "MEDIUM"]), 1)


if __name__ == "__main__":
    unittest.main()
