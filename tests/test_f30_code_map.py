"""Test F30 — code-map (fase 3): attack-surface.json dari source code.

NOL jaringan, NOL eksekusi kode target — fixture repo sintetis.
Yang dikunci:
  - routes python (AST) + JS (regex): method/path/file/line;
  - flag auth dari decorator/middleware; flag upload;
  - skip .git/node_modules; secret kandidat (konservatif);
  - reconcile: lead target_url -> route (has_auth) — findings.json
    TIDAK diubah; fail-closed repo tidak ada = exit 2.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import code_map as cm  # noqa: E402

APP_PY = '''\
from flask import Flask, request
from flask_login import login_required

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    return "ok"

@app.route("/admin/panel")
@login_required
def panel():
    return "ok"

@app.route("/upload", methods=["POST"])
def up(u: "UploadFile" = None):
    f = request.files["f"]
    return "stored"

class User(models.Model):
    name = models.CharField()

SECRET_KEY = "abcdef1234567890"
'''

SERVER_JS = '''\
const mongoose = require("mongoose");
const app = require("express")();
app.get("/api/users", auth, (req, res) => res.json([]));
app.post("/upload", multer.single("f"), (req, res) => res.end());
const S = new mongoose.Schema({name: String});
'''

VENDOR_JS = 'app.get("/api/leak", (req, res) => res.end());\n'


def _mk_repo(tmp: Path) -> Path:
    repo = tmp / "target-repo"
    (repo / "app").mkdir(parents=True)
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "app.py").write_text(APP_PY, encoding="utf-8")
    (repo / "app" / "server.js").write_text(SERVER_JS, encoding="utf-8")
    (repo / "node_modules" / "pkg" / "vendor.js").write_text(
        VENDOR_JS, encoding="utf-8")
    return repo


class CodeMapScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.repo = _mk_repo(Path(cls.tmp))
        cls.surface = cm.scan_repo(cls.repo, 100)

    def test_routes_python_and_js_extracted(self):
        paths = {r["path"] for r in self.surface["routes"]}
        self.assertIn("/login", paths)
        self.assertIn("/admin/panel", paths)
        self.assertIn("/api/users", paths)
        self.assertIn("/upload", paths)
        self.assertNotIn("/api/leak", paths, "node_modules harus skip")
        login = next(r for r in self.surface["routes"]
                     if r["path"] == "/login")
        self.assertEqual(login["methods"], ["POST"])
        self.assertEqual(login["file"], "app.py")
        self.assertEqual(login["auth"], False)
        admin = next(r for r in self.surface["routes"]
                     if r["path"] == "/admin/panel")
        self.assertEqual(admin["auth"], True)
        users = next(r for r in self.surface["routes"]
                     if r["path"] == "/api/users")
        self.assertEqual(users["auth"], True)

    def test_models_and_secrets_found(self):
        self.assertTrue(any("User" in m["decl"] or "__tablename__"
                            in m["decl"] or "Schema" in m["decl"]
                            for m in self.surface["models"]))
        sec = self.surface["secrets"]
        self.assertTrue(any("secret" in s["kind"] for s in sec),
                        sec)

    def test_admin_section_detected(self):
        files = [a["file"] for a in self.surface["admin"]]
        self.assertIn("app.py", files)

    def test_reconcile_maps_lead_to_route_without_mutating_findings(self):
        fjson = Path(self.tmp) / "f.json"
        doc = {"findings": [
            {"id": "lead-admin-1", "title": "Admin access",
             "target_url": "https://t.local/admin/panel",
             "verdict": 3, "status": "confirmed"},
            {"id": "lead-none-1", "title": "X",
             "target_url": "https://t.local/tidak-ada",
             "verdict": 2, "status": "confirmed"}]}
        fjson.write_text(json.dumps(doc), encoding="utf-8")
        before = fjson.read_text(encoding="utf-8")
        report = cm.reconcile(self.surface, fjson)
        self.assertEqual(fjson.read_text(encoding="utf-8"), before,
                         "findings.json tidak boleh berubah")
        self.assertEqual(len(report["matched"]), 1)
        m = report["matched"][0]
        self.assertEqual(m["route_file"], "app.py")
        self.assertTrue(m["has_auth"])
        self.assertEqual(report["unmatched"], 1)

    def test_fail_closed_missing_repo_exit_2(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "code_map.py"),
             "--repo", str(Path(self.tmp) / "nope"),
             "--out", str(Path(self.tmp) / "s.json")],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        self.assertEqual(r.returncode, 2)

    def test_cli_end_to_end(self):
        fjson = Path(self.tmp) / "f-cli.json"
        fjson.write_text(json.dumps({"findings": [
            {"id": "lead-admin-1", "title": "Admin access",
             "target_url": "https://t.local/admin/panel",
             "verdict": 3, "status": "confirmed"}]}), encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "code_map.py"),
             "--repo", str(self.repo),
             "--out", str(Path(self.tmp) / "surface.json"),
             "--reconcile", str(fjson)],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, r.stderr)
        s = json.loads((Path(self.tmp) / "surface.json")
                       .read_text(encoding="utf-8"))
        self.assertGreater(s["files_scanned"], 0)
        self.assertTrue((Path(self.tmp) / "surface-reconcile.json")
                        .exists())


if __name__ == "__main__":
    unittest.main()
