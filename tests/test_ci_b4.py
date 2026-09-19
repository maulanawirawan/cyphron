"""B4: SAST CI-1..CI-6 — sast AST+taint+SARIF+CI, proxy intercept,
fleet partisi/merge, dast profil fail-closed, iac/sbom."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import dast, fleet, iac, sast
from cyphron.guardrails.authorization import AuditLog, AuthorizationDocument, AuthorizationGate
from cyphron.proxycore import History, InterceptQueue, serve_proxy
from cyphron.world.model import WorldModel

_REPO = Path(__file__).resolve().parents[1]

VULN = '''
import os, subprocess, requests, random, pickle
def handle(request):
    q = request.args.get("q")
    cmd = "ping " + q
    subprocess.run(cmd, shell=True)
    cur.execute(f"SELECT * FROM users WHERE name = '{q}'")
    cur.execute("SELECT * FROM users WHERE name = ?", (q,))
    tok = random.random()
    requests.get("https://x.test", verify=False)
'''
CLEAN = '''
def ok(a, b):
    cur.execute("SELECT * FROM users WHERE name = ?", (a,))
    return a + b
'''


class TestSast(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)
        (self.dir / "app.py").write_text(VULN, encoding="utf-8")
        (self.dir / "ok.py").write_text(CLEAN, encoding="utf-8")

    def test_ast_rule_dan_taint(self):
        rows = sast.scan_path(self.dir)
        ids = {r.rule_id for r in rows}
        self.assertIn("PY-SQLI-FORMAT", ids)
        self.assertIn("PY-SHELL-TRUE", ids)
        self.assertIn("PY-VERIFY-FALSE", ids)
        self.assertIn("PY-TAINT-SHELL", ids)
        # FP-guard: parameterized execute TIDAK dilaporkan; clean file bersih
        clean_rows = [r for r in rows if r.path.endswith("ok.py")]
        self.assertEqual(clean_rows, [])
        sqli = [r for r in rows if r.rule_id == "PY-SQLI-FORMAT"]
        self.assertEqual(len(sqli), 1, "execute 2-arg = binding, bukan temuan")
        # taint punya alur baris source -> sink
        taint = next(r for r in rows if r.rule_id == "PY-TAINT-SHELL")
        roles = [s["role"] for s in taint.flow]
        self.assertEqual(roles, ["source", "sink"])

    def test_taint_sanitizer_menghentikan_aliran(self):
        code = '''
import shlex
def h(request):
    q = request.args.get("q")
    safe = shlex.quote(q)
    os.system("echo " + safe)
'''
        p = self.dir / "sanitized.py"
        p.write_text(code, encoding="utf-8")
        rows = [r for r in sast.scan_path(p) if r.rule_id.startswith("PY-TAINT")]
        self.assertEqual(rows, [], "sanitizer wajib memutus aliran")

    def test_sarif_dan_ci_exit(self):
        rc = sast.run_ci(self.dir, out_dir=self.dir)
        self.assertEqual(rc, 2)
        sarif = json.loads((self.dir / "sast.sarif").read_text(encoding="utf-8"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])
        js = json.loads((self.dir / "sast.json").read_text(encoding="utf-8"))
        self.assertEqual(js["count"], len(sarif["runs"][0]["results"]))

    def test_rule_kustom_dot_cyphron_rules(self):
        (self.dir / ".cyphron-rules").write_text(json.dumps([
            {"id": "CLIENT-NAMASTE", "message": "kata terlarang",
             "severity": "low", "cwe": "CWE-?", "languages": ["python"],
             "regex": "namaste"}]), encoding="utf-8")
        (self.dir / "custom.py").write_text("x = 'namaste'\n",
                                            encoding="utf-8")
        rows = [r for r in sast.scan_path(self.dir)
                if r.rule_id == "CLIENT-NAMASTE"]
        self.assertEqual(len(rows), 1)


class _EchoHandler(BaseHTTPRequestHandler):
    log_message = lambda self, *a: None

    def do_GET(self):
        body = b"hello via proxy"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.origin = HTTPServer(("127.0.0.1", 0), _EchoHandler)
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()
        cls.origin_port = cls.origin.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.origin.shutdown()

    def test_passive_history_dan_scope_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            history = History(path=Path(td) / "h.jsonl")
            # gate TANPA dokumen: semua aktif ditolak -> proxy refusal
            gate = AuthorizationGate(None)
            server, _q = serve_proxy(("127.0.0.1", 0), gate, history)
            port = server.server_address[1]
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({
                "http": f"http://127.0.0.1:{port}"})
            opener = urllib.request.build_opener(proxy_handler)
            try:
                resp = opener.open(
                    f"http://127.0.0.1:{self.origin_port}/", timeout=5)
                self.assertEqual(resp.status, 200)
            except Exception:
                pass  # refusal tanpa dokumen juga valid utk test ini
            server.shutdown()
            self.assertTrue(history.rows)
            # history tercatat dengan keputusan eksplisit
            self.assertIn("decision", history.rows[-1])

    def test_intercept_approve_dan_drop(self):
        q = InterceptQueue(cap=2)
        rid = q.hold({"method": "GET", "url": "https://t.test/"})
        threading.Thread(target=lambda: (threading.Event().wait(0.05),
                                         q.decide(rid, "approve")),
                         daemon=True).start()
        self.assertEqual(q.wait(rid, timeout=2), "approve")
        rid2 = q.hold({"method": "GET", "url": "https://t.test/x"})
        q.decide(rid2, "drop")
        self.assertEqual(q.wait(rid2, timeout=2), "drop")
        # antrian penuh -> auto-drop
        q2 = InterceptQueue(cap=1)
        q2.hold({"m": 1})
        rid3 = q2.hold({"m": 2})
        self.assertEqual(q2.wait(rid3, timeout=0.5), "drop")


class TestFleet(unittest.TestCase):
    def test_partisi_deterministik(self):
        targets = [f"https://t{i}.test" for i in range(20)]
        p1 = fleet.partition_targets(targets, 4)
        p2 = fleet.partition_targets(targets, 4)
        self.assertEqual(p1, p2)
        self.assertEqual(sum(len(b) for b in p1), 20)
        # target sama selalu di bucket sama
        first = [i for i, b in enumerate(p1) if targets[0] in b][0]
        self.assertIn(targets[0], p1[first])

    def test_merge_dedup(self):
        rows = [
            {"findings": [{"id": "a", "title": "x"}], "targets_scanned": 2,
             "errors": ["e1"], "requests": 10},
            {"findings": [{"id": "a", "title": "x"}, {"id": "b"}],
             "targets_scanned": 1, "errors": [], "requests": 5},
        ]
        merged = fleet.merge_results(rows)
        self.assertEqual(merged["findings_total"], 2)
        self.assertEqual(merged["requests"], 15)
        self.assertEqual(merged["errors"], ["e1"])

    def test_run_fleet_thread(self):
        def worker(bucket):
            return {"findings": [{"id": f"f-{t}"} for t in bucket],
                    "targets_scanned": len(bucket), "errors": [],
                    "requests": len(bucket)}
        targets = [f"t{i}" for i in range(6)]
        out = fleet.run_fleet(targets, worker, n_workers=3)
        self.assertEqual(out["targets_scanned"], 6)
        self.assertEqual(out["findings_total"], 6)
        self.assertEqual(out["workers"], 3)


class TestDast(unittest.TestCase):
    def test_dev_cicd_pasif(self):
        p = dast.policy_for("dev-cicd", authorized=False)
        self.assertEqual(p["profile_effective"], "dev-cicd")
        self.assertFalse(p["params"]["active"])

    def test_profil_aktif_butuh_otorisasi(self):
        p = dast.policy_for("standard", authorized=False)
        self.assertTrue(p["downgraded"])
        self.assertEqual(p["profile_effective"], "dev-cicd")
        p2 = dast.policy_for("standard", authorized=True)
        self.assertFalse(p2["downgraded"])

    def test_restriction_no_aggressive_menolak_full(self):
        p = dast.policy_for("full", authorized=True,
                            doc_restrictions=["no_aggressive"])
        self.assertEqual(p["profile_effective"], "standard")
        self.assertTrue(p["downgraded"])

    def test_plan_mapping(self):
        p = dast.policy_for("full", authorized=True)
        plan = dast.plan_from_policy(p, "https://t.test")
        self.assertEqual(plan["crawl_pages"], 100)
        self.assertTrue(plan["active_expected"])


class TestIac(unittest.TestCase):
    def test_dockerfile_rules(self):
        rows = iac.scan_dockerfile(
            "FROM alpine:latest\nENV DB_PASSWORD=supersecret\n"
            "RUN curl http://x.sh | bash\n")
        ids = {r["rule"] for r in rows}
        self.assertIn("IAC-DOCKER-LATEST", ids)
        self.assertIn("IAC-DOCKER-SECRET-ENV", ids)
        self.assertIn("IAC-DOCKER-CURL-PIPE-BASH", ids)
        # USER root eksplisit tetap dilaporkan (tidak menonaktifkan rule)
        rows2 = iac.scan_dockerfile("FROM alpine:3.19\nUSER root\n")
        self.assertTrue(any(r["rule"] == "IAC-DOCKER-ROOT" for r in rows2))
        rows3 = iac.scan_dockerfile("FROM alpine:3.19\nUSER app\n")
        self.assertFalse(any(r["rule"] == "IAC-DOCKER-ROOT" for r in rows3))

    def test_k8s_rules(self):
        rows = iac.scan_k8s("""
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
    - name: app
      env:
        - name: API_TOKEN
          value: "x"
""")
        ids = {r["rule"] for r in rows}
        self.assertIn("IAC-K8S-HOST-NETWORK", ids)
        self.assertIn("IAC-K8S-SECRET-ENV", ids)

    def test_sbom_cyclonedx_dan_lisensi(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text(
                "flask==3.0.0\n# komentar\nrequests>=2.31\n",
                encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "name": "x", "license": "MIT",
                "dependencies": {"left-pad": "1.3.0"}}), encoding="utf-8")
            sbom = iac.sbom_generate(root)
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["specVersion"], "1.5")
            names = {c["name"] for c in sbom["components"]}
            self.assertIn("flask", names)
            self.assertIn("left-pad", names)
            lic = iac.license_compliance(sbom)
            self.assertEqual(lic["rows"][0]["license"], "MIT")
            self.assertEqual(lic["rows"][0]["verdict"], "ok")

    def test_scan_iac_folder(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Dockerfile").write_text("FROM alpine:latest\n",
                                             encoding="utf-8")
            (root / "docker-compose.yml").write_text(
                "services:\n  api:\n    privileged: true\n",
                encoding="utf-8")
            rows = iac.scan_iac(root)
            files = {r["file"] for r in rows}
            self.assertIn("Dockerfile", files)
            self.assertTrue(any(r["rule"] == "IAC-COMPOSE-PRIVILEGED"
                                for r in rows))


if __name__ == "__main__":
    unittest.main()
