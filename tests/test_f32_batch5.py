"""Test F32 — batch 5: playbook rce-marker (CWE-78) + 3 skill registry
(console-exposure / xmlrpc-surface / header-reflection-matrix).

NOL jaringan eksternal (lab 127.0.0.1 + mock). Yang dikunci:
  - rce-marker: fake-shell lab — `127.0.0.1; echo <token>` -> output
    echo (L3 critical); kontrol safe menolak separator; FP-guard
    strict/safe-ikut-lolos -> L0;
  - console-exposure: signature isi; halaman login generik bukan lead;
  - xmlrpc-surface: methodResponse = L2; 404 = AMAN;
  - header-reflection: canary + perubahan respons = L2; identik = L0.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import console_exposure_checker as cec   # noqa: E402
import xmlrpc_surface as xs              # noqa: E402
import header_reflection_matrix as hrm   # noqa: E402
import exploit_engine as ee              # noqa: E402
import exploit_playbooks as ep           # noqa: E402
import lab_target                        # noqa: E402
from findings import validate_finding    # noqa: E402

REG = json.loads((ROOT / "skills" / "registry.json")
                 .read_text(encoding="utf-8"))
URL = "https://lab.local/"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


def _r(status, body, headers=None):
    return {"status": status, "len": len(body), "body": body,
            "headers": headers or {}}


class RegistryTest(unittest.TestCase):
    def test_entries(self):
        self.assertGreaterEqual(len(REG["skills"]), 86)
        self.assertEqual(len(ep.PLAYBOOKS), 38)
        by = {s["name"]: s for s in REG["skills"]}
        self.assertEqual(by["console-exposure-checker"]["safety_class"],
                         "bounded-requests")
        self.assertEqual(by["xmlrpc-surface"]["safety_class"],
                         "1-request")
        self.assertEqual(by["header-reflection-matrix"]["safety_class"],
                         "bounded-requests")
        pb = ep.PLAYBOOKS["rce-marker"]
        self.assertEqual(pb.tier, 1)
        self.assertFalse(pb.techniques & ep.NEVER_LIST)


class ConsoleExposureTest(unittest.TestCase):
    def test_actuator_signature_is_l2(self):
        res = {"/actuator": {"status": 200,
                             "body": '{"_links":{"self":...}}'},
               "/laravel/telescope": {"status": 200,
                                      "body": "<title>Telescope</title>"},
               "/admin": {"status": 200, "body": "<form>login</form>"}}
        rows, meta = cec.audit(URL, res)
        self.assertEqual(meta["open"], ["/actuator",
                                        "/laravel/telescope"])
        self.assertEqual(len([r for r in rows if r["verdict"] == 2]), 2)

    def test_login_page_not_a_claim(self):
        res = {"/actuator": {"status": 200,
                             "body": "<html>login form</html>"}}
        rows, meta = cec.audit(URL, res)
        self.assertEqual(meta["open"], [])
        self.assertEqual(one(rows, "posture")["verdict"], 0)


class XmlRpcTest(unittest.TestCase):
    def test_method_response_is_l2(self):
        res = {"status": 200,
               "body": "<?xml?><methodResponse><params><value>"
                       "system.listMethods</value></params>"
                       "</methodResponse>"}
        rows, meta = xs.audit(URL + "xmlrpc.php", res)
        f = one(rows, "XML-RPC interface open")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 2)
        self.assertEqual(meta["open"], True)

    def test_404_is_aman(self):
        rows, _ = xs.audit(URL + "xmlrpc.php",
                           {"status": 404, "body": "not found"})
        self.assertEqual(one(rows, "No XML-RPC")["verdict"], 0)


class HeaderReflectionTest(unittest.TestCase):
    CANARY = "hdr-abcdef1234567890"

    def test_xff_honored_is_l2(self):
        res = {"baseline": _r(200, "<html>ok</html>"),
               "X-Forwarded-For": _r(200, "<html>hi "
                                          f"{self.CANARY}</html>"),
               "X-Forwarded-Host": _r(200, "<html>ok</html>"),
               "X-Original-URL": _r(403, "denied"),
               "X-Rewrite-URL": _r(200, "<html>ok</html>")}
        rows, meta = hrm.audit(URL, res, self.CANARY)
        self.assertEqual(meta["honored"], ["X-Forwarded-For",
                                           "X-Original-URL"])
        f = one(rows, "Proxy header honored")
        self.assertEqual(f["verdict"], 2)
        self.assertEqual(f["cwe"], "CWE-348")

    def test_identical_response_is_l0(self):
        res = {"baseline": _r(200, "<html>ok</html>")}
        for h in hrm.HEADERS:
            res[h] = _r(200, "<html>ok</html>")
        rows, meta = hrm.audit(URL, res, self.CANARY)
        self.assertEqual(meta["honored"], [])
        self.assertEqual(one(rows, "posture")["verdict"], 0)


class LabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)


class RceMarkerE2E(LabTestCase):
    def _run(self, tmp, params_override=None):
        params = {"rce-marker": {"path": "/api/ping",
                                 "safe_path": "/api/ping-safe"}}
        params["rce-marker"].update(params_override or {})
        cfg = tmp / "c.json"
        cfg.write_text(json.dumps({
            "targets": [{"id": "lab", "base_url": self.base_url,
                         "exploit_allowed": True, "mode": "proof",
                         "params": params}],
            "playbooks": ["rce-marker"]}), encoding="utf-8")
        out = tmp / "f.json"
        rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(validate_finding(r) == []
                            for r in doc["findings"]))
        return doc["findings"]

    def test_rce_marker_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td))
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-78")
            self.assertEqual(rows[0]["severity"], "critical")
            self.assertTrue(rows[0]["reportable"])

    def test_strict_target_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td),
                             {"path": "/api/ping-safe",
                              "safe_path": "/api/ping-safe"})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])

    def test_control_also_executing_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td),
                             {"safe_path": "/api/ping"})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak dapat dipercaya", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
