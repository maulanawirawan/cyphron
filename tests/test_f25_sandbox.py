"""Test F25d — exploit sandbox Docker.

Unit test: pure builder argv + gerbang fail-closed + dry-run (NOL docker).
Integration: e2e lab-in-docker di jaringan internal — skipUnless docker
daemon jalan (hasil test tetap hijau di mesin tanpa Docker).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import exploit_sandbox as sb  # noqa: E402
import lab_target  # noqa: E402


def _docker_daemon_ok() -> bool:
    return sb.daemon_ok()


class BuildArgsTest(unittest.TestCase):
    def test_hardening_flags_present(self):
        pre, cmd = sb.build_docker_run_args(
            image="python:3.12-slim", repo=ROOT,
            config_src=ROOT / "exploit-lab.json", out_dir=Path("out"),
            net="internal", user="65532:65532",
            engine_cmd=["python", "tools/exploit_engine.py"])
        joined = pre + cmd
        for flag_pair in (("--cap-drop", "ALL"), ("--security-opt",
                         "no-new-privileges"), ("--memory", "512m"),
                         ("--pids-limit", "128"), ("--user",
                         "65532:65532"), ("--network", "internal")):
            self.assertIn(flag_pair, list(zip(joined, joined[1:])))
        self.assertIn("--read-only", pre)
        mounts = [j for j in pre if j.count(":") >= 1 and j.startswith(
            ("/", "D:", "C:"))]
        self.assertTrue(any(m.endswith(":/work:ro") for m in mounts),
                        "repo wajib read-only")
        self.assertTrue(any(m.endswith(":/out:rw") for m in mounts),
                        "folder output rw (di luar rootfs ro)")
        self.assertTrue(any("exploit.json:ro" in m for m in mounts),
                        "config wajib read-only")
        self.assertIn("PYTHONDONTWRITEBYTECODE=1",
                      [j for j in pre if j.startswith("PYTHONDONT")])
        self.assertEqual(cmd[0], "python:3.12-slim")


class GateTest(unittest.TestCase):
    def test_remote_bridge_requires_explicit_env(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "c.json"
            cfg.write_text("{}", encoding="utf-8")
            argv = ["--config", str(cfg), "--out", str(Path(td) / "o"),
                    "--net", "bridge"]
            self.assertEqual(sb.main_with_args(argv), 2)

    def test_lab_requires_internal_net(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "c.json"
            cfg.write_text("{}", encoding="utf-8")
            argv = ["--config", str(cfg), "--out", str(Path(td) / "o"),
                    "--lab-in-docker", "--net", "bridge"]
            self.assertEqual(sb.main_with_args(argv), 2)

    def test_missing_config_exit_2(self):
        self.assertEqual(sb.main_with_args(
            ["--config", "TIDAK/ADA.json", "--out", "x"]), 2)


class DryRunTest(unittest.TestCase):
    def test_dry_run_prints_plan_without_docker_call(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = tmp / "c.json"
            cfg.write_text(json.dumps({
                "targets": [{"id": "lab", "base_url": "http://127.0.0.1:1",
                             "exploit_allowed": True, "mode": "proof"}],
                "playbooks": ["idor-orders"]}), encoding="utf-8")
            # dry-run WAJIB tidak memanggil docker sama sekali
            with unittest.mock.patch.object(sb.subprocess, "run",
                                            side_effect=AssertionError(
                                                "docker dipanggil di dry-run")):
                rc = sb.main_with_args(["--config", str(cfg),
                                        "--out", str(tmp / "o"),
                                        "--dry-run"])
            self.assertEqual(rc, 0)


@unittest.skipUnless(_docker_daemon_ok(), "docker daemon tidak jalan")
class IntegrationTest(unittest.TestCase):
    """E2E sesungguhnya: lab + engine dua kontainer di jaringan internal
    Docker — TANPA internet, tanpa akses host network."""

    @classmethod
    def setUpClass(cls):
        # pull image bila belum ada (sekali, supaya timeout test stabil)
        r = sb._docker(["pull", sb.DEFAULT_IMAGE], timeout=600)
        if r.returncode != 0:
            raise unittest.SkipTest(f"image tidak bisa ditarik: "
                                    f"{r.stderr[-120:]}")

    def test_lab_in_docker_e2e_all_playbooks(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            out = tmp / "out"
            cfg = tmp / "c.json"
            cfg.write_text(json.dumps({
                "targets": [{"id": "lab", "base_url": "PLACEHOLDER",
                             "exploit_allowed": True, "mode": "mutate",
                             "credentials": {"username": "alice",
                                             "password": "alicepass"},
                             "params": {
                                 "idor-orders": {"own_id": "1001",
                                                 "other_id": "1002",
                                                 "other_owner_email":
                                                 "bob@example.com"},
                                 "admin-access": {
                                     "admin_path": "/admin/panel",
                                     "marker": "admin-panel-secret-marker"},
                                 "sqli-products": {"path": "/api/products",
                                                   "param": "name",
                                                   "baseline_value":
                                                   "keyboard",
                                                   "payload": "x' OR '1'='1"},
                                 "ssrf-callback": {"path": "/fetch",
                                                   "marker_host":
                                                   "127.0.0.1"},
                                 "jwt-weak-secret": {
                                     "token_path": "/api/token",
                                     "profile_path": "/api/profile"},
                                 "upload-bypass": {"upload_path":
                                                   "/api/upload",
                                                   "serve_prefix":
                                                   "/uploads/"},
                                 "race-coupon": {"redeem_path":
                                                 "/api/coupon/redeem",
                                                 "workers": 8},
                                 "mass-assignment": {
                                     "update_path": "/api/profile/update",
                                     "token_path": "/api/token"},
                                 "open-redirect": {"path": "/redirect",
                                                   "param": "to",
                                                   "external_url":
                                                   "https://attacker.example"
                                                   "/next"},
                                 "xxe-callback": {"path": "/api/xml",
                                                  "marker_host":
                                                  "127.0.0.1"},
                                 "deser-rce": {"path": "/api/deser",
                                               "marker_host": "127.0.0.1"},
                                 "ssti-eval": {"path": "/api/render",
                                               "param": "tpl"},
                                 "lfi-traversal": {"path": "/download",
                                                   "param": "file",
                                                   "baseline_file":
                                                   "report.txt",
                                                   "traversal_payload":
                                                   "../canary-lfi.txt",
                                                   "canary_content":
                                                   lab_target.LFI_CANARY},
                                 "nosqli-login": {"path":
                                                  "/api/nosqli-login",
                                                  "whoami_path":
                                                  "/api/whoami",
                                                  "canary_user":
                                                  "svc-canary"},
                                 "crlf-inject": {"path": "/api/note",
                                                 "param": "text",
                                                 "canary_header":
                                                 "X-Cyphron-Canary"},
                                 "reset-enum": {"path": "/api/reset",
                                                "canary_email":
                                                "alice@example.com",
                                                "unknown_email":
                                                "no-one@example.com"},
                                 "xss-reflected": {"path": "/search",
                                                   "param": "q",
                                                   "safe_path":
                                                   "/search-safe"},
                                 "proto-pollution": {},
                                 "jndi-oob": {"path": "/api/log4j",
                                              "marker_host": "127.0.0.1"},
                                 "cache-deception": {
                                     "path_prefix": "/cacheable/",
                                     "safe_prefix": "/cache-safe/",
                                     "marker":
                                     lab_target.CACHE_DECEPTION_MARKER},
                                 "host-header-poison": {
                                     "path": "/api/forgot",
                                     "safe_path": "/api/forgot-safe",
                                     "check_path": "/api/reset-check",
                                     "canary_email": "alice@example.com",
                                     "poison_host": "attacker.example"},
                                 "jwt-alg-confusion": {
                                     "path": "/api/profile-loose",
                                     "strict_path": "/api/profile"},
                                 "rce-marker": {"path": "/api/ping",
                                                "safe_path":
                                                "/api/ping-safe"},
                                 "sqli-error": {"path": "/api/search-raw",
                                                "param": "q",
                                                "safe_path":
                                                "/api/search-raw-safe"},
                                 "register-enum": {
                                     "path": "/api/register",
                                     "canary_email": "alice@example.com",
                                     "safe_path": "/api/register-safe"},
                                 "ssrf-chain": {},
                                 "xxe-file": {"path": "/api/xml2",
                                              "safe_path": "/api/xml2-safe",
                                              "entity":
                                              "file://canary-lfi.txt",
                                              "canary_content":
                                              lab_target.LFI_CANARY},
                                 "cache-poison": {},
                                 "idor-mass": {
                                     "endpoints": ["/api/orders/{id}",
                                                   "/api/tickets/{id}"],
                                     "own_id": "1001", "other_id": "1002",
                                     "other_owner_email":
                                     "bob@example.com"},
                                 "oauth-state": {},
                                 "lockout-canary": {},
                                 "session-fixation": {},
                                 "sqli-time": {},
                                 "api-version-auth": {
                                     "paths": ["/api/v1/orders/1002",
                                               "/api/v2/orders/1002"],
                                     "marker": "bob@example.com"},
                                 "session-invalidation": {},
                                 "prompt-injection": {},
                                 "llm-output": {},
                                 "rag-poisoning": {}}}],
                "playbooks": ["idor-orders", "admin-access",
                              "sqli-products", "ssrf-callback",
                              "jwt-weak-secret", "upload-bypass",
                              "race-coupon", "mass-assignment",
                              "open-redirect", "xxe-callback",
                              "deser-rce", "ssti-eval",
                              "lfi-traversal", "nosqli-login",
                              "crlf-inject", "reset-enum",
                              "xss-reflected", "proto-pollution",
                              "jndi-oob", "cache-deception",
                              "host-header-poison",
                              "jwt-alg-confusion", "rce-marker",
                              "sqli-error", "register-enum",
                              "ssrf-chain", "xxe-file",
                              "cache-poison", "idor-mass",
                              "oauth-state", "lockout-canary",
                              "session-fixation", "sqli-time",
                              "api-version-auth",
                              "session-invalidation",
                              "prompt-injection",
                              "llm-output",
                              "rag-poisoning"]}),
                encoding="utf-8")
            rc = sb.main_with_args(["--config", str(cfg), "--out", str(out),
                                    "--lab-in-docker"])
            self.assertEqual(rc, 0)
            findings = out / "findings.json"
            self.assertTrue(findings.exists())
            doc = json.loads(findings.read_text(encoding="utf-8"))
            reportable = [r for r in doc["findings"] if r["verdict"] >= 3]
            self.assertEqual(len(reportable), 38,
                             "38/38 playbook harus terbukti dari dalam "
                             "kontainer")
            # target_url harus menunjuk nama kontainer lab (jaringan internal)
            self.assertTrue(all("cyphron-lab-" in r["target_url"]
                                for r in doc["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=1)
