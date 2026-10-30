"""Test F33 — batch 6 (hasil riset topic GitHub, docs/TOPIC-RESEARCH-
2026-10.md): 3 skill registry (error-oracle, dns-axfr-check,
spf-dmarc-posture) + 2 playbook (sqli-error, register-enum) + helper
skills/dns_light.py.

NOL jaringan eksternal (lab 127.0.0.1 + mock DNS TCP/UDP lokal). Yang
dikunci:
  - error-oracle: signature ketat db/stack = L2, debug = L1; 404
    generik = AMAN; 403/429 (challenge/WAF) = tanpa klaim; refleksi
    canary tanpa signature = AMAN (FP-guard, pelajaran Cloudflare);
  - dns-axfr-check: transfer valid SOA..SOA = L2; refused = AMAN;
    NS gagal = unconfirmed; parse pointer kompresi DNS;
  - spf-dmarc-posture: SPF/DMARC hilang atau p=none = L1; lengkap =
    AMAN; DNS gagal = unconfirmed;
  - sqli-error: payload kutip -> signature DB (L3); baseline kotor /
    kontrol ikut error / tanpa signature -> L0;
  - register-enum: sinyal eksplisit known + generik unknown = L3;
    tanpa sinyal eksplisit / kontrol ikut sinyal -> L0.
"""
from __future__ import annotations

import json
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import dns_light                 # noqa: E402
import error_oracle as eo        # noqa: E402
import dns_axfr_check as ax      # noqa: E402
import spf_dmarc_posture as spd  # noqa: E402
import exploit_engine as ee      # noqa: E402
import exploit_playbooks as ep   # noqa: E402
import lab_target                # noqa: E402
from findings import validate_finding  # noqa: E402

REG = json.loads((ROOT / "skills" / "registry.json")
                 .read_text(encoding="utf-8"))
URL = "https://lab.local/"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


# --- util DNS sintetis -----------------------------------------------------

def _name_bytes(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _dns_msg(ident: int, qname: str, answers: list) -> bytes:
    """header + question + answers; name answer pakai pointer 0xC00C."""
    q = _name_bytes(qname) + struct.pack(">HH", 16, 1)
    an = b""
    for rtype, val in answers:
        if rtype == 16:
            strs = val if isinstance(val, list) else [val]
            rd = b"".join(bytes([len(s)]) + s.encode() for s in strs)
        elif rtype == 1:
            rd = socket.inet_aton(val)
        elif rtype == 2:
            rd = _name_bytes(val)
        elif rtype == 6:
            nm = _name_bytes(val)
            rd = nm + nm + struct.pack(">IIIII", 1, 2, 3, 4, 5)
        else:
            rd = b""
        an += (b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rd))
               + rd)
    header = struct.pack(">HHHHHH", ident, 0x8180, 1, len(answers), 0, 0)
    return header + q + an


class _AxfrHandler(socketserver.BaseRequestHandler):
    def handle(self):
        buf = b""
        while len(buf) < 2:
            buf += self.request.recv(2 - len(buf))
        (mlen,) = struct.unpack(">H", buf)
        while len(buf) < 2 + mlen:
            buf += self.request.recv(2 + mlen - len(buf))
        ident = struct.unpack(">H", buf[2:4])[0]
        msg = _dns_msg(ident, "lab.example",
                       [(6, "ns1.lab.example"), (2, "ns1.lab.example"),
                        (1, "203.0.113.10"), (6, "ns1.lab.example")])
        self.request.sendall(struct.pack(">H", len(msg)) + msg)


class _AxfrServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class RegistryTest(unittest.TestCase):
    def test_entries(self):
        self.assertGreaterEqual(len(REG["skills"]), 86)
        self.assertEqual(len(ep.PLAYBOOKS), 38)
        by = {s["name"]: s for s in REG["skills"]}
        self.assertEqual(by["error-oracle"]["safety_class"], "1-request")
        self.assertEqual(by["dns-axfr-check"]["safety_class"],
                         "bounded-requests")
        self.assertEqual(by["spf-dmarc-posture"]["safety_class"],
                         "read-only")
        for name in ("sqli-error", "register-enum"):
            pb = ep.PLAYBOOKS[name]
            self.assertEqual(pb.tier, 1)
            self.assertFalse(pb.techniques & ep.NEVER_LIST)

    def test_contract_rows_meta(self):
        rows, meta = eo.audit(URL, {"status": 404, "body": "not found"})
        self.assertIsInstance(rows, list)
        self.assertIsInstance(meta, dict)


class ErrorOracleTest(unittest.TestCase):
    def test_db_signature_is_l2(self):
        rows, meta = eo.audit(URL, {"status": 500, "body":
                                    "sqlite3.OperationalError: near x"})
        self.assertEqual(meta["hit"], "db:sqlite3.operationalerror")
        self.assertEqual(rows[0]["verdict"], 2)
        self.assertEqual(rows[0]["cwe"], "CWE-209")

    def test_stack_trace_is_l2(self):
        rows, meta = eo.audit(URL, {"status": 500, "body":
                                    "Traceback (most recent call last):\n"
                                    "  File \"app.py\", line 10"})
        self.assertEqual(meta["hit"], "stack:traceback (most recent call last)")
        self.assertEqual(rows[0]["verdict"], 2)

    def test_debug_banner_is_l1(self):
        rows, meta = eo.audit(URL, {"status": 500, "body":
                                    "<h1>Werkzeug Debugger</h1>"})
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertEqual(rows[0]["severity"], "low")

    def test_generic_404_is_aman(self):
        rows, meta = eo.audit(URL, {"status": 404,
                                    "body": "<h1>404 page not found</h1>"})
        self.assertIsNone(meta["hit"])
        self.assertEqual(one(rows, "posture")["verdict"], 0)

    def test_generic_error_word_no_match(self):
        rows, meta = eo.audit(URL, {"status": 404, "body":
                                    "exception handling guide: error pages"})
        self.assertIsNone(meta["hit"])

    def test_challenge_reflection_not_a_claim(self):
        # FP-guard (pelajaran Cloudflare): halaman challenge memantulkan
        # path canary — TANPA signature = tetap AMAN
        rows, meta = eo.audit(URL, {"status": 403, "body":
                                    "checking your browser: "
                                    "/cyphron-err-deadbeef challenge"})
        self.assertEqual(meta.get("waf"), True)
        self.assertEqual(rows[0]["status"], "unconfirmed")

    def test_network_error_unconfirmed(self):
        rows, meta = eo.audit(URL, {"status": None, "body": "",
                                    "error": "URLError"})
        self.assertTrue(meta.get("error"))
        self.assertEqual(rows[0]["status"], "unconfirmed")


class DnsLightTest(unittest.TestCase):
    def test_parse_txt_with_pointer(self):
        msg = _dns_msg(0x1234, "lab.example",
                       [(16, ["v=spf1 -all"]), (2, "ns1.lab.example")])
        parsed = dns_light.parse_message(msg)
        self.assertEqual(parsed["rcode"], 0)
        self.assertEqual(parsed["answers"][0]["val"], ["v=spf1 -all"])
        self.assertEqual(parsed["answers"][1]["val"], "ns1.lab.example")

    def test_parse_soa_mname(self):
        msg = _dns_msg(0x1234, "lab.example", [(6, "ns1.lab.example")])
        parsed = dns_light.parse_message(msg)
        self.assertEqual(parsed["answers"][0]["val"], "ns1.lab.example")

    def test_axfr_stream_over_tcp(self):
        with _AxfrServer(("127.0.0.1", 0), _AxfrHandler) as srv:
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                res = dns_light.axfr("127.0.0.1", "lab.example",
                                     timeout=5, port=port)
            finally:
                srv.shutdown()
        self.assertIsNotNone(res)
        self.assertEqual(res["rcode"], 0)
        types = [a["type"] for a in res["answers"]]
        self.assertEqual(types[0], dns_light.QTYPE_SOA)
        self.assertEqual(types[-1], dns_light.QTYPE_SOA)
        self.assertIn(dns_light.QTYPE_A, types)

    def test_axfr_refused_is_none(self):
        # koneksi ke port yang tidak dilayani = None (fail-closed)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
        s.close()
        res = dns_light.axfr("127.0.0.1", "lab.example", timeout=2,
                             port=free_port)
        self.assertIsNone(res)


class SpfDmarcTest(unittest.TestCase):
    def test_missing_both_two_leads(self):
        rows, meta = spd.audit("lab.example", {"txt": [], "dmarc_txt": []})
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["verdict"] == 1 for r in rows))
        self.assertEqual(meta["spf"], False)

    def test_dmarc_none_is_lead(self):
        rows, meta = spd.audit("lab.example", {
            "txt": ["v=spf1 include:_spf.lab.example -all"],
            "dmarc_txt": ["v=DMARC1; p=none; rua=mailto:agg@lab.example"]})
        self.assertEqual(len(rows), 1)
        self.assertIn("p=none", rows[0]["title"])
        self.assertEqual(rows[0]["verdict"], 1)

    def test_all_good_is_aman(self):
        rows, meta = spd.audit("lab.example", {
            "txt": ["v=spf1 -all"],
            "dmarc_txt": ["v=DMARC1; p=reject"]})
        self.assertEqual(one(rows, "posture")["verdict"], 0)
        self.assertEqual(meta["spf"], True)

    def test_dns_error_unconfirmed(self):
        rows, meta = spd.audit("lab.example", {"error": "dns-gagal"})
        self.assertTrue(meta["error"])
        self.assertEqual(rows[0]["status"], "unconfirmed")


class AxfrCheckTest(unittest.TestCase):
    ZONE = [(6, "ns1.lab.example"), (2, "ns1.lab.example"),
            (1, "203.0.113.10"), (6, "ns1.lab.example")]

    def test_valid_transfer_is_l2(self):
        answers = [{"name": "lab.example", "type": t, "ttl": 300,
                    "rdata": b"", "val": v}
                   for t, v in self.ZONE]
        rows, meta = ax.audit("lab.example", {"ns": ["ns1.lab.example"],
                                              "axfr": {"ns1.lab.example":
                                                       {"rcode": 0,
                                                        "answers": answers}}})
        self.assertEqual(meta["leaked"], ["ns1.lab.example"])
        self.assertEqual(rows[0]["verdict"], 2)
        self.assertEqual(rows[0]["cwe"], "CWE-200")
        self.assertEqual(rows[0]["severity"], "high")

    def test_refused_is_aman(self):
        rows, meta = ax.audit("lab.example", {"ns": ["ns1.lab.example"],
                                              "axfr": {"ns1.lab.example":
                                                       {"rcode": 5,
                                                        "answers": []}}})
        self.assertEqual(meta["leaked"], [])
        self.assertEqual(one(rows, "refused")["verdict"], 0)

    def test_connection_none_is_unconfirmed(self):
        rows, meta = ax.audit("lab.example", {"ns": ["ns1.lab.example"],
                                              "axfr": {"ns1.lab.example":
                                                       None}})
        self.assertEqual(meta["leaked"], [])
        self.assertEqual(one(rows, "gagal")["status"], "unconfirmed")

    def test_ns_error_unconfirmed(self):
        rows, meta = ax.audit("lab.example", {"ns": None,
                                              "ns_error": "query-NS-gagal"})
        self.assertTrue(meta.get("error"))
        self.assertEqual(rows[0]["status"], "unconfirmed")
        # regresi live-target: bentuk meta KONSISTEN di jalur error
        # (main() membaca meta["leaked"] — KeyError saat NS gagal)
        self.assertIn("leaked", meta)
        self.assertEqual(meta["leaked"], [])


class LabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)


class Batch6E2E(LabTestCase):
    def _run(self, tmp, playbooks, params):
        cfg = tmp / "c.json"
        cfg.write_text(json.dumps({
            "targets": [{"id": "lab", "base_url": self.base_url,
                         "exploit_allowed": True, "mode": "proof",
                         "params": params}],
            "playbooks": playbooks}), encoding="utf-8")
        out = tmp / "f.json"
        rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(validate_finding(r) == []
                            for r in doc["findings"]))
        return doc["findings"]

    # --- sqli-error ----------------------------------------------------

    def test_sqli_error_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["sqli-error"],
                             {"sqli-error": {"path": "/api/search-raw",
                                             "param": "q",
                                             "safe_path":
                                             "/api/search-raw-safe"}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-89")
            self.assertEqual(rows[0]["severity"], "high")
            self.assertTrue(rows[0]["reportable"])
            self.assertIn("sqlite", rows[0]["signature"])

    def test_sqli_error_no_signature_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["sqli-error"],
                             {"sqli-error": {"path": "/api/search-raw-safe",
                                             "safe_path":
                                             "/api/search-raw-safe"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])

    def test_sqli_error_control_also_error_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["sqli-error"],
                             {"sqli-error": {"path": "/api/search-raw",
                                             "safe_path":
                                             "/api/search-raw"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak dapat dipercaya", rows[0]["title"])

    def test_sqli_error_dirty_baseline_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["sqli-error"],
                             {"sqli-error": {"path": "/api/search-raw",
                                             "baseline_value": "x'",
                                             "safe_path":
                                             "/api/search-raw-safe"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("baseline", rows[0]["title"])

    # --- register-enum --------------------------------------------------

    def test_register_enum_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["register-enum"],
                             {"register-enum": {
                                 "path": "/api/register",
                                 "canary_email": "alice@example.com",
                                 "safe_path": "/api/register-safe"}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-204")
            self.assertEqual(rows[0]["severity"], "medium")
            self.assertEqual(rows[0]["known_status"], 409)
            self.assertEqual(rows[0]["unknown_status"], 200)

    def test_register_enum_no_explicit_signal_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["register-enum"],
                             {"register-enum": {
                                 "path": "/api/register-safe",
                                 "canary_email": "alice@example.com",
                                 "safe_path": "/api/register-safe"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("sinyal eksplisit", rows[0]["title"])

    def test_register_enum_control_also_signal_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["register-enum"],
                             {"register-enum": {
                                 "path": "/api/register",
                                 "canary_email": "alice@example.com",
                                 "safe_path": "/api/register"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak dapat dipercaya", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
