"""U5: identity_matrix (matriks multi-identitas) + business_logic
(IDENTITY x OBJECT x ACTION x STATE). Semua uji differential GET-only pada
fixture HTTP lokal milik sendiri; validator transisi diuji murni."""

from __future__ import annotations

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.business_logic import (
    BusinessLogicTool, infer_model, is_legal, normalize_state,
    validate_transitions)
from cyphron.tools.identity_matrix import IdentityMatrixTool
from cyphron.world.model import WorldModel

OWNER_BODY = ("INVOICE #9001 | nama: PEMILIK-A | total: 1.250.000 | "
              "alamat: Jl. Contoh No. 7 | status: PAID")


def _ctx(world: WorldModel, sessions: dict | None = None) -> ToolContext:
    ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                      world=world, rate_limit_s=0.0, timeout_s=5.0,
                      max_requests=60)
    if sessions:
        ctx.sessions.update(sessions)
    return ctx


class _MatrixHandler(BaseHTTPRequestHandler):
    """Fixture: /api/invoice/1 — perilaku diatur via mode kelas."""
    mode = "cross-account-leak"  # | secure | anon-open
    log_message = lambda self, *a: None

    def do_GET(self):
        cookie = self.headers.get("Cookie", "") or ""
        owner = "sid=a" in cookie
        other = "sid=b" in cookie
        m = self.mode
        if m == "cross-account-leak":
            if owner or other:
                self._send(200, OWNER_BODY)
            else:
                self._send(401, "login required")
        elif m == "secure":
            if owner:
                self._send(200, OWNER_BODY)
            else:
                self._send(403, "forbidden")
        else:  # anon-open
            self._send(200, OWNER_BODY)

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TestIdentityMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _MatrixHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _world(self):
        w = WorldModel()
        w.target = self.base
        ep = w.observe_endpoint(f"{self.base}/api/invoice/1", ["id"], "GET")
        ep.status = 200
        return w

    def _run(self, mode):
        _MatrixHandler.mode = mode
        w = self._world()
        ctx = _ctx(w, {"a": "sid=a", "b": "sid=b"})
        res = IdentityMatrixTool().run({"url": self.base}, ctx)
        return res, w

    def test_cross_account_leak_terdeteksi(self):
        res, _w = self._run("cross-account-leak")
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.finding_class, "weakness")
        self.assertEqual(f.cwe, "CWE-639")
        self.assertEqual(f.status, "confirmed")
        self.assertEqual(f.evidence_kind, "differential")
        kinds = [e["kind"] for e in f.evidence_chain]
        self.assertIn("probe-pair", kinds)
        self.assertIn("'b'", f.title)

    def test_anon_open_jadi_critical(self):
        res, _w = self._run("anon-open")
        sev = {f.severity for f in res.findings}
        self.assertIn("critical", sev)
        cwe = {f.cwe for f in res.findings}
        self.assertIn("CWE-306", cwe)

    def test_secure_tanpa_temuan(self):
        res, _w = self._run("secure")
        self.assertEqual(res.findings, [], "konfigurasi benar = zero temuan")
        self.assertEqual(res.data["endpoints"], 1)

    def test_tanpa_sesi_hanya_observasi(self):
        w = self._world()
        res = IdentityMatrixTool().run({"url": self.base}, _ctx(w))
        self.assertEqual(res.findings, [])
        self.assertIn("butuh >= 2 identitas", res.data.get("note", ""))


# ---------------------------------------------------------------- business
def _obs(**kw):
    base = {"object_type": "approval", "object_id": "DOC-1",
            "action": "approve", "from_state": "cancelled",
            "to_state": "approved", "identity": "userB", "source": "capture"}
    base.update(kw)
    return base


class TestBusinessLogicValidator(unittest.TestCase):
    def test_transisi_ilegal_cancelled_ke_approved(self):
        out = validate_transitions([_obs()])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "illegal-transition")
        self.assertEqual((out[0]["from_state"], out[0]["to_state"]),
                         ("cancelled", "approved"))
        self.assertFalse(is_legal("approval", "cancelled", "approved"))
        self.assertTrue(is_legal("approval", "submitted", "approved"))

    def test_rekaman_tunggal_lead_ganda_terkonfirmasi(self):
        w = WorldModel()
        ctx = _ctx(w)
        res = BusinessLogicTool().run(
            {"observations": [_obs()]}, ctx)
        self.assertEqual(res.findings[0].status, "unconfirmed")
        res2 = BusinessLogicTool().run(
            {"observations": [_obs(), _obs(source="capture-2")]}, ctx)
        self.assertEqual(res2.findings[0].status, "confirmed")
        self.assertEqual(res2.findings[0].cwe, "CWE-840")
        self.assertEqual(w.request_count, 0, "engine pasif: nol request")

    def test_refund_ganda_dan_coupon_reuse(self):
        recs = [_obs(object_type="refund", object_id="INV-7", action="refund",
                     from_state="approved", to_state="refunded",
                     identity="userA"),
                _obs(object_type="refund", object_id="INV-7", action="refund",
                     from_state="refunded", to_state="refunded",
                     identity="userA")]
        out = validate_transitions(recs)
        kinds = {v["kind"] for v in out}
        self.assertIn("repeated-terminal", kinds)
        # (refunded, refunded) juga ilegal secara transisi
        self.assertIn("illegal-transition", kinds)
        coupon = [_obs(object_type="coupon", object_id="KUPON-X",
                       action="redeem", from_state="unused", to_state="used"),
                  _obs(object_type="coupon", object_id="KUPON-X",
                       action="redeem", from_state="used", to_state="used")]
        out2 = validate_transitions(coupon)
        self.assertTrue(any(v["kind"] == "repeated-terminal" for v in out2))

    def test_keadaan_tak_dikenal_fail_open(self):
        self.assertEqual(validate_transitions([
            _obs(from_state="warp-speed", to_state="approved")]), [])
        self.assertEqual(validate_transitions([
            _obs(object_type="quantum", from_state="x", to_state="y")]), [])

    def test_alias_normalisasi(self):
        self.assertEqual(normalize_state("CANCELED"), "cancelled")
        self.assertEqual(normalize_state("redeemed"), "used")
        self.assertEqual(infer_model("POST /api/voucher/redeem"), "coupon")
        self.assertEqual(infer_model("POST /api/orders/5/refund"), "refund")

    def test_permukaan_state_machine_lead_tanpa_request(self):
        w = WorldModel()
        w.observe_endpoint("https://t.test/api/orders", ["status", "coupon"],
                           "GET")
        ctx = _ctx(w)
        res = BusinessLogicTool().run({}, ctx)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].severity, "info")
        self.assertEqual(res.findings[0].status, "unconfirmed")
        self.assertEqual(res.data["surfaces"], ["coupon", "status"])

    def test_observations_file(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "obs.json"
            p.write_text(json.dumps([_obs(), _obs(source="capture-2")]),
                         encoding="utf-8")
            w = WorldModel()
            res = BusinessLogicTool().run(
                {"observations_file": str(p)}, _ctx(w))
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].status, "confirmed")


if __name__ == "__main__":
    unittest.main()
