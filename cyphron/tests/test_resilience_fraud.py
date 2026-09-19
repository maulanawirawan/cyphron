"""Resilience (ladder bounded + knee + verdict) dan fraud-intel (prefix
operator/bank + dossier eskalasi resmi, tanpa resolusi identitas)."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.fraudintel import (
    analyze_account, analyze_phone, build_fraud_case, mask_account,
    mask_phone, render_fraud_dossier)
from cyphron.resilience import (
    classify, detect_knee, render_resilience_report, run_resilience)

_REPO = Path(__file__).resolve().parents[1]


class _HealthyHandler(BaseHTTPRequestHandler):
    log_message = lambda self, *a: None

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _DegradingHandler(BaseHTTPRequestHandler):
    """Mulai 503 setelah N request total (simulasi saturasi)."""
    limit = 60
    served = 0
    log_message = lambda self, *a: None

    def do_GET(self):
        _DegradingHandler.served += 1
        if _DegradingHandler.served > self.limit:
            body = b"overloaded"
            self.send_response(503)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class TestResilience(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.healthy = HTTPServer(("127.0.0.1", 0), _HealthyHandler)
        threading.Thread(target=cls.healthy.serve_forever,
                         daemon=True).start()
        _DegradingHandler.served = 0
        cls.degrading = HTTPServer(("127.0.0.1", 0), _DegradingHandler)
        threading.Thread(target=cls.degrading.serve_forever,
                         daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.healthy.shutdown()
        cls.degrading.shutdown()

    def test_survive_di_server_sehat(self):
        res = run_resilience(f"http://127.0.0.1:{self.healthy.server_address[1]}",
                             profile="quick")
        self.assertEqual(res["verdict"], "SURVIVE")
        self.assertIsNone(res["knee"])
        md = render_resilience_report(res)
        self.assertIn("SURVIVE", md)
        self.assertIn("bounded", md)
        self.assertIn("bukan modul flood", md)

    def test_degrade_terdeteksi_di_server_jenuh(self):
        _DegradingHandler.limit = 25  # cepat jenuh di ladder awal
        _DegradingHandler.served = 0
        try:
            res = run_resilience(
                f"http://127.0.0.1:{self.degrading.server_address[1]}",
                profile="quick")
        finally:
            _DegradingHandler.limit = 60
        self.assertIn(res["verdict"], ("DEGRADE", "FAIL"))
        md = render_resilience_report(res)
        self.assertIn(res["verdict"], md)
        self.assertIn("Rekomendasi", md)

    def test_knee_dan_classify_murni(self):
        stages = [
            {"vus": 2, "duration_s": 1, "total": 100, "rps": 90,
             "p95_ms": 40, "p50_ms": 20, "ok": 100, "5xx": 0, "net_err": 0,
             "error_rate": 0.0},
            {"vus": 10, "duration_s": 1, "total": 100, "rps": 30,
             "p95_ms": 400, "p50_ms": 200, "ok": 40, "5xx": 55,
             "net_err": 5, "error_rate": 0.6},
        ]
        knee = detect_knee(stages)
        self.assertIsNotNone(knee)
        self.assertEqual(knee["vus"], 10)
        verdict, reason = classify(stages, knee)
        self.assertEqual(verdict, "FAIL")
        stages2 = [stages[0],
                   {**stages[0], "vus": 10, "rps": 95, "p95_ms": 90,
                    "error_rate": 0.0}]
        self.assertIsNone(detect_knee(stages2))
        self.assertEqual(classify(stages2, None)[0], "SURVIVE")

    def test_cap_ladder(self):
        from cyphron import resilience as r
        # ladder internal wajib bounded (VU cap + total durasi cap)
        self.assertLessEqual(sum(s["duration_s"] for s in r.DEFAULT_LADDER),
                             r.TOTAL_DURATION_CAP_S)
        self.assertLessEqual(max(s["vus"] for s in r.DEFAULT_LADDER),
                             r.VU_CAP)
        self.assertLessEqual(max(s["duration_s"] for s in r.DEFAULT_LADDER),
                             r.STAGE_DURATION_CAP_S)
        for s in r.DEFAULT_LADDER + r.QUICK_LADDER:
            self.assertLessEqual(s["vus"], r.VU_CAP)


class TestFraudIntel(unittest.TestCase):
    def test_phone_prefix_dan_masking(self):
        res = analyze_phone("+62 838-6506-3443")
        self.assertTrue(res["input_valid"])
        self.assertEqual(res["prefix"], "838")
        self.assertEqual(res["candidates"][0]["operator"], "Axis (grup XL)")
        self.assertFalse(res["ambiguous"])
        # PII discipline: nomor penuh TIDAK muncul di output teredaksi
        self.assertNotIn("3443", res["e164_masked"].replace("****", ""))
        self.assertIn("****", res["e164_masked"])

    def test_phone_format_varian(self):
        for raw in ("083865063443", "6283865063443", "+62 838 6506 3443"):
            res = analyze_phone(raw)
            self.assertEqual(res["prefix"], "838")

    def test_prefix_tak_dikenal_ambigu(self):
        res = analyze_phone("+62 5000000000")
        self.assertTrue(res["ambiguous"])
        self.assertEqual(res["candidates"], [])

    def test_account_kandidat_dan_ambigu(self):
        res = analyze_account("901017704020")
        self.assertEqual(res["digits"], 12)
        self.assertIn("****", res["account_masked"])
        self.assertNotIn("901017704020", json.dumps(res))
        # tanpa hint dan >1 kandidat = ambigu (dilabel)
        self.assertTrue(res["ambiguous"] or len(res["candidates"]) == 1)
        # hint klien mempersempit
        res2 = analyze_account("901017704020", bank_hint="Jenius")
        self.assertEqual(res2["candidates"][0]["bank"], "Jenius (BTPN)")
        self.assertFalse(res2["ambiguous"])

    def test_batas_resolusi_identitas_ditegaskan(self):
        res = analyze_phone("+6283865063443")
        self.assertIn("TIDAK dilakukan", res["identity_resolution"])
        acc = analyze_account("901017704020")
        self.assertIn("TIDAK dilakukan", acc["identity_resolution"])

    def test_dossier_teredaksi_dan_langkah_resmi(self):
        case = build_fraud_case(
            phone_raw="+62 838-6506-3443",
            account_raw="901017704020",
            case_note="simulasi korban",
            out_dir=Path(tempfile.mkdtemp()))
        md = case["markdown"]
        self.assertIn("# Dossier Pengaduan Penipuan", md)
        self.assertIn("CekRekening.id", md)
        self.assertIn("OJK 157", md)
        self.assertIn("Tipid Siber", md)
        self.assertIn("TIDAK dilakukan", md)
        self.assertIn("data kebocoran", md.lower())
        # nomor lengkap tidak boleh tercetak di dossier
        self.assertNotIn("65063443", md.replace("****", ""))
        self.assertNotIn("901017704020", md)

    def test_mask_helpers(self):
        self.assertEqual(mask_account("901017704020"), "9010****4020")
        self.assertTrue(mask_phone("+6283865063443").startswith("+62 838-"))


if __name__ == "__main__":
    unittest.main()
