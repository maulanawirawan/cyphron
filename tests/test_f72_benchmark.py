"""F72 — benchmark accuracy: metrik + ground-truth matcher (tanpa scan).

Scan penuh dijalankan manual via tools/benchmark_accuracy.py --run
(memerlukan binary release); unit test di sini menguji MATEMATIKA
metrik dan aturan deteksi terhadap fixture sintetis — deterministik.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import benchmark_accuracy as ba  # noqa: E402


def row(tool: str, verdict: int = 1, title: str = "x") -> dict:
    return {"tool": tool, "verdict": verdict, "title": title}


class MetricsTest(unittest.TestCase):
    def test_perfect_scan(self):
        rows = [row(t) for t in ba.EXPECTED_TOOLS]
        m = ba.metrics(ba.EXPECTED_TOOLS, rows)
        self.assertEqual(m["tp"], len(ba.EXPECTED_TOOLS))
        self.assertEqual(m["fp_count"], 0)
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 1.0)

    def test_fp_mengurangi_precision_tidak_recall(self):
        expected = {"a", "b"}
        rows = [row("a"), row("b"), row("backend-error-noise")]
        m = ba.metrics(expected, rows)
        self.assertEqual(m["tp"], 2)
        self.assertEqual(m["fp_count"], 1)
        self.assertAlmostEqual(m["precision"], 2 / 3, delta=0.001)
        self.assertEqual(m["recall"], 1.0)

    def test_fn_mengurangi_recall_tidak_precision(self):
        expected = {"a", "b", "c"}
        rows = [row("a"), row("b")]  # c tidak ditemukan
        m = ba.metrics(expected, rows)
        self.assertEqual(m["tp"], 2)
        self.assertEqual(m["fn"], ["c"])
        self.assertEqual(m["precision"], 1.0)
        self.assertAlmostEqual(m["recall"], 2 / 3, delta=0.001)

    def test_hardened_scan_semua_deteksi_adalah_fp(self):
        # mode hardened: expected kosong — deteksi apa pun = FP
        m = ba.metrics(set(), [row("http-security-headers"), row("cdn-detector")])
        self.assertEqual(m["fp_count"], 2)
        self.assertEqual(m["precision"], 0.0)

    def test_l0_inventory_tidak_dihitung_deteksi(self):
        doc = {"findings": [
            row("rdap-whois", verdict=0, title="postur"),
            row("http-security-headers", verdict=1, title="header hilang"),
        ]}
        rows = ba.detections(doc)
        self.assertEqual(len(rows), 1)  # L0 fakta bukan alarm
        self.assertEqual(rows[0]["tool"], "http-security-headers")

    def test_empty_scan_perfect_on_hardened(self):
        m = ba.metrics(set(), [])
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["fp_count"], 0)

    def test_ground_truth_mencakup_11_kondisi(self):
        # dokumentasi desain: 11 kondisi ditanam (10 awal + error-oracle)
        self.assertGreaterEqual(len(ba.GROUND_TRUTH), 10)
        tools = {t for t, _ in ba.GROUND_TRUTH}
        # tiap kondisi dipetakan ke skill yang ADA di registry
        import json
        reg = json.loads((ROOT / "skills" / "registry.json")
                         .read_text(encoding="utf-8"))
        names = {s["name"] for s in reg["skills"]}
        self.assertTrue(tools <= names,
                        f"skill ground truth tidak terdaftar: {tools - names}")


class TargetServerTest(unittest.TestCase):
    def test_vulnerable_vs_hardened_paths_differ(self):
        import urllib.request
        from benchmark_target import serve
        import threading

        def fetch(url: str) -> tuple[int, str, dict]:
            import urllib.error
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    return r.status, r.read().decode(), dict(r.headers)
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode(), dict(e.headers)

        httpd, port = serve("vulnerable")
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            code, body, headers = fetch(f"http://127.0.0.1:{port}/")
            self.assertNotIn("Content-Security-Policy", headers)
            self.assertIn("session=", headers.get("Set-Cookie", ""))
            code, body, _ = fetch(f"http://127.0.0.1:{port}/files/")
            self.assertIn("Directory listing", body)
            code, body, _ = fetch(f"http://127.0.0.1:{port}/debug")
            self.assertIn("1.2.3", body)
            code, body, _ = fetch(f"http://127.0.0.1:{port}/robots.txt")
            self.assertIn("/admin/", body)
        finally:
            httpd.shutdown()

        httpd, port = serve("hardened")
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            code, body, headers = fetch(f"http://127.0.0.1:{port}/")
            self.assertEqual(headers.get("Content-Security-Policy"),
                             "default-src 'self'")
            self.assertIn("Secure", headers.get("Set-Cookie", ""))
            code, _, _ = fetch(f"http://127.0.0.1:{port}/debug")
            self.assertEqual(code, 404)
            code, body, _ = fetch(f"http://127.0.0.1:{port}/robots.txt")
            self.assertNotIn("/admin/", body)
        finally:
            httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
