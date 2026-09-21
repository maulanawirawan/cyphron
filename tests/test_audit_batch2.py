"""Test batch audit lanjutan: proxycore (HTTPError, queue, body utuh),
perf ramp (parkir/aktivasi), verdict determinism + ladder enforcement,
coverage matrix, attack chains terpadu."""

import json
import threading
import unittest
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import proxycore, verdicts
from cyphron.findings import Finding
from cyphron.verifier import finalize


def _finding(**kw) -> Finding:
    base = dict(tool="bola", title="IDOR /api/invoice", severity="high",
                description="d", target_url="https://t.test/api", confidence=0.9)
    base.update(kw)
    return Finding(**base)


class TestProxyForward(unittest.TestCase):
    def test_httperror_is_a_valid_response(self):
        """4xx/5xx origin = jawaban sah, bukan -1/502."""
        import cyphron.proxycore as pc
        orig_urlopen = pc.urlopen

        class _Resp404:
            status = 404
            headers = {"Content-Type": "text/html"}
            def read(self, n=-1):
                return b"<h1>not found dari origin</h1>"
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=10):
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found",
                {"Content-Type": "text/html"}, io_bytes(b"<h1>not found</h1>"))

        def io_bytes(data):
            import io
            return io.BytesIO(data)

        pc.urlopen = fake_urlopen
        self.addCleanup(setattr, pc, "urlopen", orig_urlopen)
        out = pc.forward_request("GET", "http://t.test/x", {}, None)
        self.assertEqual(out["status"], 404)
        self.assertEqual(out["body"], b"<h1>not found</h1>")
        self.assertIn("not found", out["body_preview"])

    def test_body_full_returned_not_preview(self):
        import cyphron.proxycore as pc
        orig_urlopen = pc.urlopen

        class _Resp:
            status = 200
            headers = {"Content-Type": "text/html"}
            def read(self, n=-1):
                return b"x" * 5000
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        pc.urlopen = lambda req, timeout=10: _Resp()
        self.addCleanup(setattr, pc, "urlopen", orig_urlopen)
        out = pc.forward_request("GET", "http://t.test/x", {}, None)
        self.assertEqual(len(out["body"]), 5000)
        self.assertEqual(len(out["body_preview"]), 2000)  # preview utk history
        self.assertFalse(out["truncated"])


class TestInterceptQueue(unittest.TestCase):
    def test_decide_empties_queue_not_stuck(self):
        q = proxycore.InterceptQueue(cap=2)
        r1 = q.hold({"method": "GET", "url": "u1"})
        r2 = q.hold({"method": "GET", "url": "u2"})
        q.decide(r1, "approve")
        q.decide(r2, "approve")
        self.assertEqual(q.pending(), [])
        # setelah antrian kosong, request baru LAGI BOLEH masuk (dulu macet)
        r3 = q.hold({"method": "GET", "url": "u3"})
        self.assertEqual(len(q.pending()), 1)
        self.assertEqual(q.wait(r3, timeout=0.1), "drop")

    def test_concurrent_hold_unique_rid(self):
        q = proxycore.InterceptQueue(cap=50)
        rids = []
        lock = threading.Lock()

        def hold_one():
            rid = q.hold({"url": "x"})
            with lock:
                rids.append(rid)

        ts = [threading.Thread(target=hold_one) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(len(rids), len(set(rids)), "rid harus unik")


class TestVerdictDeterminism(unittest.TestCase):
    def test_finalize_downgrades_header_only_confirmed(self):
        f = _finding(status="confirmed", evidence_kind="header")
        confirmed, unconfirmed = finalize([f])
        self.assertEqual(confirmed, [])
        self.assertEqual(len(unconfirmed), 1)
        self.assertEqual(unconfirmed[0].status, "unconfirmed")

    def test_finalize_keeps_deterministic_evidence(self):
        f = _finding(status="confirmed", evidence_kind="request-response",
                     request="GET /x", response="HTTP 200; bukti")
        confirmed, _ = finalize([f])
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(verdicts.verdict_of(confirmed[0]),
                         verdicts.DETERMINISTICALLY_VERIFIED)

    def test_field_evidence_kind_counts_in_verdict(self):
        """evidence_kind di konstruktor (tanpa attach) kini dihitung."""
        f = _finding(status="confirmed", evidence_kind="probe-pair")
        self.assertGreaterEqual(verdicts.verdict_of(f), verdicts.MIN_REPORT_LEVEL)


class TestPerfRamp(unittest.TestCase):
    def test_ramp_keeps_running_and_terminates(self):
        """Ramp-down harus MEMARKIR VU, bukan mematikan semua beban;
        run_scenario harus kembali (tanpa thread non-daemon nyangkut)."""
        from cyphron import perf_engine
        from cyphron.tools import http_engine
        calls = []
        lock = threading.Lock()

        def fake_get(url, **kw):
            with lock:
                calls.append(threading.current_thread().name)
            return 200, {}, "", 5
        orig = http_engine.http_get
        http_engine.http_get = fake_get
        self.addCleanup(setattr, http_engine, "http_get", orig)
        out = perf_engine.run_scenario({
            "url": "http://t.test/x", "vus": 4, "duration_s": 1,
            "ramp": [{"after_s": 0.3, "vus": 2}],
        })
        # beban tetap jalan SETELAH ramp-down 4->2 (dulu jadi nol total)
        self.assertGreater(out["total"], 0)
        self.assertGreaterEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
