"""Test F39 — deteksi dini memory-disclosure kelas Heartbleed
(skills/tls_heartbleed_check.py). NOL jaringan: server TLS disimulasikan
dengan byte-stream kaleng lewat fake socket. Yang dikunci:
  - overread (klaim 1 byte, jawab >1) = VULNERABLE, dan konten bocoran
    TIDAK pernah masuk bukti (zero data retention);
  - jawaban sesuai klaim = AMAN L0;
  - alert saat handshake = unconfirmed;
  - ClientHello membawa heartbeat extension + SNI host.
"""
from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import tls_heartbeat_overread as th  # noqa: E402
from findings import validate_finding  # noqa: E402

URL = "https://target.example/"


def hs_msg(t: int, body: bytes) -> bytes:
    return bytes([t]) + struct.pack(">I", len(body))[1:] + body


def rec(t: int, payload: bytes) -> bytes:
    return bytes([t]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload


def handshake_bytes() -> bytes:
    server_hello = hs_msg(2, b"\x03\x03" + bytes(32) + b"\x00"
                          + b"\x00\x2f" + b"\x01\x00")
    return rec(22, server_hello) + rec(22, hs_msg(14, b""))


def hb_resp(actual: int) -> bytes:
    msg = (b"\x02" + struct.pack(">H", actual) + b"A" * actual)
    return rec(24, msg)


class FakeSock:
    """recv() mengalirkan bytes yang disiapkan; sendall dicatat."""

    def __init__(self, stream: bytes):
        self.stream = stream
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def settimeout(self, t):
        pass

    def recv(self, n):
        chunk, self.stream = self.stream[:n], self.stream[n:]
        return chunk

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def run_check(stream: bytes) -> tuple[dict, list[dict]]:
    sock = FakeSock(stream)
    with patch.object(th.socket, "create_connection",
                      lambda *a, **k: sock):
        res = th.check(URL)
    rows, meta = th.audit(URL, res)
    return res, rows


class ClientHelloTest(unittest.TestCase):
    def test_has_heartbeat_ext_and_sni(self):
        ch = th.build_client_hello("target.example")
        self.assertIn(b"\x00\x0f\x00\x01\x01", ch)  # heartbeat ext
        self.assertIn(b"target.example", ch)        # SNI
        self.assertTrue(ch.startswith(b"\x16\x03\x01"))

    def test_heartbeat_request_claims_16384_sends_1(self):
        hb = th.build_heartbeat_request()
        self.assertTrue(hb.startswith(b"\x18"))
        (ln,) = struct.unpack(">H", hb[3:5])
        self.assertEqual(ln, 4)  # type(1) + len(2) + payload(1)
        (claimed,) = struct.unpack(">H", hb[6:8])
        self.assertEqual(claimed, 16384)
        self.assertEqual(hb[8:9], b"A")


class OverreadTest(unittest.TestCase):
    def test_overread_is_vulnerable_no_leak_in_evidence(self):
        res, rows = run_check(handshake_bytes() + hb_resp(100))
        self.assertTrue(res["vulnerable"])
        self.assertEqual(res["overread_len"], 99)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))
        f = rows[0]
        self.assertEqual(f["verdict"], 3)
        self.assertEqual(f["cwe"], "CWE-125")
        self.assertFalse(f["leaked_content_retained"])
        self.assertNotIn("A" * 50, f["response"])  # isi bocoran tidak ada

    def test_exact_claim_not_vulnerable(self):
        res, rows = run_check(handshake_bytes() + hb_resp(1))
        self.assertFalse(res["vulnerable"])
        self.assertEqual(rows[0]["verdict"], 0)

    def test_alert_during_handshake_unconfirmed(self):
        res, rows = run_check(rec(21, b"\x02\x28"))
        self.assertIn("error", res)
        self.assertEqual(rows[0]["status"], "unconfirmed")

    def test_cve_context_and_port(self):
        sock = FakeSock(handshake_bytes() + hb_resp(100))
        with patch.object(th.socket, "create_connection",
                          lambda *a, **k: sock):
            res = th.check(URL, port=8443)
        self.assertEqual(res["port"], 8443)
        rows, meta = th.audit(URL, res)
        f = rows[0]
        self.assertEqual(f["cve"], "CVE-2014-0160")
        self.assertEqual(f["port"], 8443)
        self.assertIn("legacy/IoT", f["description"])
        self.assertIn("nvd.nist.gov", f["recommendation"])
        self.assertIn("[CVE-2014-0160]", f["title"])

    def test_contract(self):
        _, rows = run_check(handshake_bytes() + hb_resp(1))
        self.assertIsInstance(rows, list)


if __name__ == "__main__":
    unittest.main()
