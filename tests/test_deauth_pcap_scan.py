"""Nol jaringan — test deauth_pcap_scan (DFIR deauth 802.11 read-only).

Pcap sintetis dibangun in-memory (radiotap + 802.11 management frame
asli-format) — tidak ada packet yang dikirim, tidak ada jaringan.
Format frame mengikuti IEEE 802.11 (frame control / address field /
reason code) dan format pcap classic.
"""
from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import deauth_pcap_scan as dp  # noqa: E402


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def radiotap() -> bytes:
    # version 0, pad 0, len 8, present bitmap 0
    return b"\x00\x00" + struct.pack("<H", 8) + b"\x00\x00\x00\x00"


def mgmt_frame(subtype: int, a1: str, a2: str, a3: str,
               reason: int | None = None) -> bytes:
    fc0 = (subtype << 4) | (0 << 2)  # type=0 management
    frame = bytes([fc0, 0x00]) + b"\x00\x00"  # fc + duration
    frame += _mac(a1) + _mac(a2) + _mac(a3) + b"\x00\x00"  # seq
    if reason is not None:
        frame += struct.pack("<H", reason)
    return frame


def pcap_bytes(packets: "list[tuple[float, bytes]]",
               linktype: int = 127) -> bytes:
    out = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 262144,
                                            linktype)
    for ts, pkt in packets:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6),
                           len(pkt), len(pkt)) + pkt
    return out


AP = "02:00:00:00:aa:01"
STA = "02:00:00:00:aa:02"
ATTACKER = "02:00:00:00:aa:66"
BCAST = "ff:ff:ff:ff:ff:ff"


def wrap(pkt: bytes, ts: float) -> "tuple[float, bytes]":
    return ts, radiotap() + pkt


class TestScan(unittest.TestCase):
    """Nol jaringan — pipeline scan pcap sintetis."""

    def test_bersih_beacon_saja(self):
        data = pcap_bytes([wrap(mgmt_frame(8, BCAST, AP, AP), 1.0)] * 5)
        r = dp.scan(data)
        self.assertEqual(r["deauth_count"], 0)
        self.assertEqual(r["verdict"], "CLEAN_NO_DEAUTH")
        self.assertEqual(r["packets_scanned"], 5)

    def test_storm_dari_satua_transmitter(self):
        pkts = [wrap(mgmt_frame(0xC, STA, ATTACKER, AP, reason=7), 1.0 + i * 0.2)
                for i in range(12)]
        r = dp.scan(pcap_bytes(pkts))
        self.assertEqual(r["deauth_count"], 12)
        self.assertEqual(r["verdict"], "MALICIOUS_PATTERN_DETECTED")
        self.assertEqual(len(r["alerts"]), 1)
        self.assertEqual(r["alerts"][0]["transmitter"], ATTACKER)
        self.assertEqual(r["reason_codes"].get("class3-from-nonassoc"), 12)

    def test_bawah_ambang_tidak_alert(self):
        pkts = [wrap(mgmt_frame(0xC, STA, ATTACKER, AP, reason=3), 1.0 + i * 0.2)
                for i in range(5)]
        r = dp.scan(pcap_bytes(pkts))
        self.assertEqual(r["deauth_count"], 5)
        self.assertEqual(r["alerts"], [])
        self.assertEqual(r["verdict"], "SUSPICIOUS")

    def test_broadcast_dihitung(self):
        pkts = [wrap(mgmt_frame(0xC, BCAST, ATTACKER, AP, reason=7), 1.0 + i * 0.1)
                for i in range(11)]
        r = dp.scan(pcap_bytes(pkts))
        self.assertEqual(r["broadcast_count"], 11)
        self.assertEqual(r["alerts"][0]["kind"], "deauth-storm")

    def test_disassoc_dan_linktype_105(self):
        # linktype 105 = 802.11 tanpa radiotap
        pkts = [(1.0, mgmt_frame(0xA, STA, AP, AP, reason=8)),
                (1.5, mgmt_frame(0xA, STA, AP, AP, reason=8)),
                (2.0, mgmt_frame(0xA, STA, AP, AP, reason=8))]
        r = dp.scan(pcap_bytes(pkts, linktype=105))
        self.assertEqual(r["disassoc_count"], 3)
        self.assertEqual(r["by_transmitter"][AP], 3)

    def test_truncated_fail_marked(self):
        full = pcap_bytes([wrap(mgmt_frame(0xC, STA, ATTACKER, AP, 7), 1.0)])
        r = dp.scan(full[:-6])  # potong di tengah frame terakhir
        self.assertTrue(r["truncated"])

    def test_linktype_asing_diabaikan(self):
        pkts = [(1.0, b"\x00" * 60)]  # ethernet-ish, bukan 802.11
        r = dp.scan(pcap_bytes(pkts, linktype=1))
        self.assertEqual(r["deauth_count"], 0)
        self.assertEqual(r["linktypes"].get("1"), 1)


class TestFailClosed(unittest.TestCase):
    """Nol jaringan — parser menolak input tidak valid."""

    def test_magic_asing_ditolak(self):
        with self.assertRaises(ValueError):
            dp.scan(b"\xde\xad\xbe\xef" + b"\x00" * 30)

    def test_pendek_ditolak(self):
        with self.assertRaises(ValueError):
            dp.scan(b"\xd4\xc3\xb2\xa1")

    def test_cli_file_tidak_ada_exit2(self):
        self.assertEqual(
            dp.main(["--pcap", "TIDAK-ADA-12345.pcap"]), 2)

    def test_cli_file_bukan_pcap_exit2(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.pcap"
            p.write_bytes(b"ini bukan pcap sama sekali, hanya teks panjang")
            self.assertEqual(dp.main(["--pcap", str(p)]), 2)


class TestLiveVerifyHelper(unittest.TestCase):
    """Nol jaringan — builder pcap sintetis konsisten dgn parser."""

    def test_pcap_builder_roundtrip(self):
        data = pcap_bytes([wrap(mgmt_frame(0xC, STA, ATTACKER, AP, 7), 5.5)])
        r = dp.scan(data)
        self.assertEqual(r["packets_scanned"], 1)
        self.assertEqual(r["deauth_count"], 1)
        self.assertEqual(r["by_bssid"][AP], 1)


if __name__ == "__main__":
    unittest.main()
