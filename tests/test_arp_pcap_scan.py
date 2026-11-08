"""Nol jaringan — test arp_pcap_scan (deteksi ARP poisoning dari pcap).

Fixture = frame ARP sintetis yang dibangun langsung di memori (byte
Ethernet II + ARP RFC 826); tidak ada file capture dan tidak ada trafik.
"""
from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import arp_pcap_scan as aps  # noqa: E402


def _ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def eth_arp(oper: int, sha: str, spa: str, tha: str = "00:00:00:00:00:00",
            tpa: str | None = None, extra_len: int = 0) -> bytes:
    """Frame Ethernet II berisi ARP standar (htype=1, ptype=IPv4)."""
    t = _ip(tpa) if tpa is not None else _ip(spa)  # default: gratuitous
    eth = _mac(tha if oper == 2 else "ff:ff:ff:ff:ff:ff") + _mac(sha) \
        + struct.pack(">H", 0x0806)
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, oper) + _mac(sha) + _ip(spa) \
        + _mac(tha) + t
    return eth + arp + b"\x00" * extra_len


def pcap_bytes(packets: "list[tuple[float, bytes]]") -> bytes:
    out = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 1)
    for ts, pkt in packets:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6),
                           len(pkt), len(pkt)) + pkt
    return out


GW = "10.0.0.1"
HOST = "10.0.0.50"
GW_MAC = "02:00:00:00:aa:01"
HOST_MAC = "02:00:00:00:aa:02"
ATK = "02:00:00:00:bb:66"

CHECKS = "set(f['check'] for f in findings)"


def checks(fnds: "list[dict]") -> "set[str]":
    return {f["check"] for f in fnds}


class TestScan(unittest.TestCase):
    """Nol jaringan — pipeline scan pcap ARP sintetis."""

    def test_lalu_lintas_sehat_bersih(self):
        # request + reply normal gateway<->host, bergantian cukup jauh
        pkts = []
        t = 1.0
        for _ in range(5):
            pkts.append((t, eth_arp(1, HOST_MAC, HOST, tpa=GW)))
            pkts.append((t + 0.5, eth_arp(2, GW_MAC, GW, tha=HOST_MAC,
                                          tpa=HOST)))
            t += 30.0
        r = aps.scan(pcap_bytes(pkts))
        self.assertEqual(r["verdict"], "CLEAN_NO_POISONING")
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["arp_requests"], 5)
        self.assertEqual(r["arp_replies"], 5)

    def test_duplicate_ip_dua_mac(self):
        pkts = [
            (1.0, eth_arp(2, GW_MAC, GW, tha=HOST_MAC, tpa=HOST)),
            (2.0, eth_arp(2, ATK, GW, tha=HOST_MAC, tpa=HOST)),
        ]
        r = aps.scan(pcap_bytes(pkts))
        self.assertIn("duplicate-ip", checks(r["findings"]))
        self.assertEqual(r["verdict"], "MALICIOUS_PATTERN_DETECTED")
        f = next(f for f in r["findings"] if f["check"] == "duplicate-ip")
        self.assertEqual(f["ip"], GW)
        self.assertEqual(set(f["macs"]), {GW_MAC, ATK})

    def test_flip_flop_bergantian(self):
        pkts = []
        t = 1.0
        for i in range(8):  # 7 transisi A->B->A->...
            mac = GW_MAC if i % 2 == 0 else ATK
            pkts.append((t, eth_arp(2, mac, GW, tha=HOST_MAC, tpa=HOST)))
            t += 1.0
        r = aps.scan(pcap_bytes(pkts))
        self.assertIn("mac-flip-flop", checks(r["findings"]))
        f = next(f for f in r["findings"] if f["check"] == "mac-flip-flop")
        self.assertEqual(f["transitions"], 7)

    def test_tanpa_bergantian_tidak_flip(self):
        # satu MAC saja berulang -> tidak ada flip-flop maupun duplicate
        pkts = [(1.0 + i, eth_arp(2, GW_MAC, GW, tha=HOST_MAC, tpa=HOST))
                for i in range(6)]
        r = aps.scan(pcap_bytes(pkts))
        self.assertNotIn("mac-flip-flop", checks(r["findings"]))
        self.assertNotIn("duplicate-ip", checks(r["findings"]))

    def test_gratuitous_flood(self):
        pkts = [(1.0 + i * 0.1, eth_arp(2, ATK, GW)) for i in range(12)]
        r = aps.scan(pcap_bytes(pkts))
        self.assertEqual(r["gratuitous_replies"], 12)
        self.assertIn("gratuitous-flood", checks(r["findings"]))
        f = next(f for f in r["findings"]
                 if f["check"] == "gratuitous-flood")
        self.assertEqual(f["sender"], ATK)
        self.assertEqual(f["count"], 12)

    def test_gratuitous_sedikit_tidak_flood(self):
        pkts = [(1.0 + i * 5.0, eth_arp(2, GW_MAC, GW)) for i in range(6)]
        r = aps.scan(pcap_bytes(pkts), flood_count=10)
        self.assertNotIn("gratuitous-flood", checks(r["findings"]))

    def test_volume_spike_medium(self):
        pkts = [(1.0 + i * 0.05, eth_arp(1, HOST_MAC, HOST, tpa=GW))
                for i in range(60)]
        r = aps.scan(pcap_bytes(pkts))
        self.assertIn("arp-volume-spike", checks(r["findings"]))
        f = next(f for f in r["findings"]
                 if f["check"] == "arp-volume-spike")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["count"], 60)
        # hanya spike medium -> SUSPICIOUS, bukan MALICIOUS
        self.assertEqual(r["verdict"], "SUSPICIOUS")

    def test_gateway_mac_change(self):
        pkts = [
            (1.0, eth_arp(2, GW_MAC, GW, tha=HOST_MAC, tpa=HOST)),
            (2.0, eth_arp(2, ATK, GW, tha=HOST_MAC, tpa=HOST)),
            (3.0, eth_arp(2, GW_MAC, GW, tha=HOST_MAC, tpa=HOST)),
        ]
        r = aps.scan(pcap_bytes(pkts), gateway_ip=GW)
        self.assertIn("gateway-mac-change", checks(r["findings"]))
        f = next(f for f in r["findings"]
                 if f["check"] == "gateway-mac-change")
        self.assertEqual(f["ip"], GW)

    def test_non_arp_dan_malformed_dicatat(self):
        raw_http = _mac("ff:ff:ff:ff:ff:ff") + _mac(GW_MAC) \
            + struct.pack(">H", 0x0800) + b"\x45\x00" + b"\x00" * 30
        arp_pendek = _mac("ff:ff:ff:ff:ff:ff") + _mac(GW_MAC) \
            + struct.pack(">H", 0x0806) + b"\x00\x01" + b"\x00" * 8
        r = aps.scan(pcap_bytes([(1.0, raw_http), (2.0, arp_pendek)]))
        self.assertEqual(r["non_arp_frames"], 1)
        self.assertEqual(r["arp_malformed"], 1)
        # frame ARP (termasuk malformed) terhitung; frame IP tidak
        self.assertEqual(r["arp_frames"], 1)

    def test_fail_closed_bukan_pcap(self):
        with self.assertRaises(ValueError):
            aps.scan(b"bukan pcap sama sekali" * 4)

    def test_truncated_paket_terakhir(self):
        full = eth_arp(1, HOST_MAC, HOST, tpa=GW)
        data = pcap_bytes([(1.0, full), (2.0, full)])
        r = aps.scan(data[:-6])  # potong 6 byte paket terakhir
        self.assertTrue(r["truncated"])
        self.assertEqual(r["packets_scanned"], 2)


class TestCLI(unittest.TestCase):
    """Nol jaringan — CLI: exit code 0/1/2 + JSON."""

    def test_exit_1_ada_temuan_high(self):
        data = pcap_bytes([
            (1.0, eth_arp(2, GW_MAC, GW, tha=HOST_MAC, tpa=HOST)),
            (2.0, eth_arp(2, ATK, GW, tha=HOST_MAC, tpa=HOST)),
        ])
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            fh.write(data)
            p = fh.name
        try:
            out = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "arp_pcap_scan.py"),
                 "--pcap", p, "--json"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(out.returncode, 1)
            res = json.loads(out.stdout)
            self.assertEqual(res["schema"], "secai.arp-pcap-scan/1")
            self.assertIn("duplicate-ip", checks(res["findings"]))
        finally:
            Path(p).unlink()

    def test_exit_0_bersih_dan_exit_2_error(self):
        data = pcap_bytes([(1.0, eth_arp(1, HOST_MAC, HOST, tpa=GW))])
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            fh.write(data)
            p = fh.name
        try:
            r0 = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "arp_pcap_scan.py"),
                 "--pcap", p],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r0.returncode, 0)
            self.assertIn("CLEAN_NO_POISONING", r0.stdout)
            r2 = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "arp_pcap_scan.py"),
                 "--pcap", p + ".tidak-ada"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r2.returncode, 2)
        finally:
            Path(p).unlink()


if __name__ == "__main__":
    unittest.main()
