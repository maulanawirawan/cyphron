"""Test F76 — lan_watch (inventaris LAN milik sendiri, NOL jaringan).

Yang dikunci (fungsi murni, subprocess di-mock):
  - parse_arp: output `arp -a` Windows -> {ip: mac}, buang broadcast/
    invalid, normalisasi '-' -> ':';
  - oui_vendor: OUI kurasi, MAC acak (bit lokal) dikenali;
  - subnet_of / local boundary;
  - diff_state: perangkat baru vs baseline (first_seen dipertahankan),
    perangkat hilang tercatat;
  - finding_rows: perangkat baru = lead L1 kontrak-valid (fakta, bukan
    klaim penyerang);
  - block_guide: URL router + kriteria lulus/gagal + larangan ARP-cut.
DISIPLIN: tool TIDAK memblokir, TIDAK ARP-spoof — panduan router saja.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import lan_watch as lw  # noqa: E402
from findings import validate_finding  # noqa: E402

ARP_SAMPLE = """
Antarmuka: 192.168.1.188 --- 0xb
  alamat internet           alamat fisik            jenis
  192.168.1.1          98-3f-a4-01-2b-b8     dinamis
  192.168.1.204        5e-6c-db-11-eb-21     dinamis
  192.168.1.255        ff-ff-ff-ff-ff-ff     statis
  224.0.0.22           01-00-5e-00-00-16     statis
  255.255.255.255      ff-ff-ff-ff-ff-ff     statis
"""


class ParseArpTest(unittest.TestCase):
    def test_parse_windows_output(self):
        out = lw.parse_arp(ARP_SAMPLE)
        self.assertEqual(out["192.168.1.1"], "98:3f:a4:01:2b:b8")
        self.assertEqual(out["192.168.1.204"], "5e:6c:db:11:eb:21")
        # broadcast/multicast dibuang
        self.assertNotIn("192.168.1.255", out)
        self.assertNotIn("224.0.0.22", out)

    def test_oui_vendor(self):
        self.assertEqual(lw.oui_vendor("64:24:4d:88:84:01"), "TP-Link")
        self.assertEqual(lw.oui_vendor("30:cb:f8:ef:33:6f"), "Samsung")
        self.assertEqual(lw.oui_vendor("06:be:bf:4c:c2:c9"),
                         "Randomized")
        # MAC acak perangkat modern (bit lokal 0x02 octet pertama),
        # OUI tidak ada di tabel kurasi -> fallback
        self.assertIn("acak", (lw.oui_vendor("b6:50:ac:00:00:01")
                               or "").lower())
        self.assertEqual(lw.oui_vendor("ae:c9:d6:74:39:6a"), "Randomized")

    def test_subnet_of(self):
        self.assertEqual(lw.subnet_of("192.168.1.188"), "192.168.1")
        self.assertIsNone(lw.subnet_of("bukan-ip"))


class DiffStateTest(unittest.TestCase):
    def _scan(self, ip, mac, epoch):
        return {"ok": True, "subnet": "192.168.1", "scan_epoch": epoch,
                "devices": [{"ip": ip, "mac": mac, "vendor": "TP-Link",
                             "hostname": None}], "requests": 254}

    def test_new_vs_persist_first_seen(self):
        old_state = {"devices": {
            "aa:aa:aa:aa:aa:aa": {
                "ip": "192.168.1.2", "mac": "aa:aa:aa:aa:aa:aa",
                "vendor": "TP-Link", "hostname": None,
                "first_seen": 1000, "last_seen": 1000, "names": []}}}
        scan = self._scan("192.168.1.2", "aa:aa:aa:aa:aa:aa", 2000)
        diff = lw.diff_state(scan, old_state)
        self.assertEqual(diff["new_keys"], [])
        self.assertIn("aa:aa:aa:aa:aa:aa", diff["known"])
        self.assertEqual(diff["known"]["aa:aa:aa:aa:aa:aa"]["first_seen"],
                         1000)  # dipertahankan
        # perangkat baru
        scan2 = self._scan("192.168.1.204", "5e:6c:db:11:eb:21", 3000)
        diff2 = lw.diff_state(scan2, {"devices": diff["known"]})
        self.assertEqual(diff2["new_keys"], ["5e:6c:db:11:eb:21"])
        # perangkat lama hilang
        self.assertEqual(diff2["gone_keys"], ["aa:aa:aa:aa:aa:aa"])


class FindingRowsTest(unittest.TestCase):
    def test_new_device_is_contract_valid_l1(self):
        scan = {"ok": True, "subnet": "192.168.1", "scan_epoch": 1,
                "devices": [], "requests": 254}
        diff = {"known": {"5e:6c:db:11:eb:21": {
            "ip": "192.168.1.204", "mac": "5e:6c:db:11:eb:21",
            "vendor": "Randomized", "hostname": None,
            "first_seen": 1, "last_seen": 1, "names": []}},
            "new_keys": ["5e:6c:db:11:eb:21"], "gone_keys": []}
        rows = lw.finding_rows(scan, diff)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["tool"], "lan-watch")
        self.assertEqual(r["verdict"], 1)
        self.assertEqual(r["status"], "confirmed")
        self.assertIn("192.168.1.204", r["title"])
        # fakta kebaruan, bukan klaim penyerang
        self.assertIn("BUKAN klaim penyerang", r["description"])
        self.assertEqual(validate_finding(r), [])


class BlockGuideTest(unittest.TestCase):
    def test_guide_router_url_dan_kriteria(self):
        g = lw.block_guide("192.168.1.204", {"devices": [
            {"ip": "192.168.1.204", "mac": "5e:6c:db:11:eb:21",
             "vendor": "Randomized"}]})
        self.assertIn("http://192.168.1.1/", g)
        self.assertIn("5e:6c:db:11:eb:21", g)
        self.assertIn("MAC Filtering", g)
        self.assertIn("GUEST SSID", g)
        self.assertIn("Kriteria lulus:", g)
        self.assertIn("Kriteria gagal:", g)

    def test_no_arp_cut(self):
        # disiplin: tool tidak menawarkan ARP-spoofing
        g = lw.block_guide("192.168.1.204", None)
        self.assertIn("bukan ARP-cut", g)


if __name__ == "__main__":
    unittest.main()
