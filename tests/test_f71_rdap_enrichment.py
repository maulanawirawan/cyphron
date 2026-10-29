"""F71 — rdap-enrichment: drift deteksi dari snapshot RDAP.

Semua uji TANPA jaringan: fetch_rdap di-mock; state pakai tmp dir
(ditunjuk lewat monkeypatch STATE_DIR). Fokus: snapshot deterministik,
aturan drift (registrar/NS/hold/expiry), dan L0 postur.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import rdap_enrichment as re_mod  # noqa: E402

DOC = {
    "events": [
        {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-06-01T00:00:00Z"},
    ],
    "entities": [
        {"roles": ["registrar"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Registrar A"]]]},
    ],
    "nameservers": [{"ldhName": "NS2.Example.COM"}, {"ldhName": "ns1.example.com"}],
    "status": ["clientTransferProhibited"],
}


class RdapEnrichmentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._state_dir = re_mod.STATE_DIR
        re_mod.STATE_DIR = Path(self.tmp.name) / "state"

    def tearDown(self):
        re_mod.STATE_DIR = self._state_dir
        self.tmp.cleanup()

    def _snap(self, **over):
        snap = re_mod.snapshot_of(DOC)
        snap.update(over)
        return snap

    def test_snapshot_deterministic_normalized(self):
        snap = self._snap()
        # NS dinormalisasi lowercase + urut — konsisten antar-run
        self.assertEqual(snap["nameservers"], ["ns1.example.com", "ns2.example.com"])
        self.assertEqual(snap["registrar"], "Registrar A")
        self.assertEqual(snap["statuses"], ["clientTransferProhibited"])

    def test_first_run_baseline_no_drift(self):
        # audit() memanggil jaringan — uji drift_findings langsung
        rows = re_mod.drift_findings("contoh.id", None, self._snap(), "rdap:contoh.id")
        self.assertEqual(rows, [], "run pertama = baseline, bukan temuan drift")

    def test_registrar_change_flagged(self):
        old = self._snap()
        new = self._snap()
        new["registrar"] = "Registrar B"
        rows = re_mod.drift_findings("contoh.id", old, new, "rdap:contoh.id")
        self.assertEqual(len(rows), 1)
        self.assertIn("Registrar A -> Registrar B", rows[0]["title"])
        self.assertEqual(rows[0]["verdict"], 0)  # fakta, bukan klaim kerentanan

    def test_nameserver_change_flagged(self):
        old = self._snap()
        new = self._snap()
        new["nameservers"] = ["ns1.evil.example", "ns2.evil.example"]
        rows = re_mod.drift_findings("contoh.id", old, new, "rdap:contoh.id")
        self.assertTrue(any("Nameserver" in r["title"] for r in rows))

    def test_hold_status_flagged(self):
        old = self._snap()
        new = self._snap()
        new["statuses"] = ["clientTransferProhibited", "serverHold"]
        rows = re_mod.drift_findings("contoh.id", old, new, "rdap:contoh.id")
        self.assertTrue(any("serverHold" in r["title"] for r in rows))
        # hold yang sudah ada sebelumnya TIDAK dianggap drift baru
        rows2 = re_mod.drift_findings("contoh.id", new, self._snap(**{
            "statuses": ["clientTransferProhibited", "serverHold"]}), "rdap:contoh.id")
        self.assertFalse(any("serverHold" in r["title"] for r in rows2))

    def test_expiry_proximity_flagged(self):
        old = self._snap()
        new = self._snap()
        new["expiration"] = "2026-11-10T00:00:00Z"  # < 30 hari dari 2026-10-30
        rows = re_mod.drift_findings("contoh.id", old, new, "rdap:contoh.id")
        self.assertTrue(any("kedaluwarsa" in r["title"] for r in rows))

    def test_state_roundtrip_and_corrupt_state_is_baseline(self):
        re_mod.save_state("contoh.id", self._snap())
        loaded = re_mod.load_state("contoh.id")
        self.assertEqual(loaded["registrar"], "Registrar A")
        (re_mod.STATE_DIR / "contoh.id.json").write_text("{rusak", encoding="utf-8")
        self.assertIsNone(re_mod.load_state("contoh.id"))


class RegistryGateTest(unittest.TestCase):
    def test_rdap_enrichment_registered_as_domain_readonly(self):
        reg = json.loads((ROOT / "skills" / "registry.json")
                         .read_text(encoding="utf-8"))
        entry = next(s for s in reg["skills"] if s["name"] == "rdap-enrichment")
        self.assertEqual(entry["needs"], "domain")
        self.assertEqual(entry["safety_class"], "read-only")


if __name__ == "__main__":
    unittest.main()
