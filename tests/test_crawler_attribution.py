"""Test F21 — crawler-attribution: atribusi crawler dari log, nol jaringan.

Dokumentasi crawler dipatch (doh_ptr/rdap_ip di-mock); yang diuji adalah
klasifikasi, kontrak temuan, dan fail-closed parsing log.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import crawler_attribution as ca  # noqa: E402
from findings import validate_finding  # noqa: E402


def fake_infra(ip):
    """Mock infrastruktur: IP pertama tanpa PTR, kedua bermegapath."""
    if ip.startswith("69.33."):
        return {"ptr": [], "rdap": {"org": "MegaPath", "country": "US"}}
    if ip.startswith("82.39."):
        return {"ptr": [], "rdap": {"org": "Deutsche Telekom", "country": "DE"}}
    return {"ptr": ["host.example."], "rdap": {"org": "Example Corp",
                                               "country": "US"}}


class DocumentedCrawlerTest(unittest.TestCase):
    def test_documented_ua_is_surface_l0(self):
        entries = [{"ip": "216.73.217.15", "ua": "Mozilla/5.0 (compatible; "
                   "ClaudeBot/1.0; +claudebot@anthropic.com)",
                   "host": "example.com", "path": "/", "ts": "t"}]
        with patch.object(ca, "doh_ptr", fake_infra and (lambda ip: [])), \
                patch.object(ca, "rdap_ip", lambda ip: {}):
            rows, meta = ca.audit(entries, [], [])
        hit = [r for r in rows if "Documented crawler" in r["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["verdict"], 0)
        self.assertEqual(hit[0]["operator"], "Anthropic")
        self.assertEqual(meta["documented"], 1)
        for r in rows:
            self.assertEqual(validate_finding(r), [])


class UndocumentedCrawlerTest(unittest.TestCase):
    def test_undocumented_ua_is_lead_with_infra_profile(self):
        entries = [
            {"ip": "69.33.135.152", "ua": "RHRegistrationWatch/1.0",
             "host": "example.com", "path": "/", "ts": "t1"},
            {"ip": "82.39.255.155", "ua": "RHRegistrationWatch/1.0",
             "host": "example.com", "path": "/about", "ts": "t2"},
        ]
        with patch.object(ca, "doh_ptr", fake_infra and (lambda ip: [])), \
                patch.object(ca, "rdap_ip", fake_infra and (
                    lambda ip: fake_infra(ip)["rdap"])):
            rows, meta = ca.audit(entries, [], [])
        lead = [r for r in rows if "Undocumented crawler" in r["title"]]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["verdict"], 1)
        self.assertEqual(lead[0]["ip_count"], 2)
        # bukti infra: dua jaringan berbeda tercatat sebagai profil
        nets = lead[0]["networks"]
        self.assertIn("MegaPath", " ".join(nets))
        self.assertIn("Deutsche Telekom", " ".join(nets))
        # deskripsi berisi disclaimer fail-closed (bukan tuduhan)
        self.assertIn("TIDAK diklaim", lead[0]["description"])
        for r in rows:
            self.assertEqual(validate_finding(r), [])


class LogParsingTest(unittest.TestCase):
    def test_parse_valid_cloudflare_export(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "log.json"
            p.write_text(json.dumps([
                {"clientIP": "1.2.3.4", "userAgent": "X/1",
                 "clientRequestHTTPHost": "h.id",
                 "clientRequestPath": "/", "datetime": "2026-01-01"}]),
                encoding="utf-8")
            entries = ca.parse_log(str(p))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip"], "1.2.3.4")

    def test_fail_closed_on_missing_and_corrupt(self):
        with self.assertRaises(SystemExit):
            ca.parse_log("Z:/tidak/ada.json")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "log.json"
            p.write_text("{rusak", encoding="utf-8")
            with self.assertRaises(SystemExit):
                ca.parse_log(str(p))


class UaDatabaseTest(unittest.TestCase):
    def test_match(self):
        hit = ca.match_ua("Mozilla/5.0 (compatible; ClaudeBot/1.0; +x)")
        self.assertEqual(hit["operator"], "Anthropic")
        self.assertIsNone(ca.match_ua("RHRegistrationWatch/1.0"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
