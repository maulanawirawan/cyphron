"""Test F22 — program discovery. Semua sumber di-mock (nol jaringan).

Yang dikunci:
  - seeds/meta parser fail-closed (domain invalid = error keras);
  - kriteria usia perusahaan/pendanaan TIDAK pernah ditebak (unverified);
  - verdict kandidat maksimal L1 (bukan klaim kerentanan);
  - dedup lintas-sumber by domain + diff lintas-run by ID deterministik;
  - baris findings lolos kontrak (validate_finding) semua;
  - registry entry program-discovery: bounded-requests, needs none,
    seeds default kosong (no-op 0 request).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "skills"))

import program_discovery as pd  # noqa: E402
from findings import validate_finding  # noqa: E402


def _sectxt_meta(domain: str, contact: str | None, requests: int = 2):
    fields = {"contact": [contact]} if contact else {}
    rows, _ = None, None
    meta = {"domain": domain, "found": bool(contact), "path": "/.well-known/security.txt",
            "fields": fields, "requests": requests}
    return [], meta


class ParseSeedsTest(unittest.TestCase):
    def test_comments_blank_and_dedup(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "seeds.txt"
            p.write_text("# komentar\n\nexample.com\nEXAMPLE.com\n", encoding="utf-8")
            self.assertEqual(pd.parse_seeds(p), ["example.com"])

    def test_invalid_domain_is_hard_error(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "seeds.txt"
            p.write_text("example.com\nbukan domain!!\n", encoding="utf-8")
            with self.assertRaises(pd.ConfigError):
                pd.parse_seeds(p)

    def test_missing_seeds_file_is_hard_error(self):
        with self.assertRaises(pd.ConfigError):
            pd.parse_seeds(Path("TIDAK/ADA/x.txt"))

    def test_normalize_strips_scheme_port_path(self):
        self.assertEqual(pd.normalize_domain("HTTPS://Sub.Example.com/path?q=1#f:8443"),
                         "sub.example.com")


class CriteriaTest(unittest.TestCase):
    def test_age_criteria_only_from_meta_never_guessed(self):
        c = {"website": True, "email_domain": True}
        crit = pd.evaluate_criteria(c, None)
        self.assertEqual(crit["unverified"], ["founded_years", "funding_age_years"])
        self.assertNotIn("founded<=5th", " ".join(crit["verified"]))
        self.assertNotIn("funding", " ".join(crit["verified"]))

    def test_meta_csv_age_counts_pass(self):
        c = {"website": True, "email_domain": True}
        import datetime
        now = datetime.datetime(2026, 10, 18)
        crit = pd.evaluate_criteria(c, {"founded_year": "2022", "funded_year": "2025"}, now=now)
        self.assertEqual(crit["founded_years"], 4)
        self.assertEqual(crit["funding_age_years"], 1)
        self.assertTrue(crit["founded_ok"] and crit["funding_ok"])
        self.assertIn("founded<=5th", crit["verified"])
        self.assertIn("funding<=2th", crit["verified"])

    def test_old_company_fails_founded_criterion(self):
        c = {"website": True, "email_domain": True}
        import datetime
        now = datetime.datetime(2026, 10, 18)
        crit = pd.evaluate_criteria(c, {"founded_year": "1998", "funded_year": ""}, now=now)
        self.assertFalse(crit["founded_ok"])
        self.assertNotIn("founded<=5th", crit["verified"])

    def test_meta_csv_duplicate_domain_is_hard_error(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "meta.csv"
            p.write_text("domain,founded_year,funded_year\n"
                         "a.com,2022,\na.com,2023,\n", encoding="utf-8")
            with self.assertRaises(pd.ConfigError):
                pd.parse_meta_csv(p)


class SourceSeedsTest(unittest.TestCase):
    def test_contact_same_domain_is_email_domain_hit(self):
        seeds = ["example.com"]
        with patch.object(pd.security_txt, "audit",
                          side_effect=lambda d: _sectxt_meta(d, "security@example.com")):
            cands, meta = pd.source_seeds(seeds, 10)
        self.assertEqual(meta["requests"], 2)
        self.assertTrue(cands[0]["email_domain"])
        self.assertIn("security@example.com", cands[0]["contact_emails"])

    def test_contact_other_domain_is_miss(self):
        with patch.object(pd.security_txt, "audit",
                          side_effect=lambda d: _sectxt_meta(d, "sec@other.example")):
            cands, _ = pd.source_seeds(["example.com"], 10)
        self.assertFalse(cands[0]["email_domain"])

    def test_cap_truncates_and_records(self):
        with patch.object(pd.security_txt, "audit",
                          side_effect=lambda d: _sectxt_meta(d, None, 1)):
            cands, meta = pd.source_seeds([f"d{i}.example" for i in range(5)], 3)
        self.assertEqual(len(cands), 3)
        self.assertEqual(meta["truncated"], 2)


class MergeAndDiffTest(unittest.TestCase):
    def test_dedup_by_domain_merges_sources_min_name(self):
        raw = [
            {"domain": "a.com", "name": "zeta", "source": "seeds", "website": True,
             "email_domain": True},
            {"domain": "a.com", "name": "alpha", "source": "github-list", "website": True},
            {"domain": "b.com", "name": "bee", "source": "github-list"},
            {"source": "aggregator", "error": "tanpa regex"},  # non-domain baris audit
        ]
        merged, dropped = pd.merge_candidates(raw)
        self.assertEqual([c["domain"] for c in merged], ["a.com", "b.com"])
        self.assertEqual(merged[0]["name"], "alpha")  # deterministik: min
        self.assertEqual(sorted(merged[0]["sources"]), ["github-list", "seeds"])
        self.assertEqual(dropped, 1)

    def test_diff_state_new_and_not_seen(self):
        state = {"version": 1, "candidates": {"lama.com": {}}}
        d = pd.diff_state(state, ["baru.com"])
        self.assertEqual(d["new_domains"], ["baru.com"])
        self.assertEqual(d["not_seen_this_run"], ["lama.com"])
        d2 = pd.diff_state(state, ["lama.com"])
        self.assertEqual(d2["new_domains"], [])
        self.assertEqual(d2["not_seen_this_run"], [])


class MainEndToEndTest(unittest.TestCase):
    def _sectxt(self, contact: str | None, requests: int = 2):
        def fake(domain):
            return [], {"domain": domain, "found": bool(contact),
                        "path": "/.well-known/security.txt",
                        "fields": {"contact": [contact]} if contact else {},
                        "requests": requests}
        return fake

    def test_run_then_rerun_marks_new_once_and_contract_valid(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            seeds = tdp / "seeds.txt"
            seeds.write_text("example.com\n", encoding="utf-8")
            out = tdp / "out" / "findings.json"
            cdir = tdp / "discovery"
            with patch.object(pd.security_txt, "audit",
                              side_effect=self._sectxt("security@example.com")):
                rc = pd.main_with_args(["--seeds", str(seeds), "--out", str(out),
                                        "--candidates-dir", str(cdir)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["data"]["requests"], 2)
            self.assertEqual(doc["data"]["candidates_new"], 1)
            row = doc["findings"][0]
            self.assertEqual(validate_finding(row), [],
                             f"kontrak dilanggar: {validate_finding(row)}")
            self.assertEqual(row["verdict"], 1)  # website + email_domain = LEAD
            self.assertTrue(row["is_new"])
            # kandidat baru tersimpan per-file untuk dibedah manual
            files = [p for p in cdir.glob("*.json")
                     if p.name not in ("known-candidates.json",
                                       "discovery-diff.json")]
            self.assertEqual(len(files), 1)
            # run kedua: bukan baru lagi, tidak ada file kandidat tambahan
            out2 = tdp / "out2" / "findings.json"
            with patch.object(pd.security_txt, "audit",
                              side_effect=self._sectxt("security@example.com")):
                pd.main_with_args(["--seeds", str(seeds), "--out", str(out2),
                                   "--candidates-dir", str(cdir)])
            doc2 = json.loads(out2.read_text(encoding="utf-8"))
            self.assertEqual(doc2["data"]["candidates_new"], 0)
            self.assertFalse(doc2["findings"][0]["is_new"])

    def test_no_contact_stays_l0_observed(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            seeds = tdp / "seeds.txt"
            seeds.write_text("example.com\n", encoding="utf-8")
            out = tdp / "findings.json"
            with patch.object(pd.security_txt, "audit",
                              side_effect=self._sectxt(None)):
                pd.main_with_args(["--seeds", str(seeds), "--out", str(out),
                                   "--candidates-dir", str(tdp / "d")])
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["findings"][0]["verdict"], 0)

    def test_all_rows_never_above_l1(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            seeds = tdp / "seeds.txt"
            seeds.write_text("example.com\na.example\nb.example\n", encoding="utf-8")
            out = tdp / "findings.json"
            with patch.object(pd.security_txt, "audit",
                              side_effect=self._sectxt("x@example.com")):
                pd.main_with_args(["--seeds", str(seeds), "--out", str(out),
                                   "--candidates-dir", str(tdp / "d")])
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(all(r["verdict"] in (0, 1) for r in doc["findings"]))
            self.assertTrue(all(validate_finding(r) == [] for r in doc["findings"]))

    def test_empty_seeds_is_noop_zero_requests(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            seeds = tdp / "seeds.txt"
            seeds.write_text("# hanya komentar\n", encoding="utf-8")
            out = tdp / "findings.json"
            rc = pd.main_with_args(["--seeds", str(seeds), "--out", str(out),
                                    "--candidates-dir", str(tdp / "d")])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["data"]["requests"], 0)
            self.assertEqual(doc["findings"], [])


class RegistryEntryTest(unittest.TestCase):
    def test_registry_has_bounded_requests_needs_none(self):
        reg = json.loads((ROOT / "skills" / "registry.json").read_text(encoding="utf-8"))
        entry = next(s for s in reg["skills"] if s["name"] == "program-discovery")
        self.assertEqual(entry["safety_class"], "bounded-requests")
        self.assertEqual(entry["needs"], "none")
        self.assertIn("--out", entry["cmd"])
        self.assertIn("@OUT@", entry["cmd"])
        self.assertIn("--seeds", entry["cmd"])

    def test_default_seeds_file_empty_noop(self):
        seeds = ROOT / "skills" / "discovery-seeds.txt"
        self.assertTrue(seeds.exists())
        self.assertEqual(pd.parse_seeds(seeds), [],
                         "seed default wajib kosong (no-op 0 request di tier0)")


if __name__ == "__main__":
    unittest.main(verbosity=1)
