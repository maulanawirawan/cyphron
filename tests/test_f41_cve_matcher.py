"""Test F41 — cve-matcher (product/version -> CVE, fail-closed).

NOL jaringan (KEV sintetis, KB sintetis). Yang dikunci:
  - KEV match = lead L1 product-level, TANPA klaim versi rentan;
  - alias kurasi (apache/iis/zimbra/wordpress/dll) + direct product;
  - klaim terikat versi HANYA dari KB operator dgn source_url;
  - FP-guard: teks generik, versi di luar rentang, versi tak terurai,
    entri KB tanpa source_url, tool di luar allowlist;
  - KEV hilang = baris audit (bukan crash); kontrak (rows, meta).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import cve_matcher as cm  # noqa: E402
from findings import validate_finding  # noqa: E402


def kev(vendor, product, cve, cwes=None, ransom="Unknown"):
    return {"cveID": cve, "vendorProject": vendor, "product": product,
            "vulnerabilityName": f"{vendor} {product} bug",
            "knownRansomwareCampaignUse": ransom,
            "cwes": cwes or []}


KEV = [
    kev("Apache", "HTTP Server", "CVE-2021-41773"),
    kev("Apache", "Tomcat", "CVE-2020-1938"),
    kev("Microsoft", "Internet Information Services (IIS)",
        "CVE-2021-31166"),
    kev("Synacor", "Zimbra Collaboration Suite (ZCS)", "CVE-2022-41352"),
    kev("WordPress", "Core", "CVE-2023-2732"),
    kev("OpenSSL", "OpenSSL", "CVE-2022-3602", ransom="Known"),
    kev("Adobe", "ColdFusion", "CVE-2023-26360"),
    kev("Ivanti", "Pulse Connect Secure", "CVE-2021-22893"),
]


def fact_row(tool, text, url="http://example.com"):
    return {"tool": tool, "response": text, "title": "t",
            "target_url": url, "extra": {}, "status": "confirmed"}


def kb_entry(cve="CVE-2021-41773", product="apache",
             introduced="2.4.49", fixed="2.4.51",
             source="https://httpd.apache.org/security"):
    e = {"product": product, "cve": cve, "fixed": fixed,
         "source_url": source, "note": "uji"}
    if introduced is not None:
        e["introduced"] = introduced
    return e


class KevMatchingTest(unittest.TestCase):
    def test_alias_banner_apache_is_l1_lead_no_version_claim(self):
        rows, meta = cm.match_cves(
            [fact_row("server-version-disclosure", "Apache/2.4.49 (Win64)")],
            KEV)
        f = [r for r in rows if r.get("cve") == "CVE-2021-41773"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["verdict"], 1)
        self.assertFalse(f[0]["version_claim"])
        self.assertIn("VERIFIKASI MANUAL", f[0]["description"])

    def test_alias_version_detected_recorded_but_not_claimed(self):
        rows, meta = cm.match_cves(
            [fact_row("banner-posture", "Server: Apache/2.4.49")], KEV)
        f = [r for r in rows if r.get("cve") == "CVE-2021-41773"]
        self.assertEqual(f[0]["version_detected"], "2.4.49")
        self.assertFalse(f[0]["version_claim"])
        self.assertEqual(f[0]["via"], "alias:apache")

    def test_direct_product_substring(self):
        rows, meta = cm.match_cves(
            [fact_row("js-library-version-checker", "coldfusion 2021")],
            KEV)
        self.assertTrue(any(r.get("cve") == "CVE-2023-26360"
                            for r in rows))

    def test_ransomware_known_raises_severity_not_verdict(self):
        rows, meta = cm.match_cves(
            [fact_row("server-version-disclosure", "OpenSSL/1.1.1k")], KEV)
        f = [r for r in rows if r.get("cve") == "CVE-2022-3602"]
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["verdict"], 1)

    def test_iis_and_zimbra_and_wordpress_aliases(self):
        rows, _ = cm.match_cves([
            fact_row("server-version-disclosure", "Microsoft-IIS/10.0",
                     "http://example.com/a"),
            fact_row("tech-fingerprint", "zimbra collaboration",
                     "http://example.com/b"),
            fact_row("tech-fingerprint", "wordpress 6.2 meta generator",
                     "http://example.com/c"),
        ], KEV)
        cves = {r.get("cve") for r in rows
                if r.get("category") == "CVE-MATCH"}
        self.assertIn("CVE-2021-31166", cves)
        self.assertIn("CVE-2022-41352", cves)
        self.assertIn("CVE-2023-2732", cves)

    def test_no_match_emits_single_aman_summary(self):
        rows, meta = cm.match_cves(
            [fact_row("server-version-disclosure", "nginx/1.18.0")], KEV)
        self.assertEqual(meta["matches"], 0)
        self.assertEqual(len([r for r in rows if r["verdict"] == 0]), 1)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_generic_support_text_does_not_match_remote_support(self):
        # KEV punya produk "Remote Support" — teks generik TIDAK boleh match
        kev2 = KEV + [kev("BeyondTrust", "Remote Support",
                          "CVE-2026-102764")]
        rows, meta = cm.match_cves(
            [fact_row("tech-fingerprint",
                      "customer support portal contact page")], kev2)
        self.assertEqual(meta["matches"], 0)

    def test_generic_product_token_never_direct_matches(self):
        # entri KEV semacam "TrueConf :: Server" tidak boleh mencemari
        # teks apa pun yang mengandung kata "server"
        kev2 = KEV + [kev("TrueConf", "Server", "CVE-2026-72529"),
                      kev("Other", "Service", "CVE-2026-11111")]
        rows, meta = cm.match_cves(
            [fact_row("server-version-disclosure",
                      "nginx/1.18.0 server header")], kev2)
        self.assertEqual(meta["matches"], 0)

    def test_umbrella_entries_vendor_eq_product_not_direct_matched(self):
        # "Microsoft :: Microsoft" jangan muncul dari banner microsoft-iis
        kev2 = KEV + [kev("Microsoft", "Microsoft", "CVE-2026-42897")]
        rows, meta = cm.match_cves(
            [fact_row("server-version-disclosure", "Microsoft-IIS/10.0")],
            kev2)
        cves = {r.get("cve") for r in rows
                if r.get("category") == "CVE-MATCH"}
        self.assertNotIn("CVE-2026-42897", cves)
        self.assertIn("CVE-2021-31166", cves)

    def test_rows_from_non_allowlist_tools_never_become_facts(self):
        rows, meta = cm.match_cves(
            [fact_row("nuclei-templates-scan", "apache http server")], KEV)
        self.assertEqual(meta["facts"], 0)
        self.assertEqual(meta["matches"], 0)

    def test_apache_banner_does_not_pull_tomcat(self):
        rows, meta = cm.match_cves(
            [fact_row("server-version-disclosure", "Apache/2.4.49")], KEV)
        cves = {r.get("cve") for r in rows
                if r.get("category") == "CVE-MATCH"}
        self.assertNotIn("CVE-2020-1938", cves)  # tomcat tidak ikut
        self.assertIn("CVE-2021-41773", cves)

    def test_contract_all_rows_valid(self):
        rows, meta = cm.match_cves(
            [fact_row("server-version-disclosure", "Apache/2.4.49")], KEV)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))
        self.assertIn("kev_entries", meta)


class OperatorKbTest(unittest.TestCase):
    def _run(self, text, entries):
        valid = []
        for e in entries:
            fixed = cm.parse_version(str(e["fixed"]))
            intro = (cm.parse_version(str(e["introduced"]))
                     if e.get("introduced") else None)
            valid.append({**e, "_product": cm.norm_text(e["product"]),
                          "_fixed": fixed, "_introduced": intro})
        return cm.match_cves([fact_row("server-version-disclosure", text)],
                             KEV, valid)

    def test_version_in_range_claims_bound_to_version(self):
        rows, meta = self._run("Server: Apache/2.4.49",
                               [kb_entry()])
        f = [r for r in rows if r.get("via") == "operator-kb"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["version_detected"], "2.4.49")
        self.assertTrue(f[0]["version_claim"])
        self.assertEqual(f[0]["verdict"], 1)  # tetap L1, ladder utuh
        self.assertEqual(meta["ranges_checked"], 1)

    def test_version_above_fixed_not_claimed(self):
        rows, meta = self._run("Server: Apache/2.4.62", [kb_entry()])
        self.assertEqual(
            len([r for r in rows if r.get("via") == "operator-kb"]),
            0)

    def test_version_below_introduced_not_claimed(self):
        rows, meta = self._run("Server: Apache/2.4.48", [kb_entry()])
        self.assertEqual(
            len([r for r in rows if r.get("via") == "operator-kb"]),
            0)

    def test_unparseable_version_skipped_and_counted(self):
        rows, meta = self._run("Server: Apache/2.4.x", [kb_entry()])
        self.assertEqual(meta["ranges_skipped"], 1)
        self.assertEqual(
            len([r for r in rows if r.get("via") == "operator-kb"]),
            0)

    def test_kb_entry_without_source_url_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "kb.json"
            p.write_text(json.dumps({"entries": [
                {"product": "apache", "cve": "CVE-2021-41773",
                 "fixed": "2.4.51"}]}), encoding="utf-8")
            valid, rej = cm.load_kb(p)
            self.assertEqual(len(valid), 0)
            self.assertEqual(len(rej), 1)
            rows, meta = cm.match_cves(
                [fact_row("server-version-disclosure", "Apache/2.4.49")],
                KEV, valid, rej)
            self.assertTrue(any("ditolak" in r["title"] for r in rows))

    def test_load_kb_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "kb.json"
            p.write_text(json.dumps({"entries": [kb_entry()]}),
                         encoding="utf-8")
            valid, rej = cm.load_kb(p)
            self.assertEqual(len(valid), 1)
            self.assertEqual(valid[0]["_fixed"], (2, 4, 51))


class FailClosedTest(unittest.TestCase):
    def test_missing_kev_is_audit_row_not_crash(self):
        rows, meta = cm.match_cves(
            [fact_row("server-version-disclosure", "Apache/2.4.49")], None)
        self.assertTrue(meta.get("kev_missing"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertIn("intel_sync", rows[0]["recommendation"])

    def test_empty_everything_is_single_aman(self):
        rows, meta = cm.match_cves([], KEV)
        self.assertEqual(meta["facts"], 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)

    def test_template_index_built_and_cached(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            corpus = td / "corpus" / "cves" / "2021"
            corpus.mkdir(parents=True)
            (corpus / "CVE-2021-41773.yaml").write_text(
                "id: CVE-2021-41773\ninfo:\n  classification:\n"
                "    cve-id: CVE-2021-41773\n", encoding="utf-8")
            cache = td / "idx.json"
            idx = cm.build_template_index(td / "corpus", "v1", cache)
            self.assertIn("CVE-2021-41773", idx["cves"])
            again = cm.build_template_index(td / "corpus", "v1", cache)
            self.assertEqual(again["corpus_version"], "v1")
            # versi korpus beda = rebuild (cache basi tidak dipakai)
            fresh = cm.build_template_index(td / "corpus", "v2", cache)
            self.assertEqual(fresh["corpus_version"], "v2")

    def test_template_missing_corpus_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(cm.build_template_index(
                Path(td) / "nope", "v1", Path(td) / "c.json"))

    def test_version_parsing_fail_closed(self):
        self.assertIsNone(cm.parse_version("2.4.x"))
        self.assertIsNone(cm.parse_version(""))
        self.assertEqual(cm.parse_version("2.4.49"), (2, 4, 49))

    def test_alias_hit_without_version_stays_product_level(self):
        rows, meta = cm.match_cves(
            [fact_row("tech-fingerprint", "apache httpd detected")], KEV)
        f = [r for r in rows if r.get("cve") == "CVE-2021-41773"]
        self.assertEqual(len(f), 1)
        self.assertIsNone(f[0]["version_detected"])
        self.assertFalse(f[0]["version_claim"])


if __name__ == "__main__":
    unittest.main()
