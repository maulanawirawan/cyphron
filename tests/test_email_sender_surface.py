"""Test suite skill email-sender-surface v2 — DoH di-mock, NOL jaringan.

Regresi utama (FP-class):
  - F1: "No DMARC pada subdomain" TIDAK boleh medium bila org domain
    menetapkan sp=reject/p=reject (warisan RFC 7489) — kasus live
    apex (p=reject;sp=reject) vs subdomainnya
    (contoh multi-label: mail.example.go.id vs example.go.id).
Kontrak: findings.json satu pintu (core/findings.py) — shape, verdict
ladder, id deterministik, reportable hanya verdict >= 3.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import email_sender_surface as ess  # noqa: E402


def mock_doh(map_by_name):
    """Buat patcher doh() dari dict {name: [(type, data), ...]}."""
    def _doh(name, rtype="TXT", timeout=20.0):
        return list(map_by_name.get(name, []))
    return _doh


APEX = "example.go.id"
SUB = "mail.example.go.id"

DMARC_REJECT_BOTH = ("v=DMARC1;p=reject;rua=mailto:admin@example.go.id;"
                     "ruf=mailto:admin@example.go.id;adkim=s;aspf=s;"
                     "pct=100;rf=afrf;ri=86400;sp=reject")


class OrgDomainTest(unittest.TestCase):
    def test_apex_none(self):
        self.assertIsNone(ess.org_domain("contoh.id"))

    def test_multi_label(self):
        self.assertEqual(ess.org_domain("mail.example.go.id"), "example.go.id")


class AuditApexTest(unittest.TestCase):
    def test_dmarc_reject_aman(self):
        with patch.object(ess, "doh", mock_doh({
            f"txt.{APEX}": [],
            APEX: [(16, '"v=spf1 include:spf.ess.barracudanetworks.com ~all"')],
            f"_dmarc.{APEX}": [(16, f'"{DMARC_REJECT_BOTH}"')],
        }),
                patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(APEX, mta_sts=False)
        dmarc = [r for r in rows if "DMARC" in r["title"] and "enforcement" in r["title"]]
        self.assertEqual(len(dmarc), 1)
        self.assertEqual(dmarc[0]["category"], "AMAN")
        self.assertEqual(dmarc[0]["verdict"], 0)
        soft = [r for r in rows if "~all" in r["title"]]
        self.assertEqual(len(soft), 1)
        self.assertEqual(soft[0]["verdict"], 1)
        self.assertEqual(soft[0]["verdict_tag"], "L1 SUSPECTED - LEAD")

    def test_no_record_at_all(self):
        with patch.object(ess, "doh", mock_doh({})), \
                patch.object(ess, "doh_doc", lambda *a, **k: None):
            rows, _gets = ess.audit(APEX, mta_sts=False)
        titles = " ".join(r["title"] for r in rows)
        self.assertIn(f"No SPF record on {APEX}", titles)
        self.assertIn(f"No DMARC record on {APEX}", titles)
        core = [r for r in rows if r["title"].startswith(("No SPF", "No DMARC"))]
        self.assertEqual(len(core), 2)
        for r in core:
            self.assertEqual(r["severity"], "medium")
            self.assertEqual(r["verdict"], 1)
            self.assertFalse(r["reportable"])


class SubdomainInheritanceTest(unittest.TestCase):
    """F1 regresi: subdomain tanpa record tapi org domain p=reject."""

    def test_no_dmarc_subdomain_covered_by_org(self):
        with patch.object(ess, "doh", mock_doh({
            f"_dmarc.{SUB}": [],
            f"_dmarc.{APEX}": [(16, f'"{DMARC_REJECT_BOTH}"')],
        }),
                patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(SUB, mta_sts=False)
        dmarc = [r for r in rows if r["title"].startswith("No DMARC")]
        self.assertEqual(len(dmarc), 1)
        r = dmarc[0]
        self.assertEqual(r["severity"], "info")     # bukan medium (F1)
        self.assertEqual(r["verdict"], 0)
        self.assertEqual(r["category"], "AMAN")
        self.assertIn("sp=reject", r["title"])
        self.assertIn(APEX, r["description"])

    def test_no_dmarc_subdomain_uncovered_when_org_none(self):
        with patch.object(ess, "doh", mock_doh({
            f"_dmarc.{SUB}": [],
            f"_dmarc.{APEX}": [],
        }),
                patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(SUB, mta_sts=False)
        dmarc = [r for r in rows if r["title"].startswith("No DMARC")]
        self.assertEqual(len(dmarc), 1)
        self.assertEqual(dmarc[0]["severity"], "medium")  # tetap risiko
        self.assertEqual(dmarc[0]["verdict"], 1)

    def test_no_spf_subdomain_annotated_and_downgraded(self):
        with patch.object(ess, "doh", mock_doh({
            SUB: [],
            f"_dmarc.{APEX}": [(16, f'"{DMARC_REJECT_BOTH}"')],
        }),
                patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(SUB, mta_sts=False)
        spf = [r for r in rows if r["title"].startswith("No SPF")]
        self.assertEqual(len(spf), 1)
        self.assertEqual(spf[0]["severity"], "low")  # dimitigasi sp=reject
        self.assertIn("dimitigasi", spf[0]["description"])

    def test_no_spf_subdomain_medium_without_org_reject(self):
        with patch.object(ess, "doh", mock_doh({SUB: []})), \
                patch.object(ess, "doh_doc", lambda *a, **k: None):
            rows, _gets = ess.audit(SUB, mta_sts=False)
        spf = [r for r in rows if r["title"].startswith("No SPF")]
        self.assertEqual(len(spf), 1)
        self.assertEqual(spf[0]["severity"], "medium")


class DkimTest(unittest.TestCase):
    def test_dkim_vendor_not_in_spf(self):
        with patch.object(ess, "doh", mock_doh({
            APEX: [(16, '"v=spf1 -all"')],
            f"_dmarc.{APEX}": [(16, '"v=DMARC1;p=reject"')],
            f"k1._domainkey.{APEX}": [(5, "s1.domainkey.sendgrid.net")],
        }),
                patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(APEX, mta_sts=False)
        vendor = [r for r in rows if "SendGrid" in r["title"]
                  and "Active DKIM" in r["title"]]
        self.assertEqual(len(vendor), 1)
        self.assertEqual(vendor[0]["verdict"], 0)
        inconsistent = [r for r in rows if "NOT in SPF" in r["title"]]
        self.assertEqual(len(inconsistent), 1)
        self.assertEqual(inconsistent[0]["verdict"], 1)

    def test_dkim_vendor_covered_in_spf_no_lead(self):
        with patch.object(ess, "doh", mock_doh({
            APEX: [(16, '"v=spf1 include:sendgrid.net -all"')],
            f"_dmarc.{APEX}": [(16, '"v=DMARC1;p=reject"')],
            f"k1._domainkey.{APEX}": [(16, '"v=DKIM1; p=MIGfMA"')],
        }),
                patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(APEX, mta_sts=False)
        inconsistent = [r for r in rows if "NOT in SPF" in r["title"]]
        self.assertEqual(len(inconsistent), 0)


class DoHFailureTest(unittest.TestCase):
    def test_doh_error_not_silent(self):
        # doh() produksi tidak pernah raise (fail-closed dengan marker) —
        # mock meniru kontrak itu: semua lookup gagal => marker error.
        def boom(name, rtype="TXT", timeout=20.0):
            return [(0, "__doh_error__ OSError: network down")]
        with patch.object(ess, "doh", boom), \
                patch.object(ess, "doh_doc", lambda *a, **k: None):
            rows, _gets = ess.audit(APEX, mta_sts=False)
        # semua lookup gagal -> dua lead fail-closed (SPF + DMARC) tetap
        # dilaporkan, bukan "aman" palsu; sub-check CAA/DNSSEC inconclusive
        # (info unconfirmed), dan TIDAK ADA temuan AMAN palsu
        titles = " ".join(r["title"] for r in rows)
        self.assertIn("No SPF", titles)
        self.assertIn("No DMARC", titles)
        self.assertIn("inconclusive", titles)
        self.assertEqual([r for r in rows if r["category"] == "AMAN"], [])


class MtaStsSubcheckTest(unittest.TestCase):
    """F18 — sub-check MTA-STS (dulu mta-sts-checker): 1 GET per domain."""

    def test_golden_valid_policy_is_aman(self):
        body = "version: STSv1\nmode: enforce\nmx: mail.example.go.id\n"
        with patch.object(ess, "doh", mock_doh({})), \
                patch.object(ess, "doh_doc", lambda *a, **k: None), \
                patch.object(ess, "fetch_mta_sts",
                             lambda d: {"status": 200, "body": body}):
            rows, gets = ess.audit(APEX, mta_sts=True)
        valid = [r for r in rows if "MTA-STS valid" in r["title"]]
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0]["category"], "AMAN")
        self.assertEqual(valid[0]["verdict"], 0)
        self.assertEqual(gets, 1, "satu GET ke target per domain")

    def test_fail_closed_no_policy_is_lead(self):
        with patch.object(ess, "doh", mock_doh({})), \
                patch.object(ess, "doh_doc", lambda *a, **k: None), \
                patch.object(ess, "fetch_mta_sts",
                             lambda d: {"status": None, "error": "refused"}):
            rows, gets = ess.audit(APEX, mta_sts=True)
        f = [r for r in rows if r["title"] == f"No MTA-STS on {APEX}"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["verdict"], 1)
        self.assertFalse(f[0]["reportable"])

    def test_wildcard_txt_is_not_mta_sts(self):
        # regresi live-target 2026-10-20 (FP ditemukan saat verifikasi
        # manual): wildcard DNS (contoh nyata: apple.com) menjawab TXT
        # untuk SEMUA subdomain — record yang BUKAN skema MTA-STS tidak
        # boleh menjadi lead "TXT exists"
        with patch.object(ess, "doh", mock_doh({
                f"_mta-sts.{APEX}": [
                    (16, '"v=spf1 redirect=_spf.apex.example"')],
        })),                 patch.object(ess, "doh_doc", lambda *a, **k: None),                 patch.object(ess, "fetch_mta_sts",
                             lambda d: {"status": None,
                                        "error": "refused"}):
            rows, _ = ess.audit(APEX, mta_sts=True)
        self.assertFalse([r for r in rows if "TXT exists" in r["title"]],
                         "wildcard TXT tidak boleh jadi lead MTA-STS")
        w = [r for r in rows if "wildcard DNS" in r["title"]]
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["status"], "unconfirmed")

    def test_real_stsv1_txt_but_fetch_failed_is_lead(self):
        # pembanding: record skema MTA-STS RESMI (v=STSv1) + fetch gagal
        # = lead sah (kebijakan ada tapi tidak terambil)
        with patch.object(ess, "doh", mock_doh({
                f"_mta-sts.{APEX}": [
                    (16, '"v=STSv1; id=20260101T000000;"')],
        })),                 patch.object(ess, "doh_doc", lambda *a, **k: None),                 patch.object(ess, "fetch_mta_sts",
                             lambda d: {"status": None,
                                        "error": "refused"}):
            rows, _ = ess.audit(APEX, mta_sts=True)
        f = [r for r in rows if "TXT exists" in r["title"]]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["status"], "confirmed")

    def test_no_mta_sts_mode_means_zero_target_requests(self):
        with patch.object(ess, "doh", mock_doh({})), \
                patch.object(ess, "doh_doc", lambda *a, **k: None):
            rows, gets = ess.audit(APEX, mta_sts=False)
        self.assertEqual(gets, 0)
        self.assertEqual([r for r in rows if "MTA-STS" in r["title"]], [])


class DnssecCaaSubcheckTest(unittest.TestCase):
    """F18 — sub-check DNSSEC (flag AD) + CAA (type 257)."""

    def test_golden_dnssec_ad_true_is_aman(self):
        with patch.object(ess, "doh", mock_doh({})), \
                patch.object(ess, "doh_doc", lambda *a, **k: {"AD": True}):
            rows, _ = ess.audit(APEX, mta_sts=False)
        f = [r for r in rows if "DNSSEC validated" in r["title"]]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["category"], "AMAN")

    def test_dnssec_doh_fail_is_inconclusive_not_claim(self):
        with patch.object(ess, "doh", mock_doh({})), \
                patch.object(ess, "doh_doc", lambda *a, **k: None):
            rows, _ = ess.audit(APEX, mta_sts=False)
        f = [r for r in rows if "DNSSEC check inconclusive" in r["title"]]
        self.assertEqual(len(f), 1)

    def test_golden_caa_absent_is_lead_cwe306(self):
        with patch.object(ess, "doh", mock_doh({})), \
                patch.object(ess, "doh_doc", lambda *a, **k: None):
            rows, _ = ess.audit(APEX, mta_sts=False)
        f = [r for r in rows if r["title"] == f"No CAA on {APEX}"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["cwe"], "CWE-306")
        self.assertEqual(f[0]["verdict"], 1)

    def test_caa_present_is_aman(self):
        with patch.object(ess, "doh", mock_doh({
                APEX: [(257, '0 issue "letsencrypt.org"')]})), \
                patch.object(ess, "doh_doc", lambda *a, **k: None):
            rows, _ = ess.audit(APEX, mta_sts=False)
        f = [r for r in rows if "CAA present" in r["title"]]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["category"], "AMAN")


class ContractTest(unittest.TestCase):
    def test_write_findings_shape_and_id_determinism(self):
        import json
        import tempfile
        f1 = ess.make_finding(tool="t", title="x", severity="low",
                              description="d", target_url=APEX,
                              evidence_kind="dns", verdict=1)
        f2 = ess.make_finding(tool="t", title="x", severity="low",
                              description="d", target_url=APEX,
                              evidence_kind="dns", verdict=1)
        self.assertEqual(f1["id"], f2["id"])  # id deterministik
        self.assertEqual(len(f1["id"]), 16)
        self.assertFalse(f1["reportable"])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.json"
            ess.write_findings(p, [f1], {"domain": APEX})
            doc = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(set(doc.keys()), {"ok", "data", "findings", "requests"})
        self.assertTrue(doc["ok"])
        self.assertEqual(doc["requests"], 0)
        row = doc["findings"][0]
        for k in ("tool", "title", "severity", "verdict", "verdict_tag",
                  "evidence_kind", "finding_class", "status", "confidence",
                  "id", "reportable", "lab_only"):
            self.assertIn(k, row)

    def test_verdict_ladder_tags(self):
        from findings import verdict_tag, make_finding
        self.assertEqual(verdict_tag(-1), "L-x REJECTED")
        self.assertEqual(verdict_tag(0), "L0 OBSERVED - LEAD")
        self.assertEqual(verdict_tag(1), "L1 SUSPECTED - LEAD")
        self.assertEqual(verdict_tag(3), "L3 DETERMINISTICALLY VERIFIED")
        f = make_finding(tool="t", title="x", severity="info", description="d",
                         evidence_kind="request-response")
        self.assertEqual(f["verdict"], 3)  # default dari bentuk bukti
        self.assertTrue(f["reportable"])

    def test_invalid_severity_rejected(self):
        from findings import make_finding
        with self.assertRaises(ValueError):
            make_finding(tool="t", title="x", severity="catas", description="d")


if __name__ == "__main__":
    unittest.main(verbosity=2)
