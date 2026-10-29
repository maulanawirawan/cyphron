"""Gerbang bukti (Evidence Gate) — kontrak L3 wajib bukti nyata.

Audit 2026-10: temuan unconfirmed bisa membawa verdict L3 + reportable
hanya dengan mengisi metadata; validator tidak mengecek keberadaan bukti.
Fix: aturan status-verdict-bukti sinkron findings.py <-> contract.rs.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, validate_finding  # noqa: E402


def _confirmed_l3(**over):
    base = dict(
        tool="t", title="uji", severity="high",
        description="d", target_url="http://x",
        request="GET / HTTP/1.1",
        response="HTTP/1.1 200",
        evidence_kind="request-response",
        confidence=0.9, status="confirmed", verdict=3,
    )
    base.update(over)
    return make_finding(**base)


class TestMakeFindingGate(unittest.TestCase):
    def test_unconfirmed_strong_kind_derives_l1_bukan_l3(self):
        # dulu: unconfirmed + evidence_kind request-response -> L3 reportable
        f = make_finding(
            tool="t", title="x", severity="high", description="d",
            evidence_kind="request-response", status="unconfirmed",
        )
        self.assertEqual(f["verdict"], 1)
        self.assertFalse(f["reportable"])

    def test_unconfirmed_dengan_verdict_l3_ditolak(self):
        with self.assertRaises(ValueError):
            make_finding(
                tool="t", title="x", severity="high", description="d",
                status="unconfirmed", verdict=3,
            )

    def test_false_positive_wajib_minus_satu(self):
        self.assertEqual(
            make_finding(tool="t", title="x", severity="info",
                         description="d", status="false-positive")["verdict"],
            -1,
        )
        with self.assertRaises(ValueError):
            make_finding(tool="t", title="x", severity="info",
                         description="d", status="false-positive", verdict=0)

    def test_confirmed_l3_tanpa_bukti_ditolak(self):
        with self.assertRaises(ValueError):
            make_finding(
                tool="t", title="x", severity="critical", description="d",
                evidence_kind="request-response", status="confirmed", verdict=3,
            )
        # bukti whitespace bukan bukti
        with self.assertRaises(ValueError):
            _confirmed_l3(request="   ", response="", poc=None)

    def test_confirmed_l3_dengan_bukti_lolos(self):
        f = _confirmed_l3()
        self.assertEqual(f["verdict"], 3)
        self.assertTrue(f["reportable"])
        # cukup satu field bukti
        f2 = _confirmed_l3(request=None, response="HTTP/1.1 200 OK")
        self.assertTrue(f2["reportable"])

    def test_confirmed_verdict_rendah_tanpa_bukti_boleh(self):
        # posture inventory: confirmed L0 tanpa bukti request/response
        f = make_finding(
            tool="t", title="x", severity="info", description="d",
            status="confirmed", verdict=0,
        )
        self.assertFalse(f["reportable"])

    def test_confirmed_tidak_boleh_minus_satu(self):
        with self.assertRaises(ValueError):
            _confirmed_l3(verdict=-1)


class TestValidateFindingGate(unittest.TestCase):
    def test_unconfirmed_l3_via_dict_ditolak(self):
        f = _confirmed_l3()
        f["status"] = "unconfirmed"
        errs = validate_finding(f)
        self.assertTrue(any("unconfirmed" in e for e in errs), errs)

    def test_l3_tanpa_bukti_via_dict_ditolak(self):
        f = _confirmed_l3()
        f["request"] = None
        f["response"] = None
        f["poc"] = None
        errs = validate_finding(f)
        self.assertTrue(any("without evidence" in e for e in errs), errs)

    def test_false_positive_verdict_non_minus_satu_ditolak(self):
        f = _confirmed_l3()
        f["status"] = "false-positive"
        f["verdict"] = 3
        f["verdict_tag"] = "L3 DETERMINISTICALLY VERIFIED"
        f["reportable"] = True
        errs = validate_finding(f)
        self.assertTrue(any("false-positive" in e for e in errs), errs)

    def test_confidence_string_ditolak_sesuai_rust(self):
        # sync: serde f64 di contract.rs menolak "0.5" string saat parse;
        # python validator tidak boleh lebih longgar (drift dua-bahasa)
        f = _confirmed_l3(confidence=0.9)
        f["confidence"] = "0.9"
        errs = validate_finding(f)
        self.assertTrue(any("confidence" in e for e in errs), errs)

    def test_confidence_bool_ditolak(self):
        f = _confirmed_l3(confidence=0.9)
        f["confidence"] = True
        errs = validate_finding(f)
        self.assertTrue(any("confidence" in e for e in errs), errs)

    def test_temuan_lead_tanpa_bukti_valid(self):
        f = make_finding(
            tool="t", title="x", severity="low", description="d",
            evidence_kind="header", status="unconfirmed",
        )
        self.assertEqual([], validate_finding(f))


if __name__ == "__main__":
    unittest.main()
