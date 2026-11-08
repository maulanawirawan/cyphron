"""Test submission_report — nol jaringan, fixture findings inline.

Cakupan: rumus judul, empat seksi inti per platform, fail-closed
(tanpa bukti = klaim dampak tidak ditulis; unconfirmed = L1 exit 1;
input rusak = exit 2), evidence_ref pada setiap klaim, determinisme.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import submission_report as sr


def _confirmed():
    return {
        "tool": "hpp_differential", "check": "hpp",
        "title": "Parameter pollution mengubah penerima payout",
        "severity": "high", "status": "confirmed", "confidence": 0.9,
        "target_url": "https://api.example.com/v1/payout",
        "endpoint": "/v1/payout",
        "request": "POST /v1/payout HTTP/1.1\nHost: api.example.com\n\n"
                   "account=victim&account=attacker",
        "response": "HTTP/1.1 200 OK\n\n{\"payout_to\": \"attacker\"}",
        "impact": "Payout terkirim ke akun attacker meskipun korban "
                  "yang mendaftar.",
    }


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.src = Path(self.tmp.name) / "findings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, data):
        self.src.write_text(json.dumps(data), encoding="utf-8")

    def _run(self, platform="hackerone", index=0, out=None, src=None):
        out_path = Path(self.tmp.name) / "draf.md" if out is None else out
        argv = ["--findings", str(src or self.src), "--index", str(index),
                "--platform", platform, "--out", str(out_path)]
        rc = sr.main(argv)
        text = out_path.read_text(encoding="utf-8") if out_path.exists() \
            else ""
        return rc, text

    def _out_file(self, name):
        return Path(self.tmp.name) / name


class TestDraftL2(Base):
    def test_confirmed_with_evidence_is_l2_exit_0(self):
        self._write({"findings": [_confirmed()]})
        rc, text = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("DRAF L2", text)
        self.assertNotIn("DRAF L1", text)

    def test_title_formula_kelas_dampak_endpoint(self):
        self._write({"findings": [_confirmed()]})
        _, text = self._run()
        self.assertIn("[HPP] Payout terkirim ke akun attacker meskipun "
                      "korban yang mendaftar. via /v1/payout", text)

    def test_four_core_sections_present(self):
        self._write({"findings": [_confirmed()]})
        _, text = self._run()
        for sec in ("## Summary", "## Steps to Reproduce", "## Impact",
                    "## Recommended Fix"):
            self.assertIn(sec, text)

    def test_every_impact_claim_carries_evidence_ref(self):
        self._write({"findings": [_confirmed()]})
        _, text = self._run()
        impact = text.split("## Impact", 1)[1]
        self.assertIn("(bukti: findings.json#0:", impact)

    def test_request_embedded_copy_paste_ready(self):
        self._write({"findings": [_confirmed()]})
        _, text = self._run()
        self.assertIn("```http", text)
        self.assertIn("POST /v1/payout HTTP/1.1", text)
        self.assertIn("account=victim&account=attacker", text)

    def test_explicit_evidence_ref_preferred(self):
        f = _confirmed()
        f["evidence_ref"] = "lab/payout-idor.md"
        self._write({"findings": [f]})
        _, text = self._run()
        self.assertIn("(bukti: lab/payout-idor.md)",
                      text.split("## Impact", 1)[1])

    def test_deterministic_output(self):
        self._write({"findings": [_confirmed()]})
        _, t1 = self._run(out=self._out_file("a.md"))
        _, t2 = self._run(out=self._out_file("b.md"))
        self.assertEqual(t1, t2)


class TestFailClosed(Base):
    def test_unconfirmed_is_l1_exit_1_no_confirmed_claim(self):
        f = _confirmed()
        f["status"] = "unconfirmed"
        self._write({"findings": [f]})
        rc, text = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("DRAF L1", text)
        self.assertIn("PERINGATAN L1", text)

    def test_no_evidence_impact_claims_not_written(self):
        f = _confirmed()
        for k in ("request", "response", "poc"):
            f.pop(k, None)
        self._write({"findings": [f]})
        rc, text = self._run()
        self.assertEqual(rc, 1)
        impact = text.split("## Impact", 1)[1]
        self.assertIn("NEEDS-EVIDENCE", impact)
        self.assertNotIn("(bukti:", impact)

    def test_claim_without_evidence_not_written_even_if_text_present(self):
        f = _confirmed()
        for k in ("request", "response", "poc"):
            f.pop(k, None)
        self._write({"findings": [f]})
        _, text = self._run()
        impact = text.split("## Impact", 1)[1].split("## Recommended", 1)[0]
        self.assertNotIn("Payout terkirim", impact)  # klaim tak ditulis
        self.assertIn("NEEDS-EVIDENCE", impact)

    def test_missing_request_and_poc_steps_marked(self):
        f = _confirmed()
        f.pop("request")
        f.pop("response")
        self._write({"findings": [f]})
        rc, text = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("NEEDS-EVIDENCE", text)

    def test_false_positive_gets_warning_and_l1(self):
        f = _confirmed()
        f["status"] = "false-positive"
        self._write({"findings": [f]})
        rc, text = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("TIDAK untuk dikirim", text)

    def test_broken_input_exit_2(self):
        self.src.write_text("{bukan json", encoding="utf-8")
        rc, _ = self._run()
        self.assertEqual(rc, 2)

    def test_missing_file_exit_2(self):
        rc, _ = self._run(src=Path(self.tmp.name) / "tak-ada.json")
        self.assertEqual(rc, 2)

    def test_index_out_of_range_exit_2(self):
        self._write({"findings": [_confirmed()]})
        rc, _ = self._run(index=5)
        self.assertEqual(rc, 2)

    def test_unknown_platform_exit_2(self):
        self._write({"findings": [_confirmed()]})
        with self.assertRaises(SystemExit):
            sr.main(["--findings", str(self.src), "--platform",
                     "yeswehack", "--out", str(self._out_file("x.md"))])


class TestPlatforms(Base):
    def test_hackerone_sections(self):
        self._write({"findings": [_confirmed()]})
        _, text = self._run(platform="hackerone")
        self.assertIn("## Summary", text)
        self.assertIn("CVSS 3.1", text)

    def test_bugcrowd_vrt_line(self):
        self._write({"findings": [_confirmed()]})
        _, text = self._run(platform="bugcrowd")
        self.assertIn("VRT:", text)

    def test_intigriti_cvss_prominent(self):
        self._write({"findings": [_confirmed()]})
        _, text = self._run(platform="intigriti")
        self.assertIn("CVSS 3.1:", text.split("\n")[4] + text)

    def test_all_platforms_have_four_sections(self):
        self._write({"findings": [_confirmed()]})
        for p in sr.PLATFORMS:
            _, text = self._run(platform=p)
            for sec in ("## Summary", "## Steps to Reproduce",
                        "## Impact", "## Recommended Fix"):
                self.assertIn(sec, text, p)


class TestPolicy(Base):
    def test_no_theoretical_language_ever(self):
        f = _confirmed()
        f["status"] = "unconfirmed"
        for k in ("request", "response", "poc"):
            f.pop(k, None)
        self._write({"findings": [f]})
        _, text = self._run()
        low = text.lower()
        for banned in ("could potentially", "may allow", "might be"):
            self.assertNotIn(banned, low)

    def test_no_sending_no_network_notes(self):
        self._write({"findings": [_confirmed()]})
        _, text = self._run()
        self.assertIn("nol jaringan", text)
        self.assertIn("review manusia", text.lower())


if __name__ == "__main__":
    unittest.main()
