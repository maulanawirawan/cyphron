"""Test qr_vcard_triage — NOL jaringan, payload di-mock.

Kontrak yang dikunci:
  - vCard/MECARD valid terskor; bukan kartu -> diabaikan;
  - semua sinyal deterministik dari data (lure/shortener/ip/punycode/
    msg-scheme/large-photo/note-instruction/x-custom-url);
  - zero-FP: kontak normal -> 0 sinyal, clean;
  - fail-closed: tanpa kartu valid -> error (exit 2 via main).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import qr_vcard_triage as qv  # noqa: E402

NORMAL = """BEGIN:VCARD
VERSION:3.0
FN:Budi Santoso
ORG:PT Maju Jaya
TEL:+6281234567890
EMAIL:budi@majujaya.co.id
END:VCARD
"""

PHISHY = """BEGIN:VCARD
VERSION:3.0
FN:Support Bank Nagari - Verifikasi Akun
ORG:Bank Nagari Customer Service
NOTE:PENTING: scan dan login sekarang untuk verifikasi OTP akun Anda
URL:https://bit.ly/3xVerify
URL:http://203.0.113.66/login?token=1
EMAIL:cs@xn--banknagari-3of.com
X-LANDING:http://login.banknagari.example/verify
TEL:SMSTO:+62811900999:Kode OTP Anda
PHOTO:jpeg:A" * 5000
END:VCARD
"""

MECARD_OK = "MECARD:N:Santoso,Budi;TEL:+6281234567;EMAIL:budi@example.com;;"


def _write(tmp: Path, text: str) -> Path:
    p = tmp / "in.txt"
    p.write_text(text, encoding="utf-8")
    return p


class ScoringTest(unittest.TestCase):
    def test_normal_card_is_clean(self):
        res = qv.triage_text(NORMAL)
        self.assertEqual(res["cards"], 1)
        self.assertEqual(res["finding_count"], 0)
        self.assertEqual(res["clean_count"], 1)

    def test_phishy_card_scores_high_with_expected_signals(self):
        res = qv.triage_text(NORMAL + "\n" + PHISHY.replace('" * 5000', "A" * 5000))
        self.assertEqual(res["cards"], 2)
        top = res["findings"][0]
        self.assertGreaterEqual(top["score"], 3)
        self.assertEqual(top["severity"], "high")
        for s in ("brand-lure", "shortener-url", "ip-literal-url",
                  "punycode-url", "http-url", "msg-scheme-url",
                  "large-photo-blob", "note-instruction", "x-custom-url",
                  "email-lure"):
            self.assertIn(s, top["signals"], s)

    def test_mecard_is_valid_card(self):
        res = qv.triage_text(MECARD_OK)
        self.assertEqual(res["cards"], 1)
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["clean_count"], 1)

    def test_non_card_payload_ignored(self):
        res = qv.triage_text("https://bit.ly/abc\n\nhttps://203.0.113.9/x\n\n" + NORMAL)
        self.assertEqual(res["payloads"], 3)
        self.assertEqual(res["cards"], 1)  # hanya vCard terskor

    def test_json_input_accepted(self):
        res = qv.triage_text(json.dumps([NORMAL]), as_json=True)
        self.assertEqual(res["cards"], 1)


class FailClosedTest(unittest.TestCase):
    def test_no_card_raises(self):
        with self.assertRaises(ValueError):
            qv.triage_text("https://bit.ly/abc\nhttps://example.com/x\n")

    def test_main_exit_2_on_missing_file(self):
        rc = qv.main(["--file", str(ROOT / ".tmp" / "nope_vcard.txt")])
        self.assertEqual(rc, 2)

    def test_main_exit_2_on_no_cards(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = _write(Path(td), "https://example.com/a\n")
            rc = qv.main(["--file", str(p), "--out", str(Path(td) / "o.json")])
            self.assertEqual(rc, 2)

    def test_main_writes_single_json_line(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = _write(Path(td), NORMAL)
            out = Path(td) / "o.json"
            rc = qv.main(["--file", str(p), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], "secai.qr-vcard-triage/1")
            self.assertTrue(doc["read_only"])


if __name__ == "__main__":
    unittest.main()
