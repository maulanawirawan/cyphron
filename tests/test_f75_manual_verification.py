"""Test F75c — LANGKAH N: langkah verifikasi manual di laporan PDF.

Yang dikunci:
  - SETIAP lead (PERLU DICEK) dapat 3 langkah; proven/clean/unassessed
    tidak (bukan tempatnya);
  - kelas terkurasi memuat URL/setting persis + kriteria Lulus/Gagal
    (header absen, SPF/DMARC/MTA-STS/CAA, security.txt, XML-RPC,
    wp-login, throttling, determinisme);
  - kelas tak terkurasi = fallback generik dari rekomendasi (tetap 3
    langkah, tetap ada Lulus/Gagal);
  - bottom line menyebut 3 langkah verifikasi;
  - render PDF membawa blok "Cara verifikasi manual" (typst guard).
TIDAK mengubah verdict — ini kualitas laporan, bukan upgrade bukti.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import report_pdf as rp  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
import test_report_pdf as trp  # noqa: E402

TYPST_OK = trp.TYPST_OK


def lead(title, tool="t", verdict=1, target="https://contoh.example"):
    return {"tool": tool, "title": title, "verdict": verdict,
            "status": "confirmed", "severity": "low",
            "target_url": target,
            "recommendation": "Terapkan perbaikan.",
            "description": "Deskripsi temuan."}


class ManualVerificationTest(unittest.TestCase):
    def test_non_lead_kosong(self):
        self.assertEqual(rp.manual_verification(
            lead("x", verdict=0)), [])
        self.assertEqual(rp.manual_verification(
            lead("x", verdict=3)), [])
        self.assertEqual(rp.manual_verification(
            {"verdict": 1, "status": "unconfirmed"}), [])

    def test_header_absen_banner_posture(self):
        steps = rp.manual_verification(lead(
            "Security header absent on https://contoh.example/: HSTS",
            tool="banner-posture"))
        self.assertEqual(len(steps), 3)
        joined = "\n".join(steps)
        self.assertIn("curl -sI", joined)
        self.assertIn("Strict-Transport-Security", joined)
        self.assertIn("Lulus:", joined)
        self.assertIn("Gagal:", joined)

    def test_semua_header_umum_terkurasi(self):
        for h in ("X-Frame-Options", "X-Content-Type-Options",
                  "Content-Security-Policy"):
            steps = rp.manual_verification(lead(
                f"Security header absent on https://contoh.example/: {h}"))
            self.assertEqual(len(steps), 3, h)
            self.assertIn("Lulus:", "\n".join(steps), h)

    def test_spf_dmarc_mtassts_caa(self):
        for kw, needle in (("No SPF record", "v=spf1"),
                           ("No DMARC record", "v=DMARC1"),
                           ("No MTA-STS", "mta-sts"),
                           ("No CAA", "CAA")):
            steps = rp.manual_verification(lead(
                f"{kw} on contoh.example", tool="email-sender-surface"))
            self.assertEqual(len(steps), 3, kw)
            self.assertIn(needle, "\n".join(steps), kw)
            self.assertIn("Lulus:", "\n".join(steps), kw)

    def test_security_txt(self):
        steps = rp.manual_verification(lead(
            "No security.txt on contoh.example", tool="security-txt"))
        joined = "\n".join(steps)
        self.assertIn(".well-known/security.txt", joined)
        self.assertIn("Contact:", joined)
        self.assertIn("Gagal:", joined)

    def test_xmlrpc_wp_login(self):
        steps = rp.manual_verification(lead(
            "XML-RPC WordPress aktif di https://contoh.example",
            tool="wp-posture"))
        joined = "\n".join(steps)
        self.assertIn("/xmlrpc.php", joined)
        self.assertIn("405", joined)
        steps2 = rp.manual_verification(lead(
            "Halaman login WordPress terbuka di https://contoh.example",
            tool="wp-posture"))
        joined2 = "\n".join(steps2)
        self.assertIn("/wp-login.php", joined2)
        self.assertIn("Gagal:", joined2)

    def test_throttling_dan_determinisme_antibot(self):
        steps = rp.manual_verification(lead(
            "No throttling across 5 sequential GETs on "
            "https://contoh.example", tool="antibot-posture", verdict=2))
        joined = "\n".join(steps)
        self.assertIn("10 GET", joined)
        self.assertIn("429", joined)
        steps2 = rp.manual_verification(lead(
            "Responses deterministic across repeated GETs on "
            "https://contoh.example", tool="antibot-posture"))
        self.assertIn("dua kali", "\n".join(steps2))

    def test_fallback_generik_tetap_3_langkah(self):
        steps = rp.manual_verification(lead(
            "Kelas tak terkurasi apa pun", tool="tool-unknown"))
        self.assertEqual(len(steps), 3)
        self.assertIn("Lulus:", "\n".join(steps))
        self.assertIn("Terapkan perbaikan", "\n".join(steps))

    def test_build_data_membawa_langkah_hanya_untuk_check(self):
        doc = {"ok": True, "data": {"run": "x"}, "requests": 0,
               "findings": [
                   {"tool": "banner-posture", "severity": "low",
                    "title": "Security header absent on https://x/: HSTS",
                    "verdict": 1, "verdict_tag": "L1", "id": "1",
                    "status": "confirmed"},
                   {"tool": "t", "severity": "info", "title": "bersih",
                    "verdict": 0, "verdict_tag": "L0", "id": "2",
                    "status": "confirmed"},
                   {"tool": "t", "severity": "high", "title": "proven",
                    "verdict": 3, "verdict_tag": "L3", "id": "3",
                    "status": "confirmed"},
               ]}
        data = rp.build_data([doc], None, "J", "S")
        all_f = [f for c in data["categories"] for f in c["findings"]]
        by_title = {f["title"]: f for f in all_f}
        self.assertEqual(len(by_title["proven"]["manual_steps"]), 0)
        self.assertEqual(len(by_title["bersih"]["manual_steps"]), 0)
        steps = by_title["Security header absent on https://x/: HSTS"][
            "manual_steps"]
        self.assertEqual(len(steps), 3)
        self.assertTrue(all(s.startswith(("1.", "2.", "3."))
                            for s in steps))

    def test_bottom_line_sebut_3_langkah(self):
        counts = {"proven": 1, "check": 2, "clean": 3, "unassessed": 0,
                  "filtered": 0}
        s = rp.plain_bottom_line(counts)
        self.assertIn("3 langkah verifikasi manual", s)


@unittest.skipUnless(
    TYPST_OK, "typst tidak tersedia (CYPHRON_TYPST / tools/bin / PATH)")
class ManualVerificationRenderTest(trp.RenderTest):
    """Render end-to-end: blok 'Cara verifikasi manual' muncul di PDF
    (asersi dgn normalisasi whitespace — pelajaran F74: typst memotong
    frasa di tengah saat wrap)."""

    def test_render_manual_verification_block(self):
        import fitz
        f = ROOT / "tests/fixtures/report-fixture.json"
        pdf = self._render([f], title="Langkah Verifikasi Uji")
        d = fitz.open(stream=pdf, filetype="pdf")
        txt = " ".join(("\n".join(d[i].get_text()
                                  for i in range(d.page_count))).split())
        d.close()
        self.assertIn("Cara verifikasi manual", txt)
        self.assertIn("3 langkah:", txt)
        self.assertIn("Lulus:", txt)


if __name__ == "__main__":
    unittest.main()
