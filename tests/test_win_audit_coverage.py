"""Nol jaringan — test win_audit_coverage (cakupan kebijakan audit + ukuran
log Windows, dari file). Format mengikuti output nyata auditpol/wevtutil.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import win_audit_coverage as wa  # noqa: E402


def auditpol_csv(rows: list[tuple[str, str, str]]) -> str:
    lines = ["Machine Name,Policy Target,Subcategory,Subcategory GUID,"
             "Inclusion Setting,Exclusion Setting"]
    for sub, guid, setting in rows:
        lines.append(f'DESKTOP-LAB,System,"{sub}",{{{guid}}},{setting},')
    return "\n".join(lines) + "\n"


SAMPLE = auditpol_csv([
    ("Audit Credential Validation", "0CCE923F-69AE-11D9-BED3-505054503030",
     "Success and Failure"),
    ("Audit Logon", "0CCE9215-69AE-11D9-BED3-505054503030", "Success and Failure"),
    ("Audit Process Creation", "0CCE922B-69AE-11D9-BED3-505054503030",
     "No Auditing"),
    ("Audit Kerberos Service Ticket Operations",
     "0CCE9210-69AE-11D9-BED3-505054503030", "Success"),
])

WEVT_SMALL = """name: Security
enabled: true
type: Admin
isolation: Custom
logging:
  logFileName: %SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx
  retention: false
  autoBackup: false
  maxSize: 20971520
publishing:
  fileMax: 26
"""

WEVT_OK = """name: Security
enabled: true
logging:
  retention: false
  autoBackup: true
  maxSize: 1073741824
"""


class TestAuditPolicy(unittest.TestCase):
    """Nol jaringan — cek kebijakan audit."""

    def test_campuran_temuan(self):
        subcats, leads = wa.parse_auditpol(SAMPLE, "auditpol.csv")
        self.assertEqual(leads, [])
        fnds = wa.audit_policy(subcats, "auditpol.csv")
        checks = {f["check"] for f in fnds}
        self.assertIn("audit-mati", checks)              # Process Creation
        self.assertIn("audit-success-saja", checks)      # Kerberos SVC Ticket
        self.assertIn("audit-tak-terdefinisi", checks)   # Sensitive Priv Use
        # Credential Validation S+F & Logon S+F tidak di-flag
        items = {f["item"] for f in fnds}
        self.assertNotIn("credential validation", items)
        self.assertNotIn("logon", items)

    def test_lokal_non_inggris_tidak_fp_storm(self):
        # nama subkategori lokal (valid GUID tetap ada) -> satu info saja
        rows = [
            ("Audit Validasi Kredensial", "0CCE923F-69AE-11D9-BED3-505054503030",
             "Success and Failure"),
            ("Audit Masuk", "0CCE9215-69AE-11D9-BED3-505054503030", "Success"),
        ]
        subcats, leads = wa.parse_auditpol(auditpol_csv(rows), "a.csv")
        self.assertEqual(leads, [])
        fnds = wa.audit_policy(subcats, "a.csv")
        self.assertEqual(len(fnds), 1)
        self.assertEqual(fnds[0]["check"], "subkategori-tak-dikenali")
        self.assertEqual(fnds[0]["severity"], "info")

    def test_csv_rusak_fail_closed(self):
        subcats, leads = wa.parse_auditpol("baris acak tanpa guid\n", "a.csv")
        self.assertEqual(subcats, {})
        self.assertEqual(leads[0]["check"], "file-unparsed")
        self.assertEqual(leads[0]["severity"], "high")


class TestWevtutil(unittest.TestCase):
    """Nol jaringan — cek konfigurasi channel event log."""

    def test_ukuran_kecil_dan_autobackup(self):
        channels, leads = wa.parse_wevtutil(WEVT_SMALL, "wevt.txt")
        self.assertEqual(leads, [])
        self.assertEqual(channels[0]["name"], "Security")
        fnds = wa.audit_channels(channels, "wevt.txt")
        checks = {f["check"] for f in fnds}
        self.assertIn("ukuran-kecil", checks)        # 20 MB < 1 GB
        self.assertIn("tanpa-autobackup", checks)
        self.assertNotIn("channel-mati", checks)

    def test_channel_mati(self):
        text = WEVT_OK.replace("enabled: true", "enabled: false")
        channels, _ = wa.parse_wevtutil(text, "wevt.txt")
        fnds = wa.audit_channels(channels, "wevt.txt")
        self.assertTrue(any(f["check"] == "channel-mati" and f["severity"] == "high"
                            for f in fnds))

    def test_bersih_tanpa_temuan(self):
        channels, leads = wa.parse_wevtutil(WEVT_OK, "wevt.txt")
        self.assertEqual(leads, [])
        self.assertEqual(wa.audit_channels(channels, "wevt.txt"), [])

    def test_security_absen_info(self):
        text = WEVT_OK.replace("name: Security", "name: System")
        channels, _ = wa.parse_wevtutil(text, "wevt.txt")
        fnds = wa.audit_channels(channels, "wevt.txt")
        self.assertTrue(any(f["check"] == "channel-tak-ditemukan"
                            and f["severity"] == "info" for f in fnds))

    def test_garbage_fail_closed(self):
        channels, leads = wa.parse_wevtutil("tidak ada blok di sini", "wevt.txt")
        self.assertEqual(channels, [])
        self.assertEqual(leads[0]["check"], "file-unparsed")


class TestCLI(unittest.TestCase):
    """Nol jaringan — exit codes + JSON."""

    def _tmp(self, text: str, suffix: str) -> Path:
        import tempfile
        f = Path(tempfile.mkdtemp()) / suffix
        f.write_text(text, encoding="utf-8")
        return f

    def test_exit_high(self):
        f = self._tmp(SAMPLE, "auditpol.csv")
        self.assertEqual(wa.main(["--auditpol", str(f)]), 1)  # audit-mati

    def test_exit_bersih_dengan_fail_on_default(self):
        rows = SAMPLE.replace("No Auditing", "Success")
        f = self._tmp(rows, "auditpol.csv")
        self.assertEqual(wa.main(["--auditpol", str(f)]), 0)

    def test_exit_bersih_wevt(self):
        f = self._tmp(WEVT_OK, "wevt.txt")
        self.assertEqual(wa.main(["--wevtutil", str(f)]), 0)

    def test_exit_input_error(self):
        self.assertEqual(wa.main([]), 2)
        self.assertEqual(wa.main(["--auditpol", "T:/tidak-ada.csv"]), 2)

    def test_json_out(self):
        import tempfile
        jf = Path(tempfile.mkdtemp()) / "out.json"
        f = self._tmp(SAMPLE, "auditpol.csv")
        w = self._tmp(WEVT_SMALL, "wevt.txt")
        self.assertEqual(wa.main(["--auditpol", str(f), "--wevtutil", str(w),
                                  "--json", str(jf)]), 1)
        data = json.loads(jf.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "cyphron.win-audit-coverage/1")
        self.assertEqual(len(data["sources"]), 2)
        self.assertGreater(data["summary"]["medium"], 0)


if __name__ == "__main__":
    unittest.main()
