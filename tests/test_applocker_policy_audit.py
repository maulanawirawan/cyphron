"""Nol jaringan — test applocker_policy_audit (policy XML + CSV event).

Fixture dibangun inline mengikuti struktur policy AppLocker (RuleCollection/
EnforcementMode/FilePathCondition) dan export CSV event audit-mode ala
Get-WinEvent ... Export-Csv. Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("tools",):
    sys.path.insert(0, str(ROOT / sub))

import applocker_policy_audit as apa  # noqa: E402

TOOL = ROOT / "tools" / "applocker_policy_audit.py"


def _collection(rules_xml: str, ctype: str = "Exe",
                mode: str = "Enforced") -> str:
    return (f'<RuleCollection Type="{ctype}" EnforcementMode="{mode}">'
            f"{rules_xml}</RuleCollection>")


def _policy(*collections: str) -> str:
    return ('<AppLockerPolicy Version="1">'
            + "".join(collections) + "</AppLockerPolicy>")


RULE_SAFE = ('<FilePathRule Id="1" Name="Allow PF" Action="Allow"'
             ' UserOrGroupSid="S-1-1-0"><Conditions>'
             '<FilePathCondition Path="C:\\Program Files\\*"/>'
             '</Conditions></FilePathRule>')

RULE_TEMP = ('<FilePathRule Id="2" Name="Allow temp" Action="Allow"'
             ' UserOrGroupSid="S-1-1-0"><Conditions>'
             '<FilePathCondition Path="%TEMP%\\*"/>'
             '</Conditions></FilePathRule>')

RULE_DENY_MSHTA = ('<FilePathRule Id="3" Name="Deny mshta" Action="Deny"'
                   ' UserOrGroupSid="S-1-5-32-545"><Conditions>'
                   '<FilePathCondition Path="%SYSTEM32%\\mshta.exe"/>'
                   '</Conditions></FilePathRule>')


class TestPolicyChecks(unittest.TestCase):
    def _audit(self, xml: str):
        findings: list[dict] = []
        notes: list[str] = []
        summary = apa.audit_policy(xml, findings, notes)
        return findings, summary, notes

    def test_policy_baik_bersih(self):
        """Enforced + path aman + deny LOLBin lengkap -> hanya lolbin lain."""
        xml = _policy(_collection(RULE_SAFE + RULE_DENY_MSHTA))
        findings, summary, notes = self._audit(xml)
        checks = [f["check"] for f in findings]
        self.assertNotIn("policy-audit-mode", checks)
        self.assertNotIn("allow-user-writable", checks)
        self.assertNotIn("exe-collection-absent", checks)
        # mshta sudah di-deny; LOLBin lain tetap dicatat (deterministik)
        self.assertIn("lolbin-deny-missing", checks)
        self.assertEqual(summary["rules"], 2)
        self.assertTrue(any("mshta.exe" in n for n in notes))

    def test_audit_mode_medium(self):
        xml = _policy(_collection(RULE_SAFE, mode="AuditOnly"))
        findings, _, _ = self._audit(xml)
        entry = [f for f in findings if f["check"] == "policy-audit-mode"]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["severity"], "medium")
        self.assertIn("AuditOnly", entry[0]["subject"])

    def test_exe_absen_high(self):
        xml = _policy(_collection(RULE_SAFE, ctype="Script"))
        findings, _, _ = self._audit(xml)
        checks = [f["check"] for f in findings]
        self.assertIn("exe-collection-absent", checks)
        absent = [f for f in findings if f["check"] == "exe-collection-absent"]
        self.assertEqual(absent[0]["severity"], "high")

    def test_ruleset_empty_medium(self):
        xml = _policy(_collection(""))
        findings, _, _ = self._audit(xml)
        checks = [f["check"] for f in findings]
        self.assertIn("ruleset-empty", checks)

    def test_allow_user_writable_varian_path(self):
        for path, hit in (("%APPDATA%\\*", True),
                          ("C:\\Users\\*\\Downloads\\*", True),
                          ("%LOCALAPPDATA%\\Temp\\*", True),
                          ("C:\\Program Files\\App\\*", False),
                          ("%WINDIR%\\*", False)):
            rule = ('<FilePathRule Id="9" Name="r" Action="Allow"'
                    ' UserOrGroupSid="S-1-1-0"><Conditions>'
                    f'<FilePathCondition Path="{path}"/>'
                    '</Conditions></FilePathRule>')
            xml = _policy(_collection(rule))
            findings, _, _ = self._audit(xml)
            self.assertEqual(
                "allow-user-writable" in [f["check"] for f in findings],
                hit, f"path {path}")

    def test_xml_invalid_raise(self):
        with self.assertRaises(ValueError):
            self._audit("<bukan-policy>")

    def test_xml_tanpa_rulecollection_raise(self):
        with self.assertRaises(ValueError):
            self._audit("<GPO><Something/></GPO>")


def _write_csv(path: Path, rows: list[list[str]],
               header: list[str] | None = None) -> None:
    head = header or ["TimeCreated", "User", "FilePath", "FileHash"]
    lines = [",".join(head)]
    for r in rows:
        lines.append(",".join(r))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestEventChecks(unittest.TestCase):
    def test_userwritable_exec_high(self):
        findings: list[dict] = []
        notes: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ev.csv"
            _write_csv(p, [
                ["2025-01-01T00:00:00", "bob",
                 "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe",
                 "AAAA1111BBBB2222"],
                ["2025-01-01T00:01:00", "bob",
                 "C:\\Windows\\System32\\cmd.exe", "CCCC3333"],
            ])
            summary = apa.audit_events(p, findings, notes, 5, 2)
        checks = [f["check"] for f in findings]
        self.assertIn("audit-userwritable-exec", checks)
        hit = [f for f in findings
               if f["check"] == "audit-userwritable-exec"]
        self.assertEqual(hit[0]["severity"], "high")
        self.assertEqual(summary["userwritable_files"], 1)
        self.assertEqual(summary["csv_rows_skipped"], 0)

    def test_hot_dir_medium_dan_kandidat_info(self):
        findings: list[dict] = []
        notes: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ev.csv"
            rows = [["2025-01-01T00:00:00", "bob",
                     "C:\\Program Files\\Vendor\\app.exe", "H%d" % i]
                    for i in range(6)]
            _write_csv(p, rows)
            apa.audit_events(p, findings, notes, 5, 2)
        checks = [f["check"] for f in findings]
        self.assertIn("audit-hot-dir", checks)
        self.assertIn("audit-block-candidate", checks)

    def test_header_case_insensitive(self):
        findings: list[dict] = []
        notes: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ev.csv"
            _write_csv(p, [["u", "C:\\Users\\x\\Desktop\\tool.exe", "Z1"]],
                       header=["user", "file path", "hash"])
            apa.audit_events(p, findings, notes, 5, 2)
        self.assertTrue(any(f["check"] == "audit-userwritable-exec"
                            for f in findings))

    def test_tanpa_kolom_filepath_raise(self):
        findings: list[dict] = []
        notes: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ev.csv"
            _write_csv(p, [["a", "b"]], header=["foo", "bar"])
            with self.assertRaises(ValueError):
                apa.audit_events(p, findings, notes, 5, 2)

    def test_baris_kosong_dihitung_skipped(self):
        findings: list[dict] = []
        notes: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ev.csv"
            _write_csv(p, [["", "", "", ""],
                           ["u", "C:\\Windows\\notepad.exe", "H"]])
            summary = apa.audit_events(p, findings, notes, 5, 2)
        self.assertEqual(summary["csv_rows_skipped"], 1)


class TestCli(unittest.TestCase):
    def test_tanpa_input_exit_2(self):
        r = subprocess.run([sys.executable, str(TOOL)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_policy_valid_exit_dan_json(self):
        with tempfile.TemporaryDirectory() as td:
            xml = Path(td) / "policy.xml"
            xml.write_text(_policy(_collection(RULE_TEMP)), encoding="utf-8")
            out = Path(td) / "hasil.json"
            r = subprocess.run([sys.executable, str(TOOL), "--policy",
                                str(xml), "--json", str(out)],
                               capture_output=True, text=True)
            self.assertIn(r.returncode, (0, 1))
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["kind"], "applocker-policy-audit")
            self.assertIn("attribution", doc)
            checks = [f["check"] for f in doc["findings"]]
            self.assertIn("allow-user-writable", checks)
            # CSV tidak diberikan -> notes eksplisit, bukan diam-diam
            self.assertTrue(any("CSV event tidak diberikan" in n
                                for n in doc["notes"]))

    def test_fail_on_high_mengabaikan_medium(self):
        """Policy bersih dgn hanya lolbin-missing (medium) -> fail-on high
        exit 0."""
        with tempfile.TemporaryDirectory() as td:
            xml = Path(td) / "policy.xml"
            denies = "".join(
                '<FilePathRule Id="%d" Name="deny%d" Action="Deny"'
                ' UserOrGroupSid="S-1-5-32-545"><Conditions>'
                '<FilePathCondition Path="%%SYSTEM32%%\\%s"/>'
                '</Conditions></FilePathRule>'
                % (10 + i, i, b)
                for i, b in enumerate(apa.LOLBIN_DENY_CANDIDATES))
            xml.write_text(_policy(_collection(RULE_SAFE + denies)),
                           encoding="utf-8")
            r = subprocess.run([sys.executable, str(TOOL), "--policy",
                                str(xml), "--fail-on", "high"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
