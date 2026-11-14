"""Test unquoted_service_path_triage — NOL jaringan, dump di-mock.

Kontrak yang dikunci:
  - unquoted path ber-spasi (exe token pertama bukan .exe) -> temuan
    medium dgn chain kandidat deterministik (T1574.009);
  - svchost.exe -k netsvcs (spasi di ARGUMEN) -> BUKAN temuan (zero-FP);
  - path terkutip -> bukan temuan; %var% ber-spasi -> info saja;
  - format JSON array + teks sc qc (BINARY_PATH_NAME) keduanya terparse;
  - fail-closed: tanpa entri service -> exit 2 via main.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import unquoted_service_path_triage as us  # noqa: E402

SC_QC = """SERVICE_NAME: Sysmon64
        BINARY_PATH_NAME : C:\\Program Files (x86)\\Sysinternals\\Sysmon64.exe

SERVICE_NAME: BackupSvc
        BINARY_PATH_NAME : C:\\Program Files\\BackupSvc\\bin\\svc.exe
"""

VULN_JSON = [
    {"Name": "Good", "ImagePath": '"C:\\Program Files\\Good\\svc.exe" -q'},
    {"Name": "ArgsOnly", "BinaryPathName":
        "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
    {"Name": "Expand", "ImagePath": "%ProgramFiles%\\Some App\\svc.exe"},
    {"Name": "VulnSvc", "ImagePath":
        "C:\\Program Files\\Vuln One\\agent\\svc.exe"},
]


class UnquotedServicePathTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = us.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_sc_qc_text_unquoted_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SC_QC)
            self.assertEqual(d["finding_count"], 2)
            self.assertEqual(d["severity_counts"]["medium"], 2)
            names = {f["name"] for f in d["findings"]}
            self.assertEqual(names, {"Sysmon64", "BackupSvc"})
            f = next(f for f in d["findings"] if f["name"] == "Sysmon64")
            self.assertEqual(f["chain"][0], "C:\\Program.exe")
            self.assertTrue(f["chain"][0].lower().endswith(".exe"))
            self.assertTrue(d["read_only"])

    def test_json_args_space_is_not_a_finding(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), json.dumps(VULN_JSON))
            self.assertEqual(d["finding_count"], 1)
            self.assertEqual(d["findings"][0]["name"], "VulnSvc")
            self.assertEqual(d["findings"][0]["signal"], "unquoted-space")
            self.assertEqual(len(d["findings"][0]["chain"]), 2)
            self.assertEqual(d["info_count"], 1)  # %var%
            self.assertEqual(d["services"], 4)

    def test_quoted_and_no_space_clean(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), json.dumps(VULN_JSON))
            names = {f["name"] for f in d["findings"]}
            self.assertNotIn("Good", names)
            self.assertNotIn("ArgsOnly", names)

    def test_chain_stops_at_real_exe(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(
                'ImagePath : C:\\Program Files\\X\\svc.exe -flag\n',
                encoding="utf-8")
            d = self._run(Path(td), src.read_text(encoding="utf-8"))
            self.assertEqual(d["finding_count"], 1)
            chain = d["findings"][0]["chain"]
            self.assertEqual(chain, ["C:\\Program.exe"])

    def test_fail_closed_no_services(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text("halaman web biasa\ntanpa service\n", encoding="utf-8")
            rc = us.main(["--file", str(src)])
            self.assertEqual(rc, 2)

    def test_fail_closed_missing_file(self):
        rc = us.main(["--file", str(Path("tidak/ada/svc.json"))])
        self.assertEqual(rc, 2)

    def test_ndjson_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            lines = "\n".join(json.dumps(e) for e in VULN_JSON)
            d = self._run(Path(td), lines)
            self.assertEqual(d["finding_count"], 1)
            self.assertEqual(d["findings"][0]["name"], "VulnSvc")


if __name__ == "__main__":
    unittest.main(verbosity=1)
