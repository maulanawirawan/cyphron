"""Test vm_artifact_triage — NOL jaringan, dump di-mock.

Kontrak yang dikunci:
  - dump dropper dgn cek anti-VM (proses guest + hypervisor brand + MAC
    prefix + tool analisis) terskor high;
  - zero-FP: script deploy normal tanpa artefak -> 0 sinyal, clean;
  - tiap sinyal deterministik (vm-process/vm-driver/vm-registry/
    hypervisor-brand/mac-prefix-check/analysis-tool/sandbox-path);
  - fail-closed: dump < 32 char -> exit 2 via main; file hilang -> 2.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vm_artifact_triage as va  # noqa: E402

DROPPER = r"""
$guest = Get-Process vmtoolsd,VBoxService,qemu-ga -ErrorAction SilentlyContinue
if ($guest) { Start-Sleep -Seconds 9999; exit }
$brands = "VMwareVMware","KVMKVMKVM","XenVMMXenVMM","Microsoft Hv"
foreach ($b in $brands) { if ($cpuidOut -eq $b) { exit } }
$mac = (Get-NetAdapter).MacAddress
if ($mac -like "00:0C:29*" -or $mac -like "08:00:27*") { exit }
$drv = Get-Service vmci,vmhgfs,vboxguest,vboxsf,vmmouse -ErrorAction SilentlyContinue
if ($drv) { exit }
if (Test-Path "C:\cuckoo") { exit }
if (Test-Path "C:\analysis\sample") { exit }
if (Get-Process wireshark,procmon,x64dbg -ErrorAction SilentlyContinue) { exit }
 reg query "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions"
"""

DRIVER_ONLY = r"""
Windows build check for service install of vmci.sys and vmmouse.sys
drivers on the guest machine image used by the deployment pipeline.
"""

CLEAN = """
This deployment script installs the web application into IIS,
starts the application pool, configures the health probe endpoint,
rotates the log files, and registers a scheduled task for cleanup.
Nothing unusual lives in this file, and no environment detection
of any kind is performed here.
"""


class VmArtifactTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = va.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_dropper_scores_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), DROPPER)
            self.assertEqual(d["severity"], "high")
            self.assertGreaterEqual(d["score"], 4)
            for sig in ("vm-process", "hypervisor-brand", "mac-prefix-check",
                        "vm-driver", "sandbox-path", "analysis-tool"):
                self.assertIn(sig, d["signals"])
            self.assertTrue(d["read_only"])
            self.assertIn("vm-process", d["evidence"])

    def test_driver_only_medium(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), DRIVER_ONLY)
            self.assertEqual(d["signals"], ["vm-driver"])
            self.assertEqual(d["severity"], "low")
            self.assertEqual(d["score"], 1)

    def test_zero_fp_clean_script(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CLEAN)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["signals"], [])
            self.assertEqual(d["finding_count"], 0)

    def test_fail_closed_short_dump(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text("pendek\n", encoding="utf-8")
            rc = va.main(["--file", str(src)])
            self.assertEqual(rc, 2)

    def test_fail_closed_missing_file(self):
        rc = va.main(["--file", str(Path("tidak/ada/str.txt"))])
        self.assertEqual(rc, 2)

    def test_stdout_json_valid(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(DROPPER, encoding="utf-8")
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                rc = va.main(["--file", str(src)])
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            d = json.loads(buf.getvalue())
            self.assertEqual(d["schema"], va.SCHEMA)


if __name__ == "__main__":
    unittest.main(verbosity=1)
