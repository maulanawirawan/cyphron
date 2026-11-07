"""Nol jaringan — test verify_gate (klaim butuh bukti fresh, fail-closed)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import verify_gate  # noqa: E402

PY = sys.executable or "python"


class TestAsArgv(unittest.TestCase):
    """Nol jaringan — normalisasi cmd ke argv."""

    def test_list_diterima(self):
        self.assertEqual(verify_gate._as_argv(["python", "-q"]), ["python", "-q"])

    def test_string_di_split(self):
        self.assertEqual(verify_gate._as_argv("python -m pytest -q"),
                         ["python", "-m", "pytest", "-q"])

    def test_list_kosong_ditolak(self):
        with self.assertRaises(ValueError):
            verify_gate._as_argv([])

    def test_string_kosong_ditolak(self):
        with self.assertRaises(ValueError):
            verify_gate._as_argv("   ")


class TestLoadGate(unittest.TestCase):
    """Nol jaringan — validasi gate file (fail-closed)."""

    def _write(self, data) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data) if not isinstance(data, str) else data)
        self.addCleanup(Path(path).unlink, missing_ok=True)
        return path

    def test_gate_valid(self):
        p = self._write({"claim": "x hijau", "checks": [
            {"name": "c1", "cmd": f'"{PY}" -c "pass"'}]})
        gate = verify_gate.load_gate(p)
        self.assertEqual(gate["claim"], "x hijau")
        self.assertEqual(len(gate["checks"]), 1)

    def test_tanpa_checks_ditolak(self):
        p = self._write({"claim": "x"})
        with self.assertRaises(ValueError):
            verify_gate.load_gate(p)

    def test_checks_kosong_ditolak(self):
        p = self._write({"claim": "x", "checks": []})
        with self.assertRaises(ValueError):
            verify_gate.load_gate(p)

    def test_tanpa_claim_ditolak(self):
        p = self._write({"checks": [{"name": "c", "cmd": "true"}]})
        with self.assertRaises(ValueError):
            verify_gate.load_gate(p)

    def test_cek_tanpa_cmd_ditolak(self):
        p = self._write({"claim": "x", "checks": [{"name": "c"}]})
        with self.assertRaises(ValueError):
            verify_gate.load_gate(p)

    def test_json_rusak_ditolak(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("{bukan json")
        self.addCleanup(Path(path).unlink, missing_ok=True)
        with self.assertRaises(ValueError):
            verify_gate.load_gate(path)

    def test_file_tidak_ada(self):
        with self.assertRaises(FileNotFoundError):
            verify_gate.load_gate("Z:/pastinya/tidak/ada.json")

    def test_regex_tidak_valid_ditolak(self):
        p = self._write({"claim": "x", "checks": [
            {"name": "c", "cmd": "true", "expect_regex": "(["}]})
        with self.assertRaises(ValueError):
            verify_gate.load_gate(p)

    def test_timeout_invalid_ditolak(self):
        p = self._write({"claim": "x", "checks": [
            {"name": "c", "cmd": "true", "timeout_sec": 0}]})
        with self.assertRaises(ValueError):
            verify_gate.load_gate(p)


class TestRunGate(unittest.TestCase):
    """Nol jaringan — eksekusi gate dengan perintah lokal, tanpa jaringan."""

    def test_verified(self):
        gate = {"claim": "python lulus", "checks": [
            {"name": "sanity", "cmd": [PY, "-c", "print('OK 5 passed')"],
             "expect_regex": r"\d+ passed"}]}
        ev = verify_gate.run_gate(gate)
        self.assertEqual(ev["verdict"], verify_gate.VERDICT_VERIFIED)
        self.assertEqual(ev["checks_passed"], 1)

    def test_fail_exit_code(self):
        gate = {"claim": "x", "checks": [
            {"name": "gagal", "cmd": [PY, "-c", "import sys; sys.exit(3)"]}]}
        ev = verify_gate.run_gate(gate)
        self.assertEqual(ev["verdict"], verify_gate.VERDICT_BLOCKED)
        self.assertIn("exit_code 3", ev["blocked_by"][0]["failures"][0])

    def test_fail_regex(self):
        gate = {"claim": "x", "checks": [
            {"name": "reg", "cmd": [PY, "-c", "print('tanpa marker')"],
             "expect_regex": "MARKER-WAJIB"}]}
        ev = verify_gate.run_gate(gate)
        self.assertEqual(ev["verdict"], verify_gate.VERDICT_BLOCKED)

    def test_fail_timeout(self):
        gate = {"claim": "x", "checks": [
            {"name": "lama", "cmd": [PY, "-c", "import time; time.sleep(3)"],
             "timeout_sec": 0.5}]}
        ev = verify_gate.run_gate(gate)
        self.assertEqual(ev["verdict"], verify_gate.VERDICT_BLOCKED)
        self.assertIn("timeout", ev["blocked_by"][0]["failures"][0])

    def test_fail_perintah_tak_ada(self):
        gate = {"claim": "x", "checks": [
            {"name": "hilang",
             "cmd": [PY, "-c", "import sys; sys.exit(0)"],
             "timeout_sec": 5}]}
        # executable tak ada: pakai nama yang pasti gagal di semua OS
        gate["checks"][0]["cmd"] = ["cyphron-tidak-ada-exec-xyz"]
        ev = verify_gate.run_gate(gate)
        self.assertEqual(ev["verdict"], verify_gate.VERDICT_BLOCKED)

    def test_gate_tanpa_cek_fail_closed(self):
        ev = verify_gate.run_gate({"claim": "x", "checks": []})
        self.assertEqual(ev["verdict"], verify_gate.VERDICT_BLOCKED)
        self.assertIn("tanpa cek", ev["blocked_by"][0]["failures"][0])

    def test_satu_gagal_dari_dua(self):
        gate = {"claim": "x", "checks": [
            {"name": "lulus", "cmd": [PY, "-c", "pass"]},
            {"name": "gagal", "cmd": [PY, "-c", "import sys; sys.exit(1)"]}]}
        ev = verify_gate.run_gate(gate)
        self.assertEqual(ev["verdict"], verify_gate.VERDICT_BLOCKED)
        self.assertEqual(ev["checks_passed"], 1)

    def test_semua_cek_dijalankan_tanpa_short_circuit(self):
        # cek pertama gagal; cek kedua TETAP dijalankan (bukti utuh).
        calls = []
        gate = {"claim": "x", "checks": [
            {"name": "gagal", "cmd": [PY, "-c", "import sys; sys.exit(9)"]},
            {"name": "lulus", "cmd": [PY, "-c", "pass"]}]}
        ev = verify_gate.run_gate(gate)
        for r in ev["results"]:
            calls.append(r["status"])
        self.assertEqual(calls, ["fail", "pass"])


class TestArtifacts(unittest.TestCase):
    """Nol jaringan — bukti artefak harus fresh (mtime >= mulai run)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(
            lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_artifact_fresh_lulus(self):
        art = Path(self.tmp) / "bukti.txt"
        art.write_text("evidence", encoding="utf-8")
        start = time.time() - 60  # run "dimulai" 60 detik lalu
        ok, bad = verify_gate._check_artifacts([str(art)], start, Path.cwd())
        self.assertEqual(bad, [])

    def test_artifact_stale_gagal(self):
        art = Path(self.tmp) / "lama.txt"
        art.write_text("lama", encoding="utf-8")
        past = time.time() - 3600
        os.utime(art, (past, past))
        ok, bad = verify_gate._check_artifacts([str(art)], time.time() - 60,
                                               Path.cwd())
        self.assertTrue(any("basi" in b for b in bad))

    def test_artifact_hilang_gagal(self):
        ok, bad = verify_gate._check_artifacts(
            [str(Path(self.tmp) / "tidak-ada.txt")], time.time(), Path.cwd())
        self.assertTrue(any("tidak ada" in b for b in bad))

    def test_artifact_dalam_gate(self):
        # artefak WAJIB ditulis oleh cek di dalam run yang sama — file yang
        # dibuat sebelum run = bukti basi (by design, lihat test_stale).
        art = Path(self.tmp) / "gate-art.txt"
        gate = {"claim": "x", "checks": [
            {"name": "tulis bukti",
             "cmd": [PY, "-c",
                     f"open(r'{art}', 'w', encoding='utf-8').write('fresh')"],
             "timeout_sec": 30},
            {"name": "verifikasi bukti", "cmd": [PY, "-c", "pass"],
             "artifacts": [str(art)]}]}
        ev = verify_gate.run_gate(gate)
        self.assertEqual(ev["verdict"], verify_gate.VERDICT_VERIFIED)


class TestCli(unittest.TestCase):
    """Nol jaringan — CLI mode cepat dan gate file."""

    def test_mode_cepat_verified_exit0(self):
        rc = verify_gate.main(["--claim", "sanity", "--cmd",
                               f'"{PY}" -c "print(\'2 passed\')"',
                               "--expect-regex", r"\d+ passed"])
        self.assertEqual(rc, 0)

    def test_mode_cepat_blocked_exit1(self):
        rc = verify_gate.main(["--claim", "gagal", "--cmd",
                               f'"{PY}" -c "import sys; sys.exit(1)"'])
        self.assertEqual(rc, 1)

    def test_claim_tanpa_cmd_exit2(self):
        rc = verify_gate.main(["--claim", "tanpa perintah"])
        self.assertEqual(rc, 2)

    def test_gate_tulis_out(self):
        fd, out = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(Path(out).unlink, missing_ok=True)
        rc = verify_gate.main(["--claim", "tulis", "--cmd",
                               f'"{PY}" -c "pass"', "--out", out])
        self.assertEqual(rc, 0)
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "cyphron.verify-gate/1")
        self.assertEqual(data["verdict"], "VERIFIED")

    def test_gate_invalid_exit2(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("{}")
        self.addCleanup(Path(path).unlink, missing_ok=True)
        rc = verify_gate.main(["--gate", path])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
