"""Nol jaringan — test fleet_dispatch (worker pool, fail-closed per job)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fleet_dispatch as fd  # noqa: E402

PY = sys.executable or "python"


class TestLoadJobs(unittest.TestCase):
    """Nol jaringan — validasi job file."""

    def _write(self, data) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with open(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data) if not isinstance(data, str) else data)
        self.addCleanup(Path(path).unlink, missing_ok=True)
        return path

    def test_valid(self):
        p = self._write({"jobs": [{"id": "a", "cmd": [PY, "-c", "pass"]}]})
        jobs = fd.load_jobs(p)
        self.assertEqual(jobs["workers"], min(4, fd.os.cpu_count() or 4))
        self.assertEqual(len(jobs["jobs"]), 1)

    def test_kosong_ditolak(self):
        p = self._write({"jobs": []})
        with self.assertRaises(ValueError):
            fd.load_jobs(p)

    def test_duplikat_id_ditolak(self):
        p = self._write({"jobs": [{"id": "a", "cmd": [PY]},
                                  {"id": "a", "cmd": [PY]}]})
        with self.assertRaises(ValueError):
            fd.load_jobs(p)

    def test_cmd_bukan_list_ditolak(self):
        p = self._write({"jobs": [{"id": "a", "cmd": "python -c pass"}]})
        with self.assertRaises(ValueError):
            fd.load_jobs(p)

    def test_workers_out_of_range(self):
        p = self._write({"jobs": [{"id": "a", "cmd": [PY]}], "workers": 99})
        with self.assertRaises(ValueError):
            fd.load_jobs(p)

    def test_file_tak_ada(self):
        with self.assertRaises(FileNotFoundError):
            fd.load_jobs("Z:/tidak/ada.json")


class TestDispatch(unittest.TestCase):
    """Nol jaringan — eksekusi paralel dengan perintah lokal."""

    def test_semua_ok(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: None)
        out1, out2 = tmp / "o1.json", tmp / "o2.json"
        jobs = {"workers": 2, "jobs": [
            {"id": "j1", "cmd": [PY, "-c",
                                 f"open(r'{out1}', 'w').write('x')"],
             "outputs": [str(out1)]},
            {"id": "j2", "cmd": [PY, "-c",
                                 f"open(r'{out2}', 'w').write('x')"],
             "outputs": [str(out2)]}]}
        res = fd.dispatch(jobs, tmp / "fleet")
        self.assertEqual(res["ok"], 2)
        self.assertEqual(res["failed"], 0)
        self.assertTrue((tmp / "fleet" / "ledger.json").is_file())

    def test_satu_gagal_tidak_membunuh_fleet(self):
        tmp = Path(tempfile.mkdtemp())
        out = tmp / "ok.json"
        jobs = {"workers": 2, "jobs": [
            {"id": "gagal", "cmd": [PY, "-c", "import sys; sys.exit(3)"]},
            {"id": "lulus", "cmd": [PY, "-c",
                                    f"open(r'{out}', 'w').write('x')"],
             "outputs": [str(out)]}]}
        res = fd.dispatch(jobs, tmp / "fleet")
        by_id = {e["id"]: e for e in res["ledger"]}
        self.assertEqual(by_id["gagal"]["status"], "FAIL")
        self.assertEqual(by_id["lulus"]["status"], "OK")
        self.assertEqual(res["ok"], 1)
        self.assertEqual(res["failed"], 1)

    def test_output_hilang_fail(self):
        tmp = Path(tempfile.mkdtemp())
        jobs = {"workers": 1, "jobs": [
            {"id": "j", "cmd": [PY, "-c", "pass"],  # sukses tapi tanpa output
             "outputs": [str(tmp / "hilang.json")]}]}
        res = fd.dispatch(jobs, tmp / "fleet")
        self.assertEqual(res["ledger"][0]["status"], "FAIL")
        self.assertIn("output hilang", res["ledger"][0]["reason"])

    def test_timeout_fail(self):
        tmp = Path(tempfile.mkdtemp())
        jobs = {"workers": 1, "jobs": [
            {"id": "lama", "cmd": [PY, "-c", "import time; time.sleep(5)"],
             "timeout_sec": 0.5}]}
        res = fd.dispatch(jobs, tmp / "fleet")
        self.assertEqual(res["ledger"][0]["status"], "FAIL")
        self.assertIn("timeout", res["ledger"][0]["reason"])

    def test_log_per_job_tersimpan(self):
        tmp = Path(tempfile.mkdtemp())
        jobs = {"workers": 1, "jobs": [
            {"id": "dgn-log", "cmd": [PY, "-c", "print('hello-fleet')"]}]}
        res = fd.dispatch(jobs, tmp / "fleet")
        log = Path(res["ledger"][0]["log"])
        self.assertTrue(log.is_file())
        self.assertIn("hello-fleet", log.read_text(encoding="utf-8"))


class TestCli(unittest.TestCase):
    """Nol jaringan — CLI."""

    def test_job_file_invalid_exit2(self):
        fd2, path = tempfile.mkstemp(suffix=".json")
        with open(fd2, "w", encoding="utf-8") as f:
            f.write("{}")
        self.addCleanup(Path(path).unlink, missing_ok=True)
        rc = fd.main(["--jobs", path, "--out-dir",
                      tempfile.mkdtemp()])
        self.assertEqual(rc, 2)

    def test_cli_end_to_end(self):
        tmp = Path(tempfile.mkdtemp())
        jf = tmp / "jobs.json"
        out = tmp / "result.json"
        jf.write_text(json.dumps({"jobs": [
            {"id": "a", "cmd": [PY, "-c",
                                f"open(r'{out}', 'w').write('x')"],
             "outputs": [str(out)]}]}), encoding="utf-8")
        rc = fd.main(["--jobs", str(jf), "--out-dir", str(tmp / "fleet")])
        self.assertEqual(rc, 0)
        ledger = json.loads((tmp / "fleet" / "ledger.json").read_text(
            encoding="utf-8"))
        self.assertEqual(ledger["ok"], 1)


if __name__ == "__main__":
    unittest.main()
