"""Test F40 — playbook fintech baru (idempotency replay + CSV injection).

NOL jaringan eksternal: lawan uji = tools/lab_target.py di 127.0.0.1
port ephemeral. Yang dikunci:
  - replay-transfer (tier-2): transfer canary dikirim 2x dengan
    idempotency key sama -> diproses 2x (CWE-837) -> L3; safe endpoint
    kontrol menahan replay (409);
  - csv-injection (tier-2): formula canary diekspor mentah (CWE-1236)
    -> L3; export-safe = guard OWASP (prefix kutip);
  - canary SELALU dibersihkan (transfer list kembali kosong, note
    terhapus) — jaminan tier-2 engine;
  - tangga agresi: playbook tier-2 ditolak di mode 'proof' (skip);
  - semua baris lulus kontrak validate_finding.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import exploit_engine as ee  # noqa: E402
import exploit_playbooks as ep  # noqa: E402
import lab_target  # noqa: E402
from findings import validate_finding  # noqa: E402


class LabTestCase(unittest.TestCase):
    """Lab server SATU instance untuk seluruh kelas test."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)

    def _config(self, playbooks, mode="mutate", params=None) -> Path:
        target = {"id": "lab", "base_url": self.base_url,
                  "exploit_allowed": True, "mode": mode,
                  "credentials": {"username": "alice",
                                  "password": "alicepass"},
                  "params": params or {
                      "replay-transfer": {}, "csv-injection": {}}}
        p = Path(tempfile.mkdtemp()) / "exp.json"
        p.write_text(json.dumps({"targets": [target],
                                 "playbooks": playbooks}),
                     encoding="utf-8")
        return p

    def _run(self, playbooks, mode="mutate"):
        out = Path(tempfile.mkdtemp()) / "findings.json"
        ee.main_with_args(["--config", str(self._config(playbooks, mode)),
                           "--out", str(out)])
        return json.loads(out.read_text(encoding="utf-8"))


class TestFintechPlaybooks(LabTestCase):
    """Nol jaringan — dua playbook baru end-to-end via engine."""

    def test_replay_transfer_terbukti_l3(self):
        d = self._run(["replay-transfer"])
        rows = [f for f in d["findings"] if f.get("playbook") ==
                "replay-transfer" and "not proven" not in f.get("title", "")]
        self.assertTrue(rows, "replay harus terbukti di lab vuln")
        f = rows[0]
        self.assertEqual(f["verdict"], 3)
        self.assertEqual(f["cwe"], "CWE-837")
        self.assertGreaterEqual(f["extra"]["occurrences"]
                                if "extra" in f else f["occurrences"], 2)
        self.assertEqual(validate_finding(f), [])

    def test_csv_injection_terbukti_l3(self):
        d = self._run(["csv-injection"])
        rows = [f for f in d["findings"] if f.get("playbook") ==
                "csv-injection" and "not proven" not in f.get("title", "")]
        self.assertTrue(rows, "csv injection harus terbukti di lab vuln")
        f = rows[0]
        self.assertEqual(f["verdict"], 3)
        self.assertEqual(f["cwe"], "CWE-1236")
        self.assertEqual(validate_finding(f), [])

    def test_canary_bersih_setelah_kedua_playbook(self):
        # engine run penuh, lalu verifikasi lab bersih via endpoint publik
        self._run(["replay-transfer", "csv-injection"])
        import urllib.request
        # login lagi utk cek list transfer
        req = urllib.request.Request(
            self.base_url + "/login",
            data=b"username=alice&password=alicepass", method="POST")
        with urllib.request.urlopen(req) as r:
            sid = r.headers.get("Set-Cookie", "").split(";")[0]
        rq = urllib.request.Request(self.base_url + "/api/transfer/list")
        rq.add_header("Cookie", sid)
        with urllib.request.urlopen(rq) as r:
            total = json.loads(r.read().decode())["total"]
        self.assertEqual(total, 0, "canary transfer wajib ter-bersihkan")
        rq2 = urllib.request.Request(self.base_url + "/api/statement/export")
        rq2.add_header("Cookie", sid)
        with urllib.request.urlopen(rq2) as r:
            body = r.read().decode()
        self.assertNotIn("=HYPERLINK", body,
                         "note canary wajib terhapus setelah cleanup")

    def test_tier2_ditolak_di_mode_proof(self):
        # tangga agresi: mode proof menolak playbook tier-2 (skip, bukan run)
        d = self._run(["replay-transfer", "csv-injection"], mode="proof")
        self.assertEqual(d.get("findings", []), [])
        skipped = [t for t in d.get("data", {}).get("targets", [])
                   if t.get("skipped")]
        self.assertEqual(len(skipped), 2)


class TestRegistry(unittest.TestCase):
    """Nol jaringan — registry count + never-list."""

    def test_registry_41_dan_never_list_bersih(self):
        self.assertEqual(len(ep.PLAYBOOKS), 41)
        self.assertIn("replay-transfer", ep.PLAYBOOKS)
        self.assertIn("csv-injection", ep.PLAYBOOKS)
        self.assertIsNone(ep.check_never_list(
            ep.PLAYBOOKS["replay-transfer"]))
        self.assertIsNone(ep.check_never_list(
            ep.PLAYBOOKS["csv-injection"]))


if __name__ == "__main__":
    unittest.main()
