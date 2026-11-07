"""Test tools/session_ledger.py — memori tiga lapis (fakta/intent/recall).

Nol jaringan. Yang dijamin: siklus usul→kerja→tutup, recall berlapis,
fail-closed (fakta tak dikenal, intent dobel tutup, judul kosong), baris
korup dilaporkan bukan diracuni senyap, dan ID berurutan murni dari file.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import session_ledger as ledger  # noqa: E402


class LedgerLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron_ledger_"))
        self.path = self.tmp / "session-ledger.jsonl"

    def test_fact_intent_done_roundtrip(self):
        fact = ledger.add_fact(self.path, "target X merespons 200",
                               summary="permukaan lembut",
                               evidence="status=200; bytes=1204")
        intent = ledger.add_intent(self.path, "jalankan tier0",
                                   from_ids=[fact["id"]])
        self.assertEqual(intent["from"], [fact["id"]])
        self.assertEqual(intent["status"], "open")

        ledger.close_intent(self.path, intent["id"], "done",
                            note="scan selesai")
        report = ledger.recall(self.path, layer="summary")
        intents = [r for r in report["entries"] if r["type"] == "intent"]
        self.assertEqual(intents[0]["status"], "done")
        self.assertEqual(intents[0]["note"], "scan selesai")
        self.assertIsNotNone(intents[0]["done_at"])

    def test_ids_monotonic_from_file(self):
        f1 = ledger.add_fact(self.path, "fakta satu")
        f2 = ledger.add_fact(self.path, "fakta dua")
        self.assertEqual((f1["id"], f2["id"]), ("F001", "F002"))
        # ID dihitung ulang dari isi file — proses baru lanjut benar
        entries, _ = ledger.load_entries(self.path)
        self.assertEqual(ledger.next_id(entries, "F"), "F003")

    def test_intent_sequence_ids(self):
        ledger.add_fact(self.path, "fakta")
        i1 = ledger.add_intent(self.path, "kerja satu")
        i2 = ledger.add_intent(self.path, "kerja dua")
        self.assertEqual((i1["id"], i2["id"]), ("I001", "I002"))


class LayerRecallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron_ledger_"))
        self.path = self.tmp / "ledger.jsonl"
        ledger.add_fact(self.path, "fakta ringkas",
                        summary="ringkasan kalimat",
                        evidence="payload bukti penuh")

    def test_title_layer_hides_evidence(self):
        report = ledger.recall(self.path, layer="title")
        row = report["entries"][0]
        self.assertNotIn("evidence", row)
        self.assertNotIn("summary", row)
        self.assertEqual(row["title"], "fakta ringkas")

    def test_summary_layer_has_no_evidence(self):
        row = ledger.recall(self.path, layer="summary")["entries"][0]
        self.assertEqual(row["summary"], "ringkasan kalimat")
        self.assertNotIn("evidence", row)

    def test_evidence_layer_full(self):
        row = ledger.recall(self.path, layer="evidence")["entries"][0]
        self.assertEqual(row["evidence"], "payload bukti penuh")

    def test_status_filter_open_only(self):
        ledger.add_fact(self.path, "fakta dua")
        intent = ledger.add_intent(self.path, "kerja", from_ids=["F001"])
        ledger.close_intent(self.path, intent["id"], "done")
        rows = ledger.recall(self.path, layer="summary",
                             status="open")["entries"]
        self.assertEqual(rows, [])
        rows = ledger.recall(self.path, layer="summary",
                             status="done")["entries"]
        self.assertEqual([r["id"] for r in rows], [intent["id"]])


class FailClosedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron_ledger_"))
        self.path = self.tmp / "ledger.jsonl"

    def test_intent_from_unknown_fact_rejected(self):
        with self.assertRaises(ValueError):
            ledger.add_intent(self.path, "kerja melayang",
                              from_ids=["F999"])

    def test_empty_title_rejected(self):
        with self.assertRaises(ValueError):
            ledger.add_fact(self.path, "   ")

    def test_double_close_rejected(self):
        ledger.add_fact(self.path, "fakta")
        intent = ledger.add_intent(self.path, "kerja", from_ids=["F001"])
        ledger.close_intent(self.path, intent["id"], "done")
        with self.assertRaises(ValueError):
            ledger.close_intent(self.path, intent["id"], "done")

    def test_close_unknown_intent_rejected(self):
        with self.assertRaises(ValueError):
            ledger.close_intent(self.path, "I999", "done")

    def test_bad_close_status_rejected(self):
        with self.assertRaises(ValueError):
            ledger.close_intent(self.path, "I001", "selesai-kok")


class CorruptLineTest(unittest.TestCase):
    def test_corrupt_reported_not_crashed(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron_ledger_"))
        self.path = self.tmp / "ledger.jsonl"
        ledger.add_fact(self.path, "fakta sehat")
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write("{ini bukan json\n")
            fh.write(json.dumps({"type": "misteri"}) + "\n")  # tanpa field wajib? type ada
        entries, corrupt = ledger.load_entries(self.path)
        self.assertEqual(len(entries), 2)  # fakta + entri misteri tetap terbaca
        self.assertEqual(len(corrupt), 1)
        self.assertIn("ini bukan json", corrupt[0])
        # recall tetap jalan dan melaporkan baris korup
        report = ledger.recall(self.path, layer="title")
        self.assertEqual(len(report["corrupt_lines"]), 1)


class LedgerIsJsonlTest(unittest.TestCase):
    def test_file_is_appendable_jsonl(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron_ledger_"))
        self.path = self.tmp / "ledger.jsonl"
        ledger.add_fact(self.path, "satu")
        ledger.add_fact(self.path, "dua")
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["title"], "satu")


if __name__ == "__main__":
    unittest.main()
