"""Nol jaringan — test log_chain_verify (ledger hash-chain tamper-evident)."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import log_chain_verify as lcv  # noqa: E402


def _entries(ledger: Path) -> "list[dict]":
    out = []
    for raw in ledger.read_text(encoding="utf-8").splitlines():
        obj = json.loads(raw)
        if obj.get("type") == "ledger":
            continue
        out.append(obj)
    return out


class LogChainVerifyTest(unittest.TestCase):

    def _mklog(self, td: Path, name: str, lines: "list[str]") -> Path:
        p = td / name
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def test_chain_then_verify_clean(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "app.log",
                              ["2026-11-08 INFO start",
                               "2026-11-08 WARN retry",
                               "2026-11-08 INFO ok"])
            led = tdp / "l.jsonl"
            self.assertEqual(lcv.main(
                ["chain", "--logs", str(log), "--out", str(led)]), 0)
            ents = _entries(led)
            self.assertEqual(len(ents), 3)
            self.assertEqual(ents[0]["prev_hash"], lcv.GENESIS)
            code = lcv.main(["verify", "--ledger", str(led)])
            self.assertEqual(code, 0)

    def test_chain_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["x", "y"])
            led1 = tdp / "l1.jsonl"
            led2 = tdp / "l2.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led1)])
            lcv.main(["chain", "--logs", str(log), "--out", str(led2)])
            e1 = [(e["content_hash"], e["chain_hash"])
                  for e in _entries(led1)]
            e2 = [(e["content_hash"], e["chain_hash"])
                  for e in _entries(led2)]
            self.assertEqual(e1, e2)
            # formula eksplisit: sha256(prev|content)
            self.assertEqual(e1[1][1], hashlib.sha256(
                f"{e1[0][1]}|{e1[1][0]}".encode("ascii")).hexdigest())

    def test_chain_hash_break_pinpointed(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["one", "two", "three"])
            led = tdp / "l.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led)])
            ents = _entries(led)
            ents[1]["content_hash"] = "0" * 64  # entri tengah diubah
            raw = json.dumps({"schema": lcv.SCHEMA, "type": "ledger",
                              "entries": 3}) + "\n" + \
                "\n".join(json.dumps(e) for e in ents) + "\n"
            led.write_text(raw, encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = lcv.main(["verify", "--ledger", str(led)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
            rep = json.loads(buf.getvalue())
            self.assertEqual(rep["first_break"], 1)
            self.assertIn("chain-hash-break",
                          {f["check"] for f in rep["findings"]})

    def test_prev_hash_break_detected(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["a", "b"])
            led = tdp / "l.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led)])
            ents = _entries(led)
            ents[1]["prev_hash"] = "f" * 64
            led.write_text(json.dumps({"schema": lcv.SCHEMA,
                                       "type": "ledger"}) + "\n" +
                           "\n".join(json.dumps(e) for e in ents) + "\n",
                           encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = lcv.main(["verify", "--ledger", str(led)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
            checks = {f["check"] for f in json.loads(buf.getvalue())[
                "findings"]}
            self.assertIn("prev-hash-break", checks)

    def test_malformed_ledger_line(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["a"])
            led = tdp / "l.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led)])
            led.write_text(led.read_text(encoding="utf-8") +
                           "BUKAN-JSON\n", encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = lcv.main(["verify", "--ledger", str(led)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
            checks = {f["check"] for f in json.loads(buf.getvalue())[
                "findings"]}
            self.assertIn("ledger-malformed", checks)

    def test_ledger_gap_detected(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["1", "2", "3"])
            led = tdp / "l.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led)])
            ents = _entries(led)
            del ents[1]  # entri tengah dibuang
            led.write_text(json.dumps({"schema": lcv.SCHEMA,
                                       "type": "ledger"}) + "\n" +
                           "\n".join(json.dumps(e) for e in ents) + "\n",
                           encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = lcv.main(["verify", "--ledger", str(led)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
            checks = {f["check"] for f in json.loads(buf.getvalue())[
                "findings"]}
            self.assertIn("ledger-gap", checks)

    def test_recheck_content_drift(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["v1", "v2"])
            led = tdp / "l.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led)])
            log.write_text("v1\nTAMPERED\n", encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = lcv.main(["verify", "--ledger", str(led),
                                 "--recheck", str(log)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
            rep = json.loads(buf.getvalue())
            checks = {f["check"] for f in rep["findings"]}
            self.assertIn("content-drift", checks)
            self.assertNotIn("chain-hash-break", checks)

    def test_recheck_deleted_line(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["a", "b", "c"])
            led = tdp / "l.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led)])
            log.write_text("a\n", encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = lcv.main(["verify", "--ledger", str(led),
                                 "--recheck", str(log)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
            checks = {f["check"] for f in json.loads(buf.getvalue())[
                "findings"]}
            self.assertIn("source-missing", checks)

    def test_recheck_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["a"])
            led = tdp / "l.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led)])
            log.unlink()
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = lcv.main(["verify", "--ledger", str(led),
                                 "--recheck", str(log)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
            checks = {f["check"] for f in json.loads(buf.getvalue())[
                "findings"]}
            self.assertIn("source-missing", checks)

    def test_empty_log_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = tdp / "empty.log"
            log.write_text("", encoding="utf-8")  # nol baris
            import io
            buf = io.StringIO()
            old = sys.stderr
            sys.stderr = buf
            try:
                code = lcv.main(["chain", "--logs", str(log),
                                 "--out", str(tdp / "l.jsonl")])
            finally:
                sys.stderr = old
            self.assertEqual(code, 2)
            self.assertIn("fail-closed", buf.getvalue())

    def test_checkpoint_is_sha256_of_head(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            log = self._mklog(tdp, "a.log", ["p", "q"])
            led = tdp / "l.jsonl"
            lcv.main(["chain", "--logs", str(log), "--out", str(led)])
            ents = _entries(led)
            head = ents[-1]["chain_hash"]
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = lcv.main(["checkpoint", "--ledger", str(led)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 0)
            rep = json.loads(buf.getvalue())
            self.assertEqual(rep["checkpoint"],
                             hashlib.sha256(head.encode("ascii"))
                             .hexdigest())
            self.assertEqual(rep["ledger_head"], head)

    def test_ledger_without_header_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            p = tdp / "fake.jsonl"
            p.write_text('{"i":0,"src":"x","line":1,'
                         '"content_hash":"a","prev_hash":"' + "0" * 64 +
                         '","chain_hash":"b","ts":"t"}\n',
                         encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stderr
            sys.stderr = buf
            try:
                code = lcv.main(["verify", "--ledger", str(p)])
            finally:
                sys.stderr = old
            self.assertEqual(code, 2)
            self.assertIn("header", buf.getvalue())

    def test_dir_input_multi_file(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "logs"
            tdp.mkdir()
            (tdp / "b.log").write_text("bb\n", encoding="utf-8")
            (tdp / "a.log").write_text("aa\n", encoding="utf-8")
            led = tdp / "led.jsonl"
            self.assertEqual(lcv.main(
                ["chain", "--dir", str(tdp), "--out", str(led)]), 0)
            ents = _entries(led)
            self.assertEqual(len(ents), 2)
            self.assertEqual(ents[0]["src"].endswith("a.log"), True)
            self.assertEqual(ents[1]["src"].endswith("b.log"), True)

    def test_missing_log_fail_closed(self):
        import io
        buf = io.StringIO()
        old = sys.stderr
        sys.stderr = buf
        try:
            code = lcv.main(["chain", "--logs",
                             "D:/nonexistent-b22/x.log",
                             "--out", "D:/nonexistent-b22/l.jsonl"])
        finally:
            sys.stderr = old
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
