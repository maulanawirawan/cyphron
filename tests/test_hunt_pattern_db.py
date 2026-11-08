"""Test hunt_pattern_db — nol jaringan, DB fixture di tempfile.

Cakupan: add (validasi + dedup + fail-closed tanpa bukti), match (kelas
+ irisan tech-stack sebagian + sorting), rotasi (ambang + keep), stats,
baris korup dihitung di meta (tidak diabaikan diam-diam), exit codes.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import hunt_pattern_db as hpd


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "patterns.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def _add(self, **kw):
        argv = ["add", "--db", str(self.db)]
        for k, v in kw.items():
            argv += [f"--{k.replace('_', '-')}", str(v)]
        return hpd.main(argv)

    def _run(self, *argv):
        return hpd.main(list(argv))

    def _lines(self):
        return [json.loads(l) for l in
                self.db.read_text(encoding="utf-8").splitlines() if l.strip()]


class TestAdd(Base):
    def test_add_saves_valid_line(self):
        rc = self._add(target="shop.example.com", vuln_class="idor",
                       technique="numeric-id-swap",
                       tech_stack="python,django", outcome="accepted",
                       evidence_ref="findings.json#3")
        self.assertEqual(rc, 0)
        rows = self._lines()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["target"], "shop.example.com")
        self.assertEqual(r["vuln_class"], "idor")
        self.assertEqual(r["technique"], "numeric-id-swap")
        self.assertEqual(r["tech_stack"], ["python", "django"])
        self.assertEqual(r["outcome"], "accepted")
        self.assertEqual(r["evidence_ref"], "findings.json#3")
        self.assertIn("ts", r)

    def test_add_duplicate_triplet(self):
        kw = dict(target="t.example", vuln_class="idor",
                  technique="id-swap", evidence_ref="f#1")
        self.assertEqual(self._add(**kw), 0)
        out = Path(self.tmp.name) / "r.json"
        rc = self._add(**kw, out=out)  # duplikat dgn casing beda pun duplikat
        self.assertEqual(rc, 1)
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertFalse(rep["saved"])
        self.assertTrue(rep["duplicate"])
        self.assertEqual(len(self._lines()), 1)

    def test_add_without_evidence_ref_fail_closed(self):
        argv = ["add", "--db", str(self.db), "--target", "t.example",
                "--vuln-class", "idor", "--technique", "id-swap"]
        with self.assertRaises(SystemExit):
            hpd.main(argv)
        self.assertFalse(self.db.exists())

    def test_add_empty_evidence_ref_exit_2(self):
        rc = self._add(target="t.example", vuln_class="idor",
                       technique="id-swap", evidence_ref="  ")
        self.assertEqual(rc, 2)
        self.assertFalse(self.db.exists())

    def test_add_unknown_outcome_exit_2(self):
        rc = self._add(target="t.example", vuln_class="idor",
                       technique="id-swap", outcome="menang",
                       evidence_ref="f#1")
        self.assertEqual(rc, 2)

    def test_add_missing_required_exit_2(self):
        argv = ["add", "--db", str(self.db), "--target", "t.example",
                "--technique", "id-swap", "--evidence-ref", "f#1"]
        with self.assertRaises(SystemExit):
            hpd.main(argv)  # argparse: --vuln-class wajib
        self.assertFalse(self.db.exists())

    def test_add_out_default_pending(self):
        self._add(target="t.example", vuln_class="ssrf",
                  technique="metadata-probe", evidence_ref="f#2")
        self.assertEqual(self._lines()[0]["outcome"], "pending")

    def test_add_over_corrupt_line_still_works_and_counts(self):
        self._add(target="t.example", vuln_class="idor",
                  technique="id-swap", evidence_ref="f#1")
        with open(self.db, "a", encoding="utf-8") as f:
            f.write("{baris rusak bukan json\n")
        out = Path(self.tmp.name) / "r.json"
        rc = self._add(target="u.example", vuln_class="ssrf",
                       technique="metadata", evidence_ref="f#2", out=out)
        self.assertEqual(rc, 0)
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rep["meta"]["lines_corrupt"], 1)
        self.assertEqual(rep["meta"]["corrupt"][0]["line"], 2)
        self.assertIn("error", rep["meta"]["corrupt"][0])


class TestMatch(Base):
    def setUp(self):
        super().setUp()
        self._add(target="a.example", vuln_class="idor",
                  technique="id-swap", tech_stack="python,django",
                  outcome="accepted", evidence_ref="f#1")
        self._add(target="b.example", vuln_class="ssrf",
                  technique="metadata-probe", tech_stack="nginx",
                  outcome="pending", evidence_ref="f#2")

    def test_match_by_vuln_class(self):
        out = Path(self.tmp.name) / "r.json"
        rc = self._run("match", "--db", str(self.db),
                       "--vuln-class", "idor", "--out", str(out))
        self.assertEqual(rc, 0)
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rep["count"], 1)
        self.assertEqual(rep["matches"][0]["target"], "a.example")

    def test_match_tech_stack_partial_counts(self):
        out = Path(self.tmp.name) / "r.json"
        # query python+nginx: entri a hanya irisan 'python' — sebagian dihitung
        rc = self._run("match", "--db", str(self.db),
                       "--tech-stack", "python,nginx", "--out", str(out))
        self.assertEqual(rc, 0)
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rep["count"], 2)
        a = next(m for m in rep["matches"]
                 if m["target"] == "a.example")
        self.assertEqual(a["matched_tech"], ["python"])

    def test_match_no_intersection_exit_1(self):
        rc = self._run("match", "--db", str(self.db),
                       "--tech-stack", "rust,rails")
        self.assertEqual(rc, 1)

    def test_match_class_and_stack_combined(self):
        out = Path(self.tmp.name) / "r.json"
        rc = self._run("match", "--db", str(self.db),
                       "--vuln-class", "ssrf",
                       "--tech-stack", "python", "--out", str(out))
        self.assertEqual(rc, 1)  # ssrf tapi stack tak irisan
        rc = self._run("match", "--db", str(self.db),
                       "--vuln-class", "ssrf",
                       "--tech-stack", "nginx", "--out", str(out))
        self.assertEqual(rc, 0)

    def test_match_case_insensitive(self):
        out = Path(self.tmp.name) / "r.json"
        rc = self._run("match", "--db", str(self.db),
                       "--vuln-class", "IDOR", "--out", str(out))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(
            out.read_text(encoding="utf-8"))["count"], 1)

    def test_match_sorted_accepted_first(self):
        self._add(target="c.example", vuln_class="idor",
                  technique="uuid-shadow", tech_stack="python",
                  outcome="pending", evidence_ref="f#3")
        out = Path(self.tmp.name) / "r.json"
        self._run("match", "--db", str(self.db),
                  "--vuln-class", "idor", "--out", str(out))
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rep["matches"][0]["outcome"], "accepted")

    def test_match_limit(self):
        out = Path(self.tmp.name) / "r.json"
        self._run("match", "--db", str(self.db), "--limit", "1",
                  "--out", str(out))
        self.assertEqual(json.loads(
            out.read_text(encoding="utf-8"))["count"], 1)

    def test_match_missing_db_exit_2(self):
        rc = self._run("match", "--db",
                       str(Path(self.tmp.name) / "takada.jsonl"))
        self.assertEqual(rc, 2)

    def test_match_corrupt_lines_loud_in_meta(self):
        with open(self.db, "a", encoding="utf-8") as f:
            f.write("bukan-json-sama-sekali\n")
        out = Path(self.tmp.name) / "r.json"
        self._run("match", "--db", str(self.db), "--vuln-class", "idor",
                  "--out", str(out))
        meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
        self.assertEqual(meta["lines_corrupt"], 1)
        self.assertEqual(meta["lines_ok"], 2)


class TestRotate(Base):
    def test_rotate_respects_threshold(self):
        self._add(target="t.example", vuln_class="idor",
                  technique="id-swap", evidence_ref="f#1")
        out = Path(self.tmp.name) / "r.json"
        rc = self._run("rotate", "--db", str(self.db),
                       "--max-bytes", "100000", "--out", str(out))
        self.assertEqual(rc, 0)
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertFalse(rep["rotated"])

        rc = self._run("rotate", "--db", str(self.db),
                       "--max-bytes", "10", "--out", str(out))
        self.assertEqual(rc, 0)
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(rep["rotated"])
        self.assertTrue(Path(str(self.db) + ".1").exists())
        self.assertFalse(self.db.exists())

    def test_auto_rotate_on_add_with_keep_limit(self):
        payload = "x" * 120
        for i in range(6):
            self._add(target=f"t{i}.example", vuln_class="idor",
                      technique=f"tech-{i}-{payload}",
                      evidence_ref=f"f#{i}")
            self._run("rotate", "--db", str(self.db))  # jaga aman manual
        # paksa ambang kecil: add otomatis harus merotasi
        rc = self._add(target="z.example", vuln_class="ssrf",
                       technique="metadata-probe", evidence_ref="f#9",
                       max_bytes=200, keep=2)
        self.assertEqual(rc, 0)
        backups = sorted(p.name for p in
                         Path(self.tmp.name).glob("patterns.jsonl.*"))
        self.assertIn("patterns.jsonl.1", backups)
        self.assertNotIn("patterns.jsonl.3", backups)  # keep=2 dibatasi

    def test_rotate_missing_db_exit_2(self):
        rc = self._run("rotate", "--db",
                       str(Path(self.tmp.name) / "takada.jsonl"))
        self.assertEqual(rc, 2)


class TestStats(Base):
    def test_stats_counts(self):
        self._add(target="a.example", vuln_class="idor",
                  technique="id-swap", outcome="accepted",
                  evidence_ref="f#1")
        self._add(target="b.example", vuln_class="ssrf",
                  technique="metadata", outcome="pending",
                  evidence_ref="f#2")
        out = Path(self.tmp.name) / "r.json"
        rc = self._run("stats", "--db", str(self.db), "--out", str(out))
        self.assertEqual(rc, 0)
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rep["total_entries"], 2)
        self.assertEqual(rep["by_vuln_class"], {"idor": 1, "ssrf": 1})
        self.assertEqual(rep["by_outcome"]["accepted"], 1)
        self.assertEqual(rep["by_target"]["a.example"], 1)
        self.assertGreater(rep["bytes"], 0)
        self.assertEqual(rep["meta"]["lines_corrupt"], 0)

    def test_stats_missing_db_exit_2(self):
        rc = self._run("stats", "--db",
                       str(Path(self.tmp.name) / "takada.jsonl"))
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
