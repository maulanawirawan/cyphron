"""Test F69 — kev-gap (celah coverage template komunitas vs KEV).

NOL jaringan; fixture injectable. Yang dikunci:
  - corpus id: `id: CVE-...` dan `cve-id:` keduanya terkumpul;
  - missing = KEV id yang tidak ada di corpus, urut dateAdded terbaru
    + ransomware flag naik ke atas;
  - corpus hilang = fail-closed (baris audit, bukan klaim kosong);
  - KEV hilang = baris audit (bukan crash);
  - kontrak validate_finding lolos di semua baris.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import kev_gap as kg  # noqa: E402
from findings import validate_finding  # noqa: E402

KEV_DOC = {"vulnerabilities": [
    {"cveID": "CVE-2026-20001", "vendorProject": "Acme",
     "product": "Widget", "vulnerabilityName": "RCE acme",
     "dateAdded": "2026-10-20",
     "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-89"]},
    {"cveID": "CVE-2026-20002", "vendorProject": "Beta",
     "product": "Gadget", "vulnerabilityName": "SSRF beta",
     "dateAdded": "2026-10-01",
     "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-918"]},
]}

YAML_COVERED = (
    "id: CVE-2026-20001\n"
    "info:\n"
    "  name: covered\n"
    "  classification:\n"
    "    cve-id: CVE-2026-20001\n"
)


class KevGapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron-f69-"))
        (self.tmp / "kev.json").write_text(json.dumps(KEV_DOC),
                                           encoding="utf-8")
        corp = self.tmp / "corpus"
        corp.mkdir()
        (corp / "CVE-2026-20001.yaml").write_text(YAML_COVERED,
                                                  encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_prioritized_and_contract_valid(self):
        rows, meta = kg.gap_report(KEV_DOC["vulnerabilities"],
                                   self.tmp / "corpus", top=10)
        self.assertEqual(meta["kev_entries"], 2)
        self.assertEqual(meta["with_template"], 1)
        self.assertEqual(meta["backlog"], 1)
        gap_rows = [r for r in rows if r.get("category") == "KEV-GAP"
                    and r.get("cve")]
        self.assertEqual(len(gap_rows), 1)
        self.assertEqual(gap_rows[0]["cve"], "CVE-2026-20002")
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_missing_corpus_is_fail_closed(self):
        rows, meta = kg.gap_report(KEV_DOC["vulnerabilities"],
                                   self.tmp / "tidak-ada", top=10)
        self.assertEqual(meta["backlog"], 0)
        self.assertTrue(rows[0].get("corpus_missing"))
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_missing_kev_is_audit_not_crash(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.json"
            missing = self.tmp / "nope.json"
            if missing.exists():
                missing.unlink()
            old = sys.argv
            sys.argv = ["kev_gap.py", "--kev", str(missing),
                        "--corpus", str(self.tmp / "corpus"),
                        "--out", str(out)]
            try:
                rc = kg.main()
            finally:
                sys.argv = old
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(doc["data"].get("kev_missing"))
            self.assertTrue(all(validate_finding(r) == []
                                for r in doc["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=1)
