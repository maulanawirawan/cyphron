"""Nol jaringan — test stix_bundle_audit (validasi bundle STIX 2.1 +
ekstraksi IOC).

Fixture dibangun inline mengikuti struktur bundle STIX 2.1 sah dan
berbagai bentuk tidak patuh (id bukan uuidv4, ref menggantung,
modified < created, pattern rusak, type asing, versi stale).
Tidak ada request jaringan; tidak memakai library stix2.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import stix_bundle_audit as sba  # noqa: E402
from findings import validate_finding  # noqa: E402

TS_C = "2026-01-15T00:00:00.000Z"
TS_M = "2026-02-20T00:00:00.000Z"
HASH64 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def _sdo(obj_type: str, name: str, **kw) -> dict:
    base = {"type": obj_type,
            "spec_version": "2.1",
            "id": f"{obj_type}--c9e04a1d-5b2c-4a3f-9e1b-"
                  "7d2f0a6b8c41",
            "created": TS_C,
            "modified": TS_M,
            "name": name}
    base.update(kw)
    return base


def _bundle(objs: list) -> dict:
    return {"type": "bundle",
            "id": "bundle--0b4e2f8a-3c6d-4e1f-8a2b-5c7d9e0f1a2b",
            "objects": objs}


def _tmpfile(content, suffix: str = ".json") -> Path:
    text = content if isinstance(content, str) else json.dumps(content)
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix,
                                     delete=False,
                                     encoding="utf-8") as fh:
        fh.write(text)
        return Path(fh.name)


class TestHealthy(unittest.TestCase):
    def test_valid_bundle(self):
        objs = [
            _sdo("malware", "Emotet", is_family=True),
            _sdo("attack-pattern", "Spearphishing Attachment"),
            _sdo("indicator", "hash ind",
                 pattern=f"[file:hashes.'SHA-256' = '{HASH64}']",
                 pattern_type="stix", valid_from=TS_C),
            {"type": "relationship",
             "spec_version": "2.1",
             "id": "relationship--8f1a2b3c-4d5e-4f60-9a1b-"
                   "2c3d4e5f6071",
             "created": TS_C, "modified": TS_M,
             "relationship_type": "indicates",
             "source_ref": "indicator--c9e04a1d-5b2c-4a3f-9e1b-"
                           "7d2f0a6b8c41",
             "target_ref": "malware--c9e04a1d-5b2c-4a3f-9e1b-"
                           "7d2f0a6b8c41"},
        ]
        f = _tmpfile(_bundle(objs))
        findings, iocs, meta = sba.audit_bundle(f)
        self.assertEqual(findings, [])
        self.assertEqual(meta["objects"], 4)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["type"], "hash:SHA-256")
        self.assertTrue(iocs[0]["hash_valid"])

    def test_sco_no_timestamp_required(self):
        sco = {"type": "domain-name",
               "value": "c2.example.net",
               "id": "domain-name--9b1deb4d-3b7d-4bad-9bdd-"
                     "2b0d7b3dcb6d"}
        f = _tmpfile(_bundle([sco]))
        findings, _, meta = sba.audit_bundle(f)
        self.assertEqual(findings, [])


class TestIdGrammar(unittest.TestCase):
    def test_id_type_mismatch(self):
        obj = _sdo("malware", "x")
        obj["id"] = "indicator--c9e04a1d-5b2c-4a3f-9e1b-7d2f0a6b8c41"
        f = _tmpfile(_bundle([obj]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("id-type-mismatch", codes)

    def test_id_not_uuidv4(self):
        obj = _sdo("malware", "x")
        obj["id"] = "malware--e7a5d3c1-0000-1000-8000-00805f9b34fb"
        f = _tmpfile(_bundle([obj]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("id-not-uuidv4", codes)

    def test_id_malformed(self):
        obj = _sdo("malware", "x")
        obj["id"] = "bukan-id-stix"
        f = _tmpfile(_bundle([obj]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("id-malformed", codes)


class TestPropsAndRefs(unittest.TestCase):
    def test_missing_created_and_modified(self):
        obj = _sdo("malware", "x")
        del obj["created"]
        del obj["modified"]
        f = _tmpfile(_bundle([obj]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("missing-created", codes)
        self.assertIn("missing-modified", codes)

    def test_modified_before_created(self):
        obj = _sdo("malware", "x", created=TS_M, modified=TS_C)
        f = _tmpfile(_bundle([obj]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("modified-before-created", codes)

    def test_dangling_ref(self):
        rel = {"type": "relationship", "spec_version": "2.1",
               "id": "relationship--8f1a2b3c-4d5e-4f60-9a1b-"
                     "2c3d4e5f6071",
               "created": TS_C, "modified": TS_M,
               "relationship_type": "uses",
               "source_ref": "malware--c9e04a1d-5b2c-4a3f-9e1b-"
                             "7d2f0a6b8c41",
               "target_ref": "attack-pattern--tidak-ada-di-bundle"}
        f = _tmpfile(_bundle([
            _sdo("malware", "x"), rel]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("ref-dangling", codes)

    def test_unknown_type_counted(self):
        obj = {"type": "flying-saucer",
               "id": "flying-saucer--c9e04a1d-5b2c-4a3f-9e1b-"
                     "7d2f0a6b8c41"}
        f = _tmpfile(_bundle([obj]))
        findings, _, meta = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("type-unknown", codes)
        self.assertIn("flying-saucer", meta["type_counts"])


class TestIndicator(unittest.TestCase):
    def _ind(self, pattern: str, **kw) -> dict:
        return _sdo("indicator", "ind", pattern=pattern,
                    pattern_type="stix", valid_from=TS_C, **kw)

    def test_domain_and_url_extraction(self):
        ind = self._ind("[domain-name:value = 'evil.example.com'] "
                        "AND [url:value = 'https://evil.example.com/x']")
        f = _tmpfile(_bundle([ind]))
        findings, iocs, _ = sba.audit_bundle(f)
        self.assertEqual(findings, [])
        types = {i["type"] for i in iocs}
        self.assertEqual(types, {"domain", "url"})

    def test_pattern_malformed(self):
        ind = self._ind("domain-name:value = 'no-brackets'")
        f = _tmpfile(_bundle([ind]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("pattern-malformed", codes)

    def test_missing_valid_from(self):
        ind = self._ind("[domain-name:value = 'evil.example.com']")
        del ind["valid_from"]
        f = _tmpfile(_bundle([ind]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("indicator-no-valid-from", codes)

    def test_valid_until_before_from(self):
        ind = self._ind("[domain-name:value = 'evil.example.com']",
                        valid_until="2025-01-01T00:00:00.000Z")
        f = _tmpfile(_bundle([ind]))
        findings, _, _ = sba.audit_bundle(f)
        codes = {x.get("code") for x in findings}
        self.assertIn("valid-until-before-from", codes)

    def test_hash_invalid_length_recorded(self):
        ind = self._ind("[file:hashes.'SHA-256' = 'abcd']")
        f = _tmpfile(_bundle([ind]))
        _, iocs, _ = sba.audit_bundle(f)
        self.assertFalse(iocs[0]["hash_valid"])
        # tak valid tetap diekstrak (dilaporkan, bukan dibuang)
        self.assertEqual(iocs[0]["value"], "abcd")


class TestVersions(unittest.TestCase):
    def test_stale_version_counted_newest_kept(self):
        # versi lama: modified >= created (created=2026-01-15)
        old = _sdo("malware", "old", modified="2026-01-20T00:00:00.000Z")
        new = dict(old)
        new["name"] = "new"
        new["modified"] = TS_M
        f = _tmpfile(_bundle([old, new]))
        findings, _, meta = sba.audit_bundle(f)
        self.assertEqual(meta["stale_versions"], 1)
        self.assertEqual(findings, [])


class TestMainContract(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, Path]:
        out = Path(tempfile.mkdtemp()) / "findings.json"
        rc = sba.main(argv + ["--out", str(out)])
        return rc, out

    def test_invalid_bundle_exit1_contract(self):
        obj = _sdo("malware", "x")
        obj["id"] = "bukan-stix"
        b = _tmpfile(_bundle([obj]))
        rc, out = self._run(["--bundle", str(b)])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        for x in doc["findings"]:
            self.assertEqual(validate_finding(x), [])
        self.assertEqual(doc["data"]["iocs_total"], 0)

    def test_valid_bundle_exit0(self):
        b = _tmpfile(_bundle([_sdo("malware", "x")]))
        rc, _ = self._run(["--bundle", str(b)])
        self.assertEqual(rc, 0)

    def test_not_bundle_exit2(self):
        b = _tmpfile('{"type": "tiada", "objects": []}')
        rc, _ = self._run(["--bundle", str(b)])
        self.assertEqual(rc, 2)

    def test_garbage_exit2(self):
        b = _tmpfile("{{{{bukan json")
        rc, _ = self._run(["--bundle", str(b)])
        self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc, _ = self._run(["--bundle", "nope.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
