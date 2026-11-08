"""Nol jaringan — test slsa_provenance_audit (struktur in-toto/DSSE,
ikatan digest subjek vs artefak, kebijakan builder/sumber; fail-closed
tanpa klaim verifikasi signature)."""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import slsa_provenance_audit as spa  # noqa: E402

BUILDER = ("https://github.com/slsa-framework/slsa-github-generator/"
           ".github/workflows/generator_generic_slsa3.yml@refs/tags/"
           "v2.0.0")


def mk_statement_v1(sha256: str, name: str = "artifact.bin",
                    repository: str = "github.com/org/repo",
                    builder: str = BUILDER) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"sha256": sha256}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.com/build/v1",
                "externalParameters": {"repository": repository},
                "internalParameters": {},
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {"id": builder},
                "metadata": {"invocationId": "inv-1",
                             "startedOn": "2026-11-08T00:00:00Z"},
            },
        },
    }


def mk_statement_v02(sha256: str, name: str = "artifact.bin",
                     source: str = "https://github.com/org/repo",
                     builder: str = BUILDER,
                     materials: "list | None" = None) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": name, "digest": {"sha256": sha256}}],
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
            "builder": {"id": builder},
            "buildType": "https://example.com/build/v1",
            "invocation": {"configSource": {"uri": source}},
            "metadata": {"buildStartedOn": "2026-11-08T00:00:00Z"},
            "materials": materials or [],
        },
    }


def mk_envelope(stmt: dict, signatures: "list | None" = None,
                payload_type: str = "https://in-toto.io/Statement/v1"
                ) -> dict:
    payload = base64.b64encode(
        json.dumps(stmt).encode("utf-8")).decode("ascii")
    return {"payload": payload, "payloadType": payload_type,
            "signatures": signatures if signatures is not None
            else [{"keyid": "k1", "sig": "c2ln"}]}


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Normalize(unittest.TestCase):
    def test_variants(self) -> None:
        self.assertEqual(spa.normalize_source_uri(
            "https://github.com/org/repo.git"), "github.com/org/repo")
        self.assertEqual(spa.normalize_source_uri(
            "http://github.com/org/repo/"), "github.com/org/repo")
        self.assertEqual(spa.normalize_source_uri(
            "git://github.com/org/repo"), "github.com/org/repo")
        self.assertEqual(spa.normalize_source_uri(
            "github.com/org/repo"), "github.com/org/repo")
        # pola configSource v0.2 nyata slsa-github-generator
        self.assertEqual(spa.normalize_source_uri(
            "git+https://github.com/org/repo@refs/tags/v2.6.0"),
            "github.com/org/repo")
        # user-info ssh:// tidak disentuh marker @refs/
        self.assertEqual(spa.normalize_source_uri(
            "ssh://git@host/org/repo"), "git@host/org/repo")
        self.assertEqual(spa.normalize_source_uri(""), "")

    def test_predicate_family(self) -> None:
        for ok in ("https://slsa.dev/provenance/v0.2",
                   "https://slsa.dev/provenance/v1",
                   "https://slsa.dev/provenance/v0.1",
                   "slsaprovenance", "slsaprovenance0.2"):
            self.assertTrue(spa.is_slsa_predicate(ok), ok)
        for bad in ("https://cosign.sigstore.dev/attestation/vuln/v1",
                    "https://example.com/other", "", None,
                    "https://slsa.dev/attestation/v1"):
            self.assertFalse(spa.is_slsa_predicate(bad), bad)


class Policy(unittest.TestCase):
    def test_parse_policy(self) -> None:
        self.assertEqual(spa.parse_policy(None), {})
        p = spa.parse_policy({"source_uri": "github.com/org/repo",
                              "builder_id_prefix": "https://x/"})
        self.assertEqual(p["source_uri"], "github.com/org/repo")

    def test_parse_policy_fail_closed(self) -> None:
        for bad in ({}, {"unknown_field": "x"},
                    {"source_uri": ""}, {"builder_id": 123},
                    "bukan-dict"):
            with self.assertRaises(ValueError, msg=str(bad)):
                spa.parse_policy(bad)

    def test_check_policy_source_normalization(self) -> None:
        policy = {"source_uri": "github.com/org/repo"}
        checks = spa.check_policy(policy, "https://github.com/org/repo"
                                  ".git", None)
        self.assertEqual(checks[0]["result"], "matched")
        checks = spa.check_policy(policy, "github.com/evil/repo", None)
        self.assertEqual(checks[0]["result"], "mismatched")

    def test_check_policy_builder(self) -> None:
        policy = {"builder_id_prefix": "https://github.com/slsa-"
                                       "framework/"}
        checks = spa.check_policy(policy, None, BUILDER)
        self.assertEqual(checks[0]["result"], "matched")
        checks = spa.check_policy(policy, None,
                                  "https://github.com/evil/wf.yml")
        self.assertEqual(checks[0]["result"], "mismatched")
        policy = {"builder_id": BUILDER}
        checks = spa.check_policy(policy, None, None)
        self.assertEqual(checks[0]["result"], "unresolvable")
        # fail-closed: field kebijakan ada, dokumen kosong = bukan lolos
        checks = spa.check_policy({"source_uri": "github.com/a/b"},
                                  None, None)
        self.assertEqual(checks[0]["result"], "unresolvable")


class Extract(unittest.TestCase):
    def test_v1_0_fields(self) -> None:
        stmt = mk_statement_v1("a" * 64)
        ext = spa.extract_provenance(stmt["predicate"], "v1.0")
        self.assertEqual(ext["builder_id"], BUILDER)
        self.assertEqual(ext["source_uri"], "github.com/org/repo")
        self.assertEqual(ext["source_resolved"], "recognized-field")
        self.assertEqual(ext["materials_total"], 0)

    def test_v1_0_builder_specific_source(self) -> None:
        stmt = mk_statement_v1("a" * 64)
        stmt["predicate"]["buildDefinition"]["externalParameters"] = {
            "workflowInputs": {"release_version": "v1.2.3"}}
        ext = spa.extract_provenance(stmt["predicate"], "v1.0")
        self.assertIsNone(ext["source_uri"])
        self.assertEqual(ext["source_resolved"],
                         "builder-specific-not-recognized")

    def test_v0_2_fields(self) -> None:
        stmt = mk_statement_v02("b" * 64)
        ext = spa.extract_provenance(stmt["predicate"], "v0.2")
        self.assertEqual(ext["builder_id"], BUILDER)
        self.assertEqual(ext["source_uri"],
                         "https://github.com/org/repo")
        self.assertEqual(ext["started_on"], "2026-11-08T00:00:00Z")

    def test_materials_bounded(self) -> None:
        mats = [{"uri": f"https://m/{i}", "digest": {"sha256": str(i)}}
                for i in range(25)]
        ext = spa.extract_provenance({"materials": mats}, "v0.2")
        self.assertEqual(len(ext["materials"]), spa.MAX_MATERIALS)
        self.assertEqual(ext["materials_total"], 25)


class ParseDocuments(unittest.TestCase):
    def _write(self, d: str, text: str) -> Path:
        p = Path(d) / "prov.intoto.jsonl"
        p.write_text(text, encoding="utf-8")
        return p

    def test_envelope_and_jsonl(self) -> None:
        stmt = mk_statement_v1("c" * 64)
        env = mk_envelope(stmt)
        env2 = mk_envelope(mk_statement_v02("d" * 64))
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, json.dumps(env) + "\n" +
                            json.dumps(env2) + "\n")
            docs = spa.parse_documents(p)
        self.assertEqual(len(docs), 2)
        self.assertTrue(docs[0]["envelope"])
        self.assertEqual(docs[0]["signatures"], 1)
        self.assertEqual(docs[1]["statement"]["predicateType"],
                         "https://slsa.dev/provenance/v0.2")

    def test_plain_statement(self) -> None:
        stmt = mk_statement_v1("e" * 64)
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, json.dumps(stmt))
            docs = spa.parse_documents(p)
        self.assertEqual(len(docs), 1)
        self.assertFalse(docs[0]["envelope"])

    def test_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            for bad in ("", "\n\n",
                        "bukan-json\n",
                        '[]\n',
                        json.dumps({"payload": "!!!"}) + "\n"):
                p = self._write(d, bad)
                with self.assertRaises(ValueError, msg=bad[:40]):
                    spa.parse_documents(p)


class AuditStatement(unittest.TestCase):
    def test_binding_matched_and_policy(self) -> None:
        data = b"payload of artifact"
        stmt = mk_statement_v1(sha_hex(data))
        policy = {"source_uri": "https://github.com/org/repo.git",
                  "builder_id_prefix": "https://github.com/slsa-"
                                       "framework/"}
        res = spa.audit_statement(stmt, {"a.bin": {"sha256": sha_hex(
            data)}}, policy, [])
        self.assertEqual(res["bindings_matched"], 1)
        self.assertEqual(res["findings"], [])

    def test_binding_mismatch_high(self) -> None:
        stmt = mk_statement_v1("f" * 64)
        res = spa.audit_statement(stmt, {"a.bin": {"sha256": "0" * 64}},
                                  {}, [])
        self.assertEqual(res["bindings_matched"], 0)
        self.assertTrue(any(f["class"] == "subject_digest_mismatch" and
                            f["level"] == "high"
                            for f in res["findings"]))

    def test_no_artifact_checked(self) -> None:
        stmt = mk_statement_v1("f" * 64)
        res = spa.audit_statement(stmt, {}, {}, [])
        self.assertTrue(any(f["class"] == "no_artifact_checked"
                            for f in res["findings"]))

    def test_policy_unresolvable_medium(self) -> None:
        stmt = mk_statement_v02("f" * 64)
        stmt["predicate"]["invocation"] = {}
        res = spa.audit_statement(stmt, {}, {"source_uri":
                                             "github.com/org/repo"}, [])
        self.assertTrue(any(f["class"] == "policy_unresolvable" and
                            f["level"] == "medium"
                            for f in res["findings"]))

    def test_explicit_name_not_found_low(self) -> None:
        data = b"x"
        stmt = mk_statement_v1(sha_hex(data), name="the-real-name")
        res = spa.audit_statement(stmt, {"renamed.bin": {"sha256":
                                                         sha_hex(data)}},
                                  {}, ["renamed.bin"])
        self.assertTrue(any(f["class"] == "subject_name_not_found" and
                            f["level"] == "low"
                            for f in res["findings"]))

    def test_fail_closed(self) -> None:
        good = mk_statement_v1("f" * 64)
        cases = [
            ({**good, "_type": "https://example.com/x"}, {}, []),
            ({**good, "predicateType": "https://example.com/other"},
             {}, []),
            ({k: v for k, v in good.items() if k != "subject"}, {}, []),
            ({**good, "subject": [{"name": "x", "digest": {}}]}, {}, []),
            ({**good, "predicate": "bukan-dict"}, {}, []),
            ("bukan-dict", {}, []),
        ]
        for stmt, digests, names in cases:
            with self.assertRaises(ValueError):
                spa.audit_statement(stmt, digests, {}, names)


class EvaluateDoc(unittest.TestCase):
    def test_signature_honest_status(self) -> None:
        stmt = mk_statement_v1("a" * 64)
        doc = {"line": 1, "envelope": True, "signatures": 1,
               "payload_type": "https://in-toto.io/Statement/v1",
               "statement": stmt}
        res = spa.evaluate_doc(doc, {}, {}, [])
        self.assertIn("TIDAK diverifikasi", res["signature"]["status"])
        self.assertFalse(any(f["class"] == "no_signatures"
                             for f in res["findings"]))

    def test_zero_signatures_medium(self) -> None:
        stmt = mk_statement_v1("a" * 64)
        doc = {"line": 1, "envelope": True, "signatures": 0,
               "payload_type": "https://in-toto.io/Statement/v1",
               "statement": stmt}
        res = spa.evaluate_doc(doc, {}, {}, [])
        self.assertTrue(any(f["class"] == "no_signatures" and
                            f["level"] == "medium"
                            for f in res["findings"]))

    def test_plain_statement_unsigned_medium(self) -> None:
        doc = {"line": 1, "envelope": False, "signatures": 0,
               "payload_type": None, "statement": mk_statement_v1("a"
                                                                  * 64)}
        res = spa.evaluate_doc(doc, {}, {}, [])
        self.assertTrue(any(f["class"] == "unsigned_statement" and
                            f["level"] == "medium"
                            for f in res["findings"]))
        self.assertIn("L1", res["signature"]["status"])

    def test_unusual_payload_type_info(self) -> None:
        stmt = mk_statement_v1("a" * 64)
        doc = {"line": 1, "envelope": True, "signatures": 1,
               "payload_type": "application/weird",
               "statement": stmt}
        res = spa.evaluate_doc(doc, {}, {}, [])
        self.assertTrue(any(f["class"] == "unusual_payload_type"
                            for f in res["findings"]))


class Assess(unittest.TestCase):
    def test_mixed_valid_broken(self) -> None:
        docs = [{"line": 1, "envelope": True, "signatures": 1,
                 "payload_type": None,
                 "statement": mk_statement_v1("a" * 64)},
                {"line": 2, "envelope": False, "signatures": 0,
                 "payload_type": None,
                 "statement": {"_type": "salah", "subject": [],
                               "predicateType": "x", "predicate": {}}}]
        docs.append({"line": 3, "envelope": False, "signatures": 0,
                     "payload_type": None, "statement": {}})
        res = spa.assess_documents(docs, {}, {}, [])
        self.assertEqual(len(res["audited"]), 1)
        self.assertEqual(len(res["errors"]), 2)
        self.assertIn("baris 2", res["errors"][0])
        self.assertIn("baris 3", res["errors"][1])


class Cli(unittest.TestCase):
    def _setup(self, d: str, stmt: dict, sigs: "list | None" = None):
        art = Path(d) / "artifact.bin"
        art.write_bytes(b"payload of artifact")
        prov = Path(d) / "prov.intoto.jsonl"
        env = mk_envelope(stmt, signatures=sigs)
        prov.write_text(json.dumps(env) + "\n", encoding="utf-8")
        return art, prov

    def test_matched_ok(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            art, prov = self._setup(d, mk_statement_v1(sha_hex(b"payload of artifact")))
            out = Path(d) / "out.json"
            rc = spa.main(["--provenance", str(prov),
                           "--artifact", str(art), "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"],
                             "secai.slsa-provenance-audit/1")
            doc = data["documents"][0]
            self.assertEqual(doc["bindings_matched"], 1)
            self.assertEqual(data["artifacts"]["artifact.bin"]["sha256"],
                             sha_hex(b"payload of artifact"))

    def test_policy_mismatch_exit1(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            art, prov = self._setup(d, mk_statement_v1(sha_hex(b"payload of artifact")))
            policy = Path(d) / "p.json"
            policy.write_text(json.dumps(
                {"source_uri": "github.com/evil/repo"}),
                encoding="utf-8")
            rc = spa.main(["--provenance", str(prov),
                           "--artifact", str(art),
                           "--policy", str(policy),
                           "--fail-on", "policy"])
            self.assertEqual(rc, 1)

    def test_no_artifact_fail_on_signature(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            art, prov = self._setup(d, mk_statement_v1(sha_hex(b"x")),
                                    sigs=[])
            rc = spa.main(["--provenance", str(prov), "--fail-on",
                           "signature"])
            self.assertEqual(rc, 1)

    def test_artifact_tidak_ada_exit2(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _, prov = self._setup(d, mk_statement_v1("a" * 64))
            rc = spa.main(["--provenance", str(prov),
                           "--artifact", str(Path(d) / "missing.bin")])
            self.assertEqual(rc, 2)

    def test_policy_typo_exit2(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            art, prov = self._setup(d, mk_statement_v1("a" * 64))
            policy = Path(d) / "p.json"
            policy.write_text(json.dumps({"sourc_uri": "x"}),
                              encoding="utf-8")
            rc = spa.main(["--provenance", str(prov),
                           "--artifact", str(art),
                           "--policy", str(policy)])
            self.assertEqual(rc, 2)

    def test_provenance_rusak_exit2(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            art = Path(d) / "artifact.bin"
            art.write_bytes(b"x")
            prov = Path(d) / "prov.intoto.jsonl"
            prov.write_text("{payload rusak\n", encoding="utf-8")
            rc = spa.main(["--provenance", str(prov),
                           "--artifact", str(art)])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
