"""Nol jaringan — test graphql_depth_audit (analisis introspection JSON).

Fixture skema dibangun inline: siklus User<->Post, rantai aciklis,
field root LIST, mutation; bentuk wrapper data.__schema & __schema
langsung. Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import graphql_depth_audit as gda  # noqa: E402
from findings import validate_finding  # noqa: E402


def obj(name: str, fields: list[tuple[str, dict]]) -> dict:
    return {"kind": "OBJECT", "name": name,
            "fields": [{"name": n, "type": t} for n, t in fields]}


def ref(name: str, list_wrap: bool = False, non_null: bool = False) -> dict:
    r: dict = {"kind": "OBJECT", "name": name, "ofType": None}
    if list_wrap:
        r = {"kind": "LIST", "name": None, "ofType": r}
    if non_null:
        r = {"kind": "NON_NULL", "name": None, "ofType": r}
    return r


def cyclic_schema() -> dict:
    """Query.user -> User {posts: [Post]}, Post {author: User}."""
    types = [
        obj("Query", [("user", ref("User")), ("users", ref("User",
                                                           list_wrap=True))]),
        obj("User", [("name", {"kind": "SCALAR", "name": "String",
                               "ofType": None}),
                     ("posts", ref("Post", list_wrap=True))]),
        obj("Post", [("title", {"kind": "SCALAR", "name": "String",
                                "ofType": None}),
                     ("author", ref("User"))]),
        obj("Mutation", [("createPost", ref("Post"))]),
    ]
    return {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": types,
    }}


def acyclic_schema() -> dict:
    """Query -> A -> B -> C (scalar leaf); tanpa siklus."""
    types = [
        obj("Query", [("a", ref("A", non_null=True))]),
        obj("A", [("b", ref("B"))]),
        obj("B", [("c", ref("C"))]),
        obj("C", [("leaf", {"kind": "SCALAR", "name": "Int",
                            "ofType": None})]),
    ]
    return {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": None,
        "subscriptionType": None,
        "types": types,
    }}}


class GraphqlDepthAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="gda_t"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, doc: dict, name: str = "schema.json") -> Path:
        p = self.tmp / name
        p.write_text(json.dumps(doc), encoding="utf-8")
        return p

    def test_cycle_detected_with_wrappers(self) -> None:
        cyc, depth = gda.find_cycles_from_root(
            {"Query": ["User"], "User": ["Post"], "Post": ["User"]},
            "Query")
        self.assertEqual(len(cyc), 1)
        self.assertEqual(cyc[0][0], "User")
        self.assertEqual(cyc[0][-1], "User")

    def test_full_flow_cycle(self) -> None:
        out = self.tmp / "f.json"
        rc = gda.main(["--schema", str(self._write(cyclic_schema())),
                       "--out", str(out)])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["data"]["cycles"], 1)
        self.assertTrue(doc["data"]["query_list_fields"] == ["users"])
        cycle_f = [f for f in doc["findings"]
                   if f["finding_class"] == "weakness"]
        self.assertEqual(len(cycle_f), 1)
        self.assertIn("User", cycle_f[0]["poc"])
        self.assertIn("Post", cycle_f[0]["poc"])
        self.assertEqual(cycle_f[0]["verdict"], 2)
        for f in doc["findings"]:
            self.assertEqual(validate_finding(f), [])

    def test_acyclic_clean_exit_0(self) -> None:
        out = self.tmp / "clean.json"
        rc = gda.main(["--schema", str(self._write(acyclic_schema())),
                       "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["data"]["cycles"], 0)
        self.assertEqual(doc["data"]["max_acyclic_depth"], 4)

    def test_fail_closed_cases(self) -> None:
        out = self.tmp / "bad.json"
        # bukan introspection
        p1 = self.tmp / "s1.json"
        p1.write_text('{"foo": 1}', encoding="utf-8")
        self.assertEqual(gda.main(["--schema", str(p1), "--out",
                                   str(out)]), 2)
        # types kosong
        p2 = self.tmp / "s2.json"
        p2.write_text(json.dumps({"__schema": {"queryType": {"name": "Q"},
                                               "types": []}}),
                      encoding="utf-8")
        self.assertEqual(gda.main(["--schema", str(p2), "--out",
                                   str(out)]), 2)
        # ref LIST tanpa ofType
        p3 = self.tmp / "s3.json"
        p3.write_text(json.dumps({"__schema": {
            "queryType": {"name": "Q"},
            "types": [{"kind": "OBJECT", "name": "Q",
                       "fields": [{"name": "x",
                                   "type": {"kind": "LIST"}}]}]}}),
                      encoding="utf-8")
        self.assertEqual(gda.main(["--schema", str(p3), "--out",
                                   str(out)]), 2)
        # tipe terpotong
        partial = cyclic_schema()
        partial["__schema"]["types"] = [
            t for t in partial["__schema"]["types"] if t["name"] != "Post"]
        self.assertEqual(gda.main(["--schema", str(self._write(partial)),
                                   "--out", str(out)]), 2)
        # file tidak ada / JSON rusak
        self.assertEqual(gda.main(["--schema", str(self.tmp / "no.json"),
                                   "--out", str(out)]), 2)
        p4 = self.tmp / "s4.json"
        p4.write_text("{bukan json", encoding="utf-8")
        self.assertEqual(gda.main(["--schema", str(p4), "--out",
                                   str(out)]), 2)
        self.assertFalse(out.exists())

    def test_list_root_fields_alias_amplification(self) -> None:
        schema = cyclic_schema()["__schema"]
        lst = gda.list_root_fields(schema, "Query", {})
        self.assertEqual(lst, ["users"])
        m = gda.list_root_fields(schema, "Mutation", {})
        self.assertEqual(m, [])  # createPost -> Post tunggal, bukan LIST


if __name__ == "__main__":
    unittest.main()
