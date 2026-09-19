"""Unit tests untuk Security Knowledge Graph v1 (cyphron.graph).

Cakupan:
- KnowledgeGraph dasar: add_node/add_edge, nodes/edges, neighbors, stats
- Round-trip to_json/from_json dan save_sqlite/load_sqlite
- build_from_world dengan WorldModel sintetis -> jenis node & edge sesuai
- queries: attack_surfaces hanya status 200/401/403, unauthenticated_paths,
  hypothesis_queue urut id dengan status PENDING/CONFIRMED saja.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.graph import KnowledgeGraph, build_from_world, queries
from cyphron.world.model import Endpoint, WorldModel


def _make_world() -> WorldModel:
    """WorldModel sintetis: endpoint beragam status, tech session, hipotesis."""
    w = WorldModel(target="https://lab.example.test", mode="read-only")
    w.technologies = {
        "Server: nginx/1.24.0": "header on /",
        "session cookie": "SID",
    }
    w.endpoints = {
        "https://lab.example.test/": Endpoint(
            url="https://lab.example.test/", status=200, method="GET", params=["q"]),
        "https://lab.example.test/login": Endpoint(
            url="https://lab.example.test/login", status=200, method="POST",
            form_fields=["username", "password"]),
        "https://lab.example.test/admin": Endpoint(
            url="https://lab.example.test/admin", status=403, method="GET"),
        "https://lab.example.test/api/me": Endpoint(
            url="https://lab.example.test/api/me", status=401, method="GET",
            params=["id"]),
        "https://lab.example.test/redirect": Endpoint(
            url="https://lab.example.test/redirect", status=302, method="GET"),
        "https://lab.example.test/missing": Endpoint(
            url="https://lab.example.test/missing", status=404, method="GET"),
    }
    w.hypotheses = [
        {"id": "H03", "claim": "IDOR pada /api/me", "evidence": "param id",
         "decision": "", "status": "PENDING"},
        {"id": "H01", "claim": "SQLi pada / ?q", "evidence": "error-based",
         "decision": "", "status": "PENDING"},
        {"id": "H02", "claim": "auth bypass /admin", "evidence": "403 anon",
         "decision": "confirmed", "status": "CONFIRMED"},
        {"id": "H04", "claim": "SSTI pada lupa sandi", "evidence": "-",
         "decision": "rejected", "status": "REJECTED"},
    ]
    return w


def _make_graph() -> KnowledgeGraph:
    """Graph kecil dengan props variatif (str/int/list/None/bool) uji round-trip."""
    g = KnowledgeGraph()
    g.add_node("TARGET", "https://t.example", mode="read-only")
    g.add_node("ENDPOINT", "https://t.example/a", status=200, method="GET",
               tags=["x"], flag=True, note=None)
    g.add_node("ENDPOINT", "https://t.example/b", status=401, method="POST")
    g.add_node("IDENTITY", "anonymous")
    g.add_edge("TARGET:https://t.example", "HAS_ENDPOINT",
               "ENDPOINT:https://t.example/a")
    g.add_edge("TARGET:https://t.example", "HAS_ENDPOINT",
               "ENDPOINT:https://t.example/b")
    g.add_edge("TARGET:https://t.example", "HAS_IDENTITY", "IDENTITY:anonymous",
               scope="anon")
    return g


class TestKnowledgeGraphCore(unittest.TestCase):

    def test_add_node_id_and_merge(self):
        g = KnowledgeGraph()
        nid = g.add_node("ENDPOINT", "https://t.example/a", status=200)
        self.assertEqual(nid, "ENDPOINT:https://t.example/a")
        # re-add dengan kind+key sama -> merge props, tidak duplikasi node
        nid2 = g.add_node("ENDPOINT", "https://t.example/a", method="GET")
        self.assertEqual(nid2, nid)
        self.assertEqual(len(g.nodes("ENDPOINT")), 1)
        self.assertEqual(g.nodes("ENDPOINT")[0]["props"],
                         {"status": 200, "method": "GET"})

    def test_nodes_filter_by_kind(self):
        g = _make_graph()
        kinds = {n["kind"] for n in g.nodes()}
        self.assertEqual(kinds, {"TARGET", "ENDPOINT", "IDENTITY"})
        self.assertEqual(len(g.nodes("ENDPOINT")), 2)
        self.assertTrue(all(n["kind"] == "ENDPOINT" for n in g.nodes("ENDPOINT")))

    def test_edges_and_filter_by_rel(self):
        g = _make_graph()
        self.assertEqual(len(g.edges()), 3)
        has_ep = g.edges("HAS_ENDPOINT")
        self.assertEqual(len(has_ep), 2)
        self.assertTrue(all(e["rel"] == "HAS_ENDPOINT" for e in has_ep))
        self.assertIn({"src": "TARGET:https://t.example", "rel": "HAS_ENDPOINT",
                       "dst": "ENDPOINT:https://t.example/a", "props": {}}, has_ep)

    def test_neighbors_with_and_without_rel(self):
        g = KnowledgeGraph()
        a, b, c, d = "KIND:a", "KIND:b", "KIND:c", "KIND:d"
        for nid in (a, b, c, d):
            g.add_node("KIND", nid.split(":", 1)[1])
        g.add_edge(a, "REL", b)
        g.add_edge(a, "REL", c)
        g.add_edge(a, "OTHER", d)
        g.add_edge(b, "REL", d)
        self.assertEqual(g.neighbors(a), [b, c, d])
        self.assertEqual(g.neighbors(a, "REL"), [b, c])
        self.assertEqual(g.neighbors(a, "OTHER"), [d])
        self.assertEqual(g.neighbors(d), [])
        self.assertEqual(g.neighbors("KIND:missing"), [])

    def test_stats_counts_per_kind(self):
        g = _make_graph()
        stats = g.stats()
        self.assertEqual(stats["nodes"], {"TARGET": 1, "ENDPOINT": 2, "IDENTITY": 1})
        self.assertEqual(stats["edges"], {"HAS_ENDPOINT": 2, "HAS_IDENTITY": 1})

    def test_roundtrip_json(self):
        g = _make_graph()
        g2 = KnowledgeGraph.from_json(g.to_json())
        self.assertEqual(g2.nodes(), g.nodes())
        self.assertEqual(g2.edges(), g.edges())
        self.assertEqual(g2.stats(), g.stats())
        self.assertEqual(g2.to_json(), g.to_json())  # stabil & simetris


class TestBuildFromWorld(unittest.TestCase):

    def setUp(self):
        self.g = build_from_world(_make_world())

    def test_all_node_kinds_present(self):
        kinds = {n["kind"] for n in self.g.nodes()}
        self.assertEqual(kinds, {"TARGET", "ENDPOINT", "PARAM",
                                 "TECHNOLOGY", "HYPOTHESIS", "IDENTITY"})

    def test_endpoint_nodes_have_status_method(self):
        eps = {n["id"]: n["props"] for n in self.g.nodes("ENDPOINT")}
        login = eps["ENDPOINT:https://lab.example.test/login"]
        self.assertEqual((login["status"], login["method"]), (200, "POST"))
        self.assertIn("password", login.get("form_fields", []))
        self.assertEqual(len(eps), 6)

    def test_param_nodes_keyed_url_param(self):
        pids = {n["id"] for n in self.g.nodes("PARAM")}
        self.assertEqual(pids, {
            "PARAM:https://lab.example.test/:q",
            "PARAM:https://lab.example.test/api/me:id",
        })

    def test_identity_anonymous_always_and_authenticated_on_session(self):
        ids = {n["id"] for n in self.g.nodes("IDENTITY")}
        self.assertEqual(ids, {"IDENTITY:anonymous", "IDENTITY:authenticated"})

    def test_edge_relations(self):
        rels = {e["rel"] for e in self.g.edges()}
        self.assertEqual(rels, {"HAS_ENDPOINT", "HAS_PARAM", "USES",
                                "RAISED", "HAS_IDENTITY", "AUTHENTICATES_TO",
                                "ACCESSES"})
        target = "TARGET:https://lab.example.test"
        self.assertEqual(len(self.g.neighbors(target, "HAS_ENDPOINT")), 6)
        self.assertEqual(len(self.g.neighbors(target, "USES")), 2)
        self.assertEqual(len(self.g.neighbors(target, "RAISED")), 4)
        self.assertEqual(len(self.g.neighbors(target, "HAS_IDENTITY")), 2)
        # form password di /login -> AUTHENTICATES_TO dari identity authenticated
        self.assertEqual(
            self.g.neighbors("IDENTITY:authenticated", "AUTHENTICATES_TO"),
            ["ENDPOINT:https://lab.example.test/login"])

    def test_hypothesis_props(self):
        hyps = {n["id"]: n["props"] for n in self.g.nodes("HYPOTHESIS")}
        self.assertEqual(hyps["HYPOTHESIS:H02"],
                         {"status": "CONFIRMED", "decision": "confirmed"})

    def test_no_session_tech_means_no_authenticated_identity(self):
        w = _make_world()
        w.technologies = {"Server: nginx/1.24.0": "header on /"}
        g = build_from_world(w)
        self.assertEqual({n["id"] for n in g.nodes("IDENTITY")},
                         {"IDENTITY:anonymous"})
        self.assertEqual(g.edges("AUTHENTICATES_TO"), [])


class TestSqliteRoundTrip(unittest.TestCase):

    def test_save_load_sqlite_preserves_graph(self):
        g = _make_graph()
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "graph.sqlite")
            g.save_sqlite(path)
            g2 = KnowledgeGraph.load_sqlite(path)
            self.assertEqual(g2.stats(), g.stats())
            self.assertEqual(g2.nodes(), g.nodes())
            self.assertEqual(g2.edges(), g.edges())

    def test_sqlite_schema_tables_and_columns(self):
        g = build_from_world(_make_world())
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "graph.sqlite")
            g.save_sqlite(path)
            con = sqlite3.connect(path)
            try:
                cur = con.cursor()
                tables = {r[0] for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertTrue({"nodes", "edges"} <= tables)
                cols_nodes = [r[1] for r in cur.execute("PRAGMA table_info(nodes)")]
                cols_edges = [r[1] for r in cur.execute("PRAGMA table_info(edges)")]
                self.assertEqual(cols_nodes, ["id", "kind", "props_json"])
                self.assertEqual(cols_edges, ["src", "rel", "dst", "props_json"])
            finally:
                con.close()

    def test_build_from_world_sqlite_roundtrip_stats(self):
        g = build_from_world(_make_world())
        before = g.stats()
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "world.sqlite")
            g.save_sqlite(path)
            g2 = KnowledgeGraph.load_sqlite(path)
            self.assertEqual(g2.stats(), before)


class TestQueries(unittest.TestCase):

    def setUp(self):
        self.q = queries(build_from_world(_make_world()))

    def test_attack_surfaces_only_200_401_403(self):
        surfaces = self.q["attack_surfaces"]()
        self.assertTrue(surfaces)
        allowed = {200, 401, 403}
        for row in surfaces:
            self.assertIn(row["status"], allowed)
        urls = {row["url"] for row in surfaces}
        self.assertEqual(urls, {
            "https://lab.example.test/",
            "https://lab.example.test/login",
            "https://lab.example.test/admin",
            "https://lab.example.test/api/me",
        })  # 302 dan 404 tidak masuk permukaan serangan

    def test_unauthenticated_paths_covers_all_endpoints(self):
        rows = self.q["unauthenticated_paths"]()
        self.assertEqual(len(rows), 6)
        self.assertEqual({r["url"] for r in rows},
                         {f"https://lab.example.test{p}" for p in
                          ("/", "/login", "/admin", "/api/me", "/redirect", "/missing")})

    def test_hypothesis_queue_pending_confirmed_sorted(self):
        rows = self.q["hypothesis_queue"]()
        self.assertEqual([r["id"] for r in rows], ["H01", "H02", "H03"])
        self.assertTrue(all(r["status"] in ("PENDING", "CONFIRMED") for r in rows))


if __name__ == "__main__":
    unittest.main()
