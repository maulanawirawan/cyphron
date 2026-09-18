"""Security Knowledge Graph v2 (ROADMAP-UNITY U1).

Graph ringan zero-dependency (pure stdlib) yang memetakan hasil rekognisi
WorldModel + temuan menjadi node/edge berlabel sehingga planner bisa query
permukaan serangan, jalur anonim, antrean hipotesis, dan PROVENANCE
("node ini dicapai lewat apa") secara terstruktur.

Node kinds : TARGET, ENDPOINT, PARAM, TECHNOLOGY, HYPOTHESIS, IDENTITY,
             ROLE, OBJECT, CREDENTIAL, VULNERABILITY, EVIDENCE
Edge rels  : HAS_ENDPOINT, HAS_PARAM, USES, RAISED, HAS_IDENTITY,
             AUTHENTICATES_TO, ACCESSES, OWNS, EXPOSES, TARGETS,
             LEAKED_TO, REACHED_VIA (provenance), VERIFIED_BY
"""

from __future__ import annotations

import json
import sqlite3

__all__ = ["KnowledgeGraph", "build_from_world", "build_with_findings",
           "attack_paths", "provenance", "queries"]


class KnowledgeGraph:
    """Multigraph terarah ringan: node berkind + edge berlabel (rel).

    node_id selalu ``f"{kind}:{key}"``. Edge dedupe pada (src, rel, dst);
    re-add node/edge yang sama akan merge props. Semua accessor mengembalikan
    salinan sehingga pemanggil tidak bisa merusak state internal.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, dict] = {}   # id -> {"id", "kind", "props"}
        self._edges: dict[tuple, dict] = {}  # (src, rel, dst) -> {"src","rel","dst","props"}

    # ----------------------------------------------------------- mutators
    def add_node(self, kind: str, key: str, **props) -> str:
        """Tambah (atau merge props) node; return node_id ``{kind}:{key}``."""
        node_id = f"{kind}:{key}"
        node = self._nodes.get(node_id)
        if node is None:
            self._nodes[node_id] = {"id": node_id, "kind": kind, "props": dict(props)}
        else:
            node["props"].update(props)
        return node_id

    def add_edge(self, src_node_id: str, rel: str, dst_node_id: str, **props) -> None:
        """Tambah (atau merge props) edge berlabel src --rel--> dst."""
        ekey = (src_node_id, rel, dst_node_id)
        edge = self._edges.get(ekey)
        if edge is None:
            self._edges[ekey] = {
                "src": src_node_id, "rel": rel, "dst": dst_node_id,
                "props": dict(props),
            }
        else:
            edge["props"].update(props)

    # ---------------------------------------------------------- accessors
    def nodes(self, kind: str | None = None) -> list[dict]:
        """Daftar node {id, kind, props}; filter by kind bila diberikan."""
        return [
            {"id": n["id"], "kind": n["kind"], "props": dict(n["props"])}
            for n in self._nodes.values()
            if kind is None or n["kind"] == kind
        ]

    def edges(self, kind: str | None = None) -> list[dict]:
        """Daftar edge {src, rel, dst, props}; filter by rel bila diberikan."""
        return [
            {"src": e["src"], "rel": e["rel"], "dst": e["dst"], "props": dict(e["props"])}
            for e in self._edges.values()
            if kind is None or e["rel"] == kind
        ]

    def neighbors(self, node_id: str, rel: str | None = None) -> list[str]:
        """Node tujuan dari edge keluar (src == node_id), filter by rel."""
        return [
            e["dst"] for e in self._edges.values()
            if e["src"] == node_id and (rel is None or e["rel"] == rel)
        ]

    def stats(self) -> dict:
        """Jumlah node per kind dan edge per rel, mis. {"nodes": {...}, "edges": {...}}."""
        nodes_by_kind: dict[str, int] = {}
        for n in self._nodes.values():
            nodes_by_kind[n["kind"]] = nodes_by_kind.get(n["kind"], 0) + 1
        edges_by_kind: dict[str, int] = {}
        for e in self._edges.values():
            edges_by_kind[e["rel"]] = edges_by_kind.get(e["rel"], 0) + 1
        return {"nodes": nodes_by_kind, "edges": edges_by_kind}

    # ---------------------------------------------------------- serialize
    def to_json(self) -> str:
        """Serialisasi penuh graph (node + edge + props) ke string JSON."""
        return json.dumps(
            {"nodes": list(self._nodes.values()), "edges": list(self._edges.values())},
            ensure_ascii=False,
        )

    @classmethod
    def from_json(cls, s: str) -> "KnowledgeGraph":
        """Bangun ulang graph dari hasil to_json (round-trip aman)."""
        data = json.loads(s)
        g = cls()
        for n in data.get("nodes", []):
            g._nodes[n["id"]] = {
                "id": n["id"], "kind": n["kind"], "props": dict(n.get("props", {})),
            }
        for e in data.get("edges", []):
            g._edges[(e["src"], e["rel"], e["dst"])] = {
                "src": e["src"], "rel": e["rel"], "dst": e["dst"],
                "props": dict(e.get("props", {})),
            }
        return g

    # ------------------------------------------------------------- sqlite
    def save_sqlite(self, path: str) -> None:
        """Simpan graph ke file sqlite (tabel nodes & edges; props sebagai JSON)."""
        con = sqlite3.connect(path)
        try:
            cur = con.cursor()
            cur.execute("DROP TABLE IF EXISTS nodes")
            cur.execute("DROP TABLE IF EXISTS edges")
            cur.execute(
                "CREATE TABLE nodes ("
                " id TEXT PRIMARY KEY, kind TEXT, props_json TEXT)")
            cur.execute(
                "CREATE TABLE edges ("
                " src TEXT, rel TEXT, dst TEXT, props_json TEXT,"
                " PRIMARY KEY (src, rel, dst))")
            cur.executemany(
                "INSERT INTO nodes (id, kind, props_json) VALUES (?, ?, ?)",
                [(n["id"], n["kind"],
                  json.dumps(n["props"], ensure_ascii=False))
                 for n in self._nodes.values()])
            cur.executemany(
                "INSERT INTO edges (src, rel, dst, props_json) VALUES (?, ?, ?, ?)",
                [(e["src"], e["rel"], e["dst"],
                  json.dumps(e["props"], ensure_ascii=False))
                 for e in self._edges.values()])
            con.commit()
        finally:
            con.close()

    @classmethod
    def load_sqlite(cls, path: str) -> "KnowledgeGraph":
        """Muat graph dari file sqlite hasil save_sqlite (round-trip aman)."""
        g = cls()
        con = sqlite3.connect(path)
        try:
            cur = con.cursor()
            for nid, kind, props_json in cur.execute(
                    "SELECT id, kind, props_json FROM nodes"):
                g._nodes[nid] = {
                    "id": nid, "kind": kind,
                    "props": json.loads(props_json) if props_json else {},
                }
            for src, rel, dst, props_json in cur.execute(
                    "SELECT src, rel, dst, props_json FROM edges"):
                g._edges[(src, rel, dst)] = {
                    "src": src, "rel": rel, "dst": dst,
                    "props": json.loads(props_json) if props_json else {},
                }
        finally:
            con.close()
        return g


# ------------------------------------------------------------------ builder
def build_from_world(world) -> KnowledgeGraph:
    """Proyeksikan WorldModel menjadi Security Knowledge Graph.

    Node: TARGET(target), ENDPOINT(url; props status/method),
    PARAM("{url}:{param}"), TECHNOLOGY(nama), HYPOTHESIS(id; props
    status/decision), IDENTITY("anonymous" selalu, "authenticated" bila ada
    teknologi mengandung "session").

    Edge: TARGET-HAS_ENDPOINT->ENDPOINT, ENDPOINT-HAS_PARAM->PARAM,
    TARGET-USES->TECHNOLOGY, TARGET-RAISED->HYPOTHESIS,
    TARGET-HAS_IDENTITY->IDENTITY, dan IDENTITY:authenticated
    -AUTHENTICATES_TO->ENDPOINT yang memiliki form field password (bila ada).
    """
    g = KnowledgeGraph()
    target_id = g.add_node("TARGET", world.target or "", mode=world.mode)

    for url, ep in world.endpoints.items():
        endpoint_id = g.add_node(
            "ENDPOINT", url, status=ep.status, method=ep.method,
            form_fields=list(ep.form_fields))
        g.add_edge(target_id, "HAS_ENDPOINT", endpoint_id)
        for param in ep.params:
            param_id = g.add_node("PARAM", f"{url}:{param}")
            g.add_edge(endpoint_id, "HAS_PARAM", param_id)

    for tech in world.technologies:
        tech_id = g.add_node("TECHNOLOGY", tech)
        g.add_edge(target_id, "USES", tech_id)

    for hyp in world.hypotheses:
        hyp_id = g.add_node(
            "HYPOTHESIS", hyp.get("id", ""),
            status=hyp.get("status"), decision=hyp.get("decision"))
        g.add_edge(target_id, "RAISED", hyp_id)

    has_session = any("session" in str(name).lower() for name in world.technologies)
    identities = ["anonymous"] + (["authenticated"] if has_session else [])
    for ident in identities:
        identity_id = g.add_node("IDENTITY", ident)
        g.add_edge(target_id, "HAS_IDENTITY", identity_id)
        g.add_edge(identity_id, "ACCESSES", target_id)

    if has_session:
        for url, ep in world.endpoints.items():
            if any("password" in str(f).lower() for f in ep.form_fields):
                g.add_edge("IDENTITY:authenticated", "AUTHENTICATES_TO",
                           f"ENDPOINT:{url}")

    return g


# ------------------------------------------------------------- v2: findings
def build_with_findings(world, findings) -> KnowledgeGraph:
    """v1 build + proyeksi temuan ke graph ( Vulnerability/Evidence/Object ).

    Per temuan:
    - VULNERABILITY:{id} (props: title, severity, status, tool, cwe)
    - ENDPOINT yang ditemukan-nya diurl -EXPOSES-> VULNERABILITY
    - EVIDENCE:{sha} per entri evidence_chain -VERIFIED_BY-> dari VULNERABILITY
      (bukti tinggal di graph, bukan hanya di objek Finding)
    - OBJECT:{param} bila finding.param ada; VULNERABILITY-TARGETS->OBJECT
    - provenance: VULNERABILITY-REACHED_VIA->ENDPOINT dengan props
      via=tool penemunya ("sampai sini lewat apa").
    """
    g = build_from_world(world)
    for f in findings:
        vuln_id = g.add_node(
            "VULNERABILITY", getattr(f, "id", "") or "",
            title=getattr(f, "title", ""), severity=getattr(f, "severity", ""),
            status=getattr(f, "status", ""), tool=getattr(f, "tool", ""),
            cwe=getattr(f, "cwe", "") or "")
        url = getattr(f, "target_url", None) or ""
        if url:
            ep_id = g.add_node("ENDPOINT", url)
            g.add_edge(ep_id, "EXPOSES", vuln_id)
            g.add_edge(vuln_id, "REACHED_VIA", ep_id,
                       via=getattr(f, "tool", ""))
        param = getattr(f, "param", None)
        if param:
            obj_id = g.add_node("OBJECT", f"{url}:{param}" if url else str(param))
            g.add_edge(vuln_id, "TARGETS", obj_id)
        for ev in (getattr(f, "evidence_chain", None) or []):
            sha = str(ev.get("sha256", ""))[:16] if isinstance(ev, dict) else str(ev)[:16]
            kind = ev.get("kind", "") if isinstance(ev, dict) else "raw"
            ev_id = g.add_node("EVIDENCE", sha, evidence_kind=kind)
            g.add_edge(vuln_id, "VERIFIED_BY", ev_id)
    return g


# ------------------------------------------------------- v2: graph reasoning
def attack_paths(g: KnowledgeGraph, start_node_id: str, end_node_id: str,
                 max_hops: int = 8, max_paths: int = 20) -> list[list[str]]:
    """Semua simple path start->end (BFS deterministik, urut nama tetangga).

    Return list of node-id chains (termasuk ujung). Terbatas max_hops dan
    max_paths supaya tetap murah di graph besar."""
    out: list[list[str]] = []
    if start_node_id not in {n["id"] for n in g.nodes()}:
        return out
    queue: list[tuple[str, list[str]]] = [(start_node_id, [start_node_id])]
    while queue and len(out) < max_paths:
        cur, path = queue.pop(0)
        if cur == end_node_id:
            out.append(path)
            continue
        if len(path) > max_hops:
            continue
        for nxt in sorted(g.neighbors(cur)):
            if nxt in path:
                continue
            queue.append((nxt, path + [nxt]))
    return out


def provenance(g: KnowledgeGraph, node_id: str, depth: int = 3) -> list[dict]:
    """Jawab 'node ini dicapai lewat apa': telusuri edge MASUK hingga depth.

    Return daftar {step, via, src, rel, dst} urut terdekat-dulu (BFS
    deterministik). via = props["via"] bila ada, kosong bila tidak."""
    steps: list[dict] = []
    seen = {node_id}
    frontier = [node_id]
    for level in range(1, depth + 1):
        nxt_frontier: list[str] = []
        for cur in sorted(frontier):
            ins = sorted(
                (e for e in g.edges() if e["dst"] == cur),
                key=lambda e: (e["rel"], e["src"]))
            for e in ins:
                steps.append({
                    "step": level, "via": str(e["props"].get("via", "")),
                    "src": e["src"], "rel": e["rel"], "dst": e["dst"],
                })
                if e["src"] not in seen:
                    seen.add(e["src"])
                    nxt_frontier.append(e["src"])
        frontier = nxt_frontier
        if not frontier:
            break
    return steps
def _node_key(node_id: str) -> str:
    """Ambil key asli dari node_id (bagian setelah kind prefix pertama)."""
    return node_id.split(":", 1)[1] if ":" in node_id else node_id


def _endpoint_rows(g: KnowledgeGraph, endpoints: list[dict]) -> list[dict]:
    return [
        {
            "id": n["id"],
            "url": _node_key(n["id"]),
            "status": n["props"].get("status"),
            "method": n["props"].get("method"),
        }
        for n in endpoints
    ]


def queries(g: KnowledgeGraph) -> dict:
    """Kumpulan query siap-pakai atas Security Knowledge Graph.

    - attack_surfaces(): endpoint berstatus 200/401/403 (menarik untuk probe).
    - unauthenticated_paths(): semua endpoint yang diketahui (scan anonim).
    - hypothesis_queue(): hipotesis berstatus PENDING/CONFIRMED, urut id.
    """

    def attack_surfaces() -> list[dict]:
        interesting = (200, 401, 403)
        return _endpoint_rows(g, [
            n for n in g.nodes("ENDPOINT") if n["props"].get("status") in interesting
        ])

    def unauthenticated_paths() -> list[dict]:
        # Scan berjalan sebagai identitas anonymous -> semua endpoint diketahui
        # adalah path yang terlihat oleh identitas tersebut.
        return _endpoint_rows(g, g.nodes("ENDPOINT"))

    def hypothesis_queue() -> list[dict]:
        actionable = ("PENDING", "CONFIRMED")
        rows = [
            {
                "id": _node_key(n["id"]),
                "status": n["props"].get("status"),
                "decision": n["props"].get("decision"),
            }
            for n in g.nodes("HYPOTHESIS")
            if n["props"].get("status") in actionable
        ]
        rows.sort(key=lambda r: r["id"])
        return rows

    return {
        "attack_surfaces": attack_surfaces,
        "unauthenticated_paths": unauthenticated_paths,
        "hypothesis_queue": hypothesis_queue,
    }
