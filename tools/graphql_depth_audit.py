r"""[SAFETY: read-only] graphql_depth_audit — audit kedalaman & siklus
skema GraphQL dari hasil INTROSPEKSI TERSEDIA (JSON). NOL jaringan,
read-only, stdlib murni.

Port INTI DETERMINISTIK dari dua skill antrean SKILL-PORT-QUEUE:
  #0823 mukul975/Anthropic-Cybersecurity-Skills
       'performing-graphql-depth-limit-attack'  -> deteksi siklus tipe
       (recursive relation) yang memungkinkan query bersarang tak terbatas
  #0825 mukul975/Anthropic-Cybersecurity-Skills
       'performing-graphql-security-assessment' -> sisi statis: permukaan
       mutasi/subscription + field root bertipe LIST (bahan alias
       amplification)
(Konsep sumber Apache-2.0, atribusi di sini — konsep, bukan teks.)

RANAH: analisis OFFLINE atas skema tersimpan. Eksekusi query bersarang
nyata terhadap server = serangan hidup di luar bentuk tool ini (target
berizin, alat uji terpisah). Introspection live = graphql_schema_map
(skills/, 1-request); deteksi permukaan /graphql = graphql_surface_
detector (skills/, 0-request).

Mekanisme:
  1. Parse introspection JSON: bentuk {"data":{"__schema":...}} ATAU
     {"__schema":...} langsung. WAJIB membawa type refs (fields[].type
     kind/ofType) — skema tanpa tipe = fail-closed (exit 2), bukan
     "dianalisis seadanya".
  2. Graf tipe: edge = field object-type yang menunjuk object lain.
     DFS dari query root: siklus (User->posts->Post->author->User)
     = permukaan depth-attack terstruktur (query bisa bersarang tak
     terbatas KECUALI server menegakkan depth/complexity limit — itu
     tidak terlihat dari skema, jadi TEMUAN = fakta struktur + rekom-
     endasi limit, BUKAN klaim DoS).
  3. Kedalaman maksimum TAK-SIKLIS dari root (batas bawah kedalaman
     yang sah); dgn siklus, kedalaman aktual TAK TERBATAS.
  4. Amplifikasi alias: field root (query/mutation) bertipe LIST =
     kandidat alias a1:..a10: dalam SATU request.
  5. Permukaan mutasi/subscription dihitung (fakta).

Verdict: siklus = fakta struktur terbukti dari skema -> status confirmed,
evidence_kind "arithmetic", verdict L3, poc = rantai path lengkap.
Severity medium (butuh konfirmasi limit server sebelum jadi temuan
DoS — NO-FP). Lainnya info.

Fail-closed: file tidak ada / JSON rusak / tanpa __schema / tanpa
queryType / tipe tidak lengkap -> exit 2.

Pemakaian:
  python tools/graphql_depth_audit.py --schema schema.json --out f.json
Exit: 0 tanpa siklus, 1 ada siklus/temuan, 2 error input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "secai.graphql-depth-audit/1"
MAX_DEPTH_REPORT = 64  # batas panjang path di poc (bisa ratusan)


class SchemaError(ValueError):
    pass


def _unwrap_type(ref: dict) -> str | None:
    """Kembalikan nama object di balik NON_NULL/LIST; None bila bukan."""
    kind = ref.get("kind")
    if kind in ("NON_NULL", "LIST"):
        nxt = ref.get("ofType")
        if nxt is None:
            raise SchemaError(
                f"ref {kind} tanpa ofType — introspection tidak lengkap")
        return _unwrap_type(nxt)
    if kind == "OBJECT":
        return ref.get("name")
    return None


def parse_schema(doc: dict) -> tuple[dict, dict[str, list[str]], dict]:
    """Parse JSON -> (schema, {tipe: [field]}, meta). Fail-closed."""
    if not isinstance(doc, dict):
        raise SchemaError("bukan objek JSON")
    schema = None
    if isinstance(doc.get("__schema"), dict):
        schema = doc["__schema"]
    elif isinstance(doc.get("data"), dict) and \
            isinstance(doc["data"].get("__schema"), dict):
        schema = doc["data"]["__schema"]
    if schema is None:
        raise SchemaError("tanpa __schema — bukan hasil introspection")

    types = schema.get("types")
    if not isinstance(types, list) or not types:
        raise SchemaError("__schema.types kosong — introspection tidak "
                          "lengkap (query penuh: types{kind name fields{"
                          "name type{kind name ofType{...}}}})")

    fields_by_type: dict[str, list[str]] = {}
    type_kind: dict[str, str] = {}
    for t in types:
        name = t.get("name")
        kind = t.get("kind")
        if not name or not kind:
            raise SchemaError("tipe tanpa name/kind")
        if name.startswith("__"):
            continue  # tipe introspeksi
        type_kind[name] = kind
        fields = []
        for f in t.get("fields") or []:
            fname = f.get("name")
            fref = f.get("type")
            if not fname or not isinstance(fref, dict):
                raise SchemaError(
                    f"field tanpa name/type pada tipe {name} — butuh "
                    "introspection penuh dgn type refs")
            target = _unwrap_type(fref)
            if target and target in type_kind:
                fields.append(target)
            elif target and target not in fields_by_type and \
                    not target.startswith("__"):
                # object belum terdaftar (urutan) — catat sementara
                fields.append(target)
        fields_by_type[name] = fields

    # validasi semua target object dikenal (fail-closed utk skema terpotong)
    for tname, fl in fields_by_type.items():
        for target in fl:
            if target not in type_kind:
                raise SchemaError(
                    f"tipe {target} (dari {tname}) tidak ada di __schema"
                    ".types — introspection terpotong")

    q = schema.get("queryType") or {}
    qname = q.get("name")
    if not qname:
        raise SchemaError("tanpa queryType.name")
    meta = {
        "query_type": qname,
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "subscription_type": (schema.get("subscriptionType") or {}).get(
            "name"),
    }
    return schema, fields_by_type, meta


def find_cycles_from_root(fields_by_type: dict[str, list[str]],
                          root: str) -> tuple[list[list[str]], int]:
    """DFS dari root: kumpulkan siklus + kedalaman tak-siklis maksimum."""
    cycles: list[list[str]] = []
    seen_cycles: set[tuple[str, ...]] = set()
    max_depth = 0

    def dfs(node: str, path: list[str], on_path: set[str]) -> None:
        nonlocal max_depth
        max_depth = max(max_depth, len(path))
        for target in fields_by_type.get(node, []):
            if target in on_path:
                i = path.index(target)
                cyc = tuple(path[i:])
                key = frozenset(cyc)
                if key not in seen_cycles:
                    seen_cycles.add(key)
                    cycles.append(path[i:] + [target])
                continue
            dfs(target, path + [target], on_path | {target})

    dfs(root, [root], {root})
    return cycles, max_depth


def list_root_fields(schema: dict, root_name: str | None,
                     fields_by_type: dict[str, list[str]]) -> list[str]:
    """Field root yang membungkus LIST di lapisan terluar (bahan alias
    amplification)."""
    if not root_name:
        return []
    t = next((x for x in schema.get("types", [])
              if x.get("name") == root_name), None)
    if not t:
        return []
    out: list[str] = []
    for f in t.get("fields") or []:
        ref = f.get("type") or {}
        cur = ref
        while cur.get("kind") == "NON_NULL":
            cur = cur.get("ofType") or {}
        if cur.get("kind") == "LIST":
            out.append(f.get("name", ""))
    return [n for n in out if n]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] graphql_depth_audit — audit "
                    "kedalaman/siklus skema dari introspection tersimpan "
                    "(NOL jaringan)")
    ap.add_argument("--schema", required=True,
                    help="JSON introspection (data.__schema / __schema)")
    ap.add_argument("--out", default="graphql_depth_audit_findings.json")
    args = ap.parse_args(argv)

    p = Path(args.schema)
    if not p.is_file():
        print(f"[graphql_depth_audit] skema tidak ada: {p} (fail-closed)",
              file=sys.stderr)
        return 2
    try:
        doc = json.loads(p.read_text(encoding="utf-8-sig"))
        schema, fields_by_type, meta = parse_schema(doc)
    except (json.JSONDecodeError, SchemaError) as exc:
        print(f"[graphql_depth_audit] {exc} (fail-closed)", file=sys.stderr)
        return 2

    root = meta["query_type"]
    cycles, max_depth = find_cycles_from_root(fields_by_type, root)
    q_lists = list_root_fields(schema, root, fields_by_type)
    m_lists = list_root_fields(schema, meta["mutation_type"], fields_by_type)

    findings: list[dict] = []
    for cyc in cycles:
        chain = " -> ".join(cyc)
        poc = chain if len(chain) <= 300 else chain[:300] + " ..."
        findings.append(make_finding(
            tool="graphql-depth-audit",
            title=f"siklus tipe GraphQL: {cyc[0]} <-> {cyc[-2]}"
                  if len(cyc) > 1 else f"siklus tipe: {cyc[0]}",
            severity="medium",
            description=(
                f"Skema mengandung siklus {chain} dari root {root}. "
                "Query bersarang bisa dibangun TAK TERBATAS dalam satu "
                "request kecuali server menegakkan query depth/complexity "
                "limit — batasan itu TIDAK terlihat dari introspection, "
                "jadi temuan ini fakta struktur + kebutuhan konfirmasi "
                "limit, bukan klaim DoS"),
            recommendation=(
                "Pastikan server menegakkan depth limit (mis. <=10), "
                "complexity/depth analysis, atau pagination wajib pada "
                "field list dalam siklus; uji limit dengan SATU query "
                "bersarang terkendali pada target berizin"),
            poc=poc,
            evidence_kind="arithmetic",
            finding_class="weakness",
            confidence=1.0,
            status="confirmed",
            verdict=2,
            extra={"cycle": cyc, "root": root, "schema": SCHEMA},
        ))
    if max_depth >= 2:
        findings.append(make_finding(
            tool="graphql-depth-audit",
            title=f"kedalaman tak-siklis maksimum {max_depth} dari {root}",
            severity="info",
            description=(
                f"Rantai object terpanjang tanpa pengulangan = {max_depth} "
                "level — batas bawah kedalaman sah; dgn siklus, kedalaman "
                "aktual tak terbatas"
                if cycles else
                f"Rantai object terpanjang = {max_depth} level dari root "
                f"{root} — skema tanpa siklus dari root"),
            recommendation="Bandingkan dgn depth limit server; limit di "
                           "bawah kedalaman sah yang dibutuhkan klien = "
                           "rusak fungsionalitas",
            evidence_kind="arithmetic",
            finding_class="observation",
            confidence=1.0,
            status="confirmed",
            verdict=2,
            extra={"max_acyclic_depth": max_depth, "root": root,
                   "schema": SCHEMA},
        ))
    if q_lists or m_lists:
        findings.append(make_finding(
            tool="graphql-depth-audit",
            title=f"amplifikasi alias: {len(q_lists)} field query + "
                  f"{len(m_lists)} field mutation bertipe LIST",
            severity="info",
            description=(
                f"Field root bertipe LIST: query={q_lists} "
                f"mutation={m_lists} — satu request bisa menggandakan "
                "field yang sama via alias (a1:..a10:) kecuali server "
                "membatasi jumlah alias/complexity"),
            recommendation="Pertimbangkan alias/complexity budget per "
                           "request; LAYAK dikonfirmasi ke server, bukan "
                           "kesimpulan",
            evidence_kind="arithmetic",
            finding_class="observation",
            confidence=1.0,
            status="confirmed",
            verdict=2,
            extra={"query_list_fields": q_lists,
                   "mutation_list_fields": m_lists, "schema": SCHEMA},
        ))

    meta.update({
        "schema": SCHEMA,
        "types": len(fields_by_type),
        "cycles": len(cycles),
        "max_acyclic_depth": max_depth,
        "query_list_fields": q_lists,
        "mutation_list_fields": m_lists,
        "note": "analisis statis skema — limit server tak terlihat dari "
                "introspection; DoS wajib dikonfirmasi terpisah di target "
                "berizin",
    })
    write_findings(args.out, findings, meta)
    # exit code mengikuti SIKLUS (sinyal kelemahan struktural);
    # observasi info (depth/LIST) tetap ditulis tanpa mengubah exit
    if cycles:
        print(f"[graphql_depth_audit] {len(cycles)} siklus, depth "
              f"{max_depth}, {len(q_lists) + len(m_lists)} field LIST "
              f"-> {args.out}")
        return 1
    print(f"[graphql_depth_audit] {meta['types']} tipe, tanpa siklus dari "
          f"root {root} (depth {max_depth}) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
