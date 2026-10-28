"""[SAFETY: 1-request] GraphQL schema map — introspection inventory.

SATU POST introspection query ke endpoint GraphQL target. Introspection
yang terbuka membocorkan seluruh permukaan API (tipe, field, mutasi) —
inventaris L0 + lead L1 (CWE-200) bila terbuka. Fail-closed: respons
bukan GraphQL / introspection dinonaktifkan / error = L0 info, bukan klaim.

Pemakaian:
  python skills/graphql_schema_map.py --url https://host/graphql --out f.json
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

INTROSPECTION_QUERY = (
    '{"query":"query IntrospectionMap { __schema { queryType { name } '
    'mutationType { name } types { kind name fields { name } } } }"}')


def fetch(url: str, query: str, timeout: float = 15.0):
    """SATU POST introspection. Return (status, body) — exception jadi
    (0, repr). Dipisah agar test bisa mem-patch."""
    req = urllib.request.Request(
        url, data=json.dumps({"query": query}).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", user_agent())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(64_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(64_000).decode("utf-8", "replace")
    except Exception as exc:
        return 0, repr(exc)[:200]


def audit(url: str) -> tuple[list[dict], dict]:
    status, body = fetch(url, INTROSPECTION_QUERY)
    meta = {"url": url, "requests": 1, "status": status}
    try:
        doc = json.loads(body)
    except Exception:
        doc = None
    schema = None
    if isinstance(doc, dict) and isinstance(doc.get("data"), dict):
        schema = doc["data"].get("__schema")
    if not isinstance(schema, dict):
        # introspection dinonaktifkan biasanya: errors + null data
        rows = [make_finding(
            tool="graphql-schema-map", title=f"No introspection on {url}",
            severity="info",
            description="Introspection tidak mengembalikan __schema "
                        "(dinonaktifkan/error) — tidak ada klaim (fail-"
                        "closed, AMAN).",
            target_url=url, response=body[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "1-request"})]
        meta["introspection"] = False
        return rows, meta

    types = [t for t in schema.get("types", [])
             if isinstance(t, dict) and not t.get("name", "").startswith("__")]
    fields_total = sum(len(t.get("fields") or []) for t in types)
    rows = [make_finding(
        tool="graphql-schema-map",
        title=f"GraphQL introspection terbuka di {url} "
              f"({len(types)} tipe, {fields_total} field)",
        severity="low",
        description="Endpoint GraphQL menerima introspection query — seluruh "
                    "peta API (tipe, field, mutasi) terbaca publik. Ini "
                    "inventaris permukaan (L0) + lead (L1): bukan "
                    "kerentanan, tapi mempercepat enumerasi bagi penyerang "
                    "(CWE-200).",
        recommendation="Matikan introspection di produksi bila tidak "
                       "dibutuhkan (banyak klien tetap aman di build-time "
                       "schema).",
        cwe="CWE-200", target_url=url,
        request=f"POST {url} (introspection query) -> {status}",
        response=body[:400],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=1,
        extra={"category": "SURFACE", "safety_class": "1-request",
               "types": len(types), "fields": fields_total,
               "has_mutation": schema.get("mutationType") is not None})]
    meta["introspection"] = True
    meta["types"] = len(types)
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="graphql_schema_findings.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    print(f"graphql-schema-map: {len(rows)} temuan ({meta.get('requests', 0)} POST) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
