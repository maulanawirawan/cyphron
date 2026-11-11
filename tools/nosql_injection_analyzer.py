"""[SAFETY: read-only, NOL jaringan] nosql_injection_analyzer — permukaan
injeksi operator NoSQL dari permintaan yang sudah ditangkap (berizin/lab).

Konsep NoSQL/operator-injection (CWE-943; MongoDB $-operator abuse) — dibangun
FROM SCRATCH, stdlib murni, TANPA jaringan. Tool ini TIDAK mengirim apa pun.

Ceruk vs modul lain (anti-duplikasi):
  - `waf_sqli_triage.py` = SQL injection dari audit-log WAF. Ini NoSQL.
  - exploit_playbooks `NosqliLogin` = LIVE (kirim payload, cek bypass). Ini
    OFFLINE: menilai capture; "efek" dibuktikan hanya bila capture membawa
    pasangan kontrol (request tanpa operator) yang DITOLAK.

"Kejar sampai verdict": operator ada + request sukses (2xx) SEDANGKAN kontrol
(tanpa operator) ditolak (401/403) => L2 REPRODUCED (bypass terbukti dari
bukti). Operator ada tanpa pasangan kontrol => L1 LEAD. Tidak ada operator di
mana pun => L0 OBSERVED.

Input -> mekanisme -> output:
  - Input : --captures <JSON list | JSONL>, tiap record
            {method, path, params?: {name: value}, body?: str|obj,
             status?: int, control_status?: int (status request SAMA tanpa
             operator)}.
  - Output: JSON {schema,tool,stats,notes,findings} satu-pintu; --out kontrak;
            --fail-on none|any|high|medium|low. Exit 0/1/2.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.nosql-injection-analyzer/1"
TOOL = "nosql-injection-analyzer"
MAX_RECORDS = 50_000
MAX_BLOB = 128 * 1024

# operator Mongo-style dengan batas kata — hindari FP "$5"/"$next"
_OPS = ("ne", "gt", "gte", "lt", "lte", "eq", "where", "regex", "or", "and",
        "nor", "not", "in", "nin", "exists", "elemMatch", "expr", "jsonSchema",
        "mod", "all", "size", "type", "text", "search")
_RE_OP = re.compile(r"(?<![\w$])\$(" + "|".join(_OPS) + r")\b")
_RE_BRACKET = re.compile(r"\[\s*\$(" + "|".join(_OPS) + r")\s*\]")
_RE_WHERE_JS = re.compile(r"\$where\b")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _ops_in(text: str) -> list[str]:
    found: list[str] = []
    for m in _RE_OP.finditer(text or ""):
        found.append("$" + m.group(1))
    for m in _RE_BRACKET.finditer(text or ""):
        found.append("[$%s]" % m.group(1))
    return sorted(set(found))


def _ops_in_value(val) -> list[str]:
    """Nilai bisa str atau struktur (dict/list) — periksa kunci operator."""
    if isinstance(val, str):
        return _ops_in(val)
    found: set[str] = set()
    if isinstance(val, dict):
        for k, v in val.items():
            if isinstance(k, str) and _RE_OP.match(k):
                found.add(k)
            found.update(_ops_in_value(v))
    elif isinstance(val, list):
        for v in val:
            found.update(_ops_in_value(v))
    return sorted(found)


def _scan_record(rec: dict) -> list[tuple[str, str]]:
    """-> [(lokasi, operator)] operator ditemukan di record."""
    hits: list[tuple[str, str]] = []
    params = rec.get("params") or {}
    if isinstance(params, dict):
        for name, value in params.items():
            if isinstance(name, str):
                for op in _ops_in(name):          # username[$ne]=
                    hits.append(("param-name:%s" % name, op))
            for op in _ops_in_value(value):
                hits.append(("param:%s" % name, op))
    body = rec.get("body")
    if isinstance(body, str):
        blob = body[:MAX_BLOB]
        parsed = None
        try:
            parsed = json.loads(blob)
        except (ValueError, json.JSONDecodeError):
            parsed = None
        if parsed is not None:
            for op in _ops_in_value(parsed):
                hits.append(("body-json", op))
        else:
            for op in _ops_in(blob):
                hits.append(("body", op))
    elif isinstance(body, (dict, list)):
        for op in _ops_in_value(body):
            hits.append(("body-json", op))
    # dedup stabil
    return sorted(set(hits))


def _is_2xx(s) -> bool:
    try:
        return 200 <= int(s) < 300
    except (TypeError, ValueError):
        return False


def _is_denied(s) -> bool:
    try:
        return int(s) in (401, 403)
    except (TypeError, ValueError):
        return False


def analyze(records: list[dict]) -> dict:
    if not isinstance(records, list):
        raise ValueError("captures harus list record")
    if len(records) > MAX_RECORDS:
        raise ValueError("terlalu banyak record (%d)" % len(records))
    findings: list[dict] = []
    notes: list[str] = []
    attempts = 0
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            notes.append("record #%d bukan objek, dilewati" % i)
            continue
        method = str(rec.get("method", "GET")).upper()
        path = str(rec.get("path", "/"))
        hits = _scan_record(rec)
        if not hits:
            continue
        attempts += 1
        ops = sorted({op for _, op in hits})
        locs = sorted({loc for loc, _ in hits})
        target = "%s %s" % (method, path)
        param = "nosqli:%s:%s" % (path, ",".join(ops))[:120]
        bypass = _is_2xx(rec.get("status")) and _is_denied(rec.get("control_status"))
        if bypass:
            poc = ("AUTH/FILTER BYPASS REPRODUCED (from captures):\n"
                   "- request with NoSQL operator(s) %s at %s returned HTTP %s\n"
                   "- the SAME request WITHOUT the operator returned HTTP %s "
                   "(control denied)\n=> the operator changed the query outcome."
                   % (", ".join(ops), ", ".join(locs), rec.get("status"),
                      rec.get("control_status")))
            findings.append(make_finding(
                tool=TOOL,
                title="NoSQL operator injection bypass at %s" % path,
                severity="high", cwe="CWE-943",
                description=("A captured request carrying MongoDB-style "
                             "operator(s) %s succeeded while the operator-free "
                             "control was denied — reproduced query-logic "
                             "tampering." % ", ".join(ops)),
                recommendation=("Reject $-prefixed keys / typed values from "
                                "untrusted input; cast to string; use a schema."),
                target_url=target, param=param, status="confirmed", verdict=2,
                evidence_kind="differential", confidence=1.0, poc=poc,
                extra={"operators": ops, "locations": locs, "kind": "nosqli"}))
        else:
            poc = ("NoSQL operator(s) %s present in the request at %s. LEAD: "
                   "provide a control (the same request without the operator) "
                   "that is denied, to confirm the operator changes the outcome."
                   % (", ".join(ops), ", ".join(locs)))
            findings.append(make_finding(
                tool=TOOL,
                title="NoSQL operator in request at %s" % path,
                severity="medium", cwe="CWE-943",
                description=("Request carries MongoDB-style operator(s) %s in %s "
                             "— operator injection surface; effect not yet "
                             "confirmed." % (", ".join(ops), ", ".join(locs))),
                recommendation=("Reject $-prefixed keys/typed values from "
                                "untrusted input."),
                target_url=target, param=param, status="unconfirmed", verdict=1,
                evidence_kind="payload", confidence=0.6, lab_only=True,
                extra={"operators": ops, "locations": locs, "kind": "nosqli"}))

    if not findings:
        findings.append(make_finding(
            tool=TOOL, title="No NoSQL operator injection surface found",
            severity="info",
            description=("Scanned %d record(s); no MongoDB-style operators in "
                         "params/body (checked, nothing found)." % len(records)),
            recommendation="Widen captures to strengthen this negative result.",
            param="summary", status="confirmed", verdict=0, evidence_kind="",
            confidence=0.6, extra={"kind": "summary"}))
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f.get("param") or ""))
    stats = {"records": len(records), "injection_requests": attempts,
             "findings": len(findings), "by_severity": {}}
    for f in findings:
        stats["by_severity"][f["severity"]] = stats["by_severity"].get(f["severity"], 0) + 1
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats, "notes": notes,
            "findings": findings}


def _load_captures(path: str) -> list:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    ts = text.lstrip()
    if ts.startswith("["):
        return json.loads(text)
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Analyze captured requests for NoSQL operator injection — "
                    "offline, fail-closed.")
    ap.add_argument("--captures", required=True)
    ap.add_argument("--out")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)
    try:
        records = _load_captures(args.captures)
        result = analyze(records)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("[nosql-injection-analyzer] input error: %s" % exc, file=sys.stderr)
        return 2
    result["requests"] = 0
    if args.out:
        write_findings(args.out, result["findings"], meta={
            "schema": SCHEMA, "tool": TOOL, "stats": result["stats"],
            "notes": result["notes"], "requests": 0})
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if any(f["severity"] != "info" for f in result["findings"]) else 0
    need = {"high": {"critical", "high"},
            "medium": {"critical", "high", "medium"},
            "low": {"critical", "high", "medium", "low"}}[args.fail_on]
    return 1 if any(f["severity"] in need for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
