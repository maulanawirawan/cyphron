"""[SAFETY: read-only, NOL jaringan] bola_bfla_prover — pembukti BOLA (object-
level, OWASP API1 / CWE-639) + BFLA (function-level, OWASP API5 / CWE-862) dari
BUKTI permintaan+respons yang sudah ditangkap pada >=2 peran (berizin/lab).

Konsep otorisasi-rusak (OWASP API Security Top 10) — dibangun FROM SCRATCH,
stdlib murni, TANPA menyalin kode, TANPA jaringan. Tool ini TIDAK mengirim
apa pun; ia MEMUTUSKAN dari capture yang diberikan.

Ceruk vs modul lain (anti-duplikasi):
  - `api_property_scan.py` = BOPLA (property-level: field berlebih di SATU
    respons). Tool ini butuh >=2 peran dan menilai akses lintas-peran.
  - exploit_playbooks `Idor`/`MassAssignment` = LIVE (mengirim permintaan).
    Tool ini OFFLINE: bukti differential dari capture; langkah live ditandai
    sebagai next-step untuk lead yang belum pasti.

"Kejar sampai verdict": peran-penyerang dapat 2xx pada objek milik peran lain
DAN marker pemilik muncul di responsnya => L2 REPRODUCED (confirmed
differential, PoC = pasangan permintaan+respons). 2xx tanpa marker pembukti
=> L1 LEAD + next-step. Ditolak 401/403 => L0 OBSERVED (otorisasi ditegakkan).

Input -> mekanisme -> output:
  - Input : --captures <JSON list | JSONL>, tiap record
            {role, method, path, status, body?, obj_id?}.
            --owners <JSON {obj_id: owner_role}> (kepemilikan objek — wajib
            untuk BUKTI BOLA; tanpa ini BOLA dilewati tercatat).
            --markers <JSON {role: unique_marker}> (string unik data peran;
            untuk menaikkan lead 2xx -> L2).
            --privileged "pat1,pat2" (substring path fungsi privileged, BFLA).
            --admin-roles "r1,r2" (peran yang MEMANG boleh fungsi privileged).
  - Output: JSON {schema,tool,stats,notes,findings} satu-pintu; --out bungkus
            kontrak; --fail-on none|any|high|medium|low. Exit 0/1/2.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.bola-bfla-prover/1"
TOOL = "bola-bfla-prover"
MAX_RECORDS = 50_000
MAX_BODY = 64 * 1024

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEG_ID = re.compile(r"^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$")


def _template(path: str) -> str:
    """/users/42/orders/7 -> /users/{id}/orders/{id} (dedup endpoint)."""
    out = []
    for seg in (path or "").split("/"):
        out.append("{id}" if seg and _SEG_ID.match(seg) else seg)
    return "/".join(out) or "/"


def _is_2xx(status) -> bool:
    try:
        return 200 <= int(status) < 300
    except (TypeError, ValueError):
        return False


def _is_denied(status) -> bool:
    try:
        return int(status) in (401, 403)
    except (TypeError, ValueError):
        return False


def _norm_records(raw) -> list[dict]:
    if isinstance(raw, dict):
        raw = raw.get("captures") or raw.get("records") or [raw]
    if not isinstance(raw, list):
        raise ValueError("captures harus list record (atau JSONL)")
    recs = []
    for i, r in enumerate(raw):
        if not isinstance(r, dict):
            raise ValueError("record #%d bukan objek" % i)
        role = str(r.get("role", "")).strip()
        method = str(r.get("method", "GET")).strip().upper() or "GET"
        path = str(r.get("path", "")).strip()
        if not role or not path:
            raise ValueError("record #%d wajib punya 'role' dan 'path'" % i)
        recs.append({
            "role": role, "method": method, "path": path,
            "status": r.get("status"), "obj_id": str(r.get("obj_id", "")).strip(),
            "body": str(r.get("body", ""))[:MAX_BODY],
            "template": _template(path),
        })
    return recs


def _mk(kind: str, severity: str, title: str, desc: str, rec: str, cwe: str,
        *, status: str, verdict: int | None, evidence_kind: str, poc: str,
        param: str, target: str, confidence: float, lab_only: bool = False,
        extra: dict | None = None) -> dict:
    return make_finding(
        tool=TOOL, title=title, severity=severity, description=desc,
        recommendation=rec, cwe=cwe, target_url=target, param=param,
        request=None, response=None, poc=poc, evidence_kind=evidence_kind,
        status=status, verdict=verdict, confidence=confidence,
        lab_only=lab_only, extra=dict(extra or {}, kind=kind),
    )


def analyze(records: list[dict], owners: dict | None = None,
            markers: dict | None = None, privileged: list[str] | None = None,
            admin_roles: list[str] | None = None) -> dict:
    """Deterministik, nol jaringan. SELALU >=1 finding (kejar sampai verdict).
    Menerima record MENTAH (list dict); normalisasi + validasi di sini supaya
    pemanggil modul dan CLI berperilaku identik."""
    if len(records) > MAX_RECORDS:
        raise ValueError("terlalu banyak record (%d)" % len(records))
    records = _norm_records(records)
    roles = sorted({r["role"] for r in records})
    if len(roles) < 2:
        raise ValueError("butuh >=2 peran berbeda di captures (ada %d)" % len(roles))
    owners = {str(k): str(v) for k, v in (owners or {}).items()}
    markers = {str(k): str(v) for k, v in (markers or {}).items()}
    privileged = [p for p in (privileged or []) if p]
    admin_roles = set(admin_roles or [])
    notes: list[str] = []
    findings: list[dict] = []
    bola_denied = bola_attempts = bfla_denied = bfla_attempts = 0

    # ---------------- BOLA (butuh owners untuk BUKTI) ----------------
    if not owners:
        notes.append("BOLA dilewati: --owners tak diberikan (kepemilikan objek "
                     "wajib untuk membuktikan akses lintas-pemilik)")
    else:
        for r in records:
            oid = r["obj_id"]
            if not oid or oid not in owners:
                continue
            owner = owners[oid]
            if r["role"] == owner:
                continue
            target = "%s %s" % (r["method"], r["path"])
            if _is_denied(r["status"]):
                bola_denied += 1
                continue
            if not _is_2xx(r["status"]):
                continue
            bola_attempts += 1
            owner_marker = markers.get(owner, "")
            param = "bola:%s:%s:%s" % (r["role"], r["template"], oid)
            if owner_marker and owner_marker in r["body"]:
                poc = ("CROSS-ROLE READ PROVEN:\n- object %s is owned by role "
                       "'%s'\n- role '%s' requested `%s` and got HTTP %s\n- the "
                       "owner's unique marker was present in that response "
                       "=> '%s' read '%s''s object.\n(captured evidence; no live "
                       "request sent by this tool)"
                       % (oid, owner, r["role"], target, r["status"],
                          r["role"], owner))
                findings.append(_mk(
                    "bola", "high",
                    "BOLA: role '%s' read object %s owned by '%s'" % (r["role"], oid, owner),
                    "Broken Object Level Authorization reproduced from captures: "
                    "a non-owner role obtained a 2xx AND the owner's data marker "
                    "on the owner's object.",
                    "Enforce per-object ownership checks server-side on every "
                    "object reference; never trust client-supplied object ids.",
                    "CWE-639", status="confirmed", verdict=2,
                    evidence_kind="differential", poc=poc, param=param,
                    target=target, confidence=1.0,
                    extra={"owner": owner, "actor": r["role"], "obj_id": oid}))
            else:
                poc = ("role '%s' got HTTP %s on object %s owned by '%s'. "
                       "LEAD: supply the owner's unique data marker via --markers "
                       "to confirm the response actually contains the owner's "
                       "object (vs an empty/forbidden-but-200 body)."
                       % (r["role"], r["status"], oid, owner))
                findings.append(_mk(
                    "bola", "medium",
                    "BOLA lead: role '%s' got 2xx on object %s owned by '%s'" % (r["role"], oid, owner),
                    "Non-owner role received a 2xx on another role's object; "
                    "data crossover not yet confirmed (no owner marker).",
                    "Add the owner's unique data marker to confirm; enforce "
                    "object-ownership checks.", "CWE-639",
                    status="unconfirmed", verdict=1, evidence_kind="differential",
                    poc=poc, param=param, target=target, confidence=0.6,
                    extra={"owner": owner, "actor": r["role"], "obj_id": oid}))

    # ---------------- BFLA (butuh privileged patterns) ----------------
    if privileged:
        for r in records:
            if not any(p in r["path"] for p in privileged):
                continue
            if r["role"] in admin_roles:
                continue
            target = "%s %s" % (r["method"], r["path"])
            if _is_denied(r["status"]):
                bfla_denied += 1
                continue
            if not _is_2xx(r["status"]):
                continue
            bfla_attempts += 1
            param = "bfla:%s:%s" % (r["role"], r["template"])
            admin_marker = ""
            for ar in admin_roles:
                if markers.get(ar) and markers[ar] in r["body"]:
                    admin_marker = markers[ar]
                    break
            if admin_marker:
                poc = ("PRIVILEGED FUNCTION REACHED:\n- path `%s` is privileged\n"
                       "- non-admin role '%s' got HTTP %s AND an admin-only data "
                       "marker in the response => function-level authz broken."
                       % (target, r["role"], r["status"]))
                findings.append(_mk(
                    "bfla", "high",
                    "BFLA: non-admin '%s' reached privileged %s" % (r["role"], r["path"]),
                    "Broken Function Level Authorization reproduced: a non-admin "
                    "role reached a privileged function with a 2xx and admin data.",
                    "Enforce role checks on every privileged route, server-side.",
                    "CWE-862", status="confirmed", verdict=2,
                    evidence_kind="differential", poc=poc, param=param,
                    target=target, confidence=1.0,
                    extra={"actor": r["role"]}))
            else:
                poc = ("non-admin role '%s' got HTTP %s on privileged path `%s`. "
                       "LEAD: supply an admin-only data marker via --markers (or "
                       "confirm the action's effect) to prove the function ran."
                       % (r["role"], r["status"], target))
                findings.append(_mk(
                    "bfla", "medium",
                    "BFLA lead: non-admin '%s' got 2xx on privileged %s" % (r["role"], r["path"]),
                    "Non-admin role received a 2xx on a privileged path; effect "
                    "not yet confirmed (no admin marker).",
                    "Confirm with an admin-only marker/effect; enforce role "
                    "checks.", "CWE-862", status="unconfirmed", verdict=1,
                    evidence_kind="differential", poc=poc, param=param,
                    target=target, confidence=0.6, extra={"actor": r["role"]}))
    else:
        notes.append("BFLA dilewati: --privileged tak diberikan")

    # ---------------- L0 bila tidak ada break tapi ada percobaan ----------------
    if not findings:
        enforced = bola_denied + bfla_denied
        findings.append(make_finding(
            tool=TOOL,
            title="No authorization break found across %d roles" % len(roles),
            severity="info",
            description=("Checked cross-role access on the provided captures: "
                         "%d BOLA + %d BFLA denied (401/403), no non-owner/non-"
                         "admin 2xx with crossover. Authorization appears enforced "
                         "for the captured attempts (nothing found)." % (bola_denied, bfla_denied)),
            recommendation="Widen captures (more objects/roles/functions) to "
                           "strengthen this negative result.",
            param="summary", evidence_kind="", status="confirmed",
            confidence=0.6, extra={"roles": roles, "denied": enforced}))

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f.get("param") or ""))
    stats = {"records": len(records), "roles": len(roles),
             "bola_attempts": bola_attempts, "bola_denied": bola_denied,
             "bfla_attempts": bfla_attempts, "bfla_denied": bfla_denied,
             "findings": len(findings), "by_severity": {}}
    for f in findings:
        stats["by_severity"][f["severity"]] = stats["by_severity"].get(f["severity"], 0) + 1
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats, "notes": notes,
            "findings": findings}


def _load_captures(path: str) -> list:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    text_s = text.lstrip()
    if text_s.startswith("["):
        return json.loads(text)
    if text_s.startswith("{") and "\n" not in text_s.strip():
        return [json.loads(text)]
    # JSONL
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _load_json(path: str | None):
    if not path:
        return {}
    v = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(v, dict):
        raise ValueError("%s harus objek JSON" % path)
    return v


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Prove BOLA/BFLA from captured two-role request/response "
                    "evidence — offline, fail-closed.")
    ap.add_argument("--captures", required=True, help="JSON list atau JSONL record")
    ap.add_argument("--owners", help="JSON {obj_id: owner_role}")
    ap.add_argument("--markers", help="JSON {role: unique_marker}")
    ap.add_argument("--privileged", default="", help="substring path privileged, pisah koma")
    ap.add_argument("--admin-roles", default="", help="peran admin, pisah koma")
    ap.add_argument("--out")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)
    try:
        raw = _load_captures(args.captures)
        owners = _load_json(args.owners)
        markers = _load_json(args.markers)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("[bola-bfla-prover] input error: %s" % exc, file=sys.stderr)
        return 2
    priv = [p.strip() for p in args.privileged.split(",") if p.strip()]
    admins = [a.strip() for a in args.admin_roles.split(",") if a.strip()]
    try:
        result = analyze(raw, owners, markers, priv, admins)
    except ValueError as exc:
        print("[bola-bfla-prover] input error: %s" % exc, file=sys.stderr)
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
