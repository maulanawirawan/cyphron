"""[SAFETY: read-only, NOL jaringan] iam_assume_chain — graf eskalasi IAM
AWS assume-role MULTI-HOP (CWE-269) dari `aws iam get-account-authorization-
details` JSON. TIDAK memanggil AWS; murni analisis dokumen.

Konsep assume-role chaining — dibangun FROM SCRATCH, stdlib murni, offline.

Ceruk vs modul lain (anti-duplikasi):
  - `iam_escalation_scan.py` = vektor eskalasi SATU-langkah per-policy (mis.
    iam:PassRole, CreatePolicyVersion). Tool ini membangun GRAF principal->
    principal via sts:AssumeRole dan mencari jalur >=2 hop ke node admin.

"Kejar sampai verdict": jalur assume-role >=2 hop dari sebuah principal ke
node admin-equivalent (terbukti dari policy + trust) => L2 REPRODUCED dengan
jalur di poc. Tidak ada jalur multi-hop => L0.

Input -> mekanisme -> output:
  - Input : --auth <JSON get-account-authorization-details>.
  - Output: JSON kontrak; --out; --fail-on. Exit 0/1/2.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.iam-assume-chain/1"
TOOL = "iam-assume-chain"
ADMIN_MANAGED = "arn:aws:iam::aws:policy/AdministratorAccess"


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _statements(doc) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    return [s for s in _as_list(doc.get("Statement")) if isinstance(s, dict)]


def _actions(stmt) -> list[str]:
    return [str(a).lower() for a in _as_list(stmt.get("Action"))]


def _resources(stmt) -> list[str]:
    return [str(a) for a in _as_list(stmt.get("Resource"))]


def _allow(stmt) -> bool:
    return str(stmt.get("Effect", "")).lower() == "allow"


def _action_has(actions: list[str], want: str) -> bool:
    w = want.lower()
    svc = w.split(":", 1)[0]
    return any(a == "*" or a == w or a == svc + ":*" for a in actions)


def _is_admin_doc(doc) -> bool:
    for s in _statements(doc):
        if _allow(s) and any(a == "*" for a in _actions(s)) and \
                any(r == "*" for r in _resources(s)):
            return True
    return False


def _collect_docs(entity: dict, policy_map: dict) -> list[dict]:
    docs = []
    for pol in _as_list(entity.get("UserPolicyList")) + _as_list(entity.get("RolePolicyList")):
        if isinstance(pol, dict) and pol.get("PolicyDocument"):
            docs.append(pol["PolicyDocument"])
    for ap in _as_list(entity.get("AttachedManagedPolicies")):
        arn = ap.get("PolicyArn") if isinstance(ap, dict) else None
        if arn and arn in policy_map:
            docs.append(policy_map[arn])
        if arn == ADMIN_MANAGED:
            docs.append({"Statement": [{"Effect": "Allow", "Action": "*",
                                        "Resource": "*"}]})
    return docs


def _acct(arn: str) -> str:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


def analyze(auth: dict) -> dict:
    if not isinstance(auth, dict):
        raise ValueError("auth harus objek get-account-authorization-details")
    # peta managed policy arn -> default document
    policy_map: dict[str, dict] = {}
    for p in _as_list(auth.get("Policies")):
        if not isinstance(p, dict):
            continue
        arn = p.get("Arn")
        for ver in _as_list(p.get("PolicyVersionList")):
            if isinstance(ver, dict) and ver.get("IsDefaultVersion") and ver.get("Document"):
                policy_map[arn] = ver["Document"]
    principals: dict[str, dict] = {}   # arn -> {name, type, admin, targets, docs}
    roles: dict[str, dict] = {}        # arn -> role entity (trust)
    for u in _as_list(auth.get("UserDetailList")):
        if isinstance(u, dict) and u.get("Arn"):
            principals[u["Arn"]] = {"name": u.get("UserName", u["Arn"]),
                                    "type": "user", "entity": u}
    for r in _as_list(auth.get("RoleDetailList")):
        if isinstance(r, dict) and r.get("Arn"):
            principals[r["Arn"]] = {"name": r.get("RoleName", r["Arn"]),
                                    "type": "role", "entity": r}
            roles[r["Arn"]] = r

    # hitung admin + assume-targets tiap principal
    for arn, p in principals.items():
        docs = _collect_docs(p["entity"], policy_map)
        p["admin"] = any(_is_admin_doc(d) for d in docs)
        targets: set[str] = set()
        for d in docs:
            for s in _statements(d):
                if _allow(s) and _action_has(_actions(s), "sts:assumerole"):
                    for r in _resources(s):
                        targets.add(r)
        p["targets"] = targets

    # trust: role_arn -> principals yang diizinkan asumsi
    def trust_allows(role_arn: str, who: str) -> bool:
        role = roles.get(role_arn)
        if not role:
            return False
        doc = role.get("AssumeRolePolicyDocument")
        root = "arn:aws:iam::%s:root" % _acct(who)
        for s in _statements(doc):
            if not (_allow(s) and _action_has(_actions(s), "sts:assumerole")):
                continue
            princ = s.get("Principal")
            aws = []
            if isinstance(princ, dict):
                aws = _as_list(princ.get("AWS"))
            elif isinstance(princ, str):
                aws = [princ]
            aws = [str(a) for a in aws]
            if any(a == "*" or a == who or a == root for a in aws):
                return True
        return False

    # bangun edge principal -> role
    edges: dict[str, set[str]] = {a: set() for a in principals}
    for arn, p in principals.items():
        for role_arn in roles:
            if role_arn == arn:
                continue
            can_target = ("*" in p["targets"]) or (role_arn in p["targets"])
            if can_target and trust_allows(role_arn, arn):
                edges[arn].add(role_arn)

    # BFS cari jalur >=2 hop ke node admin
    def shortest_admin_path(start: str) -> list[str] | None:
        from collections import deque
        q = deque([[start]])
        seen = {start}
        while q:
            path = q.popleft()
            node = path[-1]
            if len(path) >= 3 and principals[node]["admin"]:  # >=2 edges
                return path
            for nxt in sorted(edges.get(node, ())):
                if nxt not in seen:
                    seen.add(nxt)
                    q.append(path + [nxt])
        return None

    findings: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()
    for arn in sorted(principals):
        if principals[arn]["admin"]:
            continue  # sudah admin, bukan eskalasi
        path = shortest_admin_path(arn)
        if path:
            key = (path[0], path[-1])
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            names = " -> ".join(principals[a]["name"] for a in path)
            poc = ("ASSUME-ROLE ESCALATION PATH (%d hops):\n%s\n(each hop: the "
                   "source principal may sts:AssumeRole the next, allowed by "
                   "both an identity policy and the target's trust policy; "
                   "proven from the provided authorization details)"
                   % (len(path) - 1, names))
            findings.append(make_finding(
                tool=TOOL,
                title="IAM assume-role escalation to admin: %s" % principals[arn]["name"],
                severity="high", cwe="CWE-269",
                description=("A %d-hop sts:AssumeRole path lets '%s' reach the "
                             "admin-equivalent principal '%s'."
                             % (len(path) - 1, principals[path[0]]["name"],
                                principals[path[-1]]["name"])),
                recommendation=("Break the chain: tighten trust policies and "
                                "scope sts:AssumeRole resources; avoid transitive "
                                "role assumption into admin."),
                param="chain:%s->%s" % (path[0], path[-1]),
                status="confirmed", verdict=2, evidence_kind="differential",
                confidence=1.0, poc=poc,
                extra={"kind": "iam-chain", "path": path, "hops": len(path) - 1}))

    if not findings:
        findings.append(make_finding(
            tool=TOOL, title="No multi-hop assume-role path to admin found",
            severity="info",
            description=("Built the assume-role graph over %d principals; no "
                         ">=2-hop path reaches an admin-equivalent node "
                         "(checked, nothing found)." % len(principals)),
            recommendation="Re-check after IAM changes; keep trust policies tight.",
            param="summary", status="confirmed", verdict=0, evidence_kind="",
            confidence=0.6, extra={"kind": "summary"}))
    findings.sort(key=lambda f: (0 if f["severity"] == "high" else 9,
                                 f.get("param") or ""))
    stats = {"principals": len(principals), "roles": len(roles),
             "paths": sum(1 for f in findings if f.get("kind") == "iam-chain"),
             "findings": len(findings)}
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats, "notes": [],
            "findings": findings}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Find multi-hop AWS IAM assume-role escalation paths to "
                    "admin — offline.")
    ap.add_argument("--auth", required=True,
                    help="JSON: aws iam get-account-authorization-details")
    ap.add_argument("--out")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)
    try:
        auth = json.loads(Path(args.auth).read_text(encoding="utf-8"))
        result = analyze(auth)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("[iam-assume-chain] input error: %s" % exc, file=sys.stderr)
        return 2
    result["requests"] = 0
    if args.out:
        write_findings(args.out, result["findings"], meta={
            "schema": SCHEMA, "tool": TOOL, "stats": result["stats"],
            "notes": [], "requests": 0})
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
