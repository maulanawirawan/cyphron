r"""[SAFETY: read-only] iam_escalation_scan — analisis OFFLINE artefak
`aws iam get-account-authorization-details` untuk jalur eskalasi privilese
IAM AWS (JSON, stdlib murni, tanpa jaringan, tanpa kredensial).

Port konsep dari antrean SKILL-PORT-QUEUE #0386 (mukul975/
Anthropic-Cybersecurity-Skills, skill 'detecting-aws-iam-privilege-
escalation' — analisis gaya cloudsplaining: kombinasi izin berbahaya,
Resource "*", PassRole + CreateFunction, AssumeRole; atribusi konsep,
lisensi sumber Apache-2.0). Dibangun FROM SCRATCH: evaluasi policy
document ditulis sendiri; TIDAK memakai boto3/cloudsplaining — skill
aslinya mengunduh artefak live via API, secai menganalisis FILE yang
sudah diunduh (nol jaringan, hasil dapat diaudit ulang).

Input -> mekanisme -> output:
  - Input : file JSON hasil `aws iam get-account-authorization-details`
            (UserDetailList / GroupDetailList / RoleDetailList / Policies).
            Read-only; pengguna membuat artefak itu sendiri di akunnya.
  - Mekanisme: petakan PolicyArn -> document (versi default) -> untuk
            tiap principal kumpulkan policy terlampir + inline -> evaluasi
            Statement Effect=Allow secara deterministik.
  - Output: temuan {check, severity, principal, policy, actions, message}
            + ringkasan per principal.

Cek (verdict = LEAD; konteks bisnis menentukan apakah benar eskalasi):
  admin-wildcard        (high)  : Action "*" Effect Allow di policy.
  policy-version-swap   (high)  : iam:CreatePolicyVersion /
                                  iam:SetDefaultPolicyVersion dgn
                                  Resource "*" — backdoor versi policy.
  passrole-combo        (high)  : iam:PassRole + (lambda:CreateFunction |
                                  ec2:RunInstances | iam:CreateRole)
                                  dalam policy yang sama.
  credential-forgery    (high)  : iam:CreateAccessKey dgn Resource "*"
                                  (kunci utk user lain).
  assume-role-broad     (high)  : sts:AssumeRole dgn Resource "*".
  trust-wildcard        (high)  : trust policy role memakai Principal
                                  "*" / AWS "*" (siapa pun bisa assume).
  wildcard-sensitive    (medium): Resource "*" atas aksi sensitif
                                  (secretsmanager:GetSecretValue,
                                  kms:Decrypt, s3:GetObject, ssm:
                                  GetParameter*, dynamodb:Get*).
  notaction-unanalyzed  (info)  : Statement memakai NotAction —
                                  tidak bisa dievaluasi pasti (dicatat,
                                  TIDAK dianggap bersih).

Fail-closed: file tidak ada / JSON rusak -> exit 2; JSON sah tapi TANPA
principal sama sekali -> exit 2 (input kosong tidak boleh dilaporkan
"bersih"); Statement NotAction tidak dihitung aman.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  aws iam get-account-authorization-details > auth.json
  python tools/iam_escalation_scan.py --auth auth.json
  python tools/iam_escalation_scan.py --auth auth.json --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "secai.iam-escalation-scan/1"

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}

PASSROLE_SIBLINGS = {"lambda:createfunction", "ec2:runinstances",
                     "iam:createrole"}
SENSITIVE_WILDCARD = {
    "secretsmanager:getsecretvalue", "kms:decrypt", "s3:getobject",
    "s3:putobject", "ssm:getparameter", "ssm:getparametersbybypath",
    "ssm:getparameterbybypath", "dynamodb:getitem", "dynamodb:scan",
    "dynamodb:query", "logs:filterlogevents",
}
WRITE_IAM_HINTS = ("iam:create", "iam:put", "iam:attach", "iam:delete",
                   "iam:update", "iam:add")


def _as_list(v: Any) -> "list[str]":
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def _actions(stmt: dict) -> "list[str]":
    return [a.lower() for a in _as_list(stmt.get("Action"))]


def _resources(stmt: dict) -> "list[str]":
    return [r for r in _as_list(stmt.get("Resource"))]


def evaluate_document(doc: dict) -> "list[dict]":
    """Evaluasi satu policy document -> daftar vektor unik per policy."""
    vectors: "list[dict]" = []
    if not isinstance(doc, dict):
        return vectors
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    has_passrole = False
    siblings: "set[str]" = set()
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        actions = _actions(stmt)
        res = _resources(stmt)
        star_res = any(r == "*" for r in res)

        if "*" in actions:
            vectors.append({
                "check": "admin-wildcard", "severity": "high",
                "actions": ["*"], "resource": res,
                "message": "Policy mengizinkan Action \"*\" — hak admin "
                           "penuh (Effect Allow).",
            })
        if stmt.get("NotAction") is not None:
            vectors.append({
                "check": "notaction-unanalyzable", "severity": "info",
                "actions": _as_list(stmt.get("NotAction")),
                "resource": res,
                "message": "Statement memakai NotAction — tidak bisa "
                           "dievaluasi pasti; TIDAK dianggap aman.",
            })

        if "iam:passrole" in actions:
            has_passrole = True
        siblings.update(a for a in actions if a in PASSROLE_SIBLINGS)
        if "iam:createpolicyversion" in actions and star_res:
            vectors.append({
                "check": "policy-version-swap", "severity": "high",
                "actions": ["iam:CreatePolicyVersion"], "resource": res,
                "message": "CreatePolicyVersion pada Resource \"*\" — "
                           "bisa menimpa policy manapun lalu set default.",
            })
        if "iam:setdefaultpolicyversion" in actions:
            vectors.append({
                "check": "policy-version-swap", "severity": "high",
                "actions": ["iam:SetDefaultPolicyVersion"], "resource": res,
                "message": "SetDefaultPolicyVersion — mengaktifkan versi "
                           "policy lama/apapun yang pernah dibuat.",
            })
        if "iam:createaccesskey" in actions and star_res:
            vectors.append({
                "check": "credential-forgery", "severity": "high",
                "actions": ["iam:CreateAccessKey"], "resource": res,
                "message": "CreateAccessKey pada Resource \"*\" — bisa "
                           "membuat kunci utk user lain.",
            })
        if "sts:assumerole" in actions and star_res:
            vectors.append({
                "check": "assume-role-broad", "severity": "high",
                "actions": ["sts:AssumeRole"], "resource": res,
                "message": "AssumeRole tanpa batas resource.",
            })
        if star_res and any(a in SENSITIVE_WILDCARD for a in actions):
            hit = sorted(a for a in actions if a in SENSITIVE_WILDCARD)
            vectors.append({
                "check": "wildcard-sensitive", "severity": "medium",
                "actions": hit, "resource": res,
                "message": f"Aksi sensitif {hit} pada Resource \"*\".",
            })

    if has_passrole and siblings:
        vectors.append({
            "check": "passrole-combo", "severity": "high",
            "actions": sorted(siblings), "resource": [],
            "message": f"iam:PassRole dikombinasikan dengan "
                       f"{sorted(siblings)} dalam policy yang sama — "
                       "eskalasi via service yang membawa role.",
        })

    # dedup per check (satu vektor cukup utk triase)
    seen: "set[str]" = set()
    unique = []
    for v in vectors:
        if v["check"] not in seen:
            seen.add(v["check"])
            unique.append(v)
    return unique


def evaluate_trust(doc: Any, role_name: str) -> "list[dict]":
    """Cek trust policy role: Principal wildcard = siapa pun bisa assume."""
    if not isinstance(doc, dict):
        return []
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and
                                (principal.get("AWS") == "*"
                                 or principal.get("Service") == "*"
                                 and "Federated" in principal)):
            if principal == "*" or (
                    isinstance(principal, dict)
                    and principal.get("AWS") == "*"):
                return [{
                    "check": "trust-wildcard", "severity": "high",
                    "principal": role_name, "policy": "(trust policy)",
                    "actions": ["sts:AssumeRole"],
                    "message": f"Trust policy role {role_name} menerima "
                               "Principal \"*\" — akun/entitas manapun "
                               "bisa mengambil role ini.",
                }]
    return []


def _policy_documents(auth: dict) -> "dict[str, dict]":
    """Petakan PolicyArn -> document versi default."""
    docs: "dict[str, dict]" = {}
    for pol in auth.get("Policies") or []:
        arn = pol.get("Arn") or pol.get("policyArn") or ""
        for ver in pol.get("PolicyVersionList") or []:
            if ver.get("IsDefaultVersion"):
                docs[arn] = ver.get("Document") or {}
                break
    return docs


def _inline_documents(entry: dict, key: str) -> "list[tuple[str, dict]]":
    out: "list[tuple[str, dict]]" = []
    for pol in entry.get(key) or []:
        doc = pol.get("PolicyDocument") or {}
        if doc:
            out.append((pol.get("PolicyName") or "(inline)", doc))
    return out


def scan(auth: dict) -> dict:
    """Analisis penuh artefak authorization details -> temuan."""
    managed = _policy_documents(auth)
    findings: "list[dict]" = []
    principals: "list[str]" = []

    def principal_policies(entry: dict, name: str, attached_key: str,
                           inline_key: str) -> str:
        principals.append(name)
        pol_names: "list[str]" = []
        for att in entry.get(attached_key) or []:
            arn = att.get("PolicyArn") or att.get("PolicyName") or ""
            doc = managed.get(arn)
            label = att.get("PolicyName") or arn
            if doc is None:
                findings.append({
                    "check": "policy-doc-missing", "severity": "info",
                    "principal": name, "policy": str(label),
                    "actions": [], "message": f"Policy {arn} terlampir "
                    "tapi dokumennya tidak ada di artefak (AWS kadang "
                    "menghapus policy AWS-managed dari daftar) — tidak "
                    "dianalisis, tidak dianggap aman.",
                })
                continue
            pol_names.append(str(label))
            for v in evaluate_document(doc):
                findings.append({"principal": name, "policy": str(label),
                                 **v})
        for pname, doc in _inline_documents(entry, inline_key):
            pol_names.append(str(pname))
            for v in evaluate_document(doc):
                findings.append({"principal": name, "policy": str(pname),
                                 **v})
        return ", ".join(pol_names)

    for u in auth.get("UserDetailList") or []:
        name = u.get("UserName") or "(user-tanpa-nama)"
        principal_policies(u, f"user/{name}", "AttachedManagedPolicies",
                           "UserPolicyList")
    for g in auth.get("GroupDetailList") or []:
        name = g.get("GroupName") or "(group-tanpa-nama)"
        principal_policies(g, f"group/{name}", "AttachedManagedPolicies",
                           "GroupPolicyList")
    for r in auth.get("RoleDetailList") or []:
        name = r.get("RoleName") or "(role-tanpa-nama)"
        principal_policies(r, f"role/{name}", "AttachedManagedPolicies",
                           "RolePolicyList")
        findings.extend(evaluate_trust(
            r.get("AssumeRolePolicyDocument"), f"role/{name}"))

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["check"],
                                 str(f.get("principal", ""))))
    return {
        "schema": SCHEMA,
        "principals_total": len(principals),
        "managed_policies_mapped": len(managed),
        "findings": findings,
        "verdict": ("ESCALATION_VECTORS_FOUND" if findings
                    else "CLEAN_NO_KNOWN_VECTOR"),
        "note": "LEAD statis atas artefak snapshot — kombinasi izin "
                "bukan bukti penyalahgunaan; butuh konteks bisnis + "
                "CloudTrail (lihat cloudtrail_scan) utk konfirmasi.",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="iam_escalation_scan — analisis OFFLINE jalur "
                    "eskalasi IAM dari artefak get-account-authorization-"
                    "details (read-only, nol jaringan).")
    ap.add_argument("--auth", required=True,
                    help="file JSON hasil 'aws iam get-account-"
                         "authorization-details'")
    ap.add_argument("--fail-on", choices=["medium", "high"], default="high")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.auth)
    if not path.is_file():
        print(f"[iam] file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        auth = json.loads(path.read_text(encoding="utf-8",
                                         errors="replace"))
    except json.JSONDecodeError as exc:
        print(f"[iam] JSON tidak valid (fail-closed): {exc}",
              file=sys.stderr)
        return 2
    if not isinstance(auth, dict) or not (
            auth.get("UserDetailList") or auth.get("RoleDetailList")
            or auth.get("GroupDetailList")):
        print("[iam] artefak tidak memuat principal (UserDetailList/"
              "RoleDetailList/GroupDetailList kosong) — fail-closed",
              file=sys.stderr)
        return 2

    result = scan(auth)
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    if args.json or args.out:
        print(text)
    else:
        print(f"verdict    : {result['verdict']} "
              f"({result['principals_total']} principal, "
              f"{result['managed_policies_mapped']} policy terpetakan)")
        for f in result["findings"]:
            print(f"  [{f['severity']:6}] {f['check']} — "
                  f"{f.get('principal', '?')} via {f.get('policy', '?')}: "
                  f"{f['message']}")
        print(f"note       : {result['note']}")

    worst = max((SEV_ORDER[f["severity"]] for f in result["findings"]),
                default=0)
    return 1 if worst >= SEV_ORDER[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
