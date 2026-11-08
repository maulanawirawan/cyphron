r"""[AUDIT: read-only] lambda_config_audit — audit OFFLINE konfigurasi
serverless (AWS Lambda utama; GCP Cloud Functions ringkas) dari ekspor
JSON CLI: list-functions/get-function-configuration (runtime EOL, env
var sensitif, VPC), get-policy (invoke publik), list-function-url-configs
(function URL tanpa auth), kebijakan role eksekusi (wildcard action),
gcloud functions list (ingress ALLOW_ALL, service account default).
TANPA jaringan, tanpa boto3/gcloud.

Mengisi antrean port SKILL-PORT-QUEUE #0890 (mukul975/
Anthropic-Cybersecurity-Skills 'performing-serverless-function-security-
review'; atribusi konsep, lisensi sumber Apache-2.0). Skill sumber =
runbook review LIVE via AWS/az/gcloud CLI + Checkov/Prowler/Bandit;
inti deterministik yang diekstrak di sini = TRIASE ekspor konfigurasi
yang sudah diambil (pola ingest ala oauth_grant_audit/cspm_finding_
ingest) — from scratch, tanpa menyalin kode/konfigurasi sumber.

Pembagian ranah (TIDAK diduplikasi):
  - eskalasi IAM lintas-akun/jalur PassRole -> iam_escalation_scan
  - evaluasi Config-rule berbasis configuration-item -> aws_config_audit
  - temuan scanner (Checkov/Prowler SARIF/ASFF) -> sarif_ingest /
    cspm_finding_ingest
  - analisis KODE fungsi (SAST ala Bandit) = di luar kelas ini — ranah
    review kode manual; triase event-source injection = checklist
    PORT-AGENT-METHODS (seksi 87)
  - di sini: konfigurasi fungsi + kebijakan invoke + env var + runtime.

Input -> mekanisme -> output:
  - Input : --functions JSON (ekspor `aws lambda list-functions`:
            {"Functions":[...]} ATAU array), --configs JSON (ekspor
            `get-function-configuration`, objek/array; merge by
            FunctionName), --policies JSON (ekspor `get-policy`:
            [{FunctionName, Policy: <string-JSON|objek>}] atau
            {nama: policy}), --urls JSON (ekspor
            `list-function-url-configs`: {"FunctionUrlConfigs":[...]}
            ATAU {nama: [...]} ATAU [{FunctionName, FunctionUrlConfigs:
            [...]}]), --gcp-functions JSON (`gcloud functions list
            --format=json`), --runtime-eol JSON (array runtime EOL
            tambahan). Minimal satu sumber; baca-saja.
  - Mekanisme: merge fungsi by name -> cek deterministik per fungsi ->
            temuan severity + poc (nama fungsi + sumber).
  - Output: JSON {schema, stats, functions, findings, notes, verdict}.

Cek:
  env-secret-value      (high)  : nilai env var cocok pola kredensial
                         berkeyakinan tinggi (AKIA/ASIA{16}, ghp_/gho_/
                         github_pat_, xox[baprs]-, JWT eyJ.eyJ., header
                         PRIVATE KEY, sk_live_, db://user:pass@) — NILAI
                         TIDAK PERNAH keluar; bukti = nama var + nama
                         pola + panjang.
  env-sensitive-name    (medium): nama var memuat token sensitif
                         (password/secret/token/credential/api_key/
                         access_key/private_key) tanpa kecocokan nilai
                         — review migrasi ke Secrets Manager.
  public-invoke         (high)  : resource policy Statement Allow dgn
                         Principal "*" / {"AWS":"*"}; bila ada Condition
                         SourceAccount/ArnLike -> medium (terkendali,
                         tetap review).
  policy-unparseable    (medium): Policy string bukan JSON valid
                         (fail-closed, tidak dianggap bersih).
  url-no-auth           (high)  : FunctionUrlConfig AuthType NONE
                         (endpoint publik tanpa API Gateway).
  role-wildcard         (high)  : kebijakan role eksekusi (--role-
                         policies) punya Allow Action "*" / "svc:*"
                         + Resource "*" — blast radius penuh akun.
  runtime-eol           (medium): runtime di tabel EOL statis (bisa
                         diperluas --runtime-eol); runtime tak dikenal
                         TIDAK ditemukan (anti-FP — runtime baru sah).
  no-vpc                (info)  : tanpa VpcConfig.VpcId — banyak fungsi
                         sah; dicatat sbg info cakupan, bukan temuan.
  gcp-ingress-allow-all (high)  : ingressSettings ALLOW_ALL.
  gcp-default-sa        (medium): serviceAccountEmail default proyek
                         (*-compute@developer... / *@appspot...).

Fail-closed:
  - salah satu --*-file JSON rusak -> exit 2.
  - nol fungsi dikenali dari SEMUA sumber -> exit 2.
  - Policy string per-fungsi rusak -> temuan policy-unparseable
    (medium), bukan senyap.
  - nilai env var TIDAK PERNAH ditulis ke output (redaksi panjang).

Anti-FP: pola nilai beranchored; nama-var butuh token sensitif eksplisit
(dipisah non-alfanumerik, bukan substring "key" liar); wildcard hanya
string "*" persis / sufiks ":*"; tabel runtime EOL eksplisit.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error input.

Pemakaian:
  python tools/lambda_config_audit.py --functions functions.json
  python tools/lambda_config_audit.py --functions functions.json \
      --policies policies.json --urls urls.json \
      --role-policies roles.json --out audit.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.lambda-config-audit/1"

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

MAX_FILE_BYTES = 64 * 1024 * 1024

# Runtime Lambda yang sudah EOL/deprecated (tabel statis kurasi; bisa
# diperluas via --runtime-eol). Runtime tak dikenal = TIDAK ditemukan.
EOL_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8",
    "nodejs4.3", "nodejs4.3-edge", "nodejs6.10", "nodejs8.10",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "dotnetcore1.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet6",
    "java8", "go1.x", "ruby2.5", "ruby2.7", "provided",
}

# service account DEFAULT (dua bentuk bawaan proyek)
GCP_DEFAULT_SA_SUFFIXES = (
    "-compute@developer.gserviceaccount.com",   # Compute default
    "@appspot.gserviceaccount.com",             # App Engine default
)

# Pola nilai kredensial berkeyakinan tinggi (dari repo ini: paste_triage/
# repo-secret-scan kosakata — pola anchored, anti-FP).
VALUE_PATTERNS = (
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-temp-cred", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(
        r"\bgh[pousr]_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{22,}")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("stripe-secret", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("db-conn-with-pass", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)"
        r"://[^/\s:@]+:[^/\s:@]+@")),
)

# Token nama env var yang sensitif (dipisah non-alfanumerik, lowercase).
SENSITIVE_NAME_TOKENS = {
    "password", "passwd", "pwd", "secret", "secrets", "token", "tokens",
    "credential", "credentials", "api_key", "apikey", "access_key",
    "secretkey", "private_key", "privatekey", "signing_key", "db_pass",
}


def _add(findings: "list[dict]", fid: str, sev: str, msg: str,
         poc: str) -> None:
    findings.append({"id": fid, "severity": sev, "message": msg,
                     "poc": poc[:400]})


def _load_json(path: str, label: str) -> object:
    p = Path(path)
    try:
        if not p.is_file():
            raise ValueError(f"{label} tak ada: {path}")
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"{label} melebihi batas ukuran: {path}")
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} JSON rusak: {path}: {exc}") from exc


def _as_list(data: object, list_keys: "tuple[str, ...]") -> "list[dict]":
    """Terima array polos atau objek pembungkus {"Kunci": [...]}."""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in list_keys:
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _merge_functions(functions: "list[dict]",
                     configs: "list[dict]") -> "dict[str, dict]":
    merged: "dict[str, dict]" = {}
    for rec in functions + configs:
        name = rec.get("FunctionName") or rec.get("function_name")
        if not name or not isinstance(name, str):
            continue
        base = merged.setdefault(name, {})
        for k, v in rec.items():
            if v is not None:
                base[k] = v
    return merged


def _sensitive_name(name: str) -> bool:
    tokens = re.split(r"[^A-Za-z0-9]+", name.lower())
    return any(t in SENSITIVE_NAME_TOKENS for t in tokens if t)


def _check_env_vars(name: str, env: object,
                    findings: "list[dict]", stats: dict) -> None:
    if not isinstance(env, dict):
        return
    variables = env.get("Variables")
    if not isinstance(variables, dict):
        return
    stats["env_vars_checked"] = \
        stats.get("env_vars_checked", 0) + len(variables)
    for key, value in sorted(variables.items()):
        if not isinstance(value, str):
            continue
        for pname, pattern in VALUE_PATTERNS:
            if pattern.search(value):
                _add(findings, "env-secret-value", "high",
                     f"{name}: env var '{key}' cocok pola "
                     f"kredensial '{pname}' (panjang {len(value)}) — "
                     f"migrasi ke Secrets Manager + rotasi",
                     f"{name}:{key}:<redacted len={len(value)}>")
                stats["env_secret_hits"] = \
                    stats.get("env_secret_hits", 0) + 1
                break
        else:
            if _sensitive_name(key):
                _add(findings, "env-sensitive-name", "medium",
                     f"{name}: env var '{key}' bernama sensitif tanpa "
                     f"kecocokan pola — review (jangan klaim aman)",
                     f"{name}:{key}")


def _policy_statements(policy: object) -> "tuple[list[dict], bool]":
    """(statements, ok) — terima objek atau string JSON."""
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return [], False
    if not isinstance(policy, dict):
        return [], False
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [s for s in stmts if isinstance(s, dict)], True


def _principal_wildcard(principal: object) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for v in principal.values():
            if v == "*" or (isinstance(v, list) and "*" in v):
                return True
    return False


def _check_policy(name: str, policy: object,
                  findings: "list[dict]", stats: dict) -> None:
    stmts, ok = _policy_statements(policy)
    if not ok:
        _add(findings, "policy-unparseable", "medium",
             f"{name}: resource policy bukan JSON valid — invoke "
             f"TIDAK bisa dinilai (fail-closed)", f"{name}:policy")
        stats["policy_unparseable"] = \
            stats.get("policy_unparseable", 0) + 1
        return
    for stmt in stmts:
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        if not _principal_wildcard(stmt.get("Principal")):
            continue
        cond = stmt.get("Condition")
        constrained = isinstance(cond, dict) and bool(cond)
        _add(findings, "public-invoke",
             "medium" if constrained else "high",
             f"{name}: invoke publik (Principal wildcard) "
             f"{'dgn Condition pembatas — review' if constrained else
              'TANPA pembatas — siapa pun bisa invoke'}",
             f"{name}:{stmt.get('Sid', 'no-sid')}")
        stats["public_invoke_hits"] = \
            stats.get("public_invoke_hits", 0) + 1


def _iter_url_entries(
        udata: object) -> "list[tuple[str, list[dict]]]":
    """Normalisasi bentuk ekspor list-function-url-configs:
    {"FunctionUrlConfigs":[...]}, {nama: [cfg]}, {nama: [{FunctionName,
    FunctionUrlConfigs:[...]}]}, [{FunctionName, FunctionUrlConfigs}],
    [{cfg dengan FunctionName}]."""
    out: "list[tuple[str, list[dict]]]" = []
    if isinstance(udata, dict) and "FunctionUrlConfigs" in udata:
        for ent in udata["FunctionUrlConfigs"]:
            if isinstance(ent, dict):
                name = str(ent.get("FunctionName")
                           or _name_from_arn(ent.get("FunctionArn"))
                           or "")
                out.append((name, [ent]))
        return out
    if isinstance(udata, dict):
        for name, lst in udata.items():
            if not isinstance(lst, list):
                continue
            for item in lst:
                if isinstance(item, dict) and                         "FunctionUrlConfigs" in item:
                    inner = item["FunctionUrlConfigs"]
                    out.append((str(item.get("FunctionName") or name),
                                inner if isinstance(inner, list)
                                else []))
                else:
                    out.append((str(name),
                                [item] if isinstance(item, dict)
                                else []))
        return out
    for ent in _as_list(udata, ()):
        name = str(ent.get("FunctionName")
                   or _name_from_arn(ent.get("FunctionArn")) or "")
        if "FunctionUrlConfigs" in ent:
            inner = ent["FunctionUrlConfigs"]
            out.append((name, inner if isinstance(inner, list) else []))
        else:
            out.append((name, [ent]))
    return out


def _name_from_arn(arn: object) -> "str | None":
    """arn:aws:lambda:...:function:NAMA -> NAMA."""
    if not isinstance(arn, str):
        return None
    m = re.search(r":function:([^:]+)$", arn)
    return m.group(1) if m else None


def _check_urls(name: str, urlcfgs: "list[dict]",
                findings: "list[dict]") -> None:
    for cfg in urlcfgs:
        if not isinstance(cfg, dict):
            continue
        if str(cfg.get("AuthType", "")).upper() == "NONE":
            _add(findings, "url-no-auth", "high",
                 f"{name}: function URL tanpa auth (AuthType NONE) — "
                 f"endpoint publik langsung ke fungsi",
                 f"{name}:{cfg.get('FunctionUrl', '')}")


def _check_runtime(name: str, runtime: object, eol: "set[str]",
                   findings: "list[dict]") -> None:
    if isinstance(runtime, str) and runtime in eol:
        _add(findings, "runtime-eol", "medium",
             f"{name}: runtime '{runtime}' sudah EOL/deprecated — "
             f"naikkan ke runtime yang didukung", f"{name}:{runtime}")


def _check_vpc(name: str, rec: dict, findings: "list[dict]") -> None:
    vpc = rec.get("VpcConfig") or {}
    if not isinstance(vpc, dict) or not vpc.get("VpcId"):
        _add(findings, "no-vpc", "info",
             f"{name}: tanpa VPC — cakupan akses data tak terkendali "
             f"jaringan (info, banyak fungsi sah)", f"{name}:vpc")


def _role_from_arn(arn: object) -> "str | None":
    if not isinstance(arn, str):
        return None
    m = re.search(r":role/(.+)$", arn)
    if not m:
        return None
    return m.group(1).split("/")[-1]


def _check_role_policies(funcs: "dict[str, dict]",
                         role_policies: object,
                         findings: "list[dict]", stats: dict) -> None:
    if not isinstance(role_policies, dict):
        return
    # bentuk: {role_name: policy-dok} atau {role_name: {"policy": dok}}
    by_role: "dict[str, object]" = {}
    for role, doc in role_policies.items():
        if isinstance(doc, dict) and "policy" in doc:
            by_role[role] = doc["policy"]
        else:
            by_role[role] = doc
    for fname, rec in sorted(funcs.items()):
        role = _role_from_arn(rec.get("Role"))
        if not role or role not in by_role:
            continue
        stmts, ok = _policy_statements(by_role[role])
        if not ok:
            _add(findings, "policy-unparseable", "medium",
                 f"{fname}: kebijakan role '{role}' bukan JSON valid — "
                 f"eskalasi TIDAK bisa dinilai (fail-closed)",
                 f"{fname}:{role}")
            stats["policy_unparseable"] = \
                stats.get("policy_unparseable", 0) + 1
            continue
        for stmt in stmts:
            if str(stmt.get("Effect", "")).lower() != "allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            wildcard_actions = [a for a in actions
                                if a == "*" or
                                (isinstance(a, str) and a.endswith(":*"))]
            star_resource = any(r == "*" for r in resources
                                if isinstance(r, str))
            if wildcard_actions and star_resource:
                _add(findings, "role-wildcard", "high",
                     f"{fname}: role '{role}' Allow "
                     f"{','.join(wildcard_actions[:3])} pada Resource "
                     f"'*' — blast radius penuh akun",
                     f"{fname}:{role}")
                stats["role_wildcard_hits"] = \
                    stats.get("role_wildcard_hits", 0) + 1


def _check_gcp(data: object, findings: "list[dict]",
               stats: dict) -> int:
    funcs = _as_list(data, ())
    n = 0
    for rec in funcs:
        name = (rec.get("name") or "").split("/")[-1]
        if not name:
            continue
        n += 1
        if rec.get("ingressSettings") == "ALLOW_ALL":
            _add(findings, "gcp-ingress-allow-all", "high",
                 f"{name}: ingressSettings ALLOW_ALL — dapat diakses "
                 f"dari internet tanpa pembatasan",
                 f"gcp:{name}")
            stats["gcp_ingress_hits"] = \
                stats.get("gcp_ingress_hits", 0) + 1
        sa = rec.get("serviceAccountEmail") or ""
        if sa.endswith(GCP_DEFAULT_SA_SUFFIXES):
            _add(findings, "gcp-default-sa", "medium",
                 f"{name}: service account default proyek ({sa}) — "
                 f"review least-privilege", f"gcp:{name}:{sa}")
    return n


def _parse_args(argv: "list[str] | None") -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Audit offline konfigurasi serverless dari ekspor "
                    "JSON (AWS Lambda / GCP Cloud Functions)")
    ap.add_argument("--functions", help="ekspor aws lambda list-functions")
    ap.add_argument("--configs", help="ekspor get-function-configuration")
    ap.add_argument("--policies", help="ekspor get-policy per fungsi")
    ap.add_argument("--urls", help="ekspor list-function-url-configs")
    ap.add_argument("--role-policies",
                    help="{role: policy-doc} kebijakan role eksekusi")
    ap.add_argument("--gcp-functions",
                    help="ekspor gcloud functions list --format=json")
    ap.add_argument("--runtime-eol", help="JSON array runtime EOL "
                    "tambahan (melengkapi tabel statis)")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), default="medium")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    sources: "list[tuple[str, str]]" = [
        ("functions", args.functions), ("configs", args.configs),
        ("policies", args.policies), ("urls", args.urls),
        ("role-policies", args.role_policies),
        ("gcp-functions", args.gcp_functions),
        ("runtime-eol", args.runtime_eol),
    ]
    given = [(label, path) for label, path in sources if path]
    if not given:
        print(json.dumps({"schema": SCHEMA,
                          "error": "butuh minimal satu --*-file"}),
              file=sys.stderr)
        return 2
    try:
        loaded = {label: _load_json(path, label) for label, path in given}
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    findings: "list[dict]" = []
    notes: "list[str]" = []
    stats: dict = {}

    eol = set(EOL_RUNTIMES)
    if "runtime-eol" in loaded:
        extra = loaded["runtime-eol"]
        if isinstance(extra, list):
            eol |= {r for r in extra if isinstance(r, str)}
        else:
            notes.append("--runtime-eol bukan array — diabaikan")

    raw_funcs = _as_list(loaded.get("functions", []),
                         ("Functions",)) \
        if "functions" in loaded else []
    raw_cfgs = _as_list(loaded.get("configs", []),
                        ("FunctionConfigurations",)) \
        if "configs" in loaded else []
    funcs = _merge_functions(raw_funcs, raw_cfgs)
    stats["aws_functions"] = len(funcs)

    for name, rec in sorted(funcs.items()):
        _check_env_vars(name, rec.get("Environment"), findings, stats)
        _check_runtime(name, rec.get("Runtime"), eol, findings)
        _check_vpc(name, rec, findings)

    if "policies" in loaded:
        pdata = loaded["policies"]
        entries: "list[tuple[str, object]]" = []
        if isinstance(pdata, dict):
            for name, doc in pdata.items():
                entries.append((name, doc))
        else:
            for ent in _as_list(pdata, ()):
                pname = (ent.get("FunctionName") or ent.get("function")
                         or "")
                entries.append((pname, ent.get("Policy")))
        for name, policy in entries:
            _check_policy(str(name), policy, findings, stats)

    if "urls" in loaded:
        for name, cfgs in _iter_url_entries(loaded["urls"]):
            _check_urls(name or "(tanpa-nama)", cfgs, findings)

    if "role-policies" in loaded:
        _check_role_policies(funcs, loaded["role-policies"],
                             findings, stats)

    if "gcp-functions" in loaded:
        stats["gcp_functions"] = _check_gcp(loaded["gcp-functions"],
                                            findings, stats)

    total = stats.get("aws_functions", 0) + stats.get("gcp_functions", 0)
    if total == 0:
        print(json.dumps({"schema": SCHEMA,
                          "error": "nol fungsi dikenali dari semua "
                                   "sumber (bentuk tak dikenal?)"}),
              file=sys.stderr)
        return 2

    if stats.get("policy_unparseable"):
        notes.append("ada policy yang gagal di-parse — fail-closed: "
                     "dilaporkan sbg temuan, bukan dianggap bersih")

    findings.sort(key=lambda f: -SEV_ORDER.get(f["severity"], 0))
    threshold = SEV_ORDER[args.fail_on]
    worst = max((SEV_ORDER.get(f["severity"], 0) for f in findings),
                default=0)
    result = {
        "schema": SCHEMA,
        "stats": stats,
        "fail_on": args.fail_on,
        "functions": sorted(funcs.keys()),
        "findings": findings,
        "notes": notes,
        "verdict": "findings" if worst >= threshold else "clean",
    }
    out_text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(out_text, encoding="utf-8")
    print(out_text)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
