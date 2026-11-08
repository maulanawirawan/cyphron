r"""[SAFETY: read-only] aws_config_audit — audit OFFLINE ekspor AWS Config
(configuration-item / snapshot JSON) untuk temuan kepatuhan deterministik.
TANPA jaringan, tanpa boto3.

Port konsep dari antrean SKILL-PORT-QUEUE #0583 (mukul975/
Anthropic-Cybersecurity-Skills 'implementing-aws-config-rules-for-
compliance'; atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM
SCRATCH: evaluasi field configuration-item ditulis sendiri dari konsep
rule AWS Config publik (CIS managed rules + custom rule required-tags di
sumber). Skill sumber menjalankan AWS Config + Lambda remediation live;
secai mengevaluasi EKSPOR offline (configuration-item JSON dari
ConfigurationItemChangeNotification / get-resource-config-history /
config-snapshot S3) agar nol jaringan dan dapat dites. Ranah TIDAK
diduplikasi: terraform_audit (IaC HCL sebelum deploy), cloudtrail_scan
(log aktivitas API), iam_escalation_scan (policy JSON eskalasi) — tool
ini menilai KONFIGURASI sumber daya yang terekam Config.

Input -> mekanisme -> output:
  - Input : file JSON AWS Config, salah satu bentuk:
              (a) invoking event  {"configurationItem": {...}}
              (b) snapshot        {"configurationItems": [...]}
              (c) array item      [ {...}, ... ]
              (d) item tunggal    {..., "resourceType": "AWS::..."}
  - Mekanisme: normalisasi daftar item -> dispatch per resourceType ->
            evaluasi field configuration/supplementaryConfiguration.
  - Output: temuan {check, severity, resource_type, resource_id, message}
            + summary + notes.

Cek (semua verdict = LEAD — kebijakan organisasi bisa berbeda):
  required-tags-missing (medium): tag wajib hilang (--require-tags,
                                  default Environment,Owner) pada
                                  EC2 Instance/RDS DBInstance/S3 Bucket.
  s3-public-block       (high)  : publicAccessBlockConfiguration ada
                                  field false (blockPublicAcls/
                                  ignorePublicAcls/blockPublicPolicy/
                                  restrictPublicBuckets).
  s3-pab-absent         (medium): S3 Bucket tanpa
                                  publicAccessBlockConfiguration sama
                                  sekali (tidak disimpulkan bersih).
  s3-no-ssl-deny        (medium): bucketPolicy tanpa statement Deny
                                  aws:SecureTransport=false (S3_BUCKET_
                                  SSL_REQUESTS_ONLY).
  s3-sse-absent         (medium): serverSideEncryptionConfiguration
                                  kosong/absen (S3_BUCKET_SERVER_SIDE_
                                  ENCRYPTION_ENABLED).
  root-access-key       (high)  : pengguna "<root_account>" dgn access
                                  key aktif (IAM_ROOT_ACCESS_KEY_CHECK).
  user-access-keys      (medium): pengguna IAM biasa dgn access key
                                  aktif tanpa --allow-keys-user.
  password-policy       (medium): Require{Upper,Lower,Numbers,Symbols}
                                  false atau MinimumPasswordLength <
                                  --min-pw-len (default 14, CIS utk
                                  akun privileged).
  sg-open-port          (high)  : SecurityGroup ipPermissions mengizinkan
                                  0.0.0.0/0 utk SSH 22 / RDP 3389
                                  (restricted-ssh dsb.).
  vpc-flow-logs-off     (medium): VPC tanpa FlowLog yang mereferensikan
                                  vpcId-nya (VPC_FLOW_LOGS_ENABLED).
  rds-unencrypted       (high)  : storageEncrypted false
                                  (RDS_STORAGE_ENCRYPTED).
  ebs-unencrypted       (medium): Volume encrypted false
                                  (ENCRYPTED_VOLUMES).

Fail-closed:
  - bukan JSON / tidak ada item / item tanpa resourceType -> exit 2.
  - item tanpa field configuration dihitung items_without_configuration
    (tidak dipendam), cek yang butuh field itu dilewati eksplisit.
  - supplementaryConfiguration ber-JSON-string diparse; gagal parse
    dicatat di notes.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default info, mengikuti
yara_rule_lint/ids_rule_lint); 2 input tidak valid.

Pemakaian:
  python tools/aws_config_audit.py --item config-item.json
  python tools/aws_config_audit.py --item snapshot.json \
      --require-tags Environment,Owner,CostCenter --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}
DEFAULT_TAGS = ("Environment", "Owner")
TAGGED_TYPES = {"AWS::EC2::Instance", "AWS::RDS::DBInstance",
                "AWS::S3::Bucket"}
OPEN_PORTS = {22: "SSH", 3389: "RDP"}
CIS_MIN_PW_LEN_DEFAULT = 14


def _load_items(doc: object) -> list[dict]:
    """Normalisasi bentuk input -> daftar configuration-item (dict)."""
    if isinstance(doc, dict) and isinstance(doc.get("configurationItem"),
                                           dict):
        return [doc["configurationItem"]]
    if isinstance(doc, dict) and isinstance(doc.get("configurationItems"),
                                           list):
        return [x for x in doc["configurationItems"] if isinstance(x, dict)]
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    if isinstance(doc, dict) and "resourceType" in doc:
        return [doc]
    raise ValueError("bukan configuration-item/snapshot AWS Config yang "
                     "dikenali (butuh configurationItem/configurationItems/"
                     "array item/resourceType)")


def _conf(item: dict) -> dict:
    conf = item.get("configuration")
    return conf if isinstance(conf, dict) else {}


def _supp(item: dict, key: str) -> object:
    """Ambil supplementaryConfiguration[key]; bisa JSON-string ter-encode."""
    supp = item.get("supplementaryConfiguration")
    val = supp.get(key) if isinstance(supp, dict) else None
    if isinstance(val, str) and val.strip().startswith(("{", "[")):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return val  # gagal parse -> pemanggil notes utk catat
    return val


def _tags(conf: dict, supp_conf: object) -> dict:
    tags = conf.get("tags")
    if isinstance(tags, list):  # bentuk list {key,value}
        return {str(t.get("key")): str(t.get("value"))
                for t in tags if isinstance(t, dict)}
    if isinstance(tags, dict):
        return dict(tags)
    if isinstance(supp_conf, dict):
        t = supp_conf.get("tags")
        if isinstance(t, dict):
            return dict(t)
        if isinstance(t, list):
            return {str(x.get("key")): str(x.get("value"))
                    for x in t if isinstance(x, dict)}
    return {}


def _iter_permissions(conf: dict, supp_conf: object):
    """ipPermissions dari configuration; fallback supplementary
    IpPermissions (JSON-string sudah di-parse _supp)."""
    perms = conf.get("ipPermissions")
    if isinstance(perms, list):
        yield from (p for p in perms if isinstance(p, dict))
        return
    if isinstance(supp_conf, list):
        yield from (p for p in supp_conf if isinstance(p, dict))


def audit_items(items: list[dict], require_tags: "list[str]",
                min_pw_len: int, findings: list[dict],
                notes: list[str]) -> dict:
    """Evaluasi satu/lebih configuration-item -> temuan + summary."""
    summary: dict = {"items": len(items), "by_type": {},
                     "items_without_configuration": 0, "checks": {}}
    vpc_ids_seen: set[str] = set()
    flowlog_vpc_ids: set[str] = set()
    pending_vpcs: list[dict] = []
    for item in items:
        rtype = str(item.get("resourceType") or "")
        rid = str(item.get("resourceId") or item.get("resourceName") or "?")
        summary["by_type"][rtype] = summary["by_type"].get(rtype, 0) + 1
        conf = _conf(item)
        supp_conf = _supp(item, "PublicAccessBlockConfiguration")
        supp_tags = _supp(item, "Tags")

        def emit(check: str, severity: str, message: str) -> None:
            findings.append({"check": check, "severity": severity,
                             "resource_type": rtype, "resource_id": rid,
                             "message": message})
            summary["checks"][check] = summary["checks"].get(check, 0) + 1

        supp_raw = item.get("supplementaryConfiguration")
        if not conf and not isinstance(supp_raw, (dict, list)):
            summary["items_without_configuration"] += 1
            continue

        # --- required tags (konsep custom rule sumber) ---
        if rtype in TAGGED_TYPES:
            tags = _tags(conf, supp_tags)
            missing = [t for t in require_tags if t not in tags]
            if missing:
                emit("required-tags-missing", "medium",
                     f"tag wajib hilang: {', '.join(missing)}")

        # --- S3 bucket ---
        if rtype == "AWS::S3::Bucket":
            pab = None
            if isinstance(conf.get("publicAccessBlockConfiguration"), dict):
                pab = conf["publicAccessBlockConfiguration"]
            elif isinstance(supp_conf, dict):
                pab = supp_conf
            if isinstance(pab, dict):
                for field in ("blockPublicAcls", "ignorePublicAcls",
                              "blockPublicPolicy", "restrictPublicBuckets"):
                    if pab.get(field) is not True:
                        emit("s3-public-block", "high",
                             f"publicAccessBlock.{field} bukan true — "
                             "blok akses publik S3 tidak penuh")
                        break
            else:
                emit("s3-pab-absent", "medium",
                     "publicAccessBlockConfiguration tidak terekam — "
                     "keadaan blok publik tidak bisa disimpulkan")
            bp = conf.get("bucketPolicy")
            if isinstance(bp, str):
                try:
                    pol = json.loads(bp)
                    deny_ssl = any(
                        (st.get("Effect") == "Deny"
                         and "aws:SecureTransport"
                         in json.dumps(st.get("Condition") or {}))
                        for st in pol.get("Statement", [])
                        if isinstance(st, dict))
                    if not deny_ssl:
                        emit("s3-no-ssl-deny", "medium",
                             "bucketPolicy tanpa Deny aws:SecureTransport"
                             "=false — permintaan HTTP bisa dilayani")
                except json.JSONDecodeError:
                    notes.append(f"{rid}: bucketPolicy gagal diparse "
                                 "(fail-closed, cek SSL dilewati)")
            sse = conf.get("serverSideEncryptionConfiguration") \
                or _supp(item, "ServerSideEncryptionConfiguration")
            if not sse:
                emit("s3-sse-absent", "medium",
                     "serverSideEncryptionConfiguration kosong/absen — "
                     "SSE default tidak terbukti dinyalakan")

        # --- IAM ---
        if rtype == "AWS::IAM::User":
            uname = str(conf.get("userName") or item.get("resourceName")
                        or "")
            keys = conf.get("accessKeys") or _supp(item, "AccessKeys")
            active = [k for k in keys if isinstance(k, dict)
                      and k.get("status") == "Active"] \
                if isinstance(keys, list) else []
            if uname == "<root_account>":
                if active:
                    emit("root-access-key", "high",
                         f"{len(active)} access key aktif pada akun root — "
                         "root TIDAK boleh punya access key")
            elif active:
                emit("user-access-keys", "medium",
                     f"{len(active)} access key aktif pada pengguna "
                     f"{uname!r} — pertimbangkan role/per-token")
        if rtype == "AWS::Account":
            pp = conf.get("passwordPolicy") or _supp(item, "PasswordPolicy")
            if isinstance(pp, dict):
                for flag in ("requireUppercaseCharacters",
                             "requireLowercaseCharacters",
                             "requireNumbers", "requireSymbols"):
                    if pp.get(flag) is not True:
                        emit("password-policy", "medium",
                             f"{flag} false — kebijakan password lemah")
                length = pp.get("minimumPasswordLength")
                if isinstance(length, int) and length < min_pw_len:
                    emit("password-policy", "medium",
                         f"minimumPasswordLength={length} < {min_pw_len}")

        # --- EC2 SecurityGroup ---
        if rtype == "AWS::EC2::SecurityGroup":
            supp_ip = _supp(item, "IpPermissions")
            for p in _iter_permissions(conf, supp_ip):
                lo = p.get("fromPort")
                hi = p.get("toPort")
                ranges = p.get("ipRanges") or []
                cidrs = {r.get("cidrIp") for r in ranges
                         if isinstance(r, dict)}
                for port, name in OPEN_PORTS.items():
                    lo_num = lo if isinstance(lo, int) else 0
                    hi_num = hi if isinstance(hi, int) else 65535
                    if lo_num <= port <= hi_num and "0.0.0.0/0" in cidrs:
                        emit("sg-open-port", "high",
                             f"{name} ({port}) terbuka ke 0.0.0.0/0 — "
                             "admin service terekspos internet")

        # --- VPC / FlowLog ---
        if rtype == "AWS::EC2::VPC":
            vpc_ids_seen.add(rid)
            pending_vpcs.append({"id": rid,
                                 "conf_flow": conf.get("flowLogs")})
        if rtype == "AWS::EC2::FlowLog":
            res = conf.get("resourceId")
            if isinstance(res, str):
                flowlog_vpc_ids.add(res)

        # --- RDS / EBS ---
        if rtype == "AWS::RDS::DBInstance":
            enc = conf.get("storageEncrypted")
            if enc is False:
                emit("rds-unencrypted", "high",
                     "storageEncrypted false — storage RDS tanpa enkripsi")
        if rtype == "AWS::EC2::Volume":
            enc = conf.get("encrypted")
            if enc is False:
                emit("ebs-unencrypted", "medium",
                     "encrypted false — EBS tanpa enkripsi")

    # flow-log per VPC (setelah semua item terbaca)
    for vpc in pending_vpcs:
        if vpc["conf_flow"]:
            continue
        if vpc["id"] not in flowlog_vpc_ids:
            findings.append({
                "check": "vpc-flow-logs-off", "severity": "medium",
                "resource_type": "AWS::EC2::VPC", "resource_id": vpc["id"],
                "message": "VPC tanpa FlowLog yang mereferensikannya — "
                           "telemetri jaringan tidak terekam"})
            summary["checks"]["vpc-flow-logs-off"] = \
                summary["checks"].get("vpc-flow-logs-off", 0) + 1
    return summary


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="aws_config_audit — evaluasi OFFLINE ekspor AWS Config "
                    "(configuration-item/snapshot) dgn rule kepatuhan "
                    "deterministik (fail-closed; LEAD).")
    ap.add_argument("--item", required=True, nargs="+",
                    help="satu/lebih file JSON configuration-item/snapshot")
    ap.add_argument("--require-tags", default=",".join(DEFAULT_TAGS),
                    help="tag wajib utk EC2/RDS/S3, dipisah koma "
                         "(default Environment,Owner)")
    ap.add_argument("--min-pw-len", type=int,
                    default=CIS_MIN_PW_LEN_DEFAULT,
                    help="ambang minimumPasswordLength (default 14)")
    ap.add_argument("--json", default=None,
                    help="tulis laporan JSON ke path ini (selain stdout)")
    ap.add_argument("--fail-on", choices=sorted(SEV_ORDER), default="info",
                    help="severity minimum yang memicu exit 1 (default "
                         "info)")
    args = ap.parse_args(argv)

    all_items: list[dict] = []
    errors: list[str] = []
    for path in map(Path, args.item):
        if not path.is_file():
            print(f"error: file tidak ada: {path}", file=sys.stderr)
            return 2
        try:
            all_items.extend(_load_items(json.loads(
                path.read_text(encoding="utf-8"))))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{path}: {exc}")
    if not all_items:
        print("error: tidak ada configuration-item yang tervalidasi:\n  "
              + "\n  ".join(errors or ["(tidak ada input)"]),
              file=sys.stderr)
        return 2

    require_tags = [t.strip() for t in args.require_tags.split(",")
                    if t.strip()]
    findings: list[dict] = []
    notes: list[str] = list(errors)
    summary = audit_items(all_items, require_tags, args.min_pw_len,
                          findings, notes)
    summary["sources"] = len(args.item)

    report = {
        "kind": "aws-config-audit",
        "attribution": "konsep #0583 mukul975/implementing-aws-config-"
                       "rules-for-compliance (Apache-2.0) — dibangun from "
                       "scratch; rule id AWS Config hanya label konsep",
        "findings": findings,
        "summary": summary,
        "notes": notes,
    }
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json:
        Path(args.json).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    threshold = SEV_ORDER[args.fail_on]
    counted = [f for f in findings
               if SEV_ORDER[f["severity"]] >= threshold]
    if counted:
        print(f"-- {len(counted)} temuan >= {args.fail_on} "
              f"(high={sum(1 for f in findings if f['severity'] == 'high')} "
              f"medium={sum(1 for f in findings if f['severity'] == 'medium')})",
              file=sys.stderr)
    else:
        print(f"-- bersih: tidak ada temuan >= {args.fail_on}",
              file=sys.stderr)
    for n in notes:
        print(f"note: {n}", file=sys.stderr)
    if summary["items_without_configuration"]:
        print(f"note: {summary['items_without_configuration']} item tanpa "
              "field configuration — cek field-nya dilewati eksplisit",
              file=sys.stderr)
    return 1 if counted else 0


if __name__ == "__main__":
    sys.exit(main())
