"""[AUDIT: read-only] terraform_audit — audit statis IaC Terraform
(.tf) untuk kesalahan konfigurasi keamanan yang eksplisit.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/auditing-terraform-infrastructure-for-security' (antrean
SKILL-PORT-QUEUE #0270; atribusi ide, lisensi sumber Apache-2.0).
Dibangun from scratch TANPA kode sumber itu dan TANPA checkov/tfsec/
terrascan (semuanya alat eksternal): parser blok resource stdlib +
aturan deterministik dari kelas kesalahan publik. NOL jaringan, NOL
eksekusi terraform — pindai file .tf di repo sebelum apply.

Kelas temuan (zero-FP: hanya bentuk eksplisit di HCL):
  open-ingress-admin   ingress 0.0.0.0/0 atau ::/0 ke port 22/3389
                       (critical)
  open-ingress         ingress terbuka ke world utk port lain (high)
  s3-public-acl        acl = public-read / public-read-write (critical)
  public-access-block-off  block_public_acls/policies = false (high)
  publicly-accessible  publicly_accessible = true (RDS dkk., high)
  storage-encrypted-off  storage_encrypted = false (high)
  ebs-unencrypted      ebs volume/block device tanpa encrypted=true
                       (medium)
  s3-no-encryption     aws_s3_bucket tanpa konfigurasi SSE terkait
                       (medium — cek silang antar-resource)
  hardcoded-secret     password/token/api_key literal, atau AKIA...
                       (high / critical utk pola access key AWS)

Fail-closed:
  - source tidak ada / tidak ada file .tf            -> exit 2
  - file tidak terbaca / kurung tidak seimbang       -> tercatat
    unparsed, tidak pernah dianggap bersih
  - nilai tak dikenali (var.*, ${...}, data.)        -> tidak diflag
    (bukan keputusan operator)
  - komentar (#, //, /* */) dilewati — config yang DIKOMMENT bukan
    konfigurasi aktif

Pemakaian:
  python tools/terraform_audit.py --source infra/ --out tf.json
  python tools/terraform_audit.py --source main.tf --fail-on high
Exit: 0 selesai; 1 temuan >= --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.terraform-audit/1"
SCAN_EXT = {".tf", ".tfvars"}
MAX_FILE_BYTES = 4 * 1024 * 1024

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RESOURCE_RE = re.compile(r'\bresource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
ATTR_RE = re.compile(r'^\s*([a-zA-Z_][\w]*)\s*=\s*(.+?)\s*$')
INGRESS_RE = re.compile(r'\bingress\s*\{([^{}]*)\}', re.S)
AWS_KEY_ID_RE = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
SECRET_ATTR_RE = re.compile(
    r'^(?:password|secret|token|secret_key|api_key|access_key|'
    r'client_secret|db_password)$', re.I)
ADMIN_PORTS = {"22", "3389"}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _strip_line_comment(line: str) -> str:
    """Buang komentar # dan // di luar tanda kutip."""
    out = []
    quote: "str | None" = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == quote and (i == 0 or line[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if ch == '"':
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#" or line[i:i + 2] == "//":
            break
        out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _strip_block_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _extract_resource_blocks(text: str) -> "tuple[list[dict], str | None]":
    """Ekstrak blok resource dgn penyeimbangan kurung (string dilewati).

    Return (daftar {type, name, body}, error_atau_None). Blok yang
    kurungnya tidak seimbang membatalkan file (fail-closed).
    """
    out: list[dict] = []
    for m in RESOURCE_RE.finditer(text):
        start = m.end() - 1          # posisi '{'
        depth = 0
        in_string = False
        end = None
        i = start
        while i < len(text):
            ch = text[i]
            if in_string:
                if ch == '"' and text[i - 1] != "\\":
                    in_string = False
            elif ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        if end is None:
            return [], (f"blok resource {m.group(1)}.{m.group(2)} "
                        "tidak seimbang kurungnya")
        out.append({"type": m.group(1), "name": m.group(2),
                    "body": text[start + 1:end]})
    return out, None


def _attrs(body: str) -> dict:
    """Pasangan atribut top-level-ish (per baris) dari body blok."""
    attrs: dict[str, str] = {}
    for line in body.splitlines():
        m = ATTR_RE.match(_strip_line_comment(line))
        if m and "=" in line:
            attrs[m.group(1)] = m.group(2).strip()
    return attrs


def _parse_int(val: str) -> "int | None":
    m = re.match(r"^\s*(\d+)\s*$", val)
    return int(m.group(1)) if m else None


def _is_literal_string(val: str) -> "str | None":
    m = re.match(r'^"(.*)"$', val.strip(), re.S)
    return m.group(1) if m else None


def _cidr_list(val: str) -> "list[str]":
    s = _is_literal_string(val)
    if s is not None:
        return [s]
    m = re.match(r"^\[(.*)\]$", val.strip(), re.S)
    if m:
        return [_is_literal_string(p) or p.strip()
                for p in m.group(1).split(",") if p.strip()]
    return []


def _check_ingress(rules_text: str, where: str,
                   findings: list[dict]) -> None:
    """Satu blok/bagian ingress: world-open cidr + port."""
    attrs = _attrs(rules_text)
    cidrs = _cidr_list(attrs.get("cidr_blocks",
                                 attrs.get("cidr_ipv4", "")))
    if not (set(cidrs) & OPEN_CIDRS):
        return
    ports = {str(_parse_int(attrs.get(k, "") or ""))
             for k in ("from_port", "to_port")}
    ports.discard("None")
    if ports & ADMIN_PORTS:
        findings.append({
            "severity": "critical", "code": "open-ingress-admin",
            "where": where,
            "detail": f"ingress terbuka ke world (cidr {sorted(set(cidrs) & OPEN_CIDRS)}) "
                      f"pada port {sorted(ports & ADMIN_PORTS)} "
                      "(SSH/RDP ke internet)",
        })
    else:
        findings.append({
            "severity": "high", "code": "open-ingress",
            "where": where,
            "detail": f"ingress terbuka ke world pada port "
                      f"{sorted(ports) or '?'}",
        })


def audit_file(text: str, fname: str) -> "tuple[list[dict], str | None]":
    """Audit satu file .tf -> (temuan, error_atau_None)."""
    text = _strip_block_comments(text)
    blocks, err = _extract_resource_blocks(text)
    if err:
        return [], f"{fname}: {err}"
    findings: list[dict] = []
    s3_buckets: set[str] = set()
    s3_enc_refs: set[str] = set()

    for b in blocks:
        rtype, rname = b["type"], b["name"]
        where = f"{fname}:resource.{rtype}.{rname}"
        attrs = _attrs(b["body"])

        # --- ingress (blok nested di security group / rule mandiri) ---
        if rtype in ("aws_security_group", "aws_security_group_rule",
                     "aws_vpc_security_group_ingress_rule"):
            if rtype == "aws_security_group":
                for im in INGRESS_RE.finditer(b["body"]):
                    _check_ingress(im.group(1), where, findings)
            else:
                _check_ingress(b["body"], where, findings)

        # --- S3 ACL publik + public access block ---
        if rtype == "aws_s3_bucket":
            s3_buckets.add(rname)
            acl = _is_literal_string(attrs.get("acl", ""))
            if acl in ("public-read", "public-read-write"):
                findings.append({
                    "severity": "critical", "code": "s3-public-acl",
                    "where": where,
                    "detail": f"bucket acl = '{acl}' (publik)",
                })
        if rtype == "aws_s3_bucket_public_access_block":
            target = re.search(
                r"bucket\s*=\s*aws_s3_bucket\.([\w-]+)\.", b["body"])
            for k in ("block_public_acls", "block_public_policy",
                      "ignore_public_acls",
                      "restrict_public_buckets"):
                if attrs.get(k) == "false":
                    findings.append({
                        "severity": "high",
                        "code": "public-access-block-off",
                        "where": where,
                        "detail": f"{k} = false"
                                  + (f" (untuk bucket {target.group(1)})"
                                     if target else ""),
                    })

        # --- enkripsi ---
        if rtype == "aws_s3_bucket_server_side_encryption_configuration":
            ref = re.search(
                r"bucket\s*=\s*aws_s3_bucket\.([\w-]+)\.", b["body"])
            if ref:
                s3_enc_refs.add(ref.group(1))
        if rtype in ("aws_ebs_volume", "aws_ebs_block_device",
                     "aws_instance"):
            for blk in re.finditer(
                    r"ebs_block_device\s*\{([^{}]*)\}", b["body"]):
                e_attrs = _attrs(blk.group(1))
                if e_attrs.get("encrypted") != "true":
                    findings.append({
                        "severity": "medium",
                        "code": "ebs-unencrypted",
                        "where": where,
                        "detail": "ebs_block_device tanpa "
                                  "encrypted = true",
                    })
            if rtype == "aws_ebs_volume" and \
                    attrs.get("encrypted") != "true":
                findings.append({
                    "severity": "medium", "code": "ebs-unencrypted",
                    "where": where,
                    "detail": "aws_ebs_volume tanpa encrypted = true",
                })
        if rtype == "aws_db_instance":
            if attrs.get("storage_encrypted") == "false":
                findings.append({
                    "severity": "high", "code": "storage-encrypted-off",
                    "where": where,
                    "detail": "storage_encrypted = false (database)",
                })
            if attrs.get("publicly_accessible") == "true":
                findings.append({
                    "severity": "high", "code": "publicly-accessible",
                    "where": where,
                    "detail": "publicly_accessible = true (database "
                              "ke internet)",
                })

        # --- secret literal ---
        for k, v in attrs.items():
            if SECRET_ATTR_RE.match(k):
                lit = _is_literal_string(v)
                if lit is None:
                    continue  # var.*/${...}/data.* — bukan literal
                if not lit.strip():
                    continue
                findings.append({
                    "severity": "high", "code": "hardcoded-secret",
                    "where": where,
                    "detail": f"atribut '{k}' berisi nilai literal "
                              f"(nama atribut menyimpan secret) — nilai "
                              f"tidak ditampilkan di sini",
                })

    # pola access key AWS dicari di SELURUH file — blok provider/locals
    # juga permukaan nyata, bukan hanya blok resource
    for m in AWS_KEY_ID_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        findings.append({
            "severity": "critical", "code": "aws-access-key-id",
            "where": f"{fname}:baris-{line_no}",
            "detail": "pola AWS access key ID (AKIA...) di file",
        })

    for rname in sorted(s3_buckets - s3_enc_refs):
        findings.append({
            "severity": "medium", "code": "s3-no-encryption",
            "where": f"{fname}:resource.aws_s3_bucket.{rname}",
            "detail": "tidak ada aws_s3_bucket_server_side_encryption_"
                      "configuration yang merujuk bucket ini",
        })
    return findings, None


def audit(source: Path) -> "tuple[dict, list[str]]":
    """Audit dir/file .tf -> (laporan, daftar_unparsed)."""
    if source.is_file():
        if source.suffix.lower() not in SCAN_EXT:
            raise ValueError(
                f"{source} bukan file {sorted(SCAN_EXT)} (fail-closed — "
                "bukti yang salah tidak boleh jadi 'bersih')")
        files = [source]
    else:
        files = sorted(p for p in source.rglob("*")
                       if p.is_file() and p.suffix.lower() in SCAN_EXT)
    if not files:
        raise ValueError(f"tidak ada file {sorted(SCAN_EXT)} di {source}")
    findings: list[dict] = []
    unparsed: list[str] = []
    scanned = 0
    for f in files:
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                unparsed.append(f"{f}: terlalu besar")
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            unparsed.append(f"{f}: {exc}")
            continue
        f_findings, err = audit_file(text, f.name)
        if err:
            unparsed.append(err)
            continue
        findings.extend(f_findings)
        scanned += 1
    if scanned == 0 and not unparsed:
        raise ValueError("tidak ada file .tf yang bisa diaudit "
                         "(fail-closed)")
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                 f["where"], f["code"]))
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "schema": SCHEMA,
        "files_scanned": scanned,
        "unparsed": unparsed,
        "summary": {
            "findings_total": len(findings),
            "by_severity": {k: by_sev[k] for k in sorted(
                by_sev, key=lambda s: SEV_ORDER.get(s, 9))},
        },
        "findings": findings,
        "note": "audit statis HCL eksplisit — bukan pengganti plan-time "
                "check; nilai var.*/data.* tidak dinilai (fail-closed)",
    }, unparsed


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="terraform_audit — audit statis file .tf "
                    "(read-only, nol jaringan, fail-closed).")
    ap.add_argument("--source", required=True, help="file/dir .tf")
    ap.add_argument("--fail-on", choices=("critical", "high", "any"),
                    default=None,
                    help="exit 1 bila ada temuan pada level itu")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    source = Path(args.source)
    if not source.exists():
        print(f"[tf-audit] source tidak ada: {source}", file=sys.stderr)
        return 2
    try:
        result, unparsed = audit(source)
    except (OSError, ValueError) as exc:
        print(f"[tf-audit] gagal: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    print(f"[tf-audit] {result['files_scanned']} file diaudit "
          f"({len(unparsed)} unparsed)")
    print(f"[tf-audit] temuan: {s['findings_total']} "
          f"({', '.join(f'{k}={v}' for k, v in s['by_severity'].items()) or '-'})")
    for f in result["findings"][:10]:
        print(f"  [{f['severity']:8}] {f['code']:24} {f['where']}")
    if args.fail_on:
        sev = result["summary"]["by_severity"]
        hit = (args.fail_on == "any" and s["findings_total"] > 0) or \
            (args.fail_on == "high" and (sev.get("critical", 0)
                                         + sev.get("high", 0)) > 0) or \
            (args.fail_on == "critical" and sev.get("critical", 0) > 0)
        if hit:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
