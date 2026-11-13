r"""[SAFETY: read-only] cloudtrail_scan — triase OFFLINE log AWS CloudTrail
(JSON Records / JSONL): event berisiko tinggi deterministik, tanpa
jaringan.

Input -> mekanisme -> output:
  - Input : file log CloudTrail (.json: objek dgn "Records", atau
            .jsonl: satu event per baris), atau --dir berisi keduanya.
  - Mekanisme: normalisasi event -> cek deterministik per event +
            agregat error per identity (burst).
  - Output: temuan {check, severity, ts, identity, event, message}
            + meta (jumlah event, identity teraktif, unparsed).

Cek (verdict = LEAD utk triase; event nama sama bisa sah tergantung
perubahan):
  root-activity          (high)  : sesi Root dipakai (type == "Root").
  console-login-no-mfa   (high)  : ConsoleLogin dgn MFAUsed == "No".
  logging-impaired       (high)  : StopLogging/DeleteTrail/DeleteFlowLogs/
                                   DeleteLogGroup/DeleteDetector/
                                   StopConfigurationRecorder.
  iam-persistence        (high)  : CreateUser/CreateAccessKey/
                                   CreateLoginProfile/AddUserToGroup/
                                   Attach*Policy/Put*Policy/
                                   UpdateAssumeRolePolicy.
  secret-access          (high)  : GetSecretValue / DeleteSecret.
  sg-open-world          (high)  : AuthorizeSecurityGroup* memuat
                                   0.0.0.0/0 (dicari rekursif).
  snapshot-shared-public (high)  : ModifySnapshotAttribute dgn
                                   group=all / createVolumePermission.
  key-impact             (medium): DisableKey / ScheduleKeyDeletion.
  bucket-policy-change   (medium): PutBucketPolicy/DeleteBucketPolicy/
                                   PutBucketAcl.
  cross-account-assume   (medium): AssumeRole ke accountId berbeda.
  denied-burst           (medium): >= --deny-burst errorCode
                                   AccessDenied*/Unauthorized* per identity.

Fail-closed: file tidak ada / NOL event ter-parse -> exit 2; baris/JSON
rusak dicatat (maks 10 contoh), tidak dihitung bersih diam-diam.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/cloudtrail_scan.py --log trail.json
  python tools/cloudtrail_scan.py --dir logs/ --fail-on medium --json
  python tools/cloudtrail_scan.py --log trail.jsonl --deny-burst 20
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "secai.cloudtrail-scan/1"

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}

EVENT_CHECKS: "dict[str, tuple[str, str]]" = {
    # eventName -> (check, severity)
    "StopLogging": ("logging-impaired", "high"),
    "DeleteTrail": ("logging-impaired", "high"),
    "DeleteFlowLogs": ("logging-impaired", "high"),
    "DeleteLogGroup": ("logging-impaired", "high"),
    "DeleteDetector": ("logging-impaired", "high"),
    "StopConfigurationRecorder": ("logging-impaired", "high"),
    "CreateUser": ("iam-persistence", "high"),
    "CreateAccessKey": ("iam-persistence", "high"),
    "CreateLoginProfile": ("iam-persistence", "high"),
    "AddUserToGroup": ("iam-persistence", "high"),
    "AttachUserPolicy": ("iam-persistence", "high"),
    "AttachRolePolicy": ("iam-persistence", "high"),
    "PutUserPolicy": ("iam-persistence", "high"),
    "PutRolePolicy": ("iam-persistence", "high"),
    "UpdateAssumeRolePolicy": ("iam-persistence", "high"),
    "GetSecretValue": ("secret-access", "high"),
    "DeleteSecret": ("secret-access", "high"),
    "ModifySnapshotAttribute": ("snapshot-shared-public", "high"),
    "DisableKey": ("key-impact", "medium"),
    "ScheduleKeyDeletion": ("key-impact", "medium"),
    "PutBucketPolicy": ("bucket-policy-change", "medium"),
    "DeleteBucketPolicy": ("bucket-policy-change", "medium"),
    "PutBucketAcl": ("bucket-policy-change", "medium"),
}

DENY_CODES = {"accessdenied", "accessdeniedexception", "unauthorizedoperation",
              "unauthorizedaccessexception"}


def _iter_events(obj: Any) -> "list[dict]":
    """Ambil list event dari objek JSON CloudTrail."""
    if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
        return [e for e in obj["Records"] if isinstance(e, dict)]
    return []


def _identity(event: dict) -> str:
    ui = event.get("userIdentity") or {}
    return str(ui.get("arn") or ui.get("userName")
               or ui.get("principalId") or "unknown")


def _contains_string(node: Any, needle: str) -> bool:
    if isinstance(node, str):
        return node == needle
    if isinstance(node, dict):
        return any(_contains_string(v, needle) for v in node.values())
    if isinstance(node, list):
        return any(_contains_string(v, needle) for v in node)
    return False


def check_event(event: dict) -> "list[dict]":
    """Cek deterministik satu event -> daftar temuan (0..n)."""
    out: "list[dict]" = []
    name = str(event.get("eventName") or "")
    ident = _identity(event)
    ts = event.get("eventTime") or ""
    acct = (event.get("userIdentity") or {}).get("accountId")

    def add(check: str, severity: str, message: str) -> None:
        out.append({"check": check, "severity": severity, "ts": ts,
                    "identity": ident, "event": name, "message": message})

    if not name:
        return out
    ui = event.get("userIdentity") or {}

    if ui.get("type") == "Root":
        add("root-activity", "high",
            "Sesi Root dipakai — hindari; pakai IAM role berizin minimum.")

    if name == "ConsoleLogin":
        aed = event.get("additionalEventData") or {}
        if str(aed.get("MFAUsed", "Yes")).lower() == "no":
            add("console-login-no-mfa", "high",
                "Login konsol TANPA MFA.")

    hit = EVENT_CHECKS.get(name)
    if hit:
        check, sev = hit
        if check == "snapshot-shared-public":
            # hanya temuan bila grup "all" DITAMBAHKAN (share publik);
            # operasi remove/atribut lain bukan temuan
            rp = json.dumps(event.get("requestParameters") or {})
            if not re.search(r'"group"\s*:\s*"all"', rp):
                return out
        add(check, sev, f"Event sensitif {name} oleh {ident}.")

    if name.startswith("AuthorizeSecurityGroup"):
        if _contains_string(event.get("requestParameters"), "0.0.0.0/0"):
            add("sg-open-world", "high",
                "Aturan security group membuka 0.0.0.0/0.")

    if name == "AssumeRole":
        rp = event.get("requestParameters") or {}
        role_arn = str(rp.get("roleArn") or "")
        parts = role_arn.split(":")
        target_acct = parts[4] if len(parts) > 4 else ""
        if acct and target_acct and acct != target_acct:
            add("cross-account-assume", "medium",
                f"AssumeRole lintas akun {acct} -> {target_acct} "
                f"({role_arn}).")
    return out


def scan(events: "list[dict]", *, deny_burst: int = 10) -> dict:
    """Scan penuh event CloudTrail -> temuan + meta."""
    findings: "list[dict]" = []
    deny_per_identity: Counter[str] = Counter()
    identity_events: Counter[str] = Counter()

    for ev in events:
        identity_events[_identity(ev)] += 1
        code = str(ev.get("errorCode") or "").lower()
        if code in DENY_CODES:
            deny_per_identity[_identity(ev)] += 1
        findings.extend(check_event(ev))

    for ident, cnt in deny_per_identity.items():
        if cnt >= deny_burst:
            findings.append({
                "check": "denied-burst", "severity": "medium", "ts": "",
                "identity": ident,
                "event": f"x{cnt}",
                "message": f"{cnt} event ditolak (AccessDenied/"
                           f"Unauthorized) untuk {ident} — kredensial "
                           f"sedang disonda atau izin salah konfigurasi.",
            })

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 9),
                                 f["check"], f["ts"]))
    return {
        "schema": SCHEMA,
        "events_total": len(events),
        "identities_top": dict(identity_events.most_common(10)),
        "findings": findings,
        "verdict": ("INDICATORS_FOUND" if findings
                    else "CLEAN_NO_HIGH_RISK_EVENT"),
        "note": "LEAD per event bernama — aksi sah (ops manual) bisa "
                "memenuhi cek; keputusan dari konteks change-window, "
                "bukan nama event saja.",
    }


def _load_events(path: Path) -> "tuple[list[dict], list[str]]":
    """Baca satu file -> (events, kesalahan).

    Mendukung: dokumen {"Records": [...]}, dokumen event tunggal, array
    event, atau JSONL (satu event per baris). Dokumen rusak jatuh ke
    parse per baris (fail-closed tercatat).
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None  # mungkin JSONL — coba per baris di bawah
        if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
            return _iter_events(obj), []
        if isinstance(obj, dict):
            return [obj], []
        if isinstance(obj, list):
            return _iter_events({"Records": obj}), []
    events: "list[dict]" = []
    bad: "list[str]" = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            bad.append(line[:120])
            continue
        if isinstance(obj, dict):
            if isinstance(obj.get("Records"), list):
                events.extend(_iter_events(obj))
            else:
                events.append(obj)
        else:
            bad.append(line[:120])
    return events, bad


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="cloudtrail_scan — triase OFFLINE log AWS CloudTrail "
                    "(read-only, nol jaringan).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--log", help="file CloudTrail .json/.jsonl")
    src.add_argument("--dir", help="direktori berisi file CloudTrail")
    ap.add_argument("--deny-burst", type=int, default=10,
                    help="ambang AccessDenied per identity (default 10)")
    ap.add_argument("--fail-on", choices=["medium", "high"], default="high")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    paths: "list[Path]" = []
    if args.log:
        p = Path(args.log)
        if not p.is_file():
            print(f"[cloudtrail] file tidak ada: {p}", file=sys.stderr)
            return 2
        paths = [p]
    else:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"[cloudtrail] direktori tidak ada: {d}", file=sys.stderr)
            return 2
        paths = sorted(p for p in d.rglob("*")
                       if p.is_file() and p.suffix.lower()
                       in {".json", ".jsonl"})
    if not paths:
        print("[cloudtrail] tidak ada file log yang bisa dibaca "
              "(fail-closed)", file=sys.stderr)
        return 2

    events: "list[dict]" = []
    bad: "list[str]" = []
    for p in paths:
        evs, b = _load_events(p)
        events.extend(evs)
        bad.extend(b)
    if not events:
        print("[cloudtrail] NOL event ter-parse (fail-closed); contoh: "
              f"{bad[:3]}", file=sys.stderr)
        return 2

    result = scan(events, deny_burst=args.deny_burst)
    result["files_scanned"] = len(paths)
    result["unparsed_lines"] = len(bad)
    result["unparsed_examples"] = bad[:10]

    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    if args.json or args.out:
        print(text)
    else:
        print(f"verdict    : {result['verdict']} "
              f"({result['events_total']} event, "
              f"{result['files_scanned']} file)")
        for f in result["findings"]:
            print(f"  [{f['severity']:6}] {f['check']}: {f['message']}")
        if bad:
            print(f"  CATATAN: {len(bad)} baris/JSON gagal di-parse")
        print(f"note       : {result['note']}")

    worst = max((SEV_ORDER[f["severity"]] for f in result["findings"]),
                default=0)
    return 1 if worst >= SEV_ORDER[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
