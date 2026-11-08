r"""[SAFETY: read-only] applocker_policy_audit — audit OFFLINE kebijakan
AppLocker (policy XML) + hasil audit-mode (CSV event) untuk celah
application whitelisting. TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0579 (mukul975/
Anthropic-Cybersecurity-Skills 'implementing-application-whitelisting-with-
applocker'; atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM
SCRATCH: parser XML policy + agregasi CSV event ditulis sendiri dari
konsep AppLocker publik (RuleCollection/EnforcementMode, deny LOLBin,
gap direktori user-writable, event 8003/8004/8006/8007/8023). Skill sumber
adalah runbook PowerShell/GPO live di endpoint Windows; secai memilih
artefak offline (export policy XML `Get-AppLockerPolicy -Effective -Xml`
+ CSV event `Get-WinEvent ... Export-Csv`) agar nol jaringan dan dapat
dites. Ranah TIDAK diduplikasi: lolbin_scan (B15) mendeteksi EKSEKUSI
LOLBin dari log Sysmon/Security — tool ini menilai KEBIJAKAN/policy
coverage-nya, bukan eksekusi.

Input -> mekanisme -> output:
  - Input : (a) policy XML AppLocker (satu/lebih <RuleCollection>) dan/
            (b) CSV hasil export event audit-mode dgn kolom (header
            case-insensitive): User/FilePath/FileHash (+ EventID opsional,
            kolom TimeCreated opsional). Minimal satu input.
  - Mekanisme: parse RuleCollection -> evaluasi cek policy -> parse CSV ->
            agregasi kandidat blokir per path/direktori.
  - Output: temuan {check, severity, subject, message} + summary + notes.

Cek policy (semua verdict = LEAD — konteks lab bisa sah):
  policy-audit-mode     (medium): EnforcementMode != Enforced (AuditOnly/
                                  NotConfigured) — kebijakan tidak
                                  menegakkan (fase audit memang sah;
                                  catat sebagai status, bukan exploit).
  exe-collection-absent (high)  : tidak ada RuleCollection Type="Exe" —
                                  application control untuk EXE tidak ada.
  ruleset-empty         (medium): RuleCollection ada tapi 0 rule — mode
                                  ditulis di pesan (Enforce dgn 0 rule
                                  Exe = memblokir SEMUA, AuditOnly = tak
                                  berguna).
  allow-user-writable   (high)  : FilePathRule Action="Allow" yang
                                  mengizinkan direktori user-writable
                                  (%TEMP%, %APPDATA%, %LOCALAPPDATA%,
                                  Downloads, %USERPROFILE%, C:\Users\*,
                                  Desktop) — gap klasik T1505/T1059.
  lolbin-deny-missing   (medium): binary dalam daftar LOLBin yang sering
                                  disalahgunakan (mshta/wscript/cscript/
                                  regsvr32/certutil/msbuild/installutil/
                                  rundll32) tidak punya rule Deny untuk
                                  group selain admin — kandidat celah.

Cek event (audit-mode; bila CSV diberikan):
  audit-userwritable-exec (high): file dieksekusi (akan-diblokir) dari
                                  direktori user-writable — bukti nyata
                                  jalur eksekusi di luar kontrol.
  audit-hot-dir           (medium): direktori induk muncul >= --hot kali
                                  (default 5) — lokasi eksekusi berulang
                                  yang perlu keputusan rule/allowlist.
  audit-block-candidate   (info)  : kandidat refine (agregat per FilePath
                                  unik, >= --min-repeat, default 2).

Fail-closed:
  - tanpa input sama sekali / XML tanpa <RuleCollection> / CSV tanpa
    kolom FilePath -> exit 2 (tidak bisa disimpulkan apa-apa).
  - baris CSV tanpa FilePath dihitung summary.csv_rows_skipped, tidak
    dipendam.
  - saringan deny-LOLBin dicatat di notes (nama yang dicari), bukan
    diam-diam.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default info, mengikuti
yara_rule_lint/ids_rule_lint); 2 input tidak valid.

Pemakaian:
  python tools/applocker_policy_audit.py --policy policy.xml
  python tools/applocker_policy_audit.py --csv audit_blocked_exes.csv
  python tools/applocker_policy_audit.py --policy policy.xml \
      --csv audit.csv --json hasil.json --fail-on medium
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}

# LOLBin yang lazim di-deny utk standard users (konsep sumber step 4)
LOLBIN_DENY_CANDIDATES = ("mshta.exe", "wscript.exe", "cscript.exe",
                          "regsvr32.exe", "certutil.exe", "msbuild.exe",
                          "installutil.exe", "rundll32.exe")

# penanda direktori user-writable (case-insensitive, di path/lower)
USER_WRITABLE_TOKENS = ("%temp%", "%tmp%", "%appdata%", "%localappdata%",
                        "%userprofile%", "\\downloads", "c:\\users\\",
                        "\\desktop\\", "\\appdata\\", "\\temp\\",
                        "programdata\\")

VALID_TYPES = ("Exe", "Dll", "Script", "WindowsInstaller", "Packaged app-Installation")


def _is_user_writable(path: str) -> bool:
    low = (path or "").lower()
    return any(tok in low for tok in USER_WRITABLE_TOKENS)


def _rule_names_in_policy(xml_text: str, binary: str) -> bool:
    """Apakah ada FilePathRule yang menyebut nama binary (path/attribute)."""
    pat = re.compile(re.escape(binary), re.IGNORECASE)
    return bool(pat.search(xml_text))


def audit_policy(xml_text: str,
                 findings: list[dict], notes: list[str]) -> dict:
    """Parse policy XML AppLocker -> cek policy-side. Fail-closed: raise
    ValueError bila tidak ada RuleCollection."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"policy XML tidak dapat diparse: {exc}") from exc
    # cari RuleCollection di kedalaman berapa pun (AppLockerPolicy root
    # berisi <RuleCollection> langsung; export tergabung bisa bersarang)
    collections = [el for el in root.iter() if isinstance(el.tag, str)
                   and el.tag.lower().endswith("rulecollection")]
    if not collections:
        raise ValueError("tidak ada <RuleCollection> di policy XML — bukan "
                         "policy AppLocker yang valid")

    summary = {"collections": len(collections), "rules": 0,
               "modes": {}, "types": {}}
    has_exe = False
    for coll in collections:
        ctype = str(coll.get("Type") or "?")
        mode = str(coll.get("EnforcementMode") or "NotConfigured")
        summary["types"][ctype] = summary["types"].get(ctype, 0) + 1
        summary["modes"][mode] = summary["modes"].get(mode, 0) + 1
        rules = [r for r in coll if isinstance(r.tag, str)
                 and r.tag.lower().endswith("rule")]
        summary["rules"] += len(rules)

        if ctype == "Exe":
            has_exe = True
        if mode != "Enforced":
            findings.append({
                "check": "policy-audit-mode", "severity": "medium",
                "subject": f"{ctype}:{mode}",
                "message": f"RuleCollection {ctype} dalam mode {mode} — "
                           "kebijakan tidak menegakkan (fase audit sah; "
                           "catat status sebelum klaim kontrol aktif)",
            })
        if not rules:
            findings.append({
                "check": "ruleset-empty", "severity": "medium",
                "subject": ctype,
                "message": f"RuleCollection {ctype} tanpa satu rule pun "
                           f"(mode {mode}) — Enforce dgn 0 rule Exe "
                           "memblokir SEMUA exe; AuditOnly = kontrol "
                           "paling kosong",
            })

        # allow-rule ke direktori user-writable
        for rule in rules:
            action = str(rule.get("Action") or "").lower()
            rname = str(rule.get("Name") or "?")
            if action != "allow":
                continue
            paths: list[str] = []
            for cond in rule.iter():
                tag = cond.tag.lower()
                if tag.endswith("filepathcondition") \
                        or tag.endswith("pathcondition"):
                    p = cond.get("Path")
                    if p:
                        paths.append(str(p))
            for p in paths:
                if _is_user_writable(p):
                    findings.append({
                        "check": "allow-user-writable", "severity": "high",
                        "subject": f"{ctype}:{rname}",
                        "message": f"rule Allow '{rname}' mengizinkan path "
                                   f"user-writable: {p} — penyerang cukup "
                                   "menaruh payload di situ",
                    })

    if not has_exe:
        findings.append({
            "check": "exe-collection-absent", "severity": "high",
            "subject": "Exe",
            "message": "tidak ada RuleCollection Type=\"Exe\" — kontrol "
                       "eksekusi EXE tidak dideklarasikan",
        })

    # deny LOLBin: nama binary dicari di SELURUH teks XML ( FilePathRule
    # deny yang menuliskan path %SYSTEM32%\mshta.exe dsb.)
    for binary in LOLBIN_DENY_CANDIDATES:
        if not _rule_names_in_policy(xml_text, binary):
            findings.append({
                "check": "lolbin-deny-missing", "severity": "medium",
                "subject": binary,
                "message": f"tidak ada rule yang menyebut {binary} — "
                           "LOLBin yang sering disalahguna tanpa deny "
                           "untuk standard user (konsep sumber step 4)",
            })
    notes.append("deny-LOLBin dicari utk: "
                 + ", ".join(LOLBIN_DENY_CANDIDATES)
                 + " (keberadaan rule yang menyebut nama; kebijakan yang "
                   "sengaja mengizinkan utk admin sah = catat manual)")
    return summary


def audit_events(csv_path: Path, findings: list[dict], notes: list[str],
                 hot: int, min_repeat: int) -> dict:
    """Parse CSV event audit-mode -> agregasi kandidat blokir."""
    with csv_path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError(f"{csv_path}: CSV kosong") from None
        cols = {c.strip().lower(): i for i, c in enumerate(header)}
        idx_file = cols.get("filepath", cols.get("file path",
                                                cols.get("path", -1)))
        idx_user = cols.get("user", cols.get("username", -1))
        idx_hash = cols.get("filehash", cols.get("hash", -1))
        idx_eid = cols.get("eventid", cols.get("event id", -1))
        if idx_file < 0:
            raise ValueError(f"{csv_path}: kolom FilePath tidak ditemukan "
                             f"(header: {header}) — tidak bisa dianalisis")

    path_counter: Counter = Counter()
    dir_counter: Counter = Counter()
    userwritable_rows: list[dict] = []
    seen: set[str] = set()
    eid_counter: Counter = Counter()
    skipped = 0
    with csv_path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        next(reader)  # header
        for row in reader:
            if not row or not [c for c in row if c.strip()]:
                skipped += 1
                continue
            fpath = row[idx_file].strip() if idx_file < len(row) else ""
            if not fpath:
                skipped += 1
                continue
            path_counter[fpath] += 1
            parent = os.path.dirname(fpath).lower()
            dir_counter[parent] += 1
            if idx_eid >= 0 and idx_eid < len(row) and row[idx_eid].strip():
                eid_counter[row[idx_eid].strip()] += 1
            if _is_user_writable(fpath):
                userwritable_rows.append({
                    "file": fpath,
                    "user": row[idx_user].strip() if 0 <= idx_user < len(row)
                    else "",
                    "hash": row[idx_hash].strip() if 0 <= idx_hash < len(row)
                    else "",
                })

    if userwritable_rows:
        for u in userwritable_rows:
            if u["file"] in seen:
                continue
            seen.add(u["file"])
            findings.append({
                "check": "audit-userwritable-exec", "severity": "high",
                "subject": u["file"],
                "message": f"eksekusi dari direktori user-writable "
                           f"dicegah audit-mode: {u['file']} "
                           f"(user={u['user'] or '?'}, hash={u['hash'][:16]})"
                           " — jalur nyata di luar kebijakan",
            })
    for parent, cnt in dir_counter.most_common():
        if cnt >= hot:
            findings.append({
                "check": "audit-hot-dir", "severity": "medium",
                "subject": parent,
                "message": f"{cnt} event akan-diblokir dari direktori yang "
                           f"sama ({parent}) — butuh keputusan rule baru "
                           "atau allowlist terdokumentasi",
            })
    for fpath, cnt in path_counter.most_common():
        if cnt >= min_repeat:
            findings.append({
                "check": "audit-block-candidate", "severity": "info",
                "subject": fpath,
                "message": f"{cnt}x akan-diblokir — kandidat publisher/path "
                           "rule bila aplikasi sah",
            })
    return {"csv_rows": sum(path_counter.values()) + skipped,
            "csv_rows_skipped": skipped,
            "unique_files": len(path_counter),
            "unique_dirs": len(dir_counter),
            "userwritable_files": len(seen) if userwritable_rows else 0,
            "event_ids": dict(eid_counter)}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="applocker_policy_audit — audit OFFLINE kebijakan "
                    "AppLocker (XML) + CSV event audit-mode (fail-closed; "
                    "LEAD, bukan bukti eksploitasi).")
    ap.add_argument("--policy", default=None, help="policy XML AppLocker")
    ap.add_argument("--csv", default=None,
                    help="CSV export event audit-mode (kolom FilePath "
                         "+User/FileHash/EventID opsional)")
    ap.add_argument("--json", default=None,
                    help="tulis laporan JSON ke path ini (selain stdout)")
    ap.add_argument("--hot", type=int, default=5,
                    help="ambang event per direktori utk audit-hot-dir "
                         "(default 5)")
    ap.add_argument("--min-repeat", type=int, default=2,
                    help="ambang pengulangan file utk audit-block-candidate "
                         "(default 2)")
    ap.add_argument("--fail-on", choices=sorted(SEV_ORDER), default="info",
                    help="severity minimum yang memicu exit 1 "
                         "(default info)")
    args = ap.parse_args(argv)

    if not args.policy and not args.csv:
        print("error: minimal satu input diperlukan (--policy / --csv)",
              file=sys.stderr)
        return 2

    findings: list[dict] = []
    notes: list[str] = []
    summary: dict = {"policy": None, "events": None}
    if args.policy:
        p = Path(args.policy)
        if not p.is_file():
            print(f"error: file tidak ada: {p}", file=sys.stderr)
            return 2
        try:
            summary["policy"] = audit_policy(p.read_text(encoding="utf-8"),
                                             findings, notes)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        notes.append("policy XML tidak diberikan — cek policy-side "
                     "dilewati eksplisit (bukan disimpulkan bersih)")

    if args.csv:
        c = Path(args.csv)
        if not c.is_file():
            print(f"error: file tidak ada: {c}", file=sys.stderr)
            return 2
        try:
            summary["events"] = audit_events(c, findings, notes,
                                             args.hot, args.min_repeat)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        notes.append("CSV event tidak diberikan — cek audit-side dilewati "
                     "eksplisit (bukan disimpulkan bersih)")

    report = {
        "kind": "applocker-policy-audit",
        "attribution": "konsep #0579 mukul975/implementing-application-"
                       "whitelisting-with-applocker (Apache-2.0) — dibangun "
                       "from scratch",
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
              f"medium={sum(1 for f in findings if f['severity'] == 'medium')} "
              f"info={sum(1 for f in findings if f['severity'] == 'info')})",
              file=sys.stderr)
    else:
        print(f"-- bersih: tidak ada temuan >= {args.fail_on}",
              file=sys.stderr)
    for n in notes:
        print(f"note: {n}", file=sys.stderr)
    return 1 if counted else 0


if __name__ == "__main__":
    sys.exit(main())
