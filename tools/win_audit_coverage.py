r"""[SAFETY: read-only] win_audit_coverage — cek cakupan sumber log Windows
untuk deteksi: kebijakan audit (auditpol) + konfigurasi channel event log
(wevtutil). Offline, nol jaringan, tanpa eksekusi perintah — tool hanya
mem-PARSE teks yang disimpan operator.

Port konsep dari antrean SKILL-PORT-QUEUE #0355 (mukul975/
Anthropic-Cybersecurity-Skills, skill 'configuring-windows-event-logging-
for-detection' — advanced audit policy, process creation + command line,
ukuran log, forwarding; atribusi konsep). Dibangun FROM SCRATCH: parser
CSV auditpol dan parser blok wevtutil ditulis sendiri — tidak menyalin
kode sumber. Lisensi cyphron: PolyForm NC.

Input -> mekanisme -> output:
  - Input : (a) output `auditpol /get /category:* /r` (CSV) dan/atau
            (b) output `wevtutil gl <channel> /f:text` (bisa beberapa
            channel dalam satu file). File, bukan perintah — tool TIDAK
            menjalankan apa pun (read-only total).
  - Mekanisme: cek 15 subkategori audit kritikal-deteksi (Credential
            Validation, Logon, Process Creation, Sensitive Privilege Use,
            File Share, Removable Storage, dst.) dan konfigurasi channel
            (enabled/maxSize/autoBackup) -> lead deterministik.
  - Output: JSON {findings, summary} per sumber.

Cek auditpol:
  audit-mati        (high)  : subkategori kritikal "No Auditing".
  audit-success-saja (medium): S+F direkomendasikan tapi hanya Success.
  audit-tak-terdefinisi (medium): subkategori kritikal tidak disebut file
            (kemungkinan default OS) — lead, bukan kepastian.
Cek wevtutil:
  channel-mati      (high)  : enabled: false pada channel kritikal.
  ukuran-kecil      (medium): Security < 1 GB / PowerShell Operational
            < 512 MB (default 20 MB terisi dalam hitungan menit).
  tanpa-autobackup  (info)  : autoBackup: false — log hilang saat rotasi.
  channel-tak-ditemukan (info): Security tidak ada dalam sumber wevtutil.

Anti-FP lokalisasi: auditpol menghasilkan nama subkategori sesuai locale.
Jika file CSV valid (baris GUID ada) TAPI NOL subkategori Inggris cocok,
tool mengeluarkan SATU info "subkategori tak dikenali (locale non-Inggris)"
dan TIDAK memuntahkan temuan per-subkategori (tidak pernah FP-storm).

Fail-closed: auditpol tanpa satu baris GUID pun = lead high "file-unparsed";
file wevtutil tanpa blok channel = lead high "file-unparsed". Exit: 0
bersih; 1 ada lead >= --fail-on (default high); 2 error input.

Pemakaian (kumpulkan teksnya dulu, di mesin target berizin):
  auditpol /get /category:* /r > auditpol.csv
  wevtutil gl Security /f:text > wevt.txt
  wevtutil gl Microsoft-Windows-PowerShell/Operational /f:text >> wevt.txt
  python tools/win_audit_coverage.py --auditpol auditpol.csv --wevtutil wevt.txt
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "cyphron.win-audit-coverage/1"

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}
SEV_HIGH = "high"
SEV_MED = "medium"
SEV_INFO = "info"

# subkategori kritikal-deteksi (nama auditpol EN) -> butuh Success+Failure?
CRITICAL_SUBCATS: dict[str, bool] = {
    "credential validation": True,
    "kerberos authentication service": True,
    "kerberos service ticket operations": True,
    "logon": True,
    "logoff": False,
    "special logon": False,
    "other logon/logoff events": True,
    "security group management": False,
    "user account management": True,
    "process creation": False,
    "sensitive privilege use": True,
    "file share": True,
    "removable storage": True,
    "audit policy change": True,
    "authentication policy change": False,
    "dpapi activity": True,
}

GUID_RE = re.compile(r"\{[0-9a-fA-F-]{36}\}")
MIN_LOG_SIZE = {"security": 1073741824, "microsoft-windows-powershell/operational": 536870912}

WEVT_KV_RE = re.compile(r"^\s*(name|enabled|maxSize|retention|autoBackup):\s*(.*)$")


def _finding(check: str, sev: str, msg: str, source: str, item: str = "") -> dict[str, str]:
    return {"check": check, "severity": sev, "message": msg, "source": source,
            "item": item}


def parse_auditpol(text: str, source_label: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    """CSV auditpol -> {subcategory_lower: setting}; (None, lead) jika gagal."""
    rows = 0
    result: dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 4:
            continue
        # kolom 3 = Subcategory GUID (stabil antar locale)
        if not GUID_RE.search(row[3]):
            continue
        rows += 1
        if len(row) >= 5:
            subcat = row[2].strip()
            if subcat:
                result[subcat.lower()] = row[4].strip()
    if rows == 0:
        return {}, [_finding("file-unparsed", SEV_HIGH,
                             "tidak ada baris auditpol valid (kolom GUID tak ditemukan)",
                             source_label)]
    return result, []


def audit_policy(subcats: dict[str, str], source_label: str) -> list[dict[str, str]]:
    """Cek cakupan subkategori kritikal. Nama CSV boleh berprefix 'Audit '."""
    out: list[dict[str, str]] = []
    norm: dict[str, str] = {}
    for k, v in subcats.items():
        kl = k.lower().strip()
        norm[kl] = v
        if kl.startswith("audit "):
            norm[kl[len("audit "):]] = v
    matched = [s for s in CRITICAL_SUBCATS if s in norm]
    if not matched:
        # CSV valid (GUID ada) tapi nama tak dikenali -> locale non-Inggris
        out.append(_finding("subkategori-tak-dikenali", SEV_INFO,
                            f"{len(subcats)} subkategori terbaca tapi tidak ada nama "
                            "Inggris yang cocok — kemungkinan output auditpol "
                            "lokal non-Inggris; cek manual (anti-FP, cek per-"
                            "subkategori dilewati)", source_label))
        return out
    for sub, need_fail in CRITICAL_SUBCATS.items():
        val = norm.get(sub)
        if val is None:
            out.append(_finding("audit-tak-terdefinisi", SEV_MED,
                                f"'{sub}' tidak disebut dalam kebijakan — "
                                "kemungkinan masih default OS", source_label, sub))
        elif val.lower() == "no auditing":
            out.append(_finding("audit-mati", SEV_HIGH,
                                f"'{sub}' = No Auditing", source_label, sub))
        elif need_fail and val.lower() == "success":
            out.append(_finding("audit-success-saja", SEV_MED,
                                f"'{sub}' hanya Success — kegagalan (mis. 4625) "
                                "tidak terekam", source_label, sub))
    return out


def parse_wevtutil(text: str, source_label: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Teks `wevtutil gl X /f:text` -> daftar channel {nama: {kv}}."""
    channels: list[dict[str, str]] = []
    leads: list[dict[str, str]] = []
    cur: dict[str, str] | None = None
    for line in text.splitlines():
        m = WEVT_KV_RE.match(line)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2).strip()
        if key == "name":
            cur = {"name": val, "enabled": "", "maxsize": "", "autobackup": ""}
            channels.append(cur)
        elif cur is not None:
            cur[key] = val
    if not channels:
        return [], [_finding("file-unparsed", SEV_HIGH,
                             "tidak ada blok channel wevtutil (name: tak ditemukan)",
                             source_label)]
    return channels, leads


def audit_channels(channels: list[dict[str, str]], source_label: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    names = {c["name"].lower(): c for c in channels if c.get("name")}
    if "security" not in names:
        out.append(_finding("channel-tak-ditemukan", SEV_INFO,
                            "channel Security tidak ada dalam sumber wevtutil — "
                            "dump mungkin parsial", source_label))
    for ch, min_size in MIN_LOG_SIZE.items():
        c = names.get(ch)
        if c is None:
            continue
        if c.get("enabled", "").lower() == "false":
            out.append(_finding("channel-mati", SEV_HIGH,
                                f"channel {ch} = enabled: false", source_label, ch))
        size_raw = c.get("maxsize", "")
        try:
            size = int(size_raw)
        except ValueError:
            size = None
        if size is None:
            out.append(_finding("file-unparsed", SEV_HIGH,
                                f"maxSize channel {ch} tidak bisa dibaca "
                                f"({size_raw!r})", source_label, ch))
        elif size < min_size:
            out.append(_finding("ukuran-kecil", SEV_MED,
                                f"maxSize {ch} = {size} byte < {min_size} "
                                f"(default 20 MB terisi cepat)", source_label, ch))
        if c.get("autobackup", "").lower() == "false":
            out.append(_finding("tanpa-autobackup", SEV_INFO,
                                f"autoBackup {ch} = false — log lama hilang saat "
                                "ditimpa", source_label, ch))
    return out


def lint_sources(auditpol_files: list[Path], wevt_files: list[Path]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    findings: list[dict[str, str]] = []
    metas: list[dict[str, Any]] = []
    for f in auditpol_files:
        label = f.name
        subcats, leads = parse_auditpol(f.read_text(encoding="utf-8", errors="replace"), label)
        findings.extend(leads)
        if not leads and subcats is not None:
            findings.extend(audit_policy(subcats, label))
        metas.append({"source": label, "type": "auditpol", "subcategories": len(subcats)})
    for f in wevt_files:
        label = f.name
        channels, leads = parse_wevtutil(f.read_text(encoding="utf-8", errors="replace"), label)
        findings.extend(leads)
        if not leads:
            findings.extend(audit_channels(channels, label))
        metas.append({"source": label, "type": "wevtutil", "channels": [c.get("name") for c in channels]})
    return findings, metas


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="win_audit_coverage — cek cakupan kebijakan audit + ukuran "
                    "log Windows dari file (read-only, nol jaringan; #0355)")
    ap.add_argument("--auditpol", action="append", default=[],
                    help="file output 'auditpol /get /category:* /r' (boleh berulang)")
    ap.add_argument("--wevtutil", action="append", default=[],
                    help="file output 'wevtutil gl <channel> /f:text' (boleh berulang)")
    ap.add_argument("--json", dest="json_out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=sorted(SEV_ORDER), default="high",
                    help="threshold exit 1 (default high)")
    args = ap.parse_args(argv)

    if not args.auditpol and not args.wevtutil:
        print("ERROR butuh --auditpol dan/atau --wevtutil", file=sys.stderr)
        return 2
    ap_files: list[Path] = []
    wv_files: list[Path] = []
    for spec in args.auditpol:
        p = Path(spec)
        if not p.is_file():
            print(f"ERROR file tidak ada: {p}", file=sys.stderr)
            return 2
        ap_files.append(p)
    for spec in args.wevtutil:
        p = Path(spec)
        if not p.is_file():
            print(f"ERROR file tidak ada: {p}", file=sys.stderr)
            return 2
        wv_files.append(p)

    findings, metas = lint_sources(ap_files, wv_files)
    result = {
        "schema": SCHEMA,
        "sources": metas,
        "findings": findings,
        "summary": {
            "high": sum(1 for x in findings if x["severity"] == "high"),
            "medium": sum(1 for x in findings if x["severity"] == "medium"),
            "info": sum(1 for x in findings if x["severity"] == "info"),
        },
    }
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.json_out:
        Path(args.json_out).write_text(text, encoding="utf-8")
    else:
        print(text)
    thr = SEV_ORDER[args.fail_on]
    hit = any(SEV_ORDER[f["severity"]] >= thr for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
