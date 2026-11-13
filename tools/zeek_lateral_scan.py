"""[SAFETY: read-only] zeek_lateral_scan — triase OFFLINE log Zeek (TSV
atau JSON) untuk indikasi lateral movement: akses admin share SMB
(C$/ADMIN$/IPC$), sebaran SMB 445 antar-host internal, operasi DCE/RPC
remote service (svcctl/atsvc), NTLM spray (satu akun -> banyak host),
dan penulisan file ke admin share.

Pembagian ranah dgn alat secai lain (anti-duplikasi):
  - Beaconing/konektivitas DNS dari log Zeek -> tools/zeek_beacon_scan
    (B13) + dns_log_triage (B07); di sini hanya lateral (SMB/DCE-RPC/
    NTLM).
  - Log autentikasi Windows 4624/4625/7045 -> tools/win_auth_triage +
    win_logon_triage.

Input -> mekanisme -> output:
  - Input : direktori Zeek (--dir, default nama file standar Zeek:
            conn.log, smb_mapping.log, smb_files.log, dce_rpc.log,
            ntlm.log) atau path file eksplisit per log. Format per file
            dideteksi otomatis: TSV dgn header `#fields`, atau JSONL
            (satu objek per baris; field nested `id.orig_h` didukung).
  - Mekanisme: agregasi per host/akun -> cek ambang deterministik.
  - Output: temuan {check, severity, src, detail} + stats + notes (JSON
            deterministik). SEMUA temuan = LEAD jaringan.

Cek (ambang di-echo di meta):
  admin-share-access (high)  : smb_mapping path berakhir C$/ADMIN$/IPC$
                               — >= --share-hosts host tujuan unik per
                               host sumber (PsExec T1021.002).
  smb-spread         (high)  : conn resp_p=445 — >= --smb-hosts host
                               tujuan unik per host sumber.
  dce-remote-service (high)  : dce_rpc endpoint/operation svcctl/
                               atsvc/ITaskSchedulerService (buat service
                               / task jarak jauh).
  dce-wmi            (medium) : dce_rpc endpoint/operation wbem
                               (IWbemServices, T1047) — agregat per
                               sumber.
  ntlm-spray         (high)  : ntlm.log satu username -> >= --ntlm-hosts
                               host tujuan unik (cred spraying,
                               CrackMapExec-pattern).
  ntlm-fail-burst    (medium): ntlm.log success=F >= --ntlm-fails per
                               host sumber.
  smb-file-write     (high)  : smb_files action FILE_WRITE ke path
                               admin share.

Fail-closed: --dir tanpa log Zeek yang dikenali -> exit 2; file log
yang dikenali tapi NOL baris ter-parse dicatat eksplisit di notes.
Log yang tidak tersedia (mis. ntlm.log tidak diekspor) = catatan cek
dilewati — tidak pernah disimpulkan "bersih" dari ketidakhadiran log.

Exit: 0 selesai (temuan tetap exit 0); 2 input error.

Pemakaian:
  python tools/zeek_lateral_scan.py --dir /opt/zeek/logs/current
  python tools/zeek_lateral_scan.py --dir logs/ --smb-hosts 10
  python tools/zeek_lateral_scan.py --conn conn.log --ntlm ntlm.log
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

SCHEMA = "secai.zeek-lateral-scan/1"
MAX_FILE_BYTES = 64 * 1024 * 1024

ADMIN_SHARE_RE = re.compile(r"(?i)(c\$|admin\$|ipc\$)\s*$")
DCE_SERVICE_RE = re.compile(r"(?i)(svcctl|atsvc|itaskschedulerservice)")
DCE_WMI_RE = re.compile(r"(?i)wbem")
LOG_NAMES = ("conn", "smb_mapping", "smb_files", "dce_rpc", "ntlm")


def _get(rec: dict, field: str) -> str:
    """Ambil field Zeek; dukung flat 'id.orig_h' dan nested id.orig_h."""
    if field in rec:
        v = rec[field]
    else:
        v = rec
        for part in field.split("."):
            if not isinstance(v, dict) or part not in v:
                return ""
            v = v[part]
    if isinstance(v, dict):
        return ""
    return str(v) if v is not None else ""


def _unset(val: str) -> str:
    return "" if val in ("-", "", "(empty)") else val


def load_zeek(path: Path, fields_wanted: "list[str]") \
        -> "tuple[list[dict], int]":
    """Baca satu log Zeek (TSV #fields / JSONL) -> (records, baris
    rusak). Hanya field yang diminta diambil."""
    recs: list[dict] = []
    bad = 0
    fmt_tsv = False
    cols: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace") \
            .splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#fields"):
                cols = line.split("\t")[1:]
                fmt_tsv = True
            continue
        if line.lstrip().startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            recs.append({f: _get(rec, f) for f in fields_wanted})
        elif fmt_tsv and cols:
            parts = line.split("\t")
            if len(parts) < len(cols):
                bad += 1
                continue
            recs.append(dict(zip(cols, parts)))
        # baris TSV sebelum header #fields -> diabaikan (Zeek
        # selalu menulis header dulu)
    return recs, bad


def _load_optional(path: Path | None, fields: "list[str]",
                   label: str, present: dict, notes: "list[str]") \
        -> "list[dict]":
    if path is None or not path.is_file():
        notes.append(f"{label} tidak tersedia — cek yang butuh {label} "
                     "dilewati (ketidakhadiran log bukan bukti bersih)")
        return []
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"{label} melebihi {MAX_FILE_BYTES} byte")
        recs, bad = load_zeek(path, fields)
    except ValueError as exc:
        raise
    present[label] = len(recs)
    if bad:
        notes.append(f"{label}: {bad} baris rusak tidak dianalisis")
    if not recs:
        notes.append(f"{label}: nol baris ter-parse")
    return recs


def triage(data: "dict[str, list[dict]]", *, share_hosts: int,
           smb_hosts: int, ntlm_hosts: int, ntlm_fails: int) -> dict:
    notes: "list[str]" = []
    findings: "list[dict]" = []

    # admin-share-access (smb_mapping)
    share_by_src: "dict[str, set[str]]" = defaultdict(set)
    for r in data.get("smb_mapping", []):
        if ADMIN_SHARE_RE.search(r.get("path", "")):
            share_by_src[_unset(r.get("id.orig_h"))].add(
                _unset(r.get("id.resp_h")))
    for src in sorted(share_by_src):
        n = len(share_by_src[src])
        if src and n >= share_hosts:
            findings.append({
                "check": "admin-share-access", "severity": "high",
                "src": src,
                "detail": f"{n} host tujuan dgn akses share admin "
                          f"(C$/ADMIN$/IPC$, >= {share_hosts}) — "
                          "PsExec/lateral SMB (T1021.002)",
                "unique_hosts": n,
            })

    # smb-spread (conn 445)
    smb_by_src: "dict[str, set[str]]" = defaultdict(set)
    for r in data.get("conn", []):
        if r.get("id.resp_p") == "445":
            src, dst = _unset(r.get("id.orig_h")), _unset(r.get("id.resp_h"))
            if src and dst:
                smb_by_src[src].add(dst)
    for src in sorted(smb_by_src):
        n = len(smb_by_src[src])
        if n >= smb_hosts:
            findings.append({
                "check": "smb-spread", "severity": "high",
                "src": src,
                "detail": f"{n} host tujuan port 445 dari satu sumber "
                          f"(>= {smb_hosts}) — sebaran SMB/lateral scan",
                "unique_hosts": n,
            })

    # dce-remote-service + dce-wmi
    dce_svc: "dict[tuple[str, str], set[str]]" = defaultdict(set)
    dce_wmi: "dict[str, set[str]]" = defaultdict(set)
    for r in data.get("dce_rpc", []):
        ep = r.get("endpoint", "")
        op = r.get("operation", "")
        blob = f"{ep} {op}"
        src, dst = _unset(r.get("id.orig_h")), _unset(r.get("id.resp_h"))
        if DCE_SERVICE_RE.search(blob):
            dce_svc[(src, dst)].add(f"{ep}/{op}")
        elif DCE_WMI_RE.search(blob) and src:
            dce_wmi[src].add(dst)
    for (src, dst), ops in sorted(dce_svc.items()):
        findings.append({
            "check": "dce-remote-service", "severity": "high",
            "src": src,
            "detail": f"DCE/RPC service/task jarak jauh ke {dst}: "
                      f"{', '.join(sorted(ops))[:100]} (T1569.002/"
                      "T1053.005)",
        })
    for src in sorted(dce_wmi):
        if len(dce_wmi[src]) >= 2:
            findings.append({
                "check": "dce-wmi", "severity": "medium",
                "src": src,
                "detail": f"DCE/RPC WMI (wbem) ke {len(dce_wmi[src])} "
                          "host — eksekusi remote WMI kandidat (T1047)",
            })

    # ntlm-spray + fail-burst
    ntlm_by_user: "dict[str, set[str]]" = defaultdict(set)
    ntlm_fails_by_src: "dict[str, int]" = defaultdict(int)
    for r in data.get("ntlm", []):
        src, dst = _unset(r.get("id.orig_h")), _unset(r.get("id.resp_h"))
        user = _unset(r.get("username", "") or
                      r.get("account", ""))
        if r.get("success", "").upper() == "F":
            if src:
                ntlm_fails_by_src[src] += 1
        if user and dst:
            ntlm_by_user[user.lower()].add(dst)
    for user in sorted(ntlm_by_user):
        n = len(ntlm_by_user[user])
        if n >= ntlm_hosts:
            findings.append({
                "check": "ntlm-spray", "severity": "high",
                "src": user,
                "detail": f"akun '{user}' autentikasi NTLM ke {n} host "
                          f"unik (>= {ntlm_hosts}) — credential spray "
                          "kandidat",
                "unique_hosts": n,
            })
    for src in sorted(ntlm_fails_by_src):
        n = ntlm_fails_by_src[src]
        if n >= ntlm_fails:
            findings.append({
                "check": "ntlm-fail-burst", "severity": "medium",
                "src": src,
                "detail": f"{n} autentikasi NTLM gagal dari satu sumber "
                          f"(>= {ntlm_fails}) — brute/cred-testing "
                          "kandidat",
            })

    # smb-file-write ke admin share
    for r in data.get("smb_files", []):
        if "file_write" in r.get("action", "").lower() and \
                ADMIN_SHARE_RE.search(r.get("path", "")):
            findings.append({
                "check": "smb-file-write", "severity": "high",
                "src": _unset(r.get("id.orig_h")),
                "detail": f"tulis file '{r.get('name', '?')}' ke share "
                          f"admin {r.get('path', '')} di "
                          f"{_unset(r.get('id.resp_h'))} — staging/"
                          "penempatan payload",
            })

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["check"],
                                 f["src"]))
    return {
        "schema": SCHEMA,
        "stats": {f"parsed_{k}": len(v) for k, v in
                  sorted(data.items())},
        "notes": notes,
        "thresholds": {"share_hosts": share_hosts,
                       "smb_hosts": smb_hosts,
                       "ntlm_hosts": ntlm_hosts,
                       "ntlm_fails": ntlm_fails},
        "findings": findings,
        "verdict": ("INDICATORS_FOUND" if findings
                    else "CLEAN_NO_LATERAL_LEAD"),
    }


def _resolve(dirp: Path | None, overrides: dict) -> "dict[str, Path | None]":
    base = {name: (Path(overrides[name]) if overrides.get(name) else
                   (dirp / f"{name}.log" if dirp else None))
            for name in LOG_NAMES}
    return base


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase offline log Zeek utk lateral movement "
                    "(SMB/DCE-RPC/NTLM) — LEAD.")
    ap.add_argument("--dir", help="direktori log Zeek (conn.log dst)")
    ap.add_argument("--conn", help="path conn.log eksplisit")
    ap.add_argument("--smb-mapping", help="path smb_mapping.log eksplisit")
    ap.add_argument("--smb-files", help="path smb_files.log eksplisit")
    ap.add_argument("--dce-rpc", help="path dce_rpc.log eksplisit")
    ap.add_argument("--ntlm", help="path ntlm.log eksplisit")
    ap.add_argument("--share-hosts", type=int, default=3,
                    help="min host tujuan utk admin-share-access "
                         "(default 3)")
    ap.add_argument("--smb-hosts", type=int, default=10,
                    help="min host tujuan utk smb-spread (default 10)")
    ap.add_argument("--ntlm-hosts", type=int, default=3,
                    help="min host unik per akun utk ntlm-spray "
                         "(default 3)")
    ap.add_argument("--ntlm-fails", type=int, default=10,
                    help="min NTLM gagal per sumber (default 10)")
    ap.add_argument("--out", help="tulis JSON ke file (selain stdout)")
    args = ap.parse_args(argv)

    overrides = {"conn": args.conn,
                 "smb_mapping": getattr(args, "smb_mapping"),
                 "smb_files": getattr(args, "smb_files"),
                 "dce_rpc": getattr(args, "dce_rpc"),
                 "ntlm": args.ntlm}
    dirp = Path(args.dir) if args.dir else None
    if dirp is not None and not dirp.is_dir():
        print(f"[zeek-lateral-scan] input error: bukan direktori: {dirp}",
              file=sys.stderr)
        return 2
    if dirp is None and not any(overrides.values()):
        print("[zeek-lateral-scan] input error: --dir atau minimal satu "
              "path log wajib", file=sys.stderr)
        return 2

    notes: "list[str]" = []
    present: "dict[str, int]" = {}
    fields = {
        "conn": ["ts", "id.orig_h", "id.resp_h", "id.resp_p"],
        "smb_mapping": ["ts", "id.orig_h", "id.resp_h", "path"],
        "smb_files": ["ts", "id.orig_h", "id.resp_h", "path", "name",
                      "action"],
        "dce_rpc": ["ts", "id.orig_h", "id.resp_h", "endpoint",
                    "operation"],
        "ntlm": ["ts", "id.orig_h", "id.resp_h", "username", "success"],
    }
    data: "dict[str, list[dict]]" = {}
    parsed_files = 0
    try:
        for name in LOG_NAMES:
            recs = _load_optional(_resolve(dirp, overrides)[name],
                                  fields[name], f"{name}.log", present,
                                  notes)
            if recs or present.get(f"{name}.log"):
                parsed_files += 1
            data[name] = recs
        if parsed_files == 0:
            raise ValueError("tidak ada log Zeek yang dikenali "
                             "(conn/smb_mapping/smb_files/dce_rpc/ntlm) "
                             "— bukan ekspor Zeek?")
    except ValueError as exc:
        print(f"[zeek-lateral-scan] input error: {exc}", file=sys.stderr)
        return 2

    result = triage(data, share_hosts=args.share_hosts,
                    smb_hosts=args.smb_hosts, ntlm_hosts=args.ntlm_hosts,
                    ntlm_fails=args.ntlm_fails)
    result["notes"] = notes + result["notes"]  # catatan parser di depan
    result["stats"]["files_parsed"] = parsed_files
    rendered = json.dumps(result, ensure_ascii=False, indent=2,
                          sort_keys=True)
    print(rendered)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
