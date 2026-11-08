r"""[SAFETY: read-only] win_logon_triage — triase OFFLINE log Windows
Security (XML) untuk pola brute force logon (RDP/NLA/network): Event
4625 (gagal) + Event 4624 (sukses), T1110.001/T1110.003. TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0452 (mukul975/Anthropic-
Cybersecurity-Skills 'detecting-rdp-brute-force-attacks' — parse log
keamanan Windows utk pola tebak kredensial RDP; atribusi konsep,
lisensi sumber Apache-2.0). Dibangun FROM SCRATCH: parser XML +
logika window geser ditulis sendiri. Skill sumber memakai python-evtx
(biner EVTX); secai memilih ekspor XML (Event Viewer "Export XML"
atau `wevtutil /x`) supaya parser stdlib murni dan nol dependensi.

Input -> mekanisme -> output:
  - Input : file XML ekspor Windows Security berisi Event 4625/4624,
            atau --dir berisi beberapa file.
  - Mekanisme: kumpulkan gagal (4625) & sukses (4624) dgn LogonType
            dalam cakupan (default RDP/NLA/network: 10/3/7) -> window
            geser deterministik per IP sumber.
  - Output: temuan {check, severity, ip, ...} + stats + notes.

Cek (verdict = LEAD "teramati di log"; dugaan kompromi butuh bukti
tambahan):
  brute-force       (high)   : >= --threshold kegagalan dari satu IP
                               dalam window --window detik (sliding).
  username-spray    (high)   : >= --spray-accounts akun BERBEDA dari
                               satu IP dalam window (password spray).
  success-after-fail(high)   : 4624 sukses dari IP yang sama SETELAH
                               >= --threshold kegagalan (kandidat
                               kompromi — dicatat juga akunnya).
  account-not-found (low)    : substatus 0xC0000064 dominan pada IP
                               yang gagal (enumerasi nama akun).
  failed-logon      (info)   : kegagalan di bawah ambang dicatat
                               sebagai inventaris IP per failure
                               count (tanpa severity high).

Notes telemetri (fail-closed): bila log tidak berisi 4625 sama sekali,
deteksi brute force tidak dapat dinilai — dicatat, tidak disimpulkan
"bersih". Log tanpa 4624 = deteksi success-after-fail tidak dapat
dinilai.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input
(file tak ada, XML tak valid, nol event 4625/4624 ter-parse).

Pemakaian:
  python tools/win_logon_triage.py --log security.xml
  python tools/win_logon_triage.py --dir exports/ --threshold 20
  python tools/win_logon_triage.py --log security.xml --logon-types 10
Exit: lihat di atas.
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = "secai.win-logon-triage/1"
MAX_FILE_BYTES = 256 * 1024 * 1024

EID_FAILED = 4625
EID_SUCCESS = 4624
DEFAULT_LOGON_TYPES = frozenset({10, 3, 7})
SUBSTATUS_USER_NOT_FOUND = "0xc0000064"

_EVENTDATA_PICK = (
    "TargetUserName", "IpAddress", "IpPort", "LogonType", "SubStatus",
    "Status", "WorkstationName", "ProcessName", "AuthenticationPackageName",
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_time(val: str) -> datetime | None:
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _norm_ip(val: str) -> str:
    return (val or "").replace("::ffff:", "").strip()


def _norm_sub(val: str) -> str:
    """SubStatus ke bentuk 0x-normal lowercase; nilai desimal tak
    dikonversi (dibiarkan apa adanya, tidak pernah diekuivalenkan)."""
    v = (val or "").strip().lower()
    if v.startswith("0x"):
        return v
    return v


def parse_events(xml_text: str, src: str) -> list[dict]:
    """Parse XML -> daftar event 4624/4625 terurut waktu (stabil)."""
    wrapped = xml_text
    if not wrapped.lstrip().startswith("<?xml") and "<Event" in wrapped \
            and "<Events" not in wrapped and "<root" not in wrapped:
        wrapped = f"<root>{xml_text}</root>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        raise ValueError(f"{src}: XML tidak valid ({exc})") from None

    events: list[dict] = []
    for ev in root.iter():
        if _local(ev.tag) != "Event":
            continue
        eid = 0
        sys_time: datetime | None = None
        data: dict[str, str] = {}
        for child in ev.iter():
            loc = _local(child.tag)
            if loc == "EventID" and child.text:
                try:
                    eid = int(child.text.strip())
                except ValueError:
                    eid = 0
            elif loc == "TimeCreated":
                sys_time = _parse_time(child.get("SystemTime", ""))
            elif loc == "Data" and child.get("Name"):
                name = child.get("Name")
                if name in _EVENTDATA_PICK:
                    data[name] = (child.text or "").strip()
        if eid not in (EID_FAILED, EID_SUCCESS):
            continue
        try:
            logon_type = int(data.get("LogonType", "0") or 0)
        except ValueError:
            logon_type = 0
        events.append({
            "eid": eid, "data": data, "time": sys_time,
            "user": data.get("TargetUserName", ""),
            "ip": _norm_ip(data.get("IpAddress", "")),
            "logon_type": logon_type,
            "substatus": _norm_sub(data.get("SubStatus", "")),
        })
    if not events:
        raise ValueError(f"{src}: nol event logon (4624/4625) "
                         "ter-parse")
    events.sort(key=lambda e: (e["time"] is None,
                               e["time"] or datetime.min.replace(
                                   tzinfo=timezone.utc)))
    return events


def _max_failures_in_window(times: list[datetime],
                            window: timedelta) -> int:
    """Sliding window deterministik: max gagal oleh satu IP dalam
    window W. O(n) dua-pointer; times harus terurut."""
    best = 0
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def triage(events: list[dict], logon_types: frozenset[int],
           threshold: int, spray_accounts: int, window_s: float,
           ) -> tuple[list[dict], dict, list[str]]:
    findings: list[dict] = []
    in_scope = [e for e in events if e["logon_type"] in logon_types]

    fails: dict[str, list[dict]] = {}
    for ev in in_scope:
        if ev["eid"] == EID_FAILED and ev["ip"]:
            fails.setdefault(ev["ip"], []).append(ev)

    wins = timedelta(seconds=window_s)

    # agregat per IP
    ip_stats: dict[str, dict] = {}
    for ip, evs in fails.items():
        times = [e["time"] for e in evs if e["time"]]
        burst = _max_failures_in_window(times, wins) if times else 0
        users = {e["user"] for e in evs}
        not_found = sum(1 for e in evs
                        if e["substatus"] == SUBSTATUS_USER_NOT_FOUND)
        ip_stats[ip] = {
            "failures": len(evs),
            "burst": burst,
            "accounts": sorted(users),
            "account_not_found": not_found,
        }

    for ip, s in sorted(ip_stats.items()):
        base = {"ip": ip, "failures": s["failures"],
                "burst": s["burst"], "accounts": s["accounts"]}
        if s["burst"] >= threshold:
            findings.append({
                "check": "brute-force", "severity": "high", "ip": ip,
                "message": f"{s['burst']} kegagalan logon dalam "
                           f"{int(window_s)}s (>= ambang {threshold})",
                **base,
            })
        if len(s["accounts"]) >= spray_accounts:
            findings.append({
                "check": "username-spray", "severity": "high", "ip": ip,
                "message": f"{len(s['accounts'])} akun berbeda dari "
                           f"satu IP (>= ambang {spray_accounts})",
                **base,
            })
        if s["failures"] >= threshold and \
                s["account_not_found"] * 2 >= s["failures"]:
            findings.append({
                "check": "account-not-found", "severity": "low", "ip": ip,
                "message": "mayoritas kegagalan 0xC0000064 (akun tak "
                           "ada) — enumerasi nama akun",
                **base,
            })
        elif 0 < s["failures"] < threshold:
            findings.append({
                "check": "failed-logon", "severity": "info", "ip": ip,
                "message": f"{s['failures']} kegagalan (di bawah "
                           f"ambang {threshold})",
                **base,
            })

    # sukses setelah kegagalan dari IP yang sama
    has_success = any(e["eid"] == EID_SUCCESS for e in in_scope)
    succ_after: set[str] = set()
    if has_success:
        for ip, evs in fails.items():
            if len(evs) < threshold:
                continue
            first_fail = next((e["time"] for e in evs if e["time"]), None)
            if first_fail is None:
                continue
            for ev in in_scope:
                if ev["eid"] == EID_SUCCESS and ev["ip"] == ip \
                        and ev["time"] and ev["time"] >= first_fail:
                    succ_after.add(ip)
                    findings.append({
                        "check": "success-after-fail", "severity": "high",
                        "ip": ip,
                        "message": "logon SUKSES dari IP dengan >= "
                                   f"{threshold} kegagalan sebelumnya — "
                                   "kandidat kompromi akun "
                                   f"({ev['user']})",
                        "account": ev["user"],
                        "failures": len(evs), "burst": ip_stats[ip]["burst"],
                        "accounts": ip_stats[ip]["accounts"],
                    })

    stats = {
        "events_total": len(events),
        "events_in_scope": len(in_scope),
        "failed_4625": sum(1 for e in in_scope
                           if e["eid"] == EID_FAILED),
        "success_4624": sum(1 for e in in_scope
                            if e["eid"] == EID_SUCCESS),
        "source_ips": len(ip_stats),
    }
    notes: list[str] = []
    if stats["failed_4625"] == 0:
        notes.append("tidak ada Event 4625 di log — deteksi brute "
                     "force tidak dapat dinilai dari telemetri ini")
    if stats["failed_4625"] > 0 and not has_success:
        notes.append("tidak ada Event 4624 di log — deteksi "
                     "success-after-fail tidak dapat dinilai")
    findings.sort(key=lambda f: (f["check"], f["ip"]))
    return findings, stats, notes


def _iter_files(args: argparse.Namespace) -> list[Path]:
    if args.log:
        return [Path(args.log)]
    if args.dir:
        files = sorted(p for p in Path(args.dir).iterdir()
                       if p.suffix.lower() == ".xml" and p.is_file())
        if not files:
            raise FileNotFoundError(f"tidak ada file .xml di {args.dir}")
        return files
    raise FileNotFoundError("wajib --log atau --dir")


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase OFFLINE log Windows Security XML utk brute "
                    "force logon RDP/NLA (4625/4624) — nol jaringan")
    ap.add_argument("--log", help="file XML ekspor Windows Security")
    ap.add_argument("--dir", help="direktori berisi file .xml")
    ap.add_argument("--logon-types", default="10,3,7",
                    help="LogonType dalam cakupan, dipisah koma "
                         "(default 10=RemoteInteractive,3=Network,7="
                         "Unlock)")
    ap.add_argument("--threshold", type=int, default=10,
                    help="ambang kegagalan per IP dalam window "
                         "(default 10)")
    ap.add_argument("--spray-accounts", type=int, default=5,
                    help="ambang akun berbeda per IP utk spray "
                         "(default 5)")
    ap.add_argument("--window", type=float, default=600.0,
                    help="window geser detik (default 600)")
    ap.add_argument("--fail-on", choices=["medium", "high"],
                    default="high")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)

    try:
        logon_types = frozenset(
            int(x) for x in args.logon_types.split(",") if x.strip())
        assert logon_types
    except (ValueError, AssertionError):
        print("ERROR: --logon-types tidak valid", file=sys.stderr)
        return 2

    try:
        files = _iter_files(args)
    except (FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    events: list[dict] = []
    for path in files:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                print(f"ERROR: {path} > {MAX_FILE_BYTES} byte",
                      file=sys.stderr)
                return 2
            events.extend(parse_events(
                path.read_text(encoding="utf-8", errors="replace"),
                str(path)))
        except (OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    findings, stats, notes = triage(events, logon_types,
                                    args.threshold, args.spray_accounts,
                                    args.window)
    order = {"high": 0, "medium": 1, "info": 2, "low": 3}
    result = {
        "schema": SCHEMA,
        "findings": findings,
        "stats": stats,
        "notes": notes,
        "meta": {"logon_types": sorted(logon_types),
                 "threshold": args.threshold,
                 "spray_accounts": args.spray_accounts,
                 "window_s": args.window,
                 "fail_on": args.fail_on},
    }
    out = json.dumps(result, ensure_ascii=False, sort_keys=True,
                     indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    gate = order[args.fail_on]
    hit = any(order[f["severity"]] <= gate for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
