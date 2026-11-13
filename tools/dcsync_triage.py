r"""[SAFETY: read-only] dcsync_triage — triase OFFLINE log Windows Security
(XML) untuk DCSync / abuse replikasi AD (T1003.006): Event 4662 dengan
hak replikasi directory service (DS-Replication-Get-Changes / -All /
-In-Filtered-Set) yang dipicu akun BUKAN akun mesin/domain controller.
TANPA jaringan.

Input -> mekanisme -> output:
  - Input : file XML ekspor Windows Security (Event Viewer "Export
            XML" / wevtutil /x) berisi elemen <Event>, atau --dir.
  - Mekanisme: parse 4662 -> cocokkan GUID replikasi di ObjectType/
            ObjectName -> bedakan access mask Control Access (0x100)
            -> saring akun mesin ('$') + allowlist -> korelasi IP
            sumber dgn daftar IP DC bila diberikan.
  - Output: temuan {check, severity, eid, host, subject, ip, message}
            + stats + notes telemetri (4662 absen = audit DS Access
            kemungkinan tidak menyala — kegelapan TIDAK dilaporkan
            "bersih"; fail-closed).

Cek (verdict = LEAD; konteks replikasi sah bisa menghasilkan temuan —
pakai --allow-account untuk principal replikasi sah milik lab seperti
MSOL_*/AADConnect/SCCM):
  dcsync-replication  (high)   : 4662 GUID replikasi + AccessMask
                                 0x100 dari akun non-mesin (T1003.006;
                                 Mimikatz lsadump::dcsync /
                                 secretsdump.py).
  replication-access  (medium) : GUID replikasi teramati TANPA bit
                                 Control Access 0x100 — lead konteks
                                 (enumerasi replikasi, bukan dump).
  dcsync-ip-non-dc    (info)   : catatan tambahan pada temuan di atas
                                 bila IP sumber TIDAK ada di --dc-ip
                                 (tanpa --dc-ip cek ini dilewati
                                 eksplisit, tidak pernah ditebak).

Fail-closed:
  - XML tidak valid / nol event Security ter-parse -> exit 2.
  - EID wajib (4662) absen dari log dicatat di notes — coverage tidak
    disimpulkan dari kegelapan.
  - AccessMask tidak ter-parse tidak pernah dianggap "bukan 0x100"
    secara diam-diam: dibandingkan normalisasi hex/decimal.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/dcsync_triage.py --log security.xml
  python tools/dcsync_triage.py --dir exports/ --dc-ip 10.0.0.1,10.0.0.2
  python tools/dcsync_triage.py --log security.xml \
      --allow-account MSOL_abc123,svc-azure-sync
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.dcsync-triage/1"
MAX_FILE_BYTES = 256 * 1024 * 1024

WATCHED_EIDS = frozenset({4662})

# GUID extended-right replikasi AD (terdaftar publik di schema AD):
# trio yang dipakai DCSync utk menarik hash password (T1003.006).
REPLICATION_GUIDS = frozenset({
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c",  # Get-Changes-In-Filtered-Set
})

GUID_RE = re.compile(
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12})")
# extended-right bisa tampil sbg nama tegas di beberapa konfigurasi audit
REPLICATION_NAMES_RE = re.compile(
    r"DS-Replication-Get-Changes(?:-All|-In-Filtered-Set)?", re.I)

CONTROL_ACCESS_MASKS = frozenset({"0x100", "256"})

EVENT_NS = ".//{http://schemas.microsoft.com/win/2004/windows/events/log}"


def _strip_ipv6_prefix(ip: str) -> str:
    """Hilangkan prefix ::ffff: dari representasi IPv4-mapped."""
    return ip[7:] if ip.lower().startswith("::ffff:") else ip


def parse_event_file(path: Path) -> tuple[list[dict], int]:
    """Parse satu file XML Security -> (event 4662 tervalidasi, total
    elemen <Event>). Event tanpa EventID/EventData dilewati (dihitung)."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"XML tidak valid: {path.name}: {exc}") from exc
    events: list[dict] = []
    total = 0
    for ev in root.iter():
        if not ev.tag.endswith("}Event") and ev.tag != "Event":
            continue
        total += 1
        eid_el = ev.find(f"{EVENT_NS}EventID")
        if eid_el is None or not (eid_el.text or "").strip().isdigit():
            continue
        eid = int(eid_el.text.strip())
        if eid not in WATCHED_EIDS:
            continue
        data: dict[str, str] = {}
        for d in ev.iterfind(f"{EVENT_NS}EventData/{EVENT_NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
        comp_el = ev.find(f"{EVENT_NS}Computer")
        sys_el = ev.find(f"{EVENT_NS}TimeCreated")
        events.append({
            "eid": eid,
            "host": (comp_el.text or "").strip() if comp_el is not None else "",
            "time": (sys_el.get("SystemTime", "")
                     if sys_el is not None else ""),
            "data": data,
        })
    return events, total


def _guid_in_text(text: str) -> str | None:
    m = GUID_RE.search(text or "")
    if m and m.group(1).lower() in REPLICATION_GUIDS:
        return m.group(1).lower()
    if REPLICATION_NAMES_RE.search(text or ""):
        return "named:DS-Replication-Get-Changes*"
    return None


def _access_mask_is_control(mask: str) -> bool:
    return (mask or "").strip().lower() in CONTROL_ACCESS_MASKS


def analyze(events: list[dict], allow_accounts: frozenset[str],
            dc_ips: frozenset[str]) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    notes: list[str] = []
    eids = {e["eid"] for e in events}
    if 4662 not in eids:
        notes.append(
            "EID 4662 tidak ada di log — audit 'Directory Service "
            "Access' kemungkinan tidak menyala di DC; ketiadaan temuan "
            "bukan bukti bersih (fail-closed).")
    if not dc_ips:
        notes.append(
            "--dc-ip tidak diberikan: cek dcsync-ip-non-dc dilewati "
            "eksplisit (tanpa baseline IP DC, diverifikasi manual).")
    seen_accounts: set[str] = set()
    for ev in events:
        d = ev["data"]
        subject = d.get("SubjectUserName", "")
        domain = d.get("SubjectDomainName", "")
        subj_full = f"{domain}\\{subject}" if domain else subject
        if not subject:
            continue
        obj_text = " ".join(
            x for x in (d.get("ObjectType", ""), d.get("ObjectName", ""))
            if x)
        guid = _guid_in_text(obj_text)
        if guid is None:
            continue
        if subject.lower() in allow_accounts or subj_full.lower() in \
                allow_accounts:
            seen_accounts.add(subj_full)
            continue
        if subject.endswith("$"):
            # replikasi DC-to-DC memakai akun mesin; bukan DCSync user
            continue
        control = _access_mask_is_control(d.get("AccessMask", ""))
        check = "dcsync-replication" if control else "replication-access"
        sev = "high" if control else "medium"
        ip = _strip_ipv6_prefix(d.get("IpAddress", "").strip())
        msg = (f"Akun {subj_full} meminta hak replikasi DS ({guid}) "
               f"di {ev['host'] or '(host tak diketahui)'}")
        if control:
            msg += (" — pola DCSync (T1003.006); verifikasi apakah "
                    "principal ini principal replikasi sah (Azure AD "
                    "Connect/SCCM) sebelum eskalasi")
        findings.append({
            "check": check, "severity": sev, "eid": ev["eid"],
            "host": ev["host"], "time": ev["time"],
            "subject": subj_full, "guid": guid, "ip": ip,
            "message": msg,
        })
        if ip and dc_ips and ip not in dc_ips:
            findings.append({
                "check": "dcsync-ip-non-dc", "severity": "info",
                "eid": ev["eid"], "host": ev["host"], "time": ev["time"],
                "subject": subj_full, "guid": guid, "ip": ip,
                "message": f"IP sumber {ip} TIDAK ada di daftar IP DC "
                           "(--dc-ip) — permintaan replikasi dari luar "
                           "kontroler domain, indikator kuat DCSync "
                           "(konfirmasi NAT/proxy sebelum disimpulkan)",
            })
    if seen_accounts:
        notes.append(
            "Principal replikasi sah (allowlist): "
            + ", ".join(sorted(seen_accounts)))
    return findings, notes


def _gather_files(args: argparse.Namespace) -> list[Path]:
    if args.log:
        return [args.log]
    if args.dir:
        return sorted(
            p for p in args.dir.iterdir()
            if p.is_file() and p.suffix.lower() in {".xml", ".evtx.xml"})
    raise ValueError("butuh --log atau --dir")


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase OFFLINE Security XML utk DCSync (4662, "
                    "T1003.006) — read-only, nol jaringan.")
    ap.add_argument("--log", type=Path, help="file XML Security")
    ap.add_argument("--dir", type=Path, help="direktori berisi XML")
    ap.add_argument("--out", type=Path, help="simpan laporan JSON")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"],
                    default="high")
    ap.add_argument("--allow-account", default="",
                    help="CSV principal replikasi sah (subject)")
    ap.add_argument("--dc-ip", default="",
                    help="CSV IP domain controller utk korelasi")
    ap.add_argument("--json", action="store_true",
                    help="cetak JSON penuh ke stdout")
    args = ap.parse_args(argv)

    rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    files = _gather_files(args)
    events: list[dict] = []
    total_events = 0
    for p in files:
        if not p.is_file():
            print(f"error: file tidak ada: {p}", file=sys.stderr)
            return 2
        if p.stat().st_size > MAX_FILE_BYTES:
            print(f"error: file terlalu besar (> {MAX_FILE_BYTES} B): {p}",
                  file=sys.stderr)
            return 2
        try:
            evs, total = parse_event_file(p)
            events.extend(evs)
            total_events += total
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
    if total_events == 0:
        # nol elemen <Event> = bukan ekspor Windows Security
        print("error: tidak ada event Security ter-parse (XML kosong/"
              "bukan ekspor Windows Security?)", file=sys.stderr)
        return 2

    allow_accounts = frozenset(
        a.strip().lower() for a in args.allow_account.split(",")
        if a.strip())
    dc_ips = frozenset(
        _strip_ipv6_prefix(i.strip()) for i in args.dc_ip.split(",")
        if i.strip())
    findings, notes = analyze(events, allow_accounts, dc_ips)
    stats = {"files": len(files), "events_total": len(events),
             "findings": len(findings)}
    report = {"schema": SCHEMA, "stats": stats, "findings": findings,
              "notes": notes}
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    if args.json or args.out:
        print(text)
    else:
        # mode singkat: satu baris per temuan + ringkasan
        for f in findings:
            print(f"[{f['severity'].upper():6}] {f['check']}: "
                  f"{f['message']}")
        print(f"-- {stats['findings']} temuan, {stats['events_total']} "
              f"event dari {stats['files']} file")
        for n in notes:
            print(f"note: {n}")
    fail = rank[args.fail_on]
    return 1 if any(rank[f["severity"]] >= fail for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
