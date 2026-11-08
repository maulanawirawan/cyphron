"""[SAFETY: read-only] kerberos_log_triage — triase OFFLINE log keamanan
Windows (XML) untuk indikasi Golden Ticket / anomali Kerberos.

Mengisi antrean port SKILL-PORT-QUEUE #0418 + #0419 (mukul975/
Anthropic-Cybersecurity-Skills 'detecting-golden-ticket-attacks-in-
kerberos-logs' dan 'detecting-golden-ticket-forgery' — MITRE ATT&CK
T1558.001; lisensi sumber Apache-2.0, atribusi ide — kode dibangun from
scratch TANPA menyalin kode sumber). Konsep sumber (deteksi dari DC
Windows Security log, TGT yang dipalsukan memakai hash krbtgt):
  - Golden Ticket BYPASS AS-REQ/AS-REP, jadi TGS (Event 4769) tanpa
    TGT (Event 4768) sebelumnya dari user+IP yang sama = indikator.
  - Golden Ticket lazim dipalsukan dengan RC4 (0x17) padahal domain
    moderen menegakkan AES (0x11/0x12) — RC4 di lingkungan AES-only =
    downgrade mencurigakan.
  - Lifetime TGT/TGS yang melampaui kebijakan domain (default 10 jam)
    = indikator forgery (butuh field waktu tiket yang kadang disertakan
    ekspor/EDR; kalau tidak ada, deteksi ini dilewati dan CATATAN
    telemetri ditulis — tidak pernah pura-pura memeriksa).

Input: file XML ekspor Windows Security (Event Viewer "Export XML"
atau `wevtutil /x`), satu file berisi banyak elemen <Event>. Parser
stdlib xml.etree; namespace MS di-strip. TANPA jaringan.

Temuan (semua = LEAD "teramati di log", bukan klaim kompromi):
  rc4-downgrade     etype RC4 (0x17/0x18) pada 4768/4769 — severity
                    high bila --enforce-aes, medium bila tidak
  legacy-encryption etype DES (0x1/0x3) — lead rendah
  tgs-tanpa-tgt     4769 tanpa 4768 sebelumnya utk (user, ip) yang
                    sama dalam file; CATATAN eksplisit bila file sama
                    sekali tidak berisi 4768 (telemetri tidak lengkap)
  lifetime-anomali  durasi tiket (TicketStartTime->TicketEndTime bila
                    ada) > --max-lifetime-h (default 10)

Fail-closed: nol event ter-parse / XML tidak valid -> exit 2. Output
JSON deterministik terurut.

Pemakaian:
  python tools/kerberos_log_triage.py --log security-events.xml
  python tools/kerberos_log_triage.py --log ev.xml --enforce-aes --out triase.json
Exit: 0 selesai (temuan tetap exit 0); 2 input error.
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "secai.kerberos-log-triage/1"
MAX_FILE_BYTES = 64 * 1024 * 1024

ETYPE_MAP = {
    "0x1": "DES-CBC-CRC", "0x3": "DES-CBC-MD5",
    "0x11": "AES128-CTS-HMAC", "0x12": "AES256-CTS-HMAC",
    "0x17": "RC4-HMAC", "0x18": "RC4-HMAC-EXP",
}
RC4_ETYPOS = frozenset({"0x17", "0x18"})
DES_ETYPOS = frozenset({"0x1", "0x3"})

_EVENT_IDS = {4768: "tgt", 4769: "tgs", 4771: "preauth-failed"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_time(val: str) -> datetime | None:
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def parse_events(xml_text: str, src: str) -> list[dict]:
    """Parse XML -> daftar event Kerberos terurut waktu (stabil)."""
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
        data: dict[str, str] = {}
        sys_time: datetime | None = None
        eid = 0
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
                data[child.get("Name")] = (child.text or "").strip()
        if eid not in _EVENT_IDS:
            continue
        events.append({
            "eid": eid, "data": data, "time": sys_time,
            "user": data.get("TargetUserName", ""),
            "ip": data.get("IpAddress", "").replace("::ffff:", ""),
            "etype": data.get("TicketEncryptionType", "").lower(),
        })
    if not events:
        raise ValueError(f"{src}: nol event Kerberos (4768/4769/4771) "
                         "ter-parse")
    events.sort(key=lambda e: (e["time"] is None,
                               e["time"] or datetime.min.replace(
                                   tzinfo=timezone.utc)))
    return events


def triage(events: list[dict], enforce_aes: bool,
           max_lifetime_h: float) -> dict:
    findings: list[dict] = []
    rc4_by_user: dict[str, int] = {}
    has_tgt = False

    # indeks (user, ip) -> urutan TGT
    tgt_seen: set[tuple[str, str]] = set()
    for ev in events:
        if ev["eid"] == 4768:
            tgt_seen.add((ev["user"], ev["ip"]))

    for idx, ev in enumerate(events):
        etype = ev["etype"]
        label = ETYPE_MAP.get(etype, etype or "tidak-diketahui")
        if etype in RC4_ETYPOS and ev["eid"] in (4768, 4769):
            rc4_by_user[ev["user"]] = rc4_by_user.get(ev["user"], 0) + 1
            findings.append({
                "type": "rc4-downgrade",
                "severity": "high" if enforce_aes else "medium",
                "event": ev["eid"], "user": ev["user"],
                "ip": ev["ip"], "etype": etype, "etype_name": label,
                "detail": "etype RC4 pada permintaan tiket"
                          + (" padahal kebijakan menegakkan AES"
                             if enforce_aes else ""),
            })
        elif etype in DES_ETYPOS:
            findings.append({
                "type": "legacy-encryption", "severity": "low",
                "event": ev["eid"], "user": ev["user"], "ip": ev["ip"],
                "etype": etype, "etype_name": label,
                "detail": "etype DES warisan pada permintaan tiket",
            })

        # lifetime (bila field waktu tiket tersedia)
        try:
            st = _parse_time(ev["data"].get("TicketStartTime", ""))
            et = _parse_time(ev["data"].get("TicketEndTime", ""))
        except Exception:
            st = et = None
        if st and et:
            hours = (et - st).total_seconds() / 3600.0
            if hours > max_lifetime_h:
                findings.append({
                    "type": "lifetime-anomali",
                    "severity": "high",
                    "event": ev["eid"], "user": ev["user"],
                    "ip": ev["ip"], "etime": round(hours, 2),
                    "detail": f"durasi tiket {hours:.1f} jam > "
                              f"kebijakan {max_lifetime_h} jam",
                })

        # TGS tanpa TGT sebelumnya utk (user, ip)
        if ev["eid"] == 4769 and (ev["user"], ev["ip"]) not in tgt_seen:
            findings.append({
                "type": "tgs-tanpa-tgt", "severity": "high",
                "event": 4769, "user": ev["user"], "ip": ev["ip"],
                "detail": "TGS tanpa TGT (4768) sebelumnya dari "
                          "kombinasi user+IP yang sama — indikator "
                          "golden ticket (perlu log DC utuh utk "
                          "konfirmasi)",
            })

    findings.sort(key=lambda f: (f["type"], f["user"], f["ip"],
                                 f.get("event", 0)))
    stats = {
        "events_total": len(events),
        "tgt_4768": sum(1 for e in events if e["eid"] == 4768),
        "tgs_4769": sum(1 for e in events if e["eid"] == 4769),
        "preauth_failed_4771": sum(1 for e in events
                                   if e["eid"] == 4771),
    }
    notes: list[str] = []
    if stats["tgt_4768"] == 0:
        notes.append("tidak ada Event 4768 di log — deteksi "
                     "tgs-tanpa-tgt tidak dapat disimpulkan dari "
                     "telemetri ini (cek apakah log DC utuh)")
    if not any("TicketStartTime" in e["data"] for e in events):
        notes.append("field TicketStartTime/TicketEndTime tidak "
                     "tersedia — deteksi lifetime-anomali dilewati")
    return {
        "schema": SCHEMA, "stats": stats,
        "rc4_by_user": dict(sorted(rc4_by_user.items())),
        "notes": notes,
        "findings": findings,
    }


# ------------------------------------------------------------- cli
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase offline log Windows XML utk indikasi "
                    "Golden Ticket / anomali Kerberos (LEAD).")
    ap.add_argument("--log", required=True, help="file XML Windows "
                    "Security events (4768/4769/4771)")
    ap.add_argument("--enforce-aes", action="store_true",
                    help="kebijakan domain AES-only (RC4 = high)")
    ap.add_argument("--max-lifetime-h", type=float, default=10.0,
                    help="kebijakan lifetime maksimum tiket (jam)")
    ap.add_argument("--out", help="tulis JSON ke file (selain stdout)")
    args = ap.parse_args(argv)

    p = Path(args.log)
    try:
        if not p.is_file():
            raise ValueError(f"file tidak ada: {p}")
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"file melebihi {MAX_FILE_BYTES} byte")
        text = p.read_text(encoding="utf-8", errors="replace")
        events = parse_events(text, p.name)
    except ValueError as exc:
        print(f"[kerberos-log-triage] input error: {exc}",
              file=sys.stderr)
        return 2

    result = triage(events, args.enforce_aes, args.max_lifetime_h)
    rendered = json.dumps(result, ensure_ascii=False, indent=2,
                          sort_keys=True)
    print(rendered)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
