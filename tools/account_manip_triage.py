r"""[SAFETY: read-only] account_manip_triage — triase OFFLINE log Windows
Security (XML) untuk manipulasi akun (T1098): penambahan member ke grup
ber-hak istimewa, akun baru lalu langsung dipromosikan, SID History
(T1098.005), perubahan atribut akun (AdminCount/PasswordNeverExpires),
burst reset password, dan modifikasi objek DS AdminSDHolder. TANPA
jaringan.

Input -> mekanisme -> output:
  - Input : file XML ekspor Windows Security, atau --dir.
  - Mekanisme: dispatch per event ID -> cek deterministik + korelasi
    in-memory (akun dibuat -> ditambahkan ke grup ber-hak, window
    --correlate-minutes; burst reset password per subject).
  - Output: temuan {check, severity, eid, host, member/target,
    message} + stats + notes (keluarga EID absen dicatat — kegelapan
    tidak dilaporkan "bersih"; fail-closed).

Cek (verdict = LEAD; operasi IAM sah menghasilkan temuan — pakai
--allow-member/--allow-group utk allowlist lab):
  group-priv-add        (high)   : 4728/4732/4756 member ditambahkan
                                   ke grup ber-hak istimewa (Domain/
                                   Enterprise/Schema Admins,
                                   Administrators, Backup/Account/
                                   Server/Print Operators).
  created-then-priv     (high)   : 4720 (akun dibuat) diikuti
                                   penambahan akun YBS ke grup ber-hak
                                   dalam window --correlate-minutes
                                   (default 24 jam) — pola backdoor
                                   akun (T1098.001/1136).
  sid-history-add       (high)   : 4765/4766 SID History ditambahkan
                                   (T1098.005).
  acct-attr-suspicious  (medium) : 4738 ChangedAttributes memuat
                                   Admin Count / Password Never
                                   Expires / Smartcard Required
                                   dilepas — kandidat shadow admin.
  reset-burst           (medium) : 4724 >= --reset-burst target
                                   berbeda oleh subject sama dalam
                                   window 1 jam.
  ds-adminsdholder-mod  (medium) : 5136 modifikasi objek yang DN-nya
                                   memuat AdminSDHolder.

Fail-closed:
  - XML tidak valid / nol event ter-parse -> exit 2.
  - Keluarga EID wajib absen dicatat di notes.
  - MemberName berupa DN diurai ke CN; tidak terurai = dipakai apa
    adanya (tidak dibuang diam-diam).

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/account_manip_triage.py --log security.xml
  python tools/account_manip_triage.py --dir exports/ \
      --allow-member 'CORP\\svc-sync' --correlate-minutes 60
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "secai.account-manip-triage/1"
MAX_FILE_BYTES = 256 * 1024 * 1024

WATCHED_EIDS = frozenset({4720, 4724, 4738, 4765, 4766, 5136,
                          4728, 4732, 4756})

PRIVILEGED_GROUPS = frozenset({
    "domain admins", "enterprise admins", "enterprise administrators",
    "schema admins", "administrators", "backup operators",
    "account operators", "server operators", "print operators",
})

CN_RE = re.compile(r"CN=([^,]+)", re.I)

EVENT_NS = ".//{http://schemas.microsoft.com/win/2004/windows/events/log}"


def parse_event_file(path: Path) -> tuple[list[dict], int]:
    """Parse satu file XML Security -> (event tervalidasi, total
    <Event>). Event di luar WATCHED_EIDS dilewati (dihitung)."""
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
        t_el = ev.find(f"{EVENT_NS}TimeCreated")
        events.append({
            "eid": eid,
            "host": (comp_el.text or "").strip() if comp_el is not None
                    else "",
            "time": t_el.get("SystemTime", "") if t_el is not None else "",
            "data": data,
        })
    return events, total


def _ts(raw: str) -> "datetime | None":
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _short(name: str) -> str:
    """CN=jdoe,CN=Users,DC=... -> jdoe; nama polos tetap polos."""
    m = CN_RE.search(name or "")
    return m.group(1).strip() if m else (name or "").strip()


def _f(check: str, severity: str, eid: int, host: str, time: str,
       target: str, message: str) -> dict:
    return {"check": check, "severity": severity, "eid": eid,
            "host": host, "time": time, "target": target,
            "message": message}


def _allowed(text: str, allow: frozenset[str]) -> str | None:
    for a in allow:
        if a.lower() in text.lower():
            return a
    return None


def analyze(events: list[dict], allow_members: frozenset[str],
            allow_groups: frozenset[str], correlate_min: float,
            reset_burst: int) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    notes: list[str] = []
    eids = {e["eid"] for e in events}
    for label, fam in {
        "EID 4728/4732/4756 (tambah member grup)": {4728, 4732, 4756},
        "EID 4720 (akun dibuat)": {4720},
        "EID 4724 (reset password)": {4724},
        "EID 4738 (akun diubah)": {4738},
        "EID 4765/4766 (SID history)": {4765, 4766},
        "EID 5136 (objek DS diubah)": {5136},
    }.items():
        if not (eids & fam):
            notes.append(f"{label} tidak ada di log — sumber itu "
                         "kemungkinan tidak diaudit; ketiadaan temuan "
                         "dari sumber tsb bukan bukti bersih "
                         "(fail-closed).")

    created: dict[str, tuple[datetime, str, str]] = {}
    resets: list[tuple[datetime, str, str, str]] = []
    group_finds: list[tuple[datetime, str]] = []

    for ev in sorted(events, key=lambda e: e["time"] or ""):
        d = ev["data"]
        eid = ev["eid"]
        t = _ts(ev["time"])
        host = ev["host"]
        subject = d.get("SubjectUserName", "")
        if eid in (4728, 4732, 4756):
            group = d.get("TargetUserName", "")
            member = _short(d.get("MemberName", "") or
                            d.get("MemberSid", ""))
            full = f"{member} -> {group}"
            if _allowed(full, allow_members) or \
                    _allowed(full, allow_groups):
                continue
            if group.lower() in PRIVILEGED_GROUPS:
                findings.append(_f(
                    "group-priv-add", "high", eid, host, ev["time"],
                    full,
                    f"{subject} menambahkan {member} ke grup ber-hak "
                    f"'{group}' (T1098) — verifikasi change request "
                    "IAM sebelum eskalasi"))
                if t:
                    group_finds.append((t, member.lower()))
        elif eid == 4720:
            target = d.get("TargetUserName", "")
            if target and t:
                created.setdefault(target.lower(), (t, target, ev["time"]))
        elif eid == 4724:
            target = d.get("TargetUserName", "")
            if target and t:
                resets.append((t, subject, target, ev["time"]))
        elif eid == 4738:
            target = d.get("TargetUserName", "")
            changed = d.get("ChangedAttributes", "")
            hits = []
            for token, label_ in (
                    ("Admin Count", "AdminCount diubah"),
                    ("Password Never Expires",
                     "PasswordNeverExpires diset"),
                    ("Smartcard Required", "Smartcard dilepas")):
                if token.lower() in changed.lower():
                    hits.append(label_)
            if target and hits and not _allowed(target, allow_members):
                findings.append(_f(
                    "acct-attr-suspicious", "medium", eid, host,
                    ev["time"], target,
                    f"{subject} mengubah {target}: {'; '.join(hits)} — "
                    "kandidat shadow admin (T1098)"))
        elif eid in (4765, 4766):
            target = d.get("TargetUserName", "")
            if _allowed(target, allow_members):
                continue
            findings.append(_f(
                "sid-history-add", "high", eid, host, ev["time"],
                target,
                f"{subject} menambahkan SID History ke {target} "
                "(T1098.005) — vektor akses sisa/masked privilege"))
        elif eid == 5136:
            dn = d.get("ObjectDN", "")
            attr = d.get("AttributeLDAPDisplayName", "")
            if "adminsdholder" in dn.lower() and \
                    not _allowed(dn, allow_members):
                findings.append(_f(
                    "ds-adminsdholder-mod", "medium", eid, host,
                    ev["time"], dn,
                    f"{subject} memodifikasi objek AdminSDHolder "
                    f"(atribut {attr or '(tak dicantumkan)'}) — "
                    "kandidat persistence shadow admin (T1098)"))

    # korelasi: akun dibuat -> ditambahkan ke grup ber-hak
    for gt, member in group_finds:
        info = created.get(member)
        if info is None:
            continue
        ct, cname, ctime = info
        if (gt - ct).total_seconds() <= correlate_min * 60:
            findings.append(_f(
                "created-then-priv", "high", 4720, host, ctime, cname,
                f"Akun {cname} DIBUAT lalu ditambahkan ke grup ber-hak "
                f"dalam {correlate_min:.0f} menit — pola backdoor akun "
                "(T1098)"))

    # burst reset password per subject dalam 1 jam
    resets.sort(key=lambda r: r[0])
    for i, (t, subj, tgt, raw) in enumerate(resets):
        if not subj:
            continue
        window = [r for r in resets
                  if r[1] == subj and 0 <= (t - r[0]).total_seconds()
                  <= 3600]
        targets = {r[2].lower() for r in window}
        if len(targets) >= reset_burst:
            findings.append(_f(
                "reset-burst", "medium", 4724, host, raw, subj,
                f"{subj} me-reset password {len(targets)} akun berbeda "
                "dalam 1 jam (T1098 lead)"))
            break  # satu temuan per subject cukup utk lead

    notes.append(
        f"korelasi created-then-priv memakai window {correlate_min:.0f} "
        "menit; tanpa telemetri 4720 korelasi ini tidak mungkin — "
        "cek notes keluarga EID di atas.")
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
        description="Triase OFFLINE manipulasi akun Windows Security "
                    "(T1098) — read-only, nol jaringan.")
    ap.add_argument("--log", type=Path, help="file XML Security")
    ap.add_argument("--dir", type=Path, help="direktori berisi XML")
    ap.add_argument("--out", type=Path, help="simpan laporan JSON")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"],
                    default="high")
    ap.add_argument("--allow-member", default="",
                    help="CSV nama member/target sah (anti-FP)")
    ap.add_argument("--allow-group", default="",
                    help="CSV nama grup yang dianggap sah utk cek ini")
    ap.add_argument("--correlate-minutes", type=float, default=24 * 60,
                    help="window korelasi created-then-priv (menit)")
    ap.add_argument("--reset-burst", type=int, default=5,
                    help="ambang reset password per subject per jam")
    ap.add_argument("--json", action="store_true")
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
        print("error: tidak ada event Security ter-parse (XML kosong/"
              "bukan ekspor Windows Security?)", file=sys.stderr)
        return 2

    allow_members = frozenset(
        a.strip() for a in args.allow_member.split(",") if a.strip())
    allow_groups = frozenset(
        a.strip() for a in args.allow_group.split(",") if a.strip())
    findings, notes = analyze(events, allow_members, allow_groups,
                              args.correlate_minutes, args.reset_burst)
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
        for f in findings:
            print(f"[{f['severity'].upper():6}] {f['check']}: "
                  f"{f['message']}")
        print(f"-- {stats['findings']} temuan, {stats['events_total']} "
              f"event dari {stats['files']} file")
        for n in notes:
            print(f"note: {n}")
    return 1 if any(rank[f["severity"]] >= rank[args.fail_on]
                    for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
