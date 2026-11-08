"""[SAFETY: read-only] win_auth_triage — triase OFFLINE log Windows
Security (XML) untuk indikasi LATERAL MOVEMENT / NTLM abuse: pass-the-
hash spray, downgrade NTLMv1, mismatch workstation-IP (relay), rantai
RDP, service PsExec, akun service interaktif, reuse kredensial
eksplisit.

Mengisi antrean port SKILL-PORT-QUEUE #0425 #0426 #0440 #0442 (mukul975/
Anthropic-Cybersecurity-Skills 'detecting-lateral-movement-in-network',
'detecting-lateral-movement-with-splunk', 'detecting-ntlm-relay-with-
event-correlation', 'detecting-pass-the-hash-attacks' — lisensi sumber
Apache-2.0, atribusi konsep — kode dibangun from scratch TANPA menyalin
kode sumber). Skill sumber memakai SPL/KQL/Elastic (SIEM live); secai
memilih artefak offline: file XML ekspor Windows Security (Event Viewer
"Export XML" atau `wevtutil /x`), parser stdlib, nol jaringan.

Pembagian ranah dgn alat secai lain (anti-duplikasi):
  - Event Kerberos 4768/4769/4771  -> tools/kerberos_log_triage.py (B14)
  - Brute force 4625 / password-spray / success-after-fail
    -> tools/win_logon_triage.py (#0452, B16) — di sini TIDAK diulang;
       4625 tetap dihitung di stats saja.
  - Proses Sysmon (LOLBin/dump/injection) -> tools/lolbin_scan.py +
    tools/sysmon_triage.py.

Input -> mekanisme -> output:
  - Input : file XML Windows Security berisi banyak elemen <Event> (atau
            direktori --dir berisi beberapa file), plus opsional
            --inventory CSV (hostname,ip) utk cek mismatch relay.
  - Mekanisme: parse event 4624/4625/4648/4776/7045 -> indeks per
            user/sumber -> cek deterministik.
  - Output: temuan {check, severity, host/user/src, detail} + stats +
            notes (JSON deterministik terurut). SEMUA temuan = LEAD
            "teramati di log", bukan klaim kompromi.

Cek (verdict LEAD; ambang di-echo di meta):
  pth-spray          (high)  : 4624 LogonType=3 NTLM, satu user logon ke
                               >= --min-hosts host TUJUAN unik (pass-the-
                               hash menyapu banyak host dgn kredensial
                               sama; akun mesin `*$` dikecualikan).
  ntlm-v1            (high)  : 4624 NTLM dgn LmPackageName "NTLM V1" —
                               downgrade dari NTLMv2 = indikator relay/
                               alat ofensif.
  relay-mismatch     (high)  : 4624 LogonType=3 NTLM dgn WorkstationName
                               tercatat tapi IpAddress != IP inventory utk
                               hostname tsb — HANYA bila --inventory
                               diberikan; tanpa inventory = catatan
                               eksplisit (tidak pernah menebak).
  rdp-chain          (medium): 4624 LogonType=10, satu IP sumber ke
                               >= --rdp-hosts host unik (pivot RDP).
  psexec-service     (high)  : 7045 dgn ServiceName/ImagePath berpola
                               PSEXESVC (T1569.002).
  suspicious-service (medium): 7045 ImagePath dari UNC (\\\\...) atau
                               direktori user-writable (Temp/Public/
                               AppData/ProgramData).
  svc-interactive    (medium): 4624 LogonType 2/10 utk akun berawalan
                               --svc-prefix (default "svc").
  expl-cred-burst    (medium): 4648 >= --expl-count per (user, server
                               target) — reuse kredensial eksplisit.

Fail-closed: XML tidak valid / nol event relevan (4624/4625/4648/4776/
7045) -> exit 2. Akun mesin (`$`) & ANONYMOUS LOGON dikeluarkan dari cek
per-user.

Exit: 0 selesai (temuan tetap exit 0); 2 input error.

Pemakaian:
  python tools/win_auth_triage.py --log security-events.xml
  python tools/win_auth_triage.py --dir ev/ --inventory dns_inv.csv
  python tools/win_auth_triage.py --log ev.xml --min-hosts 5 --out t.json
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "secai.win-auth-triage/1"
MAX_FILE_BYTES = 64 * 1024 * 1024
RELEVANT_EIDS = frozenset({4624, 4625, 4648, 4776, 7045})
MAX_BAD_SAMPLES = 10

_WRITABLE_DIRS = ("\\temp\\", "\\public\\", "\\appdata\\",
                  "\\programdata\\", "/tmp/")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _bare(user: str) -> str:
    """'CORP\\alice' -> 'alice'; akun mesin tak diubah (dipanggil dgn cek $)."""
    return user.rsplit("\\", 1)[-1].strip().lower()


def _ip(val: str) -> str:
    return (val or "").replace("::ffff:", "").strip()


def _is_machine(user: str) -> bool:
    u = (user or "").strip()
    return not u or u.endswith("$") or u.lower() == "anonymous logon"


def _has_prefix(name: str, prefix: str) -> bool:
    """'svc_backup'/'svc-backup'/'svc.backup' cocok dgn prefix 'svc'."""
    p = prefix.rstrip("-_.").lower()
    return (name.startswith(p) and len(name) > len(p)
            and name[len(p)] in "-_.") or name == p


def parse_events(xml_text: str, src: str) -> "tuple[list[dict], int]":
    """Parse XML -> (events relevan terurut waktu, jumlah total <Event>)."""
    wrapped = xml_text
    if not wrapped.lstrip().startswith("<?xml") and "<Event" in wrapped \
            and "<Events" not in wrapped and "<root" not in wrapped:
        wrapped = f"<root>{xml_text}</root>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        raise ValueError(f"{src}: XML tidak valid ({exc})") from None

    events: list[dict] = []
    total = 0
    for ev in root.iter():
        if _local(ev.tag) != "Event":
            continue
        total += 1
        eid = 0
        time_s = ""
        computer = ""
        data: dict[str, str] = {}
        for child in ev.iter():
            loc = _local(child.tag)
            if loc == "EventID" and child.text:
                try:
                    eid = int(child.text.strip())
                except ValueError:
                    eid = 0
            elif loc == "TimeCreated":
                time_s = child.get("SystemTime", "")
            elif loc == "Computer" and child.text:
                computer = child.text.strip()
            elif loc == "Data" and child.get("Name"):
                data[child.get("Name")] = (child.text or "").strip()
        if eid not in RELEVANT_EIDS:
            continue
        events.append({
            "eid": eid, "time": time_s, "host": computer, "data": data,
            "user": data.get("TargetUserName", ""),
            "ip": _ip(data.get("IpAddress", "")),
            "ws": data.get("WorkstationName", ""),
            "logon_type": data.get("LogonType", ""),
            "auth_pkg": data.get("AuthenticationPackageName", ""),
            "lm_pkg": data.get("LmPackageName", ""),
            "svc": data.get("ServiceName", ""),
            "img": data.get("ImagePath", ""),
            "target_server": data.get("TargetServerName", ""),
        })
    events.sort(key=lambda e: e["time"])
    return events, total


def _load_inventory(path: Path) -> dict[str, str]:
    """CSV (hostname,ip) -> {hostname-lower: ip}. Fail-closed di pemanggil."""
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        cols = [c.lower() for c in (reader.fieldnames or [])]
        hn = next((c for c in ("hostname", "host", "name", "computer")
                   if c in cols), None)
        ipc = next((c for c in ("ip", "ipaddress", "ip_address", "address")
                    if c in cols), None)
        if hn is None or ipc is None:
            raise ValueError("inventory butuh kolom hostname+ip")
        inv: dict[str, str] = {}
        for rec in reader:
            host = (rec.get(reader.fieldnames[cols.index(hn)]) or "").strip().lower()
            ip = (rec.get(reader.fieldnames[cols.index(ipc)]) or "").strip()
            if host and ip:
                inv[host] = _ip(ip)
        return inv


def triage(events: "list[dict]", *, min_hosts: int, rdp_hosts: int,
           svc_prefix: str, expl_count: int,
           inventory: "dict[str, str] | None") -> dict:
    notes: list[str] = []
    stats = {f"eid_{e}": 0 for e in sorted(RELEVANT_EIDS)}
    findings: list[dict] = []

    # indeks
    pth: dict[str, set[str]] = defaultdict(set)      # user -> host tujuan
    rdp: dict[str, set[str]] = defaultdict(set)      # ip sumber -> host
    expl_pairs: Counter[tuple[str, str]] = Counter()
    svc_inter: list[dict] = []
    mismatches: list[dict] = []

    for ev in events:
        stats[f"eid_{ev['eid']}"] += 1
        eid = ev["eid"]
        user_bare = _bare(ev["user"])
        if eid == 4624:
            if not _is_machine(ev["user"]):
                if ev["logon_type"] == "3" and \
                        ev["auth_pkg"].lower() == "ntlm" and ev["ip"]:
                    pth[user_bare].add(ev["host"])
                    if "NTLM V1" in ev["lm_pkg"].upper():
                        findings.append({
                            "check": "ntlm-v1", "severity": "high",
                            "host": ev["host"], "user": user_bare,
                            "src": ev["ip"],
                            "detail": "logon network pakai NTLMv1 "
                                      "(LmPackageName "
                                      f"'{ev['lm_pkg']}') — downgrade "
                                      "dari NTLMv2, indikator relay/"
                                      "alat ofensif",
                        })
                    if ev["ws"] and inventory is not None:
                        expected = inventory.get(ev["ws"].lower())
                        if expected and expected != ev["ip"]:
                            mismatches.append({
                                "check": "relay-mismatch",
                                "severity": "high",
                                "host": ev["host"],
                                "user": user_bare, "src": ev["ip"],
                                "detail": f"4624 LogonType 3 NTLM utk "
                                          f"workstation '{ev['ws']}' "
                                          f"harusnya dari {expected} "
                                          f"(inventory), nyatanya "
                                          f"{ev['ip']} — pola relay "
                                          "T1557.001",
                                "expected_ip": expected,
                            })
                if ev["logon_type"] == "10" and ev["ip"]:
                    rdp[ev["ip"]].add(ev["host"])
                if ev["logon_type"] in ("2", "10") and \
                        _has_prefix(user_bare, svc_prefix):
                    svc_inter.append({
                        "check": "svc-interactive", "severity": "medium",
                        "host": ev["host"], "user": user_bare,
                        "src": ev["ip"] or "-",
                        "detail": f"akun service '{ev['user']}' logon "
                                  f"interaktif (LogonType "
                                  f"{ev['logon_type']}) — akun service "
                                  "seharusnya network-only",
                    })
        elif eid == 4625:
            pass  # brute force/spray dilayani win_logon_triage (#0452, B16)
        elif eid == 4648:
            if not _is_machine(ev["user"]):
                expl_pairs[(user_bare,
                            ev["target_server"] or ev["host"])] += 1
        elif eid == 7045:
            blob = f"{ev['svc']} {ev['img']}".lower()
            if "psexesvc" in blob:
                findings.append({
                    "check": "psexec-service", "severity": "high",
                    "host": ev["host"], "user": _bare(
                        ev["data"].get("AccountName", "")),
                    "src": "",
                    "detail": f"service '{ev['svc']}' (PsExec pattern, "
                              f"T1569.002) — ImagePath: {ev['img'][:120]}",
                })
            elif ev["img"].lower().startswith("\\\\") or any(
                    d in ev["img"].lower() for d in _WRITABLE_DIRS):
                findings.append({
                    "check": "suspicious-service", "severity": "medium",
                    "host": ev["host"], "user": _bare(
                        ev["data"].get("AccountName", "")),
                    "src": "",
                    "detail": f"service baru '{ev['svc']}' dari path "
                              f"mencurigakan: {ev['img'][:120]}",
                })

    for u in sorted(pth):
        if len(pth[u]) >= min_hosts:
            findings.append({
                "check": "pth-spray", "severity": "high",
                "host": "", "user": u, "src": "",
                "detail": f"{len(pth[u])} host tujuan unik utk logon "
                          f"network NTLM (>= {min_hosts}) — pola "
                          "pass-the-hash T1550.002 / lateral spray",
                "unique_hosts": len(pth[u]),
            })
    for src in sorted(rdp):
        if len(rdp[src]) >= rdp_hosts:
            findings.append({
                "check": "rdp-chain", "severity": "medium",
                "host": "", "user": "", "src": src,
                "detail": f"{len(rdp[src])} host di-RDP dari IP sumber "
                          f"ini (>= {rdp_hosts}) — pivot RDP berantai",
                "unique_hosts": len(rdp[src]),
            })
    for (u, srv), cnt in sorted(expl_pairs.items()):
        if cnt >= expl_count:
            findings.append({
                "check": "expl-cred-burst", "severity": "medium",
                "host": "", "user": u, "src": srv,
                "detail": f"{cnt} event 4648 (kredensial eksplisit) ke "
                          f"server sama (>= {expl_count})",
            })
    findings.extend(mismatches)
    findings.extend(svc_inter)

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["check"],
                                 f["host"], f["user"], f["src"]))

    if stats["eid_4624"] == 0:
        notes.append("tidak ada Event 4624 di log — cek pth/rdp/svc "
                     "tidak dapat disimpulkan dari telemetri ini")
    if inventory is None:
        notes.append("tanpa --inventory (hostname,ip): deteksi "
                     "relay-mismatch DILEWATI — butuh pemetaan IP->"
                     "hostname (DHCP/DNS/CMDB), tidak ditebak")
    if stats["eid_4625"]:
        notes.append(f"{stats['eid_4625']} event 4625 ada di log — "
                     "brute force/spray dilayani win_logon_triage "
                     "(#0452), di sini tidak diulang")
    return {
        "schema": SCHEMA, "stats": stats, "notes": notes,
        "inventory_size": len(inventory or {}),
        "findings": findings,
        "verdict": ("INDICATORS_FOUND" if findings
                    else "CLEAN_NO_LATERAL_LEAD"),
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase offline log Windows Security XML utk lateral "
                    "movement / NTLM abuse (LEAD).")
    ap.add_argument("--log", help="file XML Windows Security")
    ap.add_argument("--dir", help="direktori berisi file XML (alt --log)")
    ap.add_argument("--inventory", help="CSV hostname,ip utk deteksi "
                                        "relay-mismatch")
    ap.add_argument("--min-hosts", type=int, default=5,
                    help="min host tujuan unik utk pth-spray (default 5)")
    ap.add_argument("--rdp-hosts", type=int, default=3,
                    help="min host unik utk rdp-chain (default 3)")
    ap.add_argument("--svc-prefix", default="svc",
                    help="awalan akun service (default svc; cocok utk "
                         "svc-*/svc_*/svc.*)")
    ap.add_argument("--expl-count", type=int, default=20,
                    help="min 4648 per (user,server) (default 20)")
    ap.add_argument("--out", help="tulis JSON ke file (selain stdout)")
    args = ap.parse_args(argv)

    files: list[Path] = []
    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"[win-auth-triage] input error: bukan direktori: {d}",
                  file=sys.stderr)
            return 2
        files = sorted(d.glob("*.xml")) + sorted(d.glob("*.evtx.xml"))
        if not files:
            print("[win-auth-triage] input error: nol file XML di "
                  f"direktori: {d}", file=sys.stderr)
            return 2
    elif args.log:
        files = [Path(args.log)]
    else:
        print("[win-auth-triage] input error: --log atau --dir wajib",
              file=sys.stderr)
        return 2

    inventory = None
    if args.inventory:
        try:
            inventory = _load_inventory(Path(args.inventory))
        except ValueError as exc:
            print(f"[win-auth-triage] input error: inventory {exc}",
                  file=sys.stderr)
            return 2

    events: list[dict] = []
    total_events = 0
    try:
        for f in files:
            if f.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"{f} melebihi {MAX_FILE_BYTES} byte")
            parsed, total = parse_events(
                f.read_text(encoding="utf-8", errors="replace"), f.name)
            events.extend(parsed)
            total_events += total
        if not events:
            raise ValueError(
                f"nol event relevan ({', '.join(map(str, sorted(RELEVANT_EIDS)))}) "
                "ter-parse — pastikan ini ekspor XML Windows Security")
    except ValueError as exc:
        print(f"[win-auth-triage] input error: {exc}", file=sys.stderr)
        return 2

    result = triage(
        events, min_hosts=args.min_hosts, rdp_hosts=args.rdp_hosts,
        svc_prefix=args.svc_prefix, expl_count=args.expl_count,
        inventory=inventory)
    result["stats"]["files"] = len(files)
    result["stats"]["events_total"] = total_events
    result["stats"]["relevant_events"] = len(events)
    rendered = json.dumps(result, ensure_ascii=False, indent=2,
                          sort_keys=True)
    print(rendered)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
