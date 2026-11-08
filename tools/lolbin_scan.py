"""[SAFETY: read-only] lolbin_scan — triase OFFLINE log Sysmon (XML)
Event ID 1 (Process Create) + 11 (File Create) untuk indikasi LOLBin
abuse, persistence scheduled task, dan anomali parent-child.

Mengisi antrean port SKILL-PORT-QUEUE #0428 #0429 #0431 (mukul975/
Anthropic-Cybersecurity-Skills 'detecting-living-off-the-land-attacks',
'detecting-living-off-the-land-with-lolbas', 'detecting-malicious-
scheduled-tasks-with-sysmon' — lisensi sumber Apache-2.0, atribusi
konsep — kode dibangun from scratch TANPA menyalin kode sumber). Skill
sumber memakai SIEM/EDR live + Sigma; secai memilih artefak offline:
file XML ekspor Sysmon, parser stdlib, nol jaringan.

Pembagian ranah dgn alat secai lain (anti-duplikasi):
  - EID 8/10/25 (injection/lsass/tampering), EID 7, dump-cmdline
    (comsvcs MiniDump/procdump/reg save/mimikatz), WMI 19/20/21,
    UAC-hijack EID 12/13 -> tools/sysmon_triage.py (#0466 #0467 #0468
    #0471, B16) — TIDAK diulang di sini.
  - Obfuskasi PowerShell mendalam -> tools/ps_obf_scan (B13); di sini
    hanya marker cmdline kasar (-enc / -w hidden).
  - LOLBin murni cmdline + task XML + parent-child = ranah tool ini.

Input -> mekanisme -> output:
  - Input : file XML Sysmon berisi banyak elemen <Event> (atau --dir),
            plus opsional --allow-parent (parent sah utk menekan FP
            office-spawn) dan --allow-path (prefij path biner sah utk
            menekan FP LOLBin di lingkungan dev).
  - Mekanisme: parse EID 1/11 -> indeks ProcessGuid -> (image, cmdline)
            -> cek deterministik cmdline + korelasi creator task XML.
  - Output: temuan {check, severity, host, proc, detail} + stats +
            notes (JSON deterministik). SEMUA temuan = LEAD — LOLBin
            adalah alat sah; deteksi menilai KONTEKS (argumen, parent,
            path), bukan keberadaan biner.

Cek:
  lolbin-cmdline  (high/medium): certutil -urlcache/-decode (T1105/
                    T1132), mshta http/UNC/javascript (T1218.005),
                    rundll32 javascript/url.dll (T1218.011), regsvr32
                    scrobj/http (T1218.010), bitsadmin /transfer
                    (T1197), msiexec /i http (T1218.007), wmic /node:
                    process call create (T1047), schtasks /create dgn
                    payload encoded/hidden/http atau /s remote
                    (T1053.005), msbuild csproj path mencurigakan
                    (T1127).
  ps-encoded      (high/medium): powershell -enc/-encodedcommand
                    (high); -w hidden (medium) (T1059.001).
  office-spawn    (high)  : parent Word/Excel/PowerPoint/Outlook/script
                    host -> child cmd/powershell/mshta/rundll32/
                    certutil/bitsadmin dst (T1566.001 -> T1059).
  task-xml-write  (medium/high): EID 11 menulis ke
                    \\Windows\\System32\\Tasks\\ — creator dicari dari
                    indeks EID 1; creator ber-pola payload = high.

Fail-closed: XML tidak valid / nol event relevan (EID 1/11) -> exit 2.
Allowlist mengurangi FP tapi jumlah yang disaring TERCATAT eksplisit di
notes — tidak pernah dihitung bersih diam-diam.

Exit: 0 selesai (temuan tetap exit 0); 2 input error.

Pemakaian:
  python tools/lolbin_scan.py --log sysmon-events.xml
  python tools/lolbin_scan.py --dir ev/ \\
      --allow-parent winword.exe taskmgr.exe \\
      --allow-path "C:\\Windows\\System32\\"
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.lolbin-scan/1"
MAX_FILE_BYTES = 64 * 1024 * 1024
RELEVANT_EIDS = frozenset({1, 11})

OFFICE_PARENTS = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "wscript.exe", "cscript.exe", "msaccess.exe",
})
RISKY_CHILDREN = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe",
    "cscript.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "regsvr32.exe", "msiexec.exe", "wmic.exe",
})
_TASKS_DIR = "\\windows\\system32\\tasks\\"

# (check, regex, severity, penjelasan) — pola cmdline deterministik,
# dites pada "image + cmdline" lowercased (urutan = prioritas match)
LOLBIN_PATTERNS: "list[tuple[str, str, str, str]]" = [
    ("certutil-download", r"certutil\.exe.*(-urlcache|-decode|-split)",
     "high", "certutil unduh/dekode (T1105/T1132)"),
    ("mshta-remote", r"mshta\.exe.*(https?:|\\\\|javascript:|vbscript:)",
     "high", "mshta menjalankan remote/script URL (T1218.005)"),
    ("rundll32-js", r"rundll32\.exe.*(javascript:|url\.dll)",
     "high", "rundll32 JavaScript proxy (T1218.011)"),
    ("regsvr32-remote", r"regsvr32\.exe.*(scrobj|https?:|\\\\)",
     "high", "regsvr32 script object remote (T1218.010)"),
    ("bitsadmin-transfer",
     r"bitsadmin(\.exe)?.*(/transfer|/create|/addfile)",
     "medium", "bitsadmin transfer (T1197)"),
    ("msiexec-remote", r"msiexec(\.exe)?.*/i.*https?:",
     "high", "msiexec install dari URL (T1218.007)"),
    ("wmic-remote-exec", r"wmic(\.exe)?.*/node:.*process call create",
     "high", "wmic remote exec (T1047 lateral)"),
    ("schtasks-payload",
     r"schtasks(\.exe)?.*/create.*(/tr\s+.*("
     r"-enc|-encodedcommand|-w hidden|-windowstyle hidden|https?:))",
     "high", "schtasks /create dgn payload encoded/hidden/http "
             "(T1053.005)"),
    ("schtasks-remote", r"schtasks(\.exe)?.*/create.*/s\s",
     "medium", "schtasks /create remote (T1053.005 + T1021)"),
    ("msbuild-suspicious",
     r"msbuild(\.exe)?.*(\.csproj|\.xml).*("
     r"\\temp\\|\\appdata\\|\\public\\|\\programdata\\|https?:)",
     "high", "msbuild project dari path mencurigakan (T1127)"),
]
PS_ENC_RE = r"powershell(\.exe)?\s+[^\r\n]*\s(-enc\s|-encodedcommand\s)"
PS_HIDDEN_RE = (r"powershell(\.exe)?\s+[^\r\n]*\s"
                r"(-w\s+hidden|-windowstyle\s+hidden)")
CREATOR_RISK_RE = r"(-enc|-encodedcommand|-w hidden|https?:|mshta|certutil)"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


def _check_allow(path: str, allow: "tuple[str, ...]") -> bool:
    p = path.lower()
    return any(a.lower() in p for a in allow if a)


def parse_events(xml_text: str, src: str) -> "tuple[list[dict], int]":
    """Parse XML Sysmon -> (events EID 1/11 terurut waktu, total Event)."""
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
        d = {k.lower(): v for k, v in data.items()}  # Sysmon GUID vs Guid
        events.append({
            "eid": eid, "time": time_s, "host": computer, "data": d,
            "image": d.get("image", ""),
            "cmdline": d.get("commandline", ""),
            "parent_image": d.get("parentimage", ""),
            "guid": d.get("processguid", ""),
            "target_file": d.get("targetfilename", ""),
        })
    events.sort(key=lambda e: e["time"])
    return events, total


def triage(events: "list[dict]", *, allow_parent: "tuple[str, ...]",
           allow_path: "tuple[str, ...]") -> dict:
    notes: list[str] = []
    stats = {f"eid_{e}": 0 for e in sorted(RELEVANT_EIDS)}
    findings: list[dict] = []
    filtered = {"lolbin": 0, "office-spawn": 0}

    # indeks ProcessGuid -> event EID 1 (utk korelasi creator EID 11)
    by_guid: dict[str, dict] = {}
    for ev in events:
        stats[f"eid_{ev['eid']}"] += 1
        if ev["eid"] == 1 and ev["guid"]:
            by_guid[ev["guid"]] = ev

    for ev in events:
        if ev["eid"] == 1:
            img, cmd = ev["image"], ev["cmdline"]
            blob = f"{img} {cmd}".lower()
            if not _check_allow(img, allow_path):
                for name, pat, sev, why in LOLBIN_PATTERNS:
                    if re.search(pat, blob, re.IGNORECASE):
                        findings.append({
                            "check": name, "severity": sev,
                            "host": ev["host"], "proc": _basename(img),
                            "detail": f"{why} — cmdline: {cmd[:140]}",
                        })
                        break  # satu pola per event (paling dulu cocok)
                if re.search(PS_ENC_RE, blob, re.IGNORECASE):
                    findings.append({
                        "check": "ps-encoded", "severity": "high",
                        "host": ev["host"], "proc": _basename(img),
                        "detail": "PowerShell -enc/-encodedcommand "
                                  "(T1059.001) — cmdline: "
                                  f"{cmd[:140]}",
                    })
                elif re.search(PS_HIDDEN_RE, blob, re.IGNORECASE):
                    findings.append({
                        "check": "ps-hidden", "severity": "medium",
                        "host": ev["host"], "proc": _basename(img),
                        "detail": f"PowerShell -w hidden — cmdline: "
                                  f"{cmd[:140]}",
                    })
            else:
                filtered["lolbin"] += 1
            parent = _basename(ev["parent_image"])
            child = _basename(img)
            if parent in OFFICE_PARENTS and child in RISKY_CHILDREN:
                if _check_allow(ev["parent_image"], allow_parent):
                    filtered["office-spawn"] += 1
                else:
                    findings.append({
                        "check": "office-spawn", "severity": "high",
                        "host": ev["host"], "proc": child,
                        "detail": f"{parent} mem-spawn {child} — pola "
                                  "macro/fileless (T1566.001->T1059) — "
                                  f"cmdline: {cmd[:120]}",
                    })
        elif ev["eid"] == 11:
            if _TASKS_DIR not in ev["target_file"].lower():
                continue
            creator = by_guid.get(ev["guid"], {})
            cr_cmd = creator["cmdline"] if creator else ""
            risky = bool(re.search(CREATOR_RISK_RE, cr_cmd,
                                   re.IGNORECASE)) if cr_cmd else False
            findings.append({
                "check": "task-xml-write",
                "severity": "high" if risky else "medium",
                "host": ev["host"], "proc": _basename(ev["image"]),
                "detail": "tulis task XML persistence (T1053.005): "
                          f"{ev['target_file'][:120]}"
                          + (f" — creator: {cr_cmd[:120]}" if cr_cmd
                             else " — creator tidak ada di log EID 1 "
                                  "ini"),
            })

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["check"],
                                 f["host"], f["proc"]))
    if stats["eid_1"] == 0:
        notes.append("tidak ada EID 1 (Process Create) — cek cmdline/"
                     "parent tidak berjalan dari telemetri ini")
    if stats["eid_11"] == 0:
        notes.append("tidak ada EID 11 (File Create) — cek task-xml-"
                     "write dilewati (bukan bukti tak ada persistence)")
    if any(filtered.values()):
        notes.append(f"{sum(filtered.values())} event disaring "
                     f"allowlist ({filtered['lolbin']} path biner sah, "
                     f"{filtered['office-spawn']} parent sah) — tercatat "
                     "eksplisit, bukan dihitung bersih diam-diam")
    return {
        "schema": SCHEMA, "stats": stats, "notes": notes,
        "findings": findings,
        "verdict": ("INDICATORS_FOUND" if findings
                    else "CLEAN_NO_LOLBIN_LEAD"),
    }


def _parse_pairs(vals: "list[str] | None") -> "tuple[str, ...]":
    """'winword.exe:x.exe' / ['a', 'b'] -> tuple item (pemisah ':')."""
    if not vals:
        return ()
    return tuple(v for v in ":".join(vals).split(":") if v)


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase offline log Sysmon XML: LOLBin, scheduled "
                    "task, parent-child anomaly (LEAD).")
    ap.add_argument("--log", help="file XML Sysmon")
    ap.add_argument("--dir", help="direktori berisi file XML (alt --log)")
    ap.add_argument("--allow-parent", nargs="*", metavar="IMG",
                    help="parent sah (pemisah spasi/':') utk menekan FP "
                         "office-spawn")
    ap.add_argument("--allow-path", nargs="*", metavar="PREFIX",
                    help="prefij path biner sah utk menekan FP LOLBin")
    ap.add_argument("--out", help="tulis JSON ke file (selain stdout)")
    args = ap.parse_args(argv)

    files: list[Path] = []
    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"[lolbin-scan] input error: bukan direktori: {d}",
                  file=sys.stderr)
            return 2
        files = sorted(d.glob("*.xml"))
        if not files:
            print(f"[lolbin-scan] input error: nol file XML di {d}",
                  file=sys.stderr)
            return 2
    elif args.log:
        files = [Path(args.log)]
    else:
        print("[lolbin-scan] input error: --log atau --dir wajib",
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
            raise ValueError("nol event Sysmon relevan (EID 1/11) "
                             "ter-parse — pastikan ini ekspor XML Sysmon")
    except ValueError as exc:
        print(f"[lolbin-scan] input error: {exc}", file=sys.stderr)
        return 2

    result = triage(events,
                    allow_parent=_parse_pairs(args.allow_parent),
                    allow_path=_parse_pairs(args.allow_path))
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
