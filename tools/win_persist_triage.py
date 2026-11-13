r"""[SAFETY: read-only] win_persist_triage — triase OFFLINE log Windows
(Sysmon XML EID 1/11/12/13 + Security XML 4697/4698/4699/4702) untuk
LOKASI PERSISTENSI klasik (TA0003): Run/RunOnce keys (T1547.001),
Winlogon helper (T1547.004), IFEO Debugger (T1546.012), AppInit_DLLs
(T1546.010), COM InprocServer32 (T1546.015), folder Startup (T1547.001),
scheduled task (T1053.005), service install (T1543.003). TANPA jaringan.

Pembagian ranah (TIDAK diduplikasi):
  - WMI subscription EID 19/20/21 -> sysmon_triage (B16, #0466-#0471)
  - schtasks /create di cmdline -> lolbin_scan (B15, #0428-#0431)
  - service 7045 (System log)   -> win_auth_triage (B15)
  - 4697 (Security log) diperiksa di sini karena berbagi file input
    dgn 4698; 7045 tetap ranah win_auth_triage.

Input -> mekanisme -> output:
  - Input : file XML ekspor Windows (Sysmon dan/atau Security),
            atau --dir berisi beberapa file.
  - Mekanisme: dispatch per event ID -> cek path/konten deterministik.
  - Output: temuan {check, severity, eid, host, path, message} + stats
            + notes (EID keluarga absen dicatat — kegelapan tidak
            dilaporkan "bersih").

Cek (verdict = LEAD; instalasi software sah kerap menulis Run key/
InprocServer32 — pakai --allow-key/--allow-path utk allowlist lab):
  run-key-write         (high/med): EID 13 SetValue di ...\Run(Once)\
                                   (+Policies\Explorer\Run); high bila
                                   Details mencurigakan (encoded PS,
                                   LOLBin, Temp/AppData/ProgramData/
                                   Public/Downloads, http/UNC);
                                   medium = penulisan teramati.
                                   EID 12 create-key di path sama =
                                   medium (T1547.001).
  winlogon-modify       (high)   : EID 12/13 TargetObject di
                                   ...\Winlogon (Shell/Userinit/
                                   Taskman/AppSetup) (T1547.004).
  ifeo-hijack           (high)   : EID 13 value Debugger/
                                   SilentProcessExit di
                                   Image File Execution Options
                                   (T1546.012).
  appinit-dll           (high)   : EID 13 penulisan AppInit_DLLs
                                   (T1546.010).
  com-hijack            (high/med): EID 13 InprocServer32; high bila
                                   konten mencurigakan (T1546.015).
  startup-folder-file   (high/med): EID 11 file di ...Start Menu\
                                   Programs\Startup\; high utk
                                   ekstensi eksekusi/script
                                   (.exe/.lnk/.bat/.cmd/.vbs/.js/
                                   .ps1/.hta/.scr/.pif/.wsf) (T1547.001).
  startup-folder-exec   (high)   : EID 1 proses yang Image/CommandLine-
                                   nya di folder Startup.
  task-action-suspicious(high)   : 4698/4702 TaskContent berisi
                                   interpreter/payload mencurigakan
                                   (powershell/cmd/wscript/cscript/
                                   mshta/rundll32/regsvr32/msbuild/
                                   certutil, -enc, Temp/AppData/
                                   Downloads, http/https/UNC)
                                   (T1053.005).
  task-outside-microsoft(medium) : 4698/4702 TaskName di luar
                                   \Microsoft\ — kandidat inventaris.
  task-trigger          (medium) : 4698 trigger logon/boot atau
                                   interval pendek (<= 5 menit).
  service-install-susp  (high)   : 4697 BinaryPathName mencurigakan
                                   (pola sama dgn task-action)
                                   (T1543.003); 4699/4700 dihitung
                                   stats saja.

Fail-closed:
  - XML tidak valid / nol event ter-parse -> exit 2.
  - Keluarga EID wajib absen dicatat di notes (coverage tidak
    disimpulkan dari kegelapan).
  - TaskContent gagal di-parse XML = konten RAW di-scan regex; hasil
    tidak ter-parse tidak pernah "lolos bersih".

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/win_persist_triage.py --log sysmon.xml
  python tools/win_persist_triage.py --dir exports/ --fail-on medium
  python tools/win_persist_triage.py --log ev.xml \
      --allow-key 'Adobe|OneDrive' --allow-path 'C:\\Program Files'
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.win-persist-triage/1"
MAX_FILE_BYTES = 256 * 1024 * 1024

WATCHED_EIDS = frozenset({1, 11, 12, 13, 4697, 4698, 4699, 4700, 4702})

EVENT_NS = ".//{http://schemas.microsoft.com/win/2004/windows/events/log}"

# path registry autostart (case-insensitive, substring)
RUN_KEY_RE = re.compile(
    r"(?:Software\\)?Microsoft\\Windows\\CurrentVersion\\"
    r"(?:Run|RunOnce)(?:OneTime)?\\"
    r"|Policies\\(?:Microsoft\\Windows\\)?Explorer\\Run(?:Once)?\\",
    re.I)
WINLOGON_RE = re.compile(r"Winlogon\\(?:Shell|Userinit|Taskman|AppSetup)$",
                         re.I)
IFEO_RE = re.compile(r"Image File Execution Options\\", re.I)
IFEO_VALUE_RE = re.compile(r"\\(?:Debugger|SilentProcessExit)$", re.I)
APPINIT_RE = re.compile(r"AppInit_DLLs$", re.I)
COM_INPROC_RE = re.compile(r"CLSID\\[^\\]+\\InprocServer32(?:\\|$)?",
                           re.I)
STARTUP_DIR_RE = re.compile(
    r"Start Menu\\Programs\\Startup(?:\\|$)", re.I)

SUSPICIOUS_VALUE_RE = re.compile(
    r"-enc\b|-encodedcommand|\b(?:mshta|rundll32|regsvr32|wscript|"
    r"cscript|bitsadmin|certutil|msbuild|powershell|cmd)\.exe\b"
    r"|cmd\.exe\s+/c|%temp%|%appdata%|\\\\[^\\]+\\"
    r"|https?://"
    r"|\\(?:Temp|AppData|ProgramData|Users\\Public|Downloads)\\",
    re.I)

STARTUP_BAD_EXT_RE = re.compile(
    r"\.(?:exe|dll|lnk|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|hta|scr|"
    r"pif)$", re.I)

TASK_SUSPICIOUS_RE = re.compile(
    r"-enc\b|-encodedcommand|\b(?:powershell|cmd|wscript|cscript|mshta|"
    r"rundll32|regsvr32|msbuild|certutil)\b"
    r"|\\(?:Temp|AppData|Users\\Public|Downloads|Windows\\Tasks)\\"
    r"|https?://|\\\\[^\\]+\\",
    re.I)

TASK_NAME_RE = re.compile(r"<Task[^>]*>.*?</Task>", re.S)
TASK_CMD_RE = re.compile(
    r"<(?:Command|Arguments)>(.*?)</(?:Command|Arguments)>", re.S)
TASK_TRIGGER_RE = re.compile(
    r"<(?:LogonTrigger|BootTrigger)\b|<Interval>PT(?:(\d+)H)?"
    r"(?:(\d+)M)?(?:S(\d+)S)?</Interval>", re.I)

SVC_PATH_RE = re.compile(
    r"-enc\b|-encodedcommand|\b(?:powershell|cmd)\.exe\b"
    r"|\\(?:Temp|AppData|ProgramData|Users\\Public|Downloads)\\"
    r"|https?://|\\\\[^\\]+\\|%temp%|%appdata%",
    re.I)


def parse_event_file(path: Path) -> tuple[list[dict], int]:
    """Parse satu file XML Windows -> (event tervalidasi, total <Event>).
    Event tanpa EventID/di luar WATCHED_EIDS dilewati (dihitung)."""
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


def _f(check: str, severity: str, eid: int, host: str, time: str,
       path: str, message: str) -> dict:
    return {"check": check, "severity": severity, "eid": eid,
            "host": host, "time": time, "path": path, "message": message}


def _allowed(text: str, allow: frozenset[str]) -> str | None:
    for a in allow:
        if a.lower() in text.lower():
            return a
    return None


def _check_registry(ev: dict, allow_keys: frozenset[str],
                    out: list[dict]) -> None:
    d = ev["data"]
    target = d.get("TargetObject", "")
    details = d.get("Details", "")
    if not target:
        return
    allowed = _allowed(target + " " + details, allow_keys)
    if allowed:
        return
    base = dict(host=ev["host"], time=ev["time"], path=target)
    if APPINIT_RE.search(target):
        out.append(_f("appinit-dll", "high", ev["eid"], **base,
                      message=f"Penulisan AppInit_DLLs: {target} = "
                              f"{details or '(kosong)'} (T1546.010)"))
        return
    if WINLOGON_RE.search(target):
        out.append(_f("winlogon-modify", "high", ev["eid"], **base,
                      message=f"Modifikasi nilai Winlogon: {target} = "
                              f"{details or '(kosong)'} (T1547.004)"))
        return
    if IFEO_RE.search(target) and IFEO_VALUE_RE.search(target):
        out.append(_f("ifeo-hijack", "high", ev["eid"], **base,
                      message=f"Nilai Debugger/SilentProcessExit di IFEO: "
                              f"{target} = {details or '(kosong)'} "
                              "(T1546.012)"))
        return
    if RUN_KEY_RE.search(target):
        if ev["eid"] == 13:
            sus = bool(details) and bool(SUSPICIOUS_VALUE_RE.search(
                details))
            out.append(_f(
                "run-key-write", "high" if sus else "medium", ev["eid"],
                **base,
                message=f"Penulisan Run key: {target} = "
                        f"{details or '(kosong)'}"
                        + (" — konten mencurigakan (T1547.001)"
                           if sus else " (LEAD; instalasi sah biasa "
                                       "menulis Run key — verifikasi "
                                       "vendor/prosesnya)")))
        else:
            out.append(_f("run-key-write", "medium", ev["eid"], **base,
                          message=f"Key dibuat di bawah Run: {target} "
                                  "(T1547.001)"))
        return
    if COM_INPROC_RE.search(target):
        sus = bool(details) and bool(SUSPICIOUS_VALUE_RE.search(details))
        out.append(_f(
            "com-hijack", "high" if sus else "medium", ev["eid"], **base,
            message=f"Penulisan COM InprocServer32: {target} = "
                    f"{details or '(kosong)'}"
                    + (" — konten mencurigakan (T1546.015)" if sus
                       else " (LEAD; installer sah kerap menulis — "
                            "verifikasi)")))


def _check_file(ev: dict, allow_paths: frozenset[str],
                out: list[dict]) -> None:
    d = ev["data"]
    target = d.get("TargetFilename", "")
    if not target:
        return
    allowed = _allowed(target, allow_paths)
    if allowed:
        return
    if STARTUP_DIR_RE.search(target):
        bad = bool(STARTUP_BAD_EXT_RE.search(target))
        out.append(_f(
            "startup-folder-file", "high" if bad else "medium",
            ev["eid"], host=ev["host"], time=ev["time"], path=target,
            message=f"File di folder Startup: {target}"
                    + (" — ekstensi eksekusi/script (T1547.001)" if bad
                       else " (LEAD)")))


def _check_process(ev: dict, allow_paths: frozenset[str],
                   out: list[dict]) -> None:
    d = ev["data"]
    image = d.get("Image", "")
    cmdline = d.get("CommandLine", "")
    text = image + " " + cmdline
    if not text.strip():
        return
    allowed = _allowed(text, allow_paths)
    if allowed:
        return
    if STARTUP_DIR_RE.search(image):
        out.append(_f(
            "startup-folder-exec", "high", ev["eid"], host=ev["host"],
            time=ev["time"], path=image,
            message=f"Proses dieksekusi dari folder Startup: {image} "
                    f"cmdline={cmdline} (T1547.001)"))


def _task_parts(content: str) -> tuple[list[str], bool, bool, bool]:
    """Ekstrak (perintah, ada_trigger_logon/boot, interval_pendek,
    ter-parse) dari isi TaskContent XML."""
    cmds: list[str] = []
    for m in TASK_CMD_RE.finditer(content or ""):
        cmds.append(re.sub(r"\s+", " ", m.group(1)).strip())
    logon_boot = bool(re.search(
        r"<(?:LogonTrigger|BootTrigger)\b", content or "", re.I))
    short = False
    for m in re.finditer(r"<Interval>PT(?:(\d+)H)?(?:(\d+)M)?(?:"
                         r"(\d+)S)?</Interval>", content or "", re.I):
        h = int(m.group(1) or 0)
        mi = int(m.group(2) or 0)
        s = int(m.group(3) or 0)
        if 0 < (h * 3600 + mi * 60 + s) <= 300:
            short = True
    parsed = bool(cmds) or logon_boot or short or \
        bool(TASK_NAME_RE.search(content or ""))
    return cmds, logon_boot, short, parsed


def _check_task(ev: dict, allow_paths: frozenset[str],
                out: list[dict]) -> None:
    d = ev["data"]
    task_name = d.get("TaskName", "")
    content = d.get("TaskContent", "")
    subject = d.get("SubjectUserName", "")
    base = dict(host=ev["host"], time=ev["time"],
                path=task_name or "(tanpa nama)")
    allowed = _allowed(task_name + " " + content, allow_paths)
    if allowed:
        return
    cmds, logon_boot, short, parsed = _task_parts(content)
    scan_text = " ".join(cmds) if parsed else content
    if ev["eid"] in (4698, 4702):
        if scan_text and TASK_SUSPICIOUS_RE.search(scan_text):
            out.append(_f(
                "task-action-suspicious", "high", ev["eid"], **base,
                message=f"Scheduled task {ev['eid']}: {task_name} oleh "
                        f"{subject} menjalankan konten mencurigakan: "
                        f"{scan_text[:200]} (T1053.005)"))
        if task_name and not task_name.upper().startswith("\\MICROSOFT"):
            out.append(_f(
                "task-outside-microsoft", "medium", ev["eid"], **base,
                message=f"Task di luar \\Microsoft\\: {task_name} "
                        f"({'dibuat' if ev['eid'] == 4698 else 'diubah'} "
                        f"oleh {subject}) — kandidat inventaris "
                        "persistence"))
        if logon_boot or short:
            trig = []
            if logon_boot:
                trig.append("logon/boot")
            if short:
                trig.append("interval <= 5 menit")
            out.append(_f(
                "task-trigger", "medium", ev["eid"], **base,
                message=f"Trigger menarik pada task {task_name}: "
                        f"{', '.join(trig)}"))


def _check_service(ev: dict, allow_paths: frozenset[str],
                   out: list[dict]) -> None:
    d = ev["data"]
    svc = d.get("ServiceName", "")
    path = d.get("ImagePath", "") or d.get("BinaryPathName", "")
    subject = d.get("SubjectUserName", "")
    if ev["eid"] == 4699:
        return  # delete service: stats saja
    if not path:
        return
    if _allowed(path + " " + svc, allow_paths):
        return
    if SVC_PATH_RE.search(path):
        out.append(_f(
            "service-install-suspicious", "high", ev["eid"],
            host=ev["host"], time=ev["time"], path=path,
            message=f"Service '{svc}' oleh {subject} dgn path "
                    f"mencurigakan: {path} (T1543.003)"))


def analyze(events: list[dict], allow_keys: frozenset[str],
            allow_paths: frozenset[str]) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    notes: list[str] = []
    eids = {e["eid"] for e in events}
    families = {
        "EID 12/13 (registry Sysmon)": {12, 13},
        "EID 11 (file create Sysmon)": {11},
        "EID 1 (process Sysmon)": {1},
        "EID 4697/4698/4699/4700/4702 (Security)": {
            4697, 4698, 4699, 4700, 4702},
    }
    for label, fam in families.items():
        if not (eids & fam):
            notes.append(f"{label} tidak ada di log — sumber itu "
                         "kemungkinan tidak menyala; ketiadaan temuan "
                         "dari sumber tsb bukan bukti bersih "
                         "(fail-closed).")
    for ev in events:
        out: list[dict] = []
        if ev["eid"] in (12, 13):
            _check_registry(ev, allow_keys, out)
        elif ev["eid"] == 11:
            _check_file(ev, allow_paths, out)
        elif ev["eid"] == 1:
            _check_process(ev, allow_paths, out)
        elif ev["eid"] in (4698, 4702):
            _check_task(ev, allow_paths, out)
        elif ev["eid"] in (4697, 4699):
            _check_service(ev, allow_paths, out)
        findings.extend(out)
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
        description="Triase OFFLINE lokasi persistensi Windows (Run "
                    "keys/Winlogon/IFEO/AppInit/COM/Startup/task/"
                    "service) — read-only, nol jaringan.")
    ap.add_argument("--log", type=Path, help="file XML Windows")
    ap.add_argument("--dir", type=Path, help="direktori berisi XML")
    ap.add_argument("--out", type=Path, help="simpan laporan JSON")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"],
                    default="high")
    ap.add_argument("--allow-key", default="",
                    help="CSV substring registry path sah (anti-FP)")
    ap.add_argument("--allow-path", default="",
                    help="CSV substring path/proses sah (anti-FP)")
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
        print("error: tidak ada event Windows ter-parse (XML kosong/"
              "bukan ekspor Event Viewer?)", file=sys.stderr)
        return 2

    allow_keys = frozenset(
        a.strip() for a in args.allow_key.split(",") if a.strip())
    allow_paths = frozenset(
        a.strip() for a in args.allow_path.split(",") if a.strip())
    findings, notes = analyze(events, allow_keys, allow_paths)
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
