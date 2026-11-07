r"""[SAFETY: read-only] sysmon_triage — triase OFFLINE log Sysmon Windows
(XML) untuk indikasi credential dumping (T1003), process injection
(T1055), abuse elevation/UAC bypass (T1548.002), dan WMI persistence
(T1546.003). TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0466 + #0467 + #0468 +
#0471 (mukul975/Anthropic-Cybersecurity-Skills 'detecting-t1003-
credential-dumping-with-edr', 'detecting-t1055-process-injection-with-
sysmon', 'detecting-t1548-abuse-elevation-control-mechanism',
'detecting-wmi-persistence'; atribusi konsep, lisensi sumber
Apache-2.0). Dibangun FROM SCRATCH: parser XML + taksonomi deteksi
ditulis sendiri dari konsep deteksi publik (access mask Windows,
event ID Sysmon, token cmdline alat dump). Skill sumber menyaring
telemetri via SIEM live (Splunk/KQL/Sigma); cyphron memilih artefak
offline (ekspor XML Sysmon) supaya nol jaringan dan dapat dites.

Input -> mekanisme -> output:
  - Input : file XML ekspor Sysmon (Event Viewer "Export XML" atau
            `wevtutil /x`), satu file berisi banyak elemen <Event>,
            atau --dir berisi beberapa file.
  - Mekanisme: parser event -> cek deterministik per event + korelasi
            consumer-binding WMI dalam file.
  - Output: temuan {check, severity, eid, host?, message} + stats +
            notes telemetri (EID yang tidak ada di log dicatat —
            kegelapan deteksi tidak pernah dilaporkan "bersih").

Cek (verdict = LEAD "teramati di log"; konteks proses sah bisa
menghasilkan temuan — pakai --allow-source utk daftar proses sah
milik lab):
  lsass-access          (high)   : EID 10 TargetImage lsass.exe dgn
                                   GrantedAccess mencurigakan
                                   (0x0040 read, 0x1010/0x1410 query+read
                                   VM, 0x143A/0x1F0FFF/0x1F3FFF/0x1FFFFF
                                   hampir semua) — proses biasa TIDAK
                                   membaca lsasse (T1003.001).
  cross-process-write   (high)   : EID 10GrantedAccess memuat
                                   VM_WRITE(0x0020)+VM_OPERATION(0x0008)
                                   atau CREATE_THREAD(0x0002) ke proses
                                   bernilai tinggi (T1055).
  remote-thread         (high)   : EID 8 CreateRemoteThread lintas
                                   proses ke proses bernilai tinggi,
                                   sumber bukan proses sistem (T1055.001).
  process-tampering     (high)   : EID 25 image proses diganti saat
                                   runtime — hollowing (T1055.012).
  dll-unusual-path      (medium) : EID 7 DLL dimuat dari Temp/Downloads/
                                   Public/ProgramData ke proses sistem.
  dump-cmdline          (high)   : EID 1 cmdline pola dump: rundll32
                                   comsvcs.dll MiniDump, procdump -ma,
                                   reg save hklm\sam/security/system,
                                   ntdsutil ifm, vssadmin create/delete
                                   shadow, token mimikatz (sekurlsa::/
                                   lsadump::/kerberos::) (T1003).
  wmi-consumer          (high)   : EID 20 consumer CommandLineEvent-
                                   Consumer/ActiveScriptEventConsumer
                                   (eksekusi kode saat trigger)
                                   (T1546.003).
  wmi-binding           (medium) : EID 21 FilterToConsumerBinding;
                                   naik high bila consumer-nya sudah
                                   ditandai suspicious di file sama.
  wmi-filter-timer      (medium) : EID 19 WQL trigger timer (WITHIN)
                                   /proses-start — persistence mekanisme.
  uac-registry-hijack   (high)   : EID 12/13 menulis
                                   HKCU\Software\Classes\{ms-settings,
                                   mscfile,exefile}\shell\open\command
                                   (hijack auto-elevate) (T1548.002).
  auto-elevate-parent   (high)   : EID 1 auto-elevate binary (fodhelper,
                                   computerdefaults, eventvwr, sdclt,
                                   slui, cmstp) dari parent non-standar
                                   (T1548.002).

Fail-closed:
  - XML tidak valid / nol event Sysmon ter-parse -> exit 2.
  - EID wajib yang absen dari log dicatat di notes (coverage tidak
    disimpulkan dari kegelapan).
  - GrantedAccess tidak dikenal -> dibandingkan bit, bukan daftar
    hardcoded saja; nilai tidak ter-parse tidak pernah "lolos bersih".

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/sysmon_triage.py --log sysmon.xml
  python tools/sysmon_triage.py --dir exports/ --fail-on medium
  python tools/sysmon_triage.py --log sysmon.xml --allow-source myedr.exe
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "cyphron.sysmon-triage/1"
MAX_FILE_BYTES = 256 * 1024 * 1024

WATCHED_EIDS = frozenset({1, 7, 8, 10, 12, 13, 19, 20, 21, 25})

# Access mask Windows (bit tunggal) + kombinasi umum yg ditemui di log.
LSASS_SUSPECT_ACCESS = frozenset({
    "0x0040", "0x1010", "0x1410", "0x143a", "0x1f0fff",
    "0x1f3fff", "0x1fffff",
})
VM_WRITE = 0x0020
VM_OPERATION = 0x0008
CREATE_THREAD = 0x0002

HIGH_VALUE_PROCS = frozenset({
    "svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe",
    "csrss.exe", "services.exe", "smss.exe", "wininit.exe",
})
# Proses yang WAJAR membaca lsasse/operasi lintas proses di lab
# (sensor EDR/AV/task manager) — default filter FP dari konsep sumber.
DEFAULT_ALLOW_SOURCE = frozenset({
    "csrss.exe", "lsass.exe", "svchost.exe", "msmpeng.exe",
    "wmiprvse.exe", "taskmgr.exe", "procexp.exe", "procexp64.exe",
    "procmon.exe", "securityhealthservice.exe", "vmtoolsd.exe",
    "services.exe", "sms.exe",
})
SYSTEM_THREAD_SOURCES = frozenset({
    "csrss.exe", "lsass.exe", "services.exe", "svchost.exe",
    "msmpeng.exe", "securityhealthservice.exe", "vmtoolsd.exe",
})
AUTO_ELEVATE_BINARIES = frozenset({
    "fodhelper.exe", "computerdefaults.exe", "eventvwr.exe",
    "sdclt.exe", "slui.exe", "cmstp.exe",
})
AUTO_ELEVATE_ALLOWED_PARENTS = frozenset({
    "explorer.exe", "svchost.exe", "services.exe",
})
UAC_HIJACK_KEYS = (
    r"\software\classes\ms-settings\shell\open\command",
    r"\software\classes\mscfile\shell\open\command",
    r"\software\classes\exefile\shell\open\command",
)
UNUSUAL_DLL_DIRS = (
    "\\appdata\\", "\\temp\\", "\\downloads\\", "\\public\\",
    "\\programdata\\",
)
DUMP_TOKENS = (
    ("rundll32", "comsvcs.dll", "minidump"),
    ("procdump", "-ma"),
    ("procdump", "-mm"),
    ("reg", "save", "hklm\\sam"),
    ("reg", "save", "hklm\\security"),
    ("reg", "save", "hklm\\system"),
    ("ntdsutil", "ifm"),
    ("vssadmin", "create", "shadow"),
    ("vssadmin", "delete", "shadows"),
)
MIMIKATZ_TOKENS = ("sekurlsa::", "lsadump::", "kerberos::")
WMI_EXEC_CONSUMERS = ("commandlineeventconsumer",
                      "activescripteventconsumer")

_EVENTDATA_PICK = (
    "UtcTime", "SourceImage", "SourceProcessId", "TargetImage",
    "TargetProcessId", "GrantedAccess", "CallTrace", "Image",
    "ImageLoaded", "CommandLine", "ParentImage", "ParentCommandLine",
    "TargetObject", "Details", "Query", "Name", "Type", "Consumer",
    "Filter", "EventType", "NewThreadId", "StartFunction",
    "ScriptBlockText",
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_time(val: str) -> datetime | None:
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _basename(path: str) -> str:
    """Ambil nama file dari path Windows, lowercase."""
    if not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def parse_events(xml_text: str, src: str) -> list[dict]:
    """Parse XML ekspor Sysmon -> daftar event yang diawasi (stabil)."""
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
                sys_time = _parse_time(child.get("SystemTime", ""))
            elif loc == "Computer" and child.text:
                computer = child.text.strip()
            elif loc == "Data" and child.get("Name"):
                name = child.get("Name")
                if name in _EVENTDATA_PICK:
                    data[name] = (child.text or "").strip()
        if eid not in WATCHED_EIDS:
            continue
        events.append({
            "eid": eid, "data": data, "time": sys_time,
            "computer": computer, "src": src,
        })
    if not events:
        raise ValueError(
            f"{src}: nol event Sysmon ter-parse "
            f"(EID diawasi: {sorted(WATCHED_EIDS)})")
    events.sort(key=lambda e: (e["time"] is None,
                               e["time"] or datetime.min.replace(
                                   tzinfo=timezone.utc)))
    return events


def _is_allowed_source(image: str, allow: frozenset[str]) -> bool:
    return _basename(image) in allow


def _ends_with_high_value(image: str) -> bool:
    return _basename(image) in HIGH_VALUE_PROCS


def _hex_access(raw: str) -> int | None:
    """GrantedAccess '0x1010' -> 4112; None bila bukan angka hex."""
    try:
        return int(raw, 16) if raw else None
    except ValueError:
        return None


def _sysmon_time(data: dict) -> datetime | None:
    return _parse_time(data.get("UtcTime", ""))


def triage(events: list[dict],
           allow: frozenset[str] | None = None) -> tuple[list[dict],
                                                         dict,
                                                         list[str]]:
    """Semua event -> (temuan, stats, notes). Deterministik terurut."""
    allow = frozenset(allow or ()) | DEFAULT_ALLOW_SOURCE
    findings: list[dict] = []
    seen_eids = {e["eid"] for e in events}
    suspicious_consumers: set[str] = set()

    def add(check: str, severity: str, eid: int, msg: str,
            **extra: object) -> None:
        f = {"check": check, "severity": severity, "eid": eid,
             "message": msg}
        f.update(extra)
        findings.append(f)

    for ev in events:
        eid = ev["eid"]
        d = ev["data"]
        ts = (_sysmon_time(d) or ev["time"])
        ts_s = ts.isoformat() if ts else ""
        host = ev["computer"]

        if eid == 10:
            target = d.get("TargetImage", "")
            source = d.get("SourceImage", "")
            granted = d.get("GrantedAccess", "").lower()
            acc = _hex_access(d.get("GrantedAccess", ""))
            base = {"target": target, "source": source,
                    "granted_access": granted, "host": host, "ts": ts_s}
            if _basename(target) == "lsass.exe" \
                    and not _is_allowed_source(source, allow):
                if granted in LSASS_SUSPECT_ACCESS or acc is None:
                    add("lsass-access", "high", 10,
                        "akses ke lsass.exe dgn GrantedAccess "
                        f"mencurigakan ({granted or 'tak-ter-parse'})",
                        **base)
                elif acc & (VM_WRITE | VM_OPERATION):
                    add("cross-process-write", "high", 10,
                        "akses lintas-proses tulis memori ke lsass.exe",
                        **base)
            else:
                if acc is not None and (acc & (VM_WRITE | VM_OPERATION)) \
                        and acc != VM_OPERATION \
                        and _ends_with_high_value(target) \
                        and source and not _is_allowed_source(source, allow) \
                        and _basename(source) != _basename(target):
                    add("cross-process-write", "high", 10,
                        "akses lintas-proses tulis memori (VM_WRITE+"
                        "VM_OPERATION) ke proses bernilai tinggi",
                        **base)

        elif eid == 8:
            target = d.get("TargetImage", "")
            source = d.get("SourceImage", "")
            if target and source \
                    and _basename(source) != _basename(target) \
                    and _ends_with_high_value(target) \
                    and _basename(source) not in SYSTEM_THREAD_SOURCES:
                add("remote-thread", "high", 8,
                    "CreateRemoteThread lintas proses ke proses "
                    "bernilai tinggi",
                    source=source, target=target, host=host, ts=ts_s)

        elif eid == 25:
            add("process-tampering", "high", 25,
                "image proses diganti saat runtime (ProcessTampering) "
                "— indikasi process hollowing",
                image=d.get("Image", ""), host=host, ts=ts_s)

        elif eid == 7:
            image = d.get("Image", "")
            loaded = d.get("ImageLoaded", "")
            low = loaded.lower()
            if low and any(m in low for m in UNUSUAL_DLL_DIRS) \
                    and _ends_with_high_value(image):
                add("dll-unusual-path", "medium", 7,
                    "DLL dari direktori tak lazim dimuat proses sistem",
                    image=image, loaded=loaded, host=host, ts=ts_s)

        elif eid == 1:
            cmdline = d.get("CommandLine", "").lower()
            image = d.get("Image", "")
            parent = d.get("ParentImage", "")
            hit = next((toks for toks in DUMP_TOKENS
                        if all(t in cmdline for t in toks)), None)
            if hit is None \
                    and any(t in cmdline for t in MIMIKATZ_TOKENS):
                hit = ("mimikatz",)
            if hit:
                add("dump-cmdline", "high", 1,
                    "pola cmdline dump kredensial ("
                    + " ".join(hit) + ")",
                    image=image, command_line=d.get("CommandLine", ""),
                    host=host, ts=ts_s)
            elif _basename(image) in AUTO_ELEVATE_BINARIES \
                    and _basename(parent) not in AUTO_ELEVATE_ALLOWED_PARENTS \
                    and parent:
                add("auto-elevate-parent", "high", 1,
                    "binary auto-elevate dijalankan dari parent "
                    "non-standar — indikasi UAC bypass",
                    image=image, parent_image=parent,
                    command_line=d.get("CommandLine", ""),
                    host=host, ts=ts_s)

        elif eid in (12, 13):
            target_obj = d.get("TargetObject", "").lower()
            if any(k in target_obj for k in UAC_HIJACK_KEYS):
                add("uac-registry-hijack", "high", eid,
                    "penulisan key hijack auto-elevate (shell\\open\\"
                    "command) — indikasi UAC bypass (T1548.002)",
                    target_object=d.get("TargetObject", ""),
                    details=d.get("Details", ""), image=d.get("Image", ""),
                    host=host, ts=ts_s)

        elif eid == 19:
            query = d.get("Query", "")
            qlow = query.lower()
            if "within" in qlow or "win32_processstarttrace" in qlow \
                    or "__instancemodificationevent" in qlow:
                add("wmi-filter-timer", "medium", 19,
                    "WMI event filter trigger timer/proses-start "
                    "(mekanisme persistence)",
                    query=query, name=d.get("Name", ""), host=host,
                    ts=ts_s)

        elif eid == 20:
            ctype = d.get("Type", "").lower() or _basename(
                d.get("Name", ""))
            name = d.get("Name", "")
            low_fields = " ".join([
                d.get("Name", ""), d.get("Type", ""),
                d.get("CommandLine", ""), d.get("TargetObject", ""),
            ]).lower()
            # normalkan spasi/tanda baca: "Command Line Event Consumer"
            # dan "CommandLineEventConsumer" sama-sama cocok.
            compact = re.sub(r"[^a-z0-9]", "", low_fields)
            if any(c in compact for c in WMI_EXEC_CONSUMERS):
                suspicious_consumers.add(name or low_fields[:60])
                add("wmi-consumer", "high", 20,
                    "WMI event consumer eksekusi kode "
                    "(CommandLine/ActiveScript) — persistence T1546.003",
                    name=name, type_=d.get("Type", ""), host=host,
                    ts=ts_s)

        elif eid == 21:
            consumer = d.get("Consumer", "")
            sev = "high" if consumer in suspicious_consumers else "medium"
            add("wmi-binding", sev, 21,
                "FilterToConsumerBinding WMI aktif (konfirmasi consumer "
                "di EID 20 bila tersedia)",
                consumer=consumer, filter_=d.get("Filter", ""),
                host=host, ts=ts_s)

    stats = {
        "events_total": len(events),
        "watched_eids_present": sorted(seen_eids),
        "events_by_eid": {str(e): sum(1 for x in events if x["eid"] == e)
                          for e in sorted(seen_eids)},
    }
    notes: list[str] = []
    for eid, why in ((1, "dump-cmdline & auto-elevate-parent"),
                     (10, "lsass-access & cross-process-write"),
                     (19, "wmi-filter-timer"),
                     (20, "wmi-consumer"),
                     (21, "wmi-binding")):
        if eid not in seen_eids:
            notes.append(f"EID {eid} tidak ada di log — deteksi {why} "
                         "tidak dapat dinilai dari telemetri ini")
    findings.sort(key=lambda f: (f["check"], f.get("ts", ""),
                                 f.get("source", ""),
                                 f.get("image", ""),
                                 f.get("target_object", "")))
    return findings, stats, notes


def _iter_files(args: argparse.Namespace) -> list[Path]:
    if args.log:
        return [Path(args.log)]
    if args.dir:
        files = sorted(
            p for p in Path(args.dir).iterdir()
            if p.suffix.lower() in (".xml",) and p.is_file())
        if not files:
            raise FileNotFoundError(
                f"tidak ada file .xml di {args.dir}")
        return files
    raise FileNotFoundError("wajib --log atau --dir")


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase OFFLINE log Sysmon XML (T1003/T1055/"
                    "T1548.002/T1546.003) — nol jaringan, read-only")
    ap.add_argument("--log", help="file XML ekspor Sysmon")
    ap.add_argument("--dir", help="direktori berisi file .xml")
    ap.add_argument("--allow-source", action="append", default=[],
                    metavar="PROC.EXE",
                    help="proses sah tambahan (repeatable) utk "
                         "filter FP akses lintas proses")
    ap.add_argument("--fail-on", choices=["medium", "high"],
                    default="high")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)

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

    allow = frozenset(a.lower() for a in args.allow_source)
    findings, stats, notes = triage(events, allow)
    order = {"high": 0, "medium": 1, "low": 2}
    result = {
        "schema": SCHEMA,
        "findings": findings,
        "stats": stats,
        "notes": notes,
        "meta": {
            "allow_source": sorted(allow),
            "fail_on": args.fail_on,
        },
    }
    out = json.dumps(result, ensure_ascii=False, sort_keys=True,
                     indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    # severity "penting": high=0 <= medium=1 <= low=2. hit bila ada
    # temuan sekurang-kurangnya seberapa penting dgn --fail-on.
    hit = any(order[f["severity"]] <= order[args.fail_on]
              for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
