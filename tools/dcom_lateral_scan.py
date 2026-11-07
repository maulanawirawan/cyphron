r"""[SAFETY: read-only] dcom_lateral_scan — triase OFFLINE log Sysmon
(XML, EID 1 ProcessCreate + EID 3 NetworkConnect) utk indikasi lateral
movement via DCOM (T1021.003): instansiasi remote MMC20.Application /
ShellBrowserWindow / ShellWindows yang mengeksekusi proses tanpa
menjatuhkan file. TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0540 (mukul975/Anthropic-
Cybersecurity-Skills 'hunting-for-dcom-lateral-movement'; atribusi
konsep, lisensi sumber Apache-2.0). Dibangun FROM SCRATCH: rantai
parent-child + korelasi jaringan ditulis sendiri dari pola artefak
DCOM publik (CLSID MMC20/ShellBrowserWindow/ShellWindows, port 135 +
RPC dinamis). Ranah dibagi eksplisit: sysmon_triage = EID 8/10/25/7 +
dump-cmdline + WMI/UAC; lolbin_scan = EID 1 pola LOLBin/persistence;
tool ini = rantai DCOM EID 1/3 (parent COM-server + child shell +
koneksi RPC).

Input -> mekanisme -> output:
  - Input : file XML ekspor Sysmon (Event Viewer "Export XML" atau
            wevtutil /x), atau --dir beberapa file.
  - Mekanisme: parse event -> cek per event + korelasi per host
            (proses DCOM teramati + koneksi RPC-nya di file sama
            = rantai, bukan dua sinyal lepas).
  - Output: temuan {check, severity, eid, host?, message} + stats +
            notes telemetri (EID absen dicatat; tanpa telemetri EID 1
            'tidak ada temuan' TIDAK berarti bersih).

Cek:
  dcom-mmc-child      (high)  : EID 1 mmc.exe beranak dari svchost
                                (DcomLaunch) — instansiasi remote
                                MMC20.Application.
  dcom-dllhost-child  (high)  : EID 1 cmd/powershell beranak dari
                                dllhost.exe — eksekusi via COM surrogate.
  dcom-explorer-shell (medium) : EID 1 cmd/powershell beranak dari
                                explorer.exe (ShellWindows/
                                ShellBrowserWindow) — WAJAR juga bila
                                user membuka terminal; filter dgn
                                --allow-explorer-child.
  dcom-rpc-egress     (medium) : EID 3 dari mmc.exe/dllhost.exe ke
                                port 135 / RPC dinamis (>49151).
  dcom-lateral-chain  (high)  : korelasi dlm file: proses DCOM
                                beranak di host X DAN koneksi RPC
                                dari proses sama di host X — dua
                                sinyal berangkai (confidence naik).

Fail-closed:
  - XML tidak valid / nol event Sysmon ter-parse -> exit 2.
  - EID 1/3 absen dari bukti dicatat di notes (coverage tidak
    disimpulkan dari kegelapan).
  - dcom-explorer-shell selalu menyertakan catatan "bisa sah" — medium
    bukan confirmed compromise.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/dcom_lateral_scan.py --log sysmon.xml
  python tools/dcom_lateral_scan.py --dir exports/ --fail-on medium
  python tools/dcom_lateral_scan.py --log s.xml \
      --allow-explorer-child cmd.exe
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "cyphron.dcom-lateral-scan/1"
MAX_FILE_BYTES = 256 * 1024 * 1024
WATCHED_EIDS = frozenset({1, 3})

SHELLS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe",
})
RPC_DYNAMIC_MIN = 49152


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def parse_events(path: Path) -> "list[dict]":
    """Parse XML ekspor Sysmon -> event EID 1/3 yang diawasi."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ValueError(f"XML tidak valid: {path}: {exc}") from exc
    root = tree.getroot()
    events: "list[dict]" = []
    for ev in root.iter():
        if _local(ev.tag) != "Event":
            continue
        eid = None
        computer = ""
        data: "dict[str, str]" = {}
        for child in ev.iter():
            tag = _local(child.tag)
            if tag == "System":
                for sub in child.iter():
                    stag = _local(sub.tag)
                    if stag == "EventID" and sub.text and \
                            sub.text.strip().isdigit():
                        eid = int(sub.text.strip())
                    elif stag == "Computer" and sub.text:
                        computer = sub.text
            elif tag == "EventData":
                for d in child.iter():
                    if _local(d.tag) == "Data":
                        data[d.get("Name") or ""] = (d.text or "")
        if eid is None or eid not in WATCHED_EIDS:
            continue
        events.append({"eid": eid, "computer": computer, "data": data})
    return events


def scan(events: "list[dict]",
         allow_explorer_child: "frozenset[str]") -> "tuple[list[dict], list[str]]":
    findings: "list[dict]" = []
    notes: "list[str]" = []

    n1 = sum(1 for e in events if e["eid"] == 1)
    n3 = sum(1 for e in events if e["eid"] == 3)

    com_proc_hosts: "dict[str, set[str]]" = {}   # host -> {mmc,dllhost}
    explorer_hits: "list[str]" = []

    for ev in events:
        d = ev["data"]
        host = ev["computer"] or "?"
        eid = ev["eid"]
        image = _basename(d.get("Image"))
        parent = _basename(d.get("ParentImage"))
        pcmd = (d.get("ParentCommandLine") or "")

        if eid == 1:
            if image == "mmc.exe" and parent == "svchost.exe" \
                    and "dcomlaunch" in pcmd.lower():
                findings.append({
                    "check": "dcom-mmc-child", "severity": "high",
                    "eid": 1, "host": host,
                    "message": (
                        "mmc.exe beranak dari svchost (DcomLaunch) — "
                        "instansiasi remote MMC20.Application "
                        "(T1021.003); verifikasi perintah shell-nya di "
                        "CommandLine."),
                })
            if parent == "dllhost.exe" and image in SHELLS:
                findings.append({
                    "check": "dcom-dllhost-child", "severity": "high",
                    "eid": 1, "host": host,
                    "message": (
                        f"{image} beranak dari dllhost.exe (COM "
                        "surrogate) — eksekusi via COM tanpa file "
                        "(T1021.003)."),
                })
            if parent == "explorer.exe" and image in SHELLS:
                if image not in allow_explorer_child:
                    explorer_hits.append(f"{host}: {image}")
            if image in ("mmc.exe", "dllhost.exe"):
                com_proc_hosts.setdefault(host, set()).add(image)

        if eid == 3:
            try:
                dport = int(d.get("DestinationPort") or "0")
            except ValueError:
                dport = 0
            if image in ("mmc.exe", "dllhost.exe") and (
                    dport == 135 or dport >= RPC_DYNAMIC_MIN):
                com_proc_hosts.setdefault(host, set()).add(image)
                findings.append({
                    "check": "dcom-rpc-egress", "severity": "medium",
                    "eid": 3, "host": host,
                    "message": (
                        f"{image} membuka koneksi ke port {dport} "
                        "(RPC endpoint mapper / RPC dinamis) — normal "
                        "untuk operasi COM sah; bandingkan dgn "
                        "baseline host."),
                })

    if explorer_hits:
        findings.append({
            "check": "dcom-explorer-shell", "severity": "medium",
            "eid": 1, "host": explorer_hits[0].split(":")[0],
            "message": (
                "Shell beranak dari explorer.exe (ShellWindows/"
                "ShellBrowserWindow; T1021.003 bila berasal dari "
                "remote activation) — BISA SAH (user membuka "
                "terminal); tinjau host: " + "; ".join(explorer_hits[:8])
                + " — allowlist proses sah lab via "
                "--allow-explorer-child."),
        })

    # Korelasi: host yang punya proses DCOM-anak DAN koneksi RPC-nya.
    # Proses-DCOM anak ditandai oleh temuan mmc/dllhost di atas;
    # sinyal koneksi ditandai dcom-rpc-egress. Chain bila keduanya
    # ada di host sama.
    hosts_with_child = {f["host"] for f in findings
                        if f["check"] in ("dcom-mmc-child",
                                          "dcom-dllhost-child")}
    hosts_with_rpc = {f["host"] for f in findings
                      if f["check"] == "dcom-rpc-egress"}
    for host in sorted(hosts_with_child & hosts_with_rpc):
        findings.append({
            "check": "dcom-lateral-chain", "severity": "high",
            "eid": None, "host": host,
            "message": (
                "Rantai teramati di host ini: proses DCOM beranak DAN "
                "koneksi RPC dari proses serupa (dua sinyal "
                "berangkai) — perlakukan sbg kandidat lateral "
                "movement T1021.003 berbobot, bukan noise."),
        })

    if not n1:
        notes.append("EID 1 (ProcessCreate) tidak ada di bukti — rantai "
                     "proses tidak dapat dinilai dari kegelapan.")
    if not n3:
        notes.append("EID 3 (NetworkConnect) tidak ada di bukti — sisi "
                     "koneksi RPC tidak dapat dinilai dari kegelapan.")
    notes.append(
        "ranah: rantai DCOM EID 1/3. EID 8/10/25/7 + dump/WMI/UAC = "
        "sysmon_triage; LOLBin/schtasks EID 1/11 = lolbin_scan.")
    notes.append(
        "instansiasi DCOM sah (RSAT, konsol admin remote) bisa memicu "
        "dcom-mmc-child — konfirmasi via baseline & CommandLine; satu "
        "sinyal = lead, bukan kesimpulan.")
    return findings, notes


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase Sysmon XML EID 1/3 utk DCOM lateral movement "
                    "(offline, nol jaringan).")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--log", help="satu file XML ekspor Sysmon")
    grp.add_argument("--dir", help="direktori file XML (rekursif)")
    ap.add_argument("--allow-explorer-child", default="",
                    help="daftar proses sah beranak explorer.exe "
                         "(koma, mis. cmd.exe,pwsh.exe)")
    ap.add_argument("--fail-on", default="high",
                    choices=["medium", "high"],
                    help="severity minimum yang memicu exit 1 (default high)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    root = Path(args.log or args.dir)
    files = ([root] if root.is_file()
             else sorted(p for p in root.rglob("*.xml") if p.is_file()))
    if not files or not root.exists():
        print(json.dumps({"schema": SCHEMA,
                          "error": f"tidak ada file XML: {root}"}),
              file=sys.stderr)
        return 2

    events: "list[dict]" = []
    total_sysmon = 0
    try:
        for f in files:
            if f.stat().st_size > MAX_FILE_BYTES:
                continue
            parsed = parse_events(f)
            total_sysmon += len(parsed)
            events += parsed
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2
    if not events:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "nol event Sysmon EID 1/3 ter-parse dari bukti",
        }), file=sys.stderr)
        return 2

    allow = frozenset(
        x.strip().lower() for x in args.allow_explorer_child.split(",")
        if x.strip())
    findings, notes = scan(events, allow)
    threshold = SEVERITY_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    report = {
        "schema": SCHEMA,
        "files": len(files),
        "events_eid1": sum(1 for e in events if e["eid"] == 1),
        "events_eid3": sum(1 for e in events if e["eid"] == 3),
        "findings": findings,
        "notes": notes,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
