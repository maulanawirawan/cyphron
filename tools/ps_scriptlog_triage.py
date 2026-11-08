r"""[SAFETY: read-only] ps_scriptlog_triage — triase OFFLINE ekspor XML
log Microsoft-Windows-PowerShell/Operational (Event 4104 script block +
4103 module logging) utk indikasi AMSI bypass, download cradle, payload
ter-encode, dan akses kredensial via skrip (T1059.001). TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0534 (mukul975/Anthropic-
Cybersecurity-Skills 'hunting-for-anomalous-powershell-execution';
atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM SCRATCH:
taksonomi token + mekanisme reassembled ScriptBlockId ditulis sendiri
dari spesifikasi event logging PowerShell. Skill sumber membaca EVTX
via python-evtx/lxml; secai menerima ekspor XML Event Viewer/
wevtutil (XML stdlib) — format yang sama dengan keluarga triase
Windows repo (sysmon_triage, win_auth_triage). Ranah dibagi eksplisit:
ps_obf_scan = obfuskasi file .ps1 statis; lolbin_scan/sysmon_triage =
cmdline EID 1/11; tool ini = ISI skrip yang dieksekusi (sumber
kebenaran 4104, teks setelah deobfuskasi runtime).

Input -> mekanisme -> output:
  - Input : file XML ekspor PowerShell/Operational (bisa berisi banyak
            <Event>), atau --dir berisi beberapa file.
  - Mekanisme: parse event -> reassembled blok per ScriptBlockId
            (urut MessageNumber/Total bila ada, else urut waktu) ->
            cek token deterministik per blok.
  - Output: temuan {check, severity, scriptblock_id, path?, snippet,
            message} + stats + notes telemetri (4104 absen = script
            block logging tidak menyala — kegelapan tidak pernah
            dilaporkan bersih).

Cek:
  amsi-bypass        (high)  : token amsiutils/amsiinitfailed/
                               amsiscanbuffer di teks skrip — patch
                               refleksi AMSI (T1562.001 sisi payload).
  download-cradle    (high)  : verb unduh (downloadstring/file/data)
                               BERSAMA webclient/iex-invoke di blok
                               yang SAMA — cradle klasik.
  download-lead      (medium): verb unduh sendirian (butuh konteks).
  encoded-payload    (medium): -enc/encodedcommand/frombase64string
                               di teks — decode dulu sebelum menilai.
  cred-dump-script   (high)  : sekurlsa::/lsadump::/mimikatz/comsvcs
                               MiniDump di teks skrip (T1003).
  script-4103-only   (info)  : hanya 4103 teramati — isi skrip tidak
                               tercatat (telemetri parsial).

Fail-closed:
  - XML tidak valid / nol event ter-parse -> exit 2.
  - 4104 tidak ada di bukti -> notes eksplisit (bukan klaim bersih).
  - Snippet dibatasi + kredensial tidak dirender penuh (triase aman).

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/ps_scriptlog_triage.py --log pshell.xml
  python tools/ps_scriptlog_triage.py --dir exports/ --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.ps-scriptlog-triage/1"
MAX_FILE_BYTES = 256 * 1024 * 1024
SNIPPET_MAX = 160

WATCHED_EIDS = frozenset({4103, 4104})

_RE_AMSI = re.compile(r"amsiutils|amsiinitfailed|amsiscanbuffer", re.I)
_RE_DOWNLOAD = re.compile(
    r"downloadstring|downloadfile|downloaddata|uploadstring", re.I)
_RE_INVOKE = re.compile(
    r"invoke-expression|\biex\b|invoke-command|start-process", re.I)
_RE_ENCODED = re.compile(
    r"-enc\b|-encodedcommand\b|frombase64string|\bencode\(", re.I)
_RE_CRED = re.compile(
    r"sekurlsa::|lsadump::|invoke-mimikatz|comsvcs\.dll.*minidump"
    r"|\bmimidump\b", re.I)


def _local(tag: str) -> str:
    """Nama lokal elemen (namespace-agnostic, pola sysmon_triage)."""
    return tag.rsplit("}", 1)[-1]


def parse_events(path: Path) -> "list[dict]":
    """Parse ekspor XML -> list event {eid, time, computer, data}."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ValueError(f"XML tidak valid: {path}: {exc}") from exc
    root = tree.getroot()
    events: "list[dict]" = []
    for ev in root.iter():
        if _local(ev.tag) != "Event":
            continue
        system = None
        data_el = None
        for child in ev.iter():
            tag = _local(child.tag)
            if tag == "System":
                system = child
            elif tag == "EventData":
                data_el = child
        if system is None:
            continue
        eid = None
        time_s = ""
        computer = ""
        for child in system.iter():
            tag = _local(child.tag)
            if tag == "EventID" and child.text and child.text.strip().isdigit():
                eid = int(child.text.strip())
            elif tag == "TimeCreated":
                time_s = child.get("SystemTime") or ""
            elif tag == "Computer" and child.text:
                computer = child.text
        if eid is None or eid not in WATCHED_EIDS:
            continue
        data: "dict[str, str]" = {}
        if data_el is not None:
            for d in data_el.iter():
                if _local(d.tag) == "Data":
                    data[d.get("Name") or ""] = (d.text or "")
        events.append({
            "eid": eid, "time": time_s, "computer": computer,
            "data": data,
        })
    if not events:
        raise ValueError(f"nol event PowerShell ter-parse: {path}")
    return events


def reassemble(events: "list[dict]") -> "list[dict]":
    """Gabung 4104 per ScriptBlockId (urut MessageNumber/waktu)."""
    blocks: "dict[str, dict]" = {}
    for ev in events:
        if ev["eid"] != 4104:
            continue
        data = ev["data"]
        sbid = data.get("ScriptBlockId") or "unknown"
        text = data.get("ScriptBlockText") or ""
        try:
            msg_no = int(data.get("MessageNumber") or "1")
        except ValueError:
            msg_no = 1
        blk = blocks.setdefault(sbid, {
            "id": sbid, "path": data.get("Path") or "",
            "computer": ev["computer"], "parts": [],
        })
        blk["parts"].append((msg_no, ev["time"], text))
    out: "list[dict]" = []
    for sbid in sorted(blocks):
        blk = blocks[sbid]
        parts = sorted(blk["parts"], key=lambda t: (t[0], t[1]))
        blk["text"] = "\n".join(p[2] for p in parts)
        del blk["parts"]
        out.append(blk)
    return out


def _snippet(text: str) -> str:
    clean = " ".join(text.split())
    return clean[:SNIPPET_MAX] + ("..." if len(clean) > SNIPPET_MAX else "")


def scan(blocks: "list[dict]", n_4103: int) -> "tuple[list[dict], list[str]]":
    findings: "list[dict]" = []
    notes: "list[str]" = []

    for blk in blocks:
        text = blk["text"]
        if _RE_AMSI.search(text):
            findings.append({
                "check": "amsi-bypass", "severity": "high",
                "scriptblock_id": blk["id"], "path": blk["path"],
                "snippet": _snippet(text),
                "message": "Token bypass AMSI di teks skrip 4104 — "
                           "payload berupaya mematikan inspeksi "
                           "(patch refleksi AmsiScanBuffer).",
            })
        if _RE_CRED.search(text):
            findings.append({
                "check": "cred-dump-script", "severity": "high",
                "scriptblock_id": blk["id"], "path": blk["path"],
                "snippet": _snippet(text),
                "message": "Token akses kredensial (sekurlsa/lsadump/"
                           "mimikatz/comsvcs MiniDump) di teks skrip "
                           "(T1003) — kredensial yang terekspos wajib "
                           "direset.",
            })
        has_download = bool(_RE_DOWNLOAD.search(text))
        has_invoke = bool(_RE_INVOKE.search(text))
        if has_download and has_invoke:
            findings.append({
                "check": "download-cradle", "severity": "high",
                "scriptblock_id": blk["id"], "path": blk["path"],
                "snippet": _snippet(text),
                "message": "Verb unduh + invoke di blok yang sama — "
                           "cradle unduh-dan-jalankan (T1059.001).",
            })
        elif has_download:
            findings.append({
                "check": "download-lead", "severity": "medium",
                "scriptblock_id": blk["id"], "path": blk["path"],
                "snippet": _snippet(text),
                "message": "Verb unduh di skrip (lead) — tanpa invoke "
                           "di blok sama; lanjutkan ke URL yang "
                           "diunduh.",
            })
        if _RE_ENCODED.search(text):
            findings.append({
                "check": "encoded-payload", "severity": "medium",
                "scriptblock_id": blk["id"], "path": blk["path"],
                "snippet": _snippet(text),
                "message": "Payload ter-encode di teks — decode dulu "
                           "sebelum menilai (deep_decode).",
            })

    if not blocks and n_4103:
        findings.append({
            "check": "script-4103-only", "severity": "info",
            "scriptblock_id": "", "path": "",
            "snippet": "",
            "message": "Hanya 4103 teramati — isi skrip tidak tercatat "
                       "(script block logging mati); telemetri parsial.",
        })
    if not blocks:
        notes.append(
            "4104 tidak ada di bukti — script block logging kemungkinan "
            "tidak menyala; 'tidak ada temuan' di sini BUKAN bersih.")
    if not n_4103:
        notes.append("4103 (module logging) tidak ada di bukti — cakupan "
                     "telemetri parsial.")
    notes.append(
        "ranah: isi skrip 4104. Obfuskasi file .ps1 = ps_obf_scan; "
        "cmdline EID 1/11 = lolbin_scan/sysmon_triage.")
    return findings, notes


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase ekspor XML PowerShell/Operational 4104/4103 "
                    "(offline, nol jaringan).")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--log", help="satu file XML ekspor")
    grp.add_argument("--dir", help="direktori file XML (rekursif)")
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

    all_events: "list[dict]" = []
    try:
        for f in files:
            if f.stat().st_size > MAX_FILE_BYTES:
                continue
            all_events += parse_events(f)
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    n_4103 = sum(1 for e in all_events if e["eid"] == 4103)
    blocks = reassemble(all_events)
    findings, notes = scan(blocks, n_4103)
    threshold = SEVERITY_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    report = {
        "schema": SCHEMA,
        "files": len(files),
        "events_4104": len(all_events) - n_4103,
        "events_4103": n_4103,
        "scriptblocks": len(blocks),
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
