r"""[SAFETY: read-only] vm_artifact_triage — wave-3: skor OFFLINE dump
teks (strings binary, script, config, log) terhadap ARTIFAK VM/sandbox/
tool analisis yang biasanya DIKONGKAL malware sebelum menembak — untuk
(a) tim biru: "sampel ini mengecek lingkungan analisis apa saja?",
(b) tim merah: "VM analisis saya bocor lewat artefak apa?" (pola pafish).

Sinyal per dump (semua deterministik dari data):
  - vm-process       : nama proses guest tools (vmtoolsd, VBoxService,
                       qemu-ga, prl_tools, vmms, ...)
  - vm-driver        : nama driver guest (.sys) — vmci, vmhgfs,
                       vmmouse, vboxguest, vboxsf, prl_tg, xen*
  - vm-registry      : key registry guest-additions / ACPI VBOX/VMware
  - hypervisor-brand : string brand CPUID (VMwareVMware, KVMKVMKVM,
                       XenVMMXenVMM, Microsoft Hv, prl hyperv) — dump
                       memuat kode yang MEMBANDINGKAN brand ini
  - mac-prefix-check : prefix MAC vendor VM (00:0C:29/00:05:69/
                       00:1C:14 VMware, 08:00:27 VirtualBox, 00:16:3e Xen)
  - analysis-tool    : nama tool analisis (wireshark, procmon, x64dbg,
                       ghidra, ida, pestudio, cuckoo, fakenet, inetsim,
                       sysinternals suite, ...)
  - sandbox-path     : path analisis klasik (C:\analysis, C:\cuckoo,
                       C:\sample, C:\sandbox, /tmp/sample, ...)
Skor = jumlah sinyal; >= 4 high, 2-3 medium, 1 low, 0 info (bersih —
zero-FP). Temuan = LEAD; keberadaan string TIDAK membuktikan kode
mengeksekusi cek tersebut (LIMITASI JUJUR — verifikasi dengan disasm).

Fail-closed: dump < 32 char atau tidak ada teks -> exit 2.

Referensi konsep: entri "Check if you are in a virtual machine"
(A-poc/RedTeam-Tools) + pendekatan pafish — kode dibangun from scratch.

Pemakaian:
  python tools/vm_artifact_triage.py --file strings.txt --out f.json
  python tools/vm_artifact_triage.py --file dropper.ps1
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.vm-artifact-triage/1"

_VM_PROCESS = re.compile(
    r"(vmtoolsd|vmwareuser|vmwaretray|vmwareservice|vboxservice|"
    r"vboxtray|qemu-?ga|qemu-guest-agent|prl_tools|prl_cc|prl_disp|"
    r"\bvmms\.exe|vmcompute|xenstored|xenagent)", re.I)
_VM_DRIVER = re.compile(
    r"\b(vmci|vmhgfs|vmmouse|vmusbmouse|vsock|vboxguest|vboxsf|"
    r"vboxvideo|prl_tg|xenvbd|xennet)(\.sys)?\b", re.I)
_VM_REGISTRY = re.compile(
    r"(SOFTWARE\\\\?VMware|SOFTWARE\\\\?Oracle\\\\?VirtualBox|"
    r"ACPI\\\\?DSDT\\\\?(VBOX|VMWARE|XEN)|HARDWARE\\\\?ACPI\\\\?FADT|"
    r"ControlSet\d+\\\\?Services\\\\?(VBoxGuest|VBoxMouse|vmci))", re.I)
_HYPERVISOR_BRAND = re.compile(
    r"(VMwareVMware|KVMKVMKVM|XenVMMXenVMM|Microsoft Hv|"
    r"prl hyperv|VBoxVBoxVBox|lrpepyh vr)", re.I)
_MAC_PREFIX = re.compile(
    r"(\b00[::\-]?0[CG][::\-]?29\b|\b00:0C:29|\b00:05:69\b|\b00:1C:14\b|"
    r"\b08:00:27\b|\b00:16:3E\b)", re.I)
_ANALYSIS_TOOL = re.compile(
    r"(wireshark|procmon|procexp|processhacker|x64dbg|ollydbg|"
    r"pestudio|peid|ghidra|\bida6?4?\b|idaq|cuckoo|fakenet|fake_net|"
    r"inetsim|thug\b|autorunsc|autoruns|tcpdump|apimonitor|"
    r"regshot|sysinternals)", re.I)
_SANDBOX_PATH = re.compile(
    r"(C:\\\\?analysis\b|C:\\\\?cuckoo|C:\\\\?sample[s]?\b|"
    r"C:\\\\?sandbox|C:\\\\?users\\\\?(sandbox|user|analyst)\b|"
    r"/tmp/(sample|analysis)|/home/(sandbox|analyst))", re.I)

# keyword -> compile map untuk histogram sinyal
_SIGNALS = (
    ("vm-process", _VM_PROCESS),
    ("vm-driver", _VM_DRIVER),
    ("vm-registry", _VM_REGISTRY),
    ("hypervisor-brand", _HYPERVISOR_BRAND),
    ("mac-prefix-check", _MAC_PREFIX),
    ("analysis-tool", _ANALYSIS_TOOL),
    ("sandbox-path", _SANDBOX_PATH),
)


def triage_text(text: str) -> dict:
    if len(text.strip()) < 32:
        raise ValueError("dump terlalu pendek (<32 char) — bukan dump analisis")
    signals: list[str] = []
    evidence: dict[str, list[str]] = {}
    for name, rx in _SIGNALS:
        hits = sorted({m.group(0).strip() for m in rx.finditer(text)})
        if hits:
            signals.append(name)
            evidence[name] = [h[:60] for h in hits[:6]]
    score = len(signals)
    severity = ("high" if score >= 4 else
                "medium" if score >= 2 else
                "low" if score == 1 else "info")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    counts[severity] = 1
    return {
        "schema": SCHEMA,
        "score": score,
        "severity": severity,
        "signals": signals,
        "evidence": evidence,
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "vm-artifact", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "keberadaan string TIDAK membuktikan eksekusi cek "
                "anti-VM — verifikasi dengan disasm/debug; dump kosong "
                "dari VM nyata TIDAK berarti aman",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="dump teks: strings binary / script / config")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
