r"""[SAFETY: read-only] gha_workflow_audit — audit OFFLINE file workflow
GitHub Actions (.github/workflows/*.yml|*.yaml) untuk vektor serangan
supply chain CI/CD. TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0463 (mukul975/Anthropic-
Cybersecurity-Skills 'detecting-supply-chain-attacks-in-ci-cd' —
unpinned actions, script injection via expression, permission berlebih;
atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM SCRATCH:
scanner baris-basis ditulis sendiri; skill sumber memakai PyGithub +
yaml.safe_load, cyphron stdlib murni.

BATASAN TERSADAR (dicatat juga di meta): ini BUKAN parser YAML penuh
— pemeriksaan baris-basis bisa meleset pada konstruksi tidak lazim
(flow style, anchor, alias). Semua verdict = LEAD utk diverifikasi
manusia; baris yang tak terurai tidak pernah dianggap "bersih" —
file yang tidak terbaca = exit 2.

Input -> mekanisme -> output:
  - Input : --dir .github/workflows (atau --file workflow tunggal).
  - Mekanisme: baris-basis — deteksi `uses:`, blok `run:`, nilai
            `permissions:`, dan trigger `pull_request_target`.
  - Output: temuan {check, severity, file, line, detail} + stats.

Cek:
  unpinned-action    (medium) : uses: owner/repo@REF dengan REF bukan
                                SHA 40-hex (tag = medium).
  unpinned-action-branch (high): REF bentuk cabang (main/master/
                                refs/heads) — bisa berubah tiap push.
  script-injection   (high)   : blok run: memakai ${{ github.event.* }}
                                atau github.head_ref (kontrol penyerang
                                pada pull_request/push event).
  permissions-write-all (high) : `permissions: write-all` — token CI
                                dapat menulis repo penuh.
  pr-target-trigger  (medium) : workflow memicu pull_request_target DAN
                                punya run: — pola pwn-request; perlu
                                verifikasi manual apakah checkout PR
                                head dieksekusi.
  secret-in-run      (medium) : ${{ secrets.* }} diinterpolasi langsung
                                ke shell (risiko bocor via echo/ps/
                                error message); pola aman = mapping
                                env:.

Fail-closed: --dir/--file tidak ada, atau NOL file .yml/.yaml ditemukan
-> exit 2.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error.

Pemakaian:
  python tools/gha_workflow_audit.py --dir .github/workflows
  python tools/gha_workflow_audit.py --file wf.yml --fail-on high
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "cyphron.gha-workflow-audit/1"
MAX_FILE_BYTES = 1 * 1024 * 1024

_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)\s*$")
_RUN_INLINE_RE = re.compile(r"^\s*(?:-\s+)?run:\s*(\S.*?)?\s*$")
_PERM_RE = re.compile(r"^\s*permissions:\s*(\S.*)?$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
_INJECT_RE = re.compile(r"\$\{\{\s*github\.(event|head_ref)", re.I)
_SECRET_RE = re.compile(r"\$\{\{\s*secrets\.", re.I)
_BRANCH_RE = re.compile(
    r"^(refs/heads/|main$|master$|develop$|dev$|release)", re.I)
_LOCAL_ACT = (".", "docker://")


def audit_workflow(text: str, rel: str) -> tuple[list[dict],
                                                 list[str]]:
    """Satu file workflow -> (temuan, catatan batasan)."""
    findings: list[dict] = []
    notes: list[str] = []
    lines = text.splitlines()

    has_run = any("run:" in ln for ln in lines)
    has_pr_target = "pull_request_target" in "\n".join(lines)

    run_indent = -1
    run_content_indent: "int | None" = None
    in_run_block = False
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()

        # ---- blok run: | / > dan run: inline ----
        if in_run_block:
            indent = len(line) - len(line.lstrip())
            if not stripped:
                continue
            if run_content_indent is None:
                run_content_indent = indent  # YAML: baris konten pertama
            if indent >= run_content_indent:
                content = line
            else:
                in_run_block = False
                continue  # dedent = akhir blok; proses ulang normal
            if _INJECT_RE.search(content):
                findings.append({
                    "check": "script-injection", "severity": "high",
                    "file": rel, "line": idx,
                    "detail": "ekspresi github.event/head_ref "
                              "diinterpolasi ke shell dalam blok run "
                              "(kontrol penyerang) — kutip dgn env:",
                })
            if _SECRET_RE.search(content):
                findings.append({
                    "check": "secret-in-run", "severity": "medium",
                    "file": rel, "line": idx,
                    "detail": "${{ secrets.* }} diinterpolasi langsung "
                              "ke shell (risiko bocor ke log/ps)",
                })
            continue

        m = _RUN_INLINE_RE.match(line)
        if m:
            value = m.group(1) or ""
            if value and value[0] in "|>":
                run_indent = len(line) - len(line.lstrip())
                run_content_indent = None
                in_run_block = True
                continue
            if _INJECT_RE.search(value):
                findings.append({
                    "check": "script-injection", "severity": "high",
                    "file": rel, "line": idx,
                    "detail": "ekspresi github.event/head_ref "
                              "diinterpolasi ke shell dalam run: "
                              "(kontrol penyerang) — kutip dgn env:",
                })
            if _SECRET_RE.search(value):
                findings.append({
                    "check": "secret-in-run", "severity": "medium",
                    "file": rel, "line": idx,
                    "detail": "${{ secrets.* }} diinterpolasi langsung "
                              "ke shell (risiko bocor ke log/ps)",
                })
            continue

        # ---- uses: ----
        m = _USES_RE.match(line)
        if m:
            ref = m.group(1)
            if ref.startswith("docker://"):
                continue
            if ref.startswith(_LOCAL_ACT) and "@" not in ref:
                continue  # action lokal repo
            if "@" in ref:
                _, ver = ref.rsplit("@", 1)
                if not _SHA_RE.match(ver):
                    sev = "high" if _BRANCH_RE.search(ver) else "medium"
                    findings.append({
                        "check": "unpinned-action" +
                                 ("-branch" if sev == "high" else ""),
                        "severity": sev, "file": rel, "line": idx,
                        "detail": f"{ref} — ref '{ver}' bukan SHA "
                                  "40-hex (mutable)",
                    })
            continue

        # ---- permissions ----
        m = _PERM_RE.match(line)
        if m and (m.group(1) or "").strip() == "write-all":
            findings.append({
                "check": "permissions-write-all", "severity": "high",
                "file": rel, "line": idx,
                "detail": "permissions: write-all — GITHUB_TOKEN "
                          "menulis seluruh repo",
            })
            continue

    if has_pr_target and has_run:
        findings.append({
            "check": "pr-target-trigger", "severity": "medium",
            "file": rel, "line": 0,
            "detail": "trigger pull_request_target + step run: dalam "
                      "file yang sama — pola pwn-request; verifikasi "
                      "manual: apakah checkout PR head dieksekusi?",
        })
    notes.append("scanner baris-basis, bukan parser YAML penuh — "
                 "konstruksi tidak lazim bisa lolos; lead perlu "
                 "verifikasi manusia")
    return findings, notes


def _iter_files(args: argparse.Namespace) -> list[Path]:
    if args.file:
        p = Path(args.file)
        if not p.exists():
            raise FileNotFoundError(f"{args.file}: tidak ada")
        return [p]
    d = Path(args.dir)
    if not d.is_dir():
        raise FileNotFoundError(f"{args.dir}: bukan direktori")
    files = sorted(p for p in d.iterdir()
                   if p.suffix.lower() in (".yml", ".yaml")
                   and p.is_file())
    if not files:
        raise FileNotFoundError(f"{args.dir}: nol file .yml/.yaml")
    return files


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit OFFLINE workflow GitHub Actions utk risiko "
                    "supply chain CI/CD — nol jaringan, read-only")
    ap.add_argument("--dir", help="direktori workflow "
                                  "(mis. .github/workflows)")
    ap.add_argument("--file", help="satu file workflow")
    ap.add_argument("--fail-on", choices=["medium", "high"],
                    default="medium")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)
    if not args.dir and not args.file:
        print("ERROR: wajib --dir atau --file", file=sys.stderr)
        return 2

    try:
        files = _iter_files(args)
    except (FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    findings: list[dict] = []
    notes: list[str] = []
    scanned = 0
    for path in files:
        if path.stat().st_size > MAX_FILE_BYTES:
            print(f"ERROR: {path} > {MAX_FILE_BYTES} byte",
                  file=sys.stderr)
            return 2
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path).replace("\\", "/")
        f, n = audit_workflow(text, rel)
        findings.extend(f)
        if n and not notes:
            notes = n
        scanned += 1

    stats = {"files_scanned": scanned,
             "findings_by_check": {}}
    for f in findings:
        key = f["check"]
        stats["findings_by_check"][key] = \
            stats["findings_by_check"].get(key, 0) + 1
    order = {"high": 0, "medium": 1}
    result = {
        "schema": SCHEMA,
        "findings": findings,
        "stats": stats,
        "notes": notes,
        "meta": {"fail_on": args.fail_on,
                 "source": "#0463 (mukul975, Apache-2.0)"},
    }
    out = json.dumps(result, ensure_ascii=False, sort_keys=True,
                     indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    gate = order[args.fail_on]
    hit = any(order[f["severity"]] <= gate for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
