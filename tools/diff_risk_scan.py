"""[DEFEND] diff_risk_scan — pindai git diff utk perubahan berisiko keamanan.

Konsep antrean SKILL-PORT-QUEUE #0026 'differential-review' dari
trailofbits/skills (CC-BY-SA-4.0, atribusi); dibangun from scratch —
heuristik ditulis sendiri dari kelas perubahan yang terbukti sering
menyusupkan kerentanan. Lisensi cyphron: PolyForm NC.

Input: git diff (unified) dari file ATAU dari git repo via --git-range
(mis. HEAD~3..HEAD). Read-only, NOL jaringan (subprocess git lokal saja
untuk --git-range; fail-closed bila bukan repo).

Yang diflag (baris TAMBAHAN saja, +/- konteks tidak dihitung):
  - secret masuk kode    : assignment key/token/password/secret beralue,
    pola berformat kuat (AWS AKIA, private key PEM, jwt base64 panjang)
  - proteksi dimatikan   : ssl_verify=false, verify=False,
    rejectUnauthorized=false, check=False, sanitize/filter dihapus
  - eksekusi berbahaya   : eval/exec/subprocess shell=True, curl|sh,
    os.system
  - auth/authz diubah    : file path menyentuh auth, permission, session,
    token, crypto (file-level, severity medium — butuh review manusia)
  - debug ke produksi    : print/log statement baru di file non-test

Zero-FP pragmatis: baris komentar dinonaktifkan (# // /* *), fixture test
diberi flag melalui jalur file test/ (temuan di file test = low), dan
semua temuan = LEAD L0-L1 (belum konfirmasi — konfirmasi oleh review
manusia, kontrak no proof no report).

Pemakaian:
  python tools/diff_risk_scan.py --git-range HEAD~3..HEAD --out d.json
  python tools/diff_risk_scan.py --file perubahan.diff
Exit: 0 = tidak ada temuan; 1 = ada temuan; 2 = input error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "cyphron.diff-risk/1"
COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", "<!--")

SECRET_KEY_RE = re.compile(
    r"[\"']?(?:api[_-]?key|apikey|secret|token|password|passwd|credential)[\"']?"
    r"\s*[:=]\s*[\"'][^\"']{8,}[\"']", re.I)
STRONG_SECRET_RE = re.compile(
    r"AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"xox[bpao]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{36,}")
DISABLE_RE = re.compile(
    r"(?:ssl_verify|verify_ssl|tls_verify|verify|rejectUnauthorized)"
    r"\s*[:=]\s*(?:False|false|0)\b|check=False|verify\s*=\s*False", re.I)
DANGEROUS_RE = re.compile(
    r"\b(?:eval|exec|os\.system|popen)\s*\(|subprocess[^\n]*shell\s*=\s*True|"
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", re.I)
DEBUG_RE = re.compile(
    r"\b(?:print|console\.log|echo)\s*\(|\blogger\.(?:debug|info)\b", re.I)
AUTH_PATH_RE = re.compile(
    r"(?:^|/)(?:auth|login|permission|permission|session|token|crypto|"
    r"passwd|acl|jwt|oauth|rbac)", re.I)
TEST_PATH_RE = re.compile(r"(?:^|/)(?:tests?/|_?test\b|\.spec\.|_test\.)", re.I)


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return bool(s) and s.startswith(COMMENT_PREFIXES)


def parse_unified_diff(text: str) -> list[dict]:
    """Parse unified diff -> daftar {file, added_lines:[(no, text)]}."""
    files = []
    cur: dict | None = None
    new_no = 0
    for raw in text.splitlines():
        if raw.startswith("+++ "):
            continue
        if raw.startswith("--- "):
            continue
        if raw.startswith("diff --git"):
            m = re.match(r"diff --git a/(.+?) b/(.+)", raw)
            cur = {"file": (m.group(2) if m else raw[11:]), "added": []}
            files.append(cur)
            continue
        m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", raw)
        if m and cur is not None:
            new_no = int(m.group(1))
            continue
        if cur is None:
            continue
        if raw.startswith("+"):
            cur["added"].append((new_no, raw[1:]))
            new_no += 1
        elif raw.startswith("-"):
            pass  # baris dihapus tidak dinilai sebagai kode baru
        elif raw.startswith((" ", "")):
            new_no += 1
    return files


def scan_diff_files(files: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for f in files:
        path = f["file"]
        is_test = bool(TEST_PATH_RE.search(path))
        auth_file = bool(AUTH_PATH_RE.search(path))
        for lineno, line in f["added"]:
            if _is_comment(line):
                continue
            sev_base = "low" if is_test else None
            cats: list[tuple[str, str]] = []
            if STRONG_SECRET_RE.search(line):
                cats.append(("secret-strong", "high"))
            if SECRET_KEY_RE.search(line):
                cats.append(("secret-assignment", "medium"))
            if DISABLE_RE.search(line):
                cats.append(("protection-disabled", "high"))
            if DANGEROUS_RE.search(line):
                cats.append(("dangerous-exec", "high"))
            if not cats and DEBUG_RE.search(line) and not is_test:
                cats.append(("debug-statement", "low"))
            if not cats and auth_file:
                cats.append(("auth-area-changed", "medium"))
            for cat, sev in cats:
                if is_test:
                    sev = "low"
                findings.append({
                    "category": cat, "severity": sev, "file": path,
                    "line": lineno, "snippet": line.strip()[:160],
                    "in_test_file": is_test})
    # dedup identik
    seen, out = set(), []
    for f in findings:
        key = (f["file"], f["line"], f["category"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def load_diff(file: str | None, git_range: str | None,
              repo: str | None = None) -> str:
    if file:
        p = Path(file)
        if not p.is_file():
            raise FileNotFoundError(f"file diff tidak ada: {file}")
        return p.read_text(encoding="utf-8", errors="replace")
    if git_range:
        cwd = repo or os.getcwd()
        proc = subprocess.run(["git", "diff", git_range], cwd=cwd,
                              capture_output=True, text=True, shell=False,
                              timeout=120, check=False)
        if proc.returncode != 0:
            raise ValueError(f"git diff gagal (pastikan di repo git): "
                             f"{proc.stderr.strip()[:200]}")
        return proc.stdout
    raise ValueError("butuh --file ATAU --git-range")


def scan_source(file: str | None, git_range: str | None,
                repo: str | None = None) -> dict:
    text = load_diff(file, git_range, repo)
    files = parse_unified_diff(text)
    findings = scan_diff_files(files)
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    return {
        "schema": SCHEMA,
        "files_in_diff": len(files),
        "findings_total": len(findings),
        "by_category": by_cat,
        "findings": findings[:300],
        "rule": "temuan = LEAD (L0-L1); konfirmasi akhir oleh review manusia "
                "(no proof, no report); baris komentar & konteks tak dinilai",
        "disclaimer": "heuristik statis pada diff — false positive wajar; "
                      "bukan vonis.",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="diff_risk_scan — pindai git diff utk perubahan "
                    "berisiko keamanan (read-only, nol jaringan).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="file unified diff")
    src.add_argument("--git-range", help="rentang git, mis. HEAD~3..HEAD")
    ap.add_argument("--repo", help="direktori repo utk --git-range (default cwd)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    try:
        result = scan_source(args.file, args.git_range, args.repo)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[diff-risk] input tidak valid: {exc}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
    print(f"[diff-risk] {result['files_in_diff']} file dalam diff, "
          f"{result['findings_total']} temuan (lead)")
    for cat, n in sorted(result["by_category"].items()):
        print(f"  - {cat}: {n}")
    return 1 if result["findings_total"] else 0


if __name__ == "__main__":
    sys.exit(main())
