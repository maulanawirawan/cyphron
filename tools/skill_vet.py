"""[SAFETY: read-only] skill_vet — vetting skill panduan agent SEBELUM dipasang.

Pertanyaan yang dijawab: "apakah skill ini aman di-install?" (konsep dari
NVIDIA/SkillSpector — 24k+ stars, Apache-2.0, yang melaporkan 26.1% dari
31k skill publik mengandung kerentanan dan 5.2% niat jahat). Dibangun
from scratch TANPA kode dari repo itu; pola-pola di bawah ditulis sendiri
dari pengetahuan kelas serangan yang dipublikasikan terbuka (prompt
injection tersembunyi di SKILL.md/tool-description, exfiltration berkedok
helper, curl-pipe-shell) plus guardrails cyphron sendiri (docs/
AGENT-SAFETY.md, tools/injection_guard.py yang dipakai ulang di sini).

Read-only, NOL jaringan: pindai file/direktori panduan agent (SKILL.md,
README, *.md, plugin.json, .mcp.json).

Verdict fail-closed:
  - SAFE        : nol temuan.
  - RISKY       : ada temuan, tapi tidak memenuhi ambang DANGEROUS.
  - DANGEROUS   : >= 1 temuan critical DI LUAR code-block, ATAU >= 3
                  temuan high di luar code-block.
  - file tak bisa dibaca / biner / terlalu besar TIDAK boleh jadi SAFE —
    tercatat unscannable dan verdict tidak pernah naik (fail-closed).

Zero-FP pragmatis: teks di dalam fenced code-block markdown (` ``` `)
diberi flag `in_code_block` — skill yang mendokumentasikan serangan
(contoh: cyphron sendiri) tidak otomatis DANGEROUS hanya karena
menampilkan perintah di blok contoh; instruksi BIJAK di luar blok yang
dinilai paling keras.

Pemakaian:
  python tools/skill_vet.py --source path/ke/skill/ --out vet.json
  python tools/skill_vet.py --source SKILL.md --fail-on DANGEROUS   # gate
Exit: 0 = <= RISKY; 1 = DANGEROUS (atau >= --fail-on); 2 = input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import injection_guard  # noqa: E402  (scan_text — kelas operator-override)

SCHEMA = "cyphron.skill-vet/1"
MAX_FILE_BYTES = 512 * 1024
VERDICTS = ("SAFE", "RISKY", "DANGEROUS")
FENCE_RE = re.compile(r"^\s*(```|~~~)")

# (kategori, severity, regex) — ditulis sendiri dari kelas serangan publik
PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # --- dangerous execution (critical) ---
    ("dangerous-exec", "critical", re.compile(
        r"\b(?:curl|wget)\b[^|`]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", re.I)),
    ("dangerous-exec", "critical", re.compile(
        r"\bbase64\s+(?:-d|--decode)\b[^|]*\|\s*(?:ba)?sh\b", re.I)),
    ("dangerous-exec", "critical", re.compile(
        r"\brm\s+-rf\s+(?:/|~|\$HOME)(?:\s|$)", re.I)),
    ("dangerous-exec", "critical", re.compile(
        r"\b(?:chmod|chown)\b[^\n]*&&\s*\./", re.I)),
    # --- data exfiltration (critical/high) ---
    ("data-exfil", "critical", re.compile(
        r"(?:curl|wget|requests?\.post|fetch)\b[^\n]*"
        r"(?:\$\(cat|@|&)\s*[^\s]*(?:\.env|\.ssh|id_rsa|credentials|"
        r"\$\{?(?:API_)?KEY|TOKEN|SECRET)", re.I)),
    ("data-exfil", "high", re.compile(
        r"\b(?:curl|requests?\.post|fetch|httpx)\b[^\n]*"
        r"(?:webhook\.site|requestbin|pipedream\.net|ngrok\.io|"
        r"\battack[a-z]*\.example)", re.I)),
    ("data-exfil", "high", re.compile(
        r"\b(?:echo|cat|print)\b[^\n]*(?:API[_A-Z]*KEY|SECRET|TOKEN)"
        r"[^\n]*\|\s*(?:curl|nc|netcat)\b", re.I)),
    ("data-exfil", "high", re.compile(
        r"\bcat\b[^\n]*(?:\.env|id_rsa|credentials)[^\n]*\|\s*"
        r"(?:curl|nc|netcat|wget)\b", re.I)),
    # --- credential access (high) ---
    ("credential-access", "high", re.compile(
        r"\b(?:cat|read|open|Get-Content)\b[^\n]*"
        r"~?/?\.(?:ssh|aws|gnupg|kube)/", re.I)),
    ("credential-access", "high", re.compile(
        r"\bid_rsa\b|\.aws/credentials|\.netrc|keychain|"
        r"Login Data|Cookies\.sqlite", re.I)),
    # --- instruction override / injection (high) — reuse injection_guard
    # di scan-time; pola tambahan spesifik dokumen skill:
    ("instruction-override", "high", re.compile(
        r"\b(?:disregard|ignore|forget)\s+(?:all\s+)?(?:previous|prior|"
        r"above)\s+(?:instructions?|rules?|prompts?)\b", re.I)),
    ("instruction-override", "high", re.compile(
        r"\byou\s+are\s+now\s+(?:a|an)\s+(?:unrestricted|uncensored|"
        r"different)\s+(?:model|ai|assistant)\b", re.I)),
    ("instruction-override", "high", re.compile(
        r"\b(?:hidden|secret|covert)\s+instructions?\s+(?:for|to)\s+"
        r"the\s+(?:agent|model)\b", re.I)),
    # --- system prompt leakage (medium) ---
    ("system-prompt-leak", "medium", re.compile(
        r"\b(?:reveal|print|repeat|output|show)\s+your\s+"
        r"(?:system\s+)?(?:prompt|instructions?|rules)\b", re.I)),
    # --- excessive agency (medium) ---
    ("excessive-agency", "medium", re.compile(
        r"\b(?:never|don'?t|do\s+not)\s+ask\s+(?:for\s+)?"
        r"(?:permission|confirmation|approval)\b", re.I)),
    ("excessive-agency", "medium", re.compile(
        r"\brun\s+(?:it\s+)?(?:without|skip(?:ping)?)\s+"
        r"(?:asking|confirming|approval)\b", re.I)),
    # --- supply chain (medium/high) ---
    ("supply-chain", "medium", re.compile(
        r"\b(?:pip|npm|pnpm|yarn)\s+install\b[^\n]*https?://", re.I)),
    ("supply-chain", "high", re.compile(
        r"\"?postinstall\"?\s*:", re.I)),
]

SEVERITY_WEIGHT = {"critical": 3, "high": 2, "medium": 1, "low": 0}
HIGH_AT_DANGEROUS = 3


def _split_code_blocks(text: str) -> list[tuple[str, bool]]:
    """Baris teks + flag apakah baris itu DI DALAM fenced code-block."""
    lines, in_fence = [], False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            lines.append((line, in_fence))
            in_fence = not in_fence  # toggle di baris fence itu sendiri
            continue
        lines.append((line, in_fence))
    return lines


def scan_source(source: str) -> dict:
    """Pindai file/direktori panduan agent; hasil machine-readable."""
    src = Path(source)
    if not src.exists():
        raise FileNotFoundError(f"source tidak ada: {source}")
    findings: list[dict] = []
    files_scanned, unscannable = 0, []
    targets = ([src] if src.is_file() else
               sorted(p for p in src.rglob("*")
                      if p.is_file() and p.suffix.lower() in
                      (".md", ".json", ".txt", ".yaml", ".yml")
                      and "__pycache__" not in p.parts
                      and ".git" not in p.parts))
    for p in targets:
        try:
            raw = p.read_bytes()
        except OSError as exc:
            unscannable.append(f"{p}: {exc}")
            continue
        if len(raw) > MAX_FILE_BYTES:
            unscannable.append(f"{p}: file > {MAX_FILE_BYTES} bytes")
            continue
        if b"\x00" in raw[:8192]:
            unscannable.append(f"{p}: biner")
            continue
        files_scanned += 1
        text = raw.decode("utf-8", "replace")
        lines = _split_code_blocks(text)
        for lineno, (line, in_block) in enumerate(lines, start=1):
            # 1) injection_guard: kelas operator-override terkurasi
            for hit in injection_guard.scan_text(line):
                findings.append({
                    "category": "instruction-override",
                    "severity": "high", "file": str(p), "line": lineno,
                    "label": hit["label"], "snippet": hit["snippet"],
                    "in_code_block": in_block})
            # 2) pola kelas serangan (satu baris = satu temuan/pola)
            for cat, sev, rx in PATTERNS:
                m = rx.search(line)
                if m:
                    s = max(0, m.start() - 40)
                    findings.append({
                        "category": cat, "severity": sev,
                        "file": str(p), "line": lineno,
                        "snippet": line[s:m.end() + 40].strip()[:160],
                        "in_code_block": in_block})
    # dedup identik (file, line, kategori)
    seen, dedup = set(), []
    for f in findings:
        key = (f["file"], f["line"], f["category"], f["severity"])
        if key not in seen:
            seen.add(key)
            dedup.append(f)
    findings = dedup

    critical_live = sum(1 for f in findings
                        if f["severity"] == "critical"
                        and not f["in_code_block"])
    high_live = sum(1 for f in findings if f["severity"] == "high"
                    and not f["in_code_block"])
    if critical_live >= 1 or high_live >= HIGH_AT_DANGEROUS:
        verdict = "DANGEROUS"
    elif findings or unscannable:
        verdict = "RISKY" if findings else "RISKY"
    else:
        verdict = "SAFE"
    # fail-closed: unscannable mencegah SAFE walau tak ada temuan
    if unscannable and verdict == "SAFE":
        verdict = "RISKY"
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    return {
        "schema": SCHEMA, "source": str(src),
        "files_scanned": files_scanned, "unscannable": unscannable,
        "findings_total": len(findings), "by_category": by_cat,
        "critical_live": critical_live, "high_live": high_live,
        "verdict": verdict, "findings": findings[:200],
        "rule": (f"DANGEROUS = >=1 critical live ATAU >="
                 f"{HIGH_AT_DANGEROUS} high live (di luar code-block); "
                 "unscannable mencegah SAFE"),
        "disclaimer": "vetting statis = alat bantu keputusan install; "
                      "review manusia tetap wajib untuk skill yang akan "
                      "dipasang (no proof, no report).",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="skill_vet — vetting skill panduan agent sebelum "
                    "install (read-only, nol jaringan, fail-closed).")
    ap.add_argument("--source", required=True,
                    help="file atau direktori skill yang dinilai")
    ap.add_argument("--fail-on", default="DANGEROUS",
                    choices=VERDICTS, help="verdict minimal yang membuat "
                    "exit 1 (default DANGEROUS — gate install)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    try:
        result = scan_source(args.source)
    except FileNotFoundError as exc:
        print(f"[skill-vet] input tidak valid: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    print(f"[skill-vet] {result['files_scanned']} file dipindai "
          f"({len(result['unscannable'])} unscannable)")
    for cat, n in sorted(result["by_category"].items()):
        print(f"  - {cat}: {n}")
    print(f"[skill-vet] verdict: {result['verdict']} "
          f"(critical live {result['critical_live']}, high live "
          f"{result['high_live']})")
    threshold = VERDICTS.index(args.fail_on)
    return 1 if VERDICTS.index(result["verdict"]) >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
