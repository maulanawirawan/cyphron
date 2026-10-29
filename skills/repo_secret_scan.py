"""[SAFETY: read-only] repo-secret-scan — deteksi rahasia ter-hardcode di
source LOKAL (path via --source). NOL request jaringan.

Audit 2026-10 (eskalasi white-box Rimpa): produk sebelumnya hanya bisa
memindai secret pada JS yang disajikan target live (js-secret-scanner-v2);
review source lokal adalah celah kapabilitas. Skill ini menutupnya.

Presisi di atas recall (zero-FP): pola berformat kuat (AWS/GitHub/Google/
Stripe/Slack/PEM) langsung jadi lead; pola generik (assignment api_key=...)
wajib lolos entropi DAN lolos daftar penekan placeholder (YOUR_, <...>,
changeme, example, dsb.). Nilai TIDAK pernah ditampilkan penuh — hanya
prefix 6 karakter + panjang (masking), supaya laporan tidak membocorkan.

Pemakaian (via orchestrator: needs=source):
  python skills/repo_secret_scan.py --source <path> --out f.json
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_FILES = 8000
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             "dist", "build", "vendor", ".next", "target", "coverage"}
SKIP_SUFFIXES = (".lock", ".min.js", ".map", ".png", ".jpg", ".jpeg",
                 ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".woff",
                 ".woff2", ".ttf", ".mp4", ".mp3", ".svg", ".csv")

# pola berformat kuat — keberadaan pola = cukup (tanpa entropi)
STRONG_PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private-key-block", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----")),
    ("github-pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
    ("stripe-live-key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
]
# pola generik — wajib lolos entropi + penekan placeholder
GENERIC_PATTERN = re.compile(
    r"(?i)(?:api[_\-]?key|apikey|secret|token|password|passwd|pwd|auth)"
    r"\s*[:=]\s*['\"]([^'\"\s]{12,80})['\"]")
ENTROPY_MIN = 3.2
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:your[_\-]|<[^>]+>|\{\{|\}\}|\$\{|xxxx|abcd|example|sample|"
    r"changeme|change_me|dummy|placeholder|lorem|test_?123|123456|qwerty|"
    r"redacted|xxxxxxxx|\.\.\.|^\$?[0-9]+$)")
SKIP_BASENAMES = {"go.mod", "go.sum", "package.json", "package-lock.json",
                  "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "poetry.lock"}


def shannon(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def mask(value: str) -> str:
    return f"{value[:6]}...({len(value)} karakter)"


def audit(source: str) -> tuple[list[dict], dict]:
    root = Path(source)
    if not root.is_dir():
        return [], {"ok": False, "error": f"path tidak ada: {source}"}
    rows: list[dict] = []
    files_scanned = 0
    files_skipped = 0
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if len(rows) >= 200:
            break  # fail-closed: batas temuan per run
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES or path.name in SKIP_BASENAMES:
            files_skipped += 1
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                files_skipped += 1
                continue
            total_bytes += path.stat().st_size
            if total_bytes > MAX_TOTAL_BYTES:
                break
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            files_skipped += 1
            continue
        files_scanned += 1
        hits: list[tuple[str, str, int, str]] = []
        for kind, pattern in STRONG_PATTERNS:
            for m in pattern.finditer(text):
                hits.append((kind, m.group(0), m.start(), "strong"))
        for m in GENERIC_PATTERN.finditer(text):
            value = m.group(1)
            if PLACEHOLDER_RE.search(value):
                continue  # penekan placeholder — bukan rahasia
            if shannon(value) < ENTROPY_MIN:
                continue  # nilai generik rendah entropi (mis. "password123")
            hits.append(("generic-credential", value, m.start(1), "generic"))
        for kind, value, offset, strength in hits[:20]:
            line = text.count("\n", 0, offset) + 1
            rows.append(make_finding(
                tool="repo-secret-scan",
                title=f"Kandidat rahasia ter-hardcode ({kind}) di {rel}:{line}",
                severity="high" if strength == "strong" else "medium",
                description=(
                    "Pola kredensial terdeteksi di source lokal. NILAI DISENSOR "
                    f"di laporan: {mask(value)}. Verifikasi manual wajib sebelum "
                    "disimpulkan sebagai kebocoran nyata (bisa sampel/uji)."),
                recommendation=(
                    "Putar (rotate) kredensial bila terkonfirmasi, pindahkan ke "
                    "secret manager / env, tambahkan pre-commit hook deteksi."),
                target_url=f"file:{rel}#{line}",
                evidence_kind="file-manifest",
                finding_class="weakness",
                confidence=0.9 if strength == "strong" else 0.6,
                status="unconfirmed",
                lab_only=False,
                extra={"category": "SECRET-EXPOSURE", "pattern": kind,
                       "strength": strength,
                       "masked": mask(value),
                       "safety_class": "read-only", "requests": 0},
            ))
    meta = {"ok": True, "source": str(root),
            "files_scanned": files_scanned, "files_skipped": files_skipped,
            "candidates": len(rows), "requests": 0,
            "safety_class": "read-only",
            "note": "nilai selalu disensor; verifikasi manual per kandidat"}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True, help="path source lokal")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows, meta = audit(args.source)
    if not meta.get("ok"):
        print(f"DITOLAK: {meta.get('error')} (fail-closed)", file=sys.stderr)
        return 2
    write_findings(args.out, rows, meta)
    print(f"repo-secret-scan: {meta['files_scanned']} file, "
          f"{len(rows)} kandidat -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
