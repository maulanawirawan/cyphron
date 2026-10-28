"""[SAFETY: read-only] tech fingerprint from HTML evidence

Regex for WordPress/Joomla/Drupal/Zimbra/Nextcloud/Outlook via meta generator + script src.
Nol request â€” hanya membaca HTML evidence tersimpan.

Emits SURFACE info verdict 0 findings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

RE_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', re.I)
RE_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)

TECH_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"wordpress|wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"joomla", re.I), "Joomla"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"zimbra", re.I), "Zimbra"),
    (re.compile(r"nextcloud", re.I), "Nextcloud"),
    (re.compile(r"outlook|owa|exchange", re.I), "Outlook"),
]


def audit(url: str, html: str) -> tuple[list[dict], dict]:
    detected: list[str] = []
    # meta generator
    m = RE_GENERATOR.search(html)
    gen_content = m.group(1) if m else ""
    # script src values
    scripts = RE_SCRIPT_SRC.findall(html)
    blob = f"{gen_content} {' '.join(scripts)} {html}".lower()
    for pat, label in TECH_PATTERNS:
        if pat.search(blob) and label not in detected:
            detected.append(label)
    # fallback: also scan meta generator alone case-insensitive
    rows: list[dict] = []
    if detected:
        rows.append(make_finding(
            tool="tech-fingerprint",
            title=f"Tech fingerprint on {url}: {', '.join(sorted(detected))}",
            severity="info",
            description=f"Teknologi terdeteksi dari HTML evidence (meta generator + script src): {', '.join(sorted(detected))} â€” inventaris SURFACE, bukan klaim kerentanan.",
            target_url=url,
            response=json.dumps({"detected": sorted(detected), "scripts": scripts[:10]}, ensure_ascii=False)[:500],
            evidence_kind="header",
            finding_class="posture",
            confidence=1.0,
            status="confirmed",
            verdict=0,
            extra={"category": "SURFACE", "safety_class": "read-only", "tech": sorted(detected)},
        ))
    else:
        rows.append(make_finding(
            tool="tech-fingerprint",
            title=f"No tech fingerprint on {url} (no WordPress/Joomla/Drupal/Zimbra/Nextcloud/Outlook marker)",
            severity="info",
            description="Tidak ada penanda WordPress/Joomla/Drupal/Zimbra/Nextcloud/Outlook di meta generator atau script src â€” permukaan tidak memaparkan tech tersebut (SURFACE observation).",
            target_url=url,
            response=f"scripts: {len(scripts)} found",
            evidence_kind="header",
            finding_class="posture",
            confidence=1.0,
            status="confirmed",
            verdict=0,
            extra={"category": "SURFACE", "safety_class": "read-only", "tech": []},
        ))
    meta = {"url": url, "tech": sorted(detected), "requests": 0}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description="[SAFETY: read-only] tech fingerprint from HTML evidence")
    ap.add_argument("--url", required=True, help="target URL (label temuan)")
    ap.add_argument("--from-raw", required=True, help="path HTML evidence tersimpan (0 request)")
    ap.add_argument("--out", default="tech_findings.json", help="path output findings JSON")
    args = ap.parse_args()
    html = Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace")
    rows, meta = audit(args.url, html)
    meta["safety_class"] = "read-only"
    write_findings(args.out, rows, meta)
    print(f"tech-fingerprint: {len(rows)} temuan (SURFACE) (0 request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
