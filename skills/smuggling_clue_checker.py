"""[SAFETY: read-only] smuggling-clue-checker — clue HTTP request
smuggling dari KEPUTUSAN header (konsep publik ala smuggler, versi
PASIF — NOL payload desync dikirim).

Menganalisis evidence header respons/request yang tersimpan (.headers)
dan mendeteksi bentuk-bentuk yang menandai permukaan desync:
  - dua header Content-Length dengan nilai berbeda
  - Content-Length DAN Transfer-Encoding hadir sekaligus
  - Transfer-Encoding nilai non-"chunked" (varian TE.TE obfuscation)

Clue = L1 lead "permukaan perlu uji desync manual dalam scope" — skill
ini SENGAJA tidak menguji desync (payload desync bisa mencemari cache
front-end orang lain; uji nyata = playbook/staging terotorisasi).
Fail-closed: tanpa header relevan = AMAN L0.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings


def _load_headers(from_raw, headers_file):
    if headers_file:
        p = Path(headers_file)
        if not p.exists():
            print(f"WARN: headers-file {p} tidak ditemukan",
                  file=sys.stderr)
            return {}
        try:
            d = json.loads(p.read_text(encoding="utf-8-sig"))
            return {k.lower(): v for k, v in d.items()} \
                if isinstance(d, dict) else {}
        except Exception as e:
            print(f"WARN: header {p}: {e}", file=sys.stderr)
            return {}
    hpath = Path(str(from_raw) + ".headers")
    if not hpath.exists():
        return {}
    try:
        d = json.loads(hpath.read_text(encoding="utf-8-sig"))
        return {k.lower(): v for k, v in d.items()} \
            if isinstance(d, dict) else {}
    except Exception as e:
        print(f"WARN: header {hpath}: {e}", file=sys.stderr)
        return {}


def _find_all(headers: dict, needle: str) -> list[str]:
    """Semua nilai header dengan nama sama (duplikat dipertahankan
    email.Message items(); di dict JSON duplikat sudah lebur —
    dukung bentuk list bila ada)."""
    vals = []
    for k, v in headers.items():
        if k.lower() == needle:
            if isinstance(v, list):
                vals.extend(str(x) for x in v)
            else:
                vals.append(str(v))
    return vals


def audit(url: str, headers: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    cl = _find_all(headers, "content-length")
    te = _find_all(headers, "transfer-encoding")
    clues: list[str] = []
    if len(set(cl)) > 1:
        clues.append(f"duplikat Content-Length beda nilai: {cl}")
    if len(cl) > 1 and len(set(cl)) == 1:
        clues.append(f"duplikat Content-Length identik: {cl}")
    if cl and te:
        clues.append("Content-Length + Transfer-Encoding sekaligus")
    for v in te:
        if v.strip().lower() not in ("chunked", ""):
            clues.append(f"Transfer-Encoding non-chunked: {v!r}")
    if clues:
        rows.append(make_finding(
            tool="smuggling-clue-checker",
            title=f"Request smuggling clue on {url}",
            severity="low",
            description="; ".join(clues) + " — bentuk header yang "
                        "dikenal memicu perbedaan interpretasi antara "
                        "front-end/back-end (permukaan desync). NOL "
                        "payload desync dikirim; uji nyata butuh scope "
                        "+ staging terotorisasi (jalur playbook).",
            recommendation="Normalisasi: satu Content-Length ATAU "
                           "Transfer-Encoding chunked, bukan keduanya; "
                           "tolak header duplikat di edge.",
            cwe="CWE-444",
            target_url=url, response="; ".join(clues)[:300],
            evidence_kind="header", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "read-only",
                   "clues": clues}))
    else:
        rows.append(make_finding(
            tool="smuggling-clue-checker",
            title=f"No smuggling clue on {url}", severity="info",
            description="Header keputusan framing konsisten (CL tunggal "
                        "atau TE chunked, tanpa kombinasi ambigu) — "
                        "tidak ada permukaan desync yang terlihat "
                        "(AMAN, bukan jaminan).",
            target_url=url,
            response=f"CL={cl} TE={te}",
            evidence_kind="header", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "read-only"}))
    return rows, {"url": url, "requests": 0, "clues": clues,
                  "checked": "content-length+transfer-encoding"}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] smuggling-clue-checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True,
                    help="path evidence (sibling .headers)")
    ap.add_argument("--headers-file", default=None)
    ap.add_argument("--out", default="smuggling_clue_findings.json")
    args = ap.parse_args()
    headers = _load_headers(args.from_raw, args.headers_file)
    rows, meta = audit(args.url, headers)
    meta["safety_class"] = "read-only"
    write_findings(args.out, rows, meta)
    print(f"smuggling-clue-checker: {len(rows)} temuan "
          f"({len(meta.get('clues', []))} clue) (0 request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
