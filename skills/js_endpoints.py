"""[SAFETY: read-only] JS/asset endpoint extractor — dari bukti tersimpan.

Mengekstrak permukaan aplikasi dari HTML yang SUDAH tersimpan (nol
request): script src, endpoint ala API di inline script, form action.
Hasilnya inventaris permukaan (L0/L1 lead), bukan klaim kerentanan.

Pemakaian:
  python skills/js_endpoints.py --url https://host/ \
      --from-raw evidence.html --out f.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

RE_SCRIPT = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
RE_API = re.compile(
    r"""["'`](/(?:api|v\d|rest|graphql|ajax|json)/[A-Za-z0-9_\-/.]{1,80})["'`]""",
    re.I)
RE_FORM = re.compile(r"""<form[^>]+action=["']([^"']+)["']""", re.I)
RE_SECRETISH = re.compile(
    r"""["']((?:sk|pk|key|token|secret|Bearer)[_\-][A-Za-z0-9_\-]{8,})["']""",
    re.I)


def extract(url: str, html: str) -> dict:
    scripts = sorted({urljoin(url, s) for s in RE_SCRIPT.findall(html)})
    apis = sorted({m for m in RE_API.findall(html)})
    forms = sorted({urljoin(url, a) for a in RE_FORM.findall(html)})
    secrets = sorted({m for m in RE_SECRETISH.findall(html)})
    return {"scripts": scripts, "api_paths": apis, "form_actions": forms,
            "secret_like": secrets}


def audit(url: str, html: str) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    data = extract(url, html)

    rows.append(make_finding(
        tool="js-endpoints",
        title=f"App surface on {url}: {len(data['scripts'])} scripts, "
              f"{len(data['api_paths'])} api paths, "
              f"{len(data['form_actions'])} forms",
        severity="info",
        description="Inventaris permukaan aplikasi dari HTML tersimpan — "
                    "nol request. Endpoint daftar dipakai untuk perencanaan "
                    "pengujian berotorisasi.",
        target_url=url, response=json.dumps(data)[:400],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=0,
        extra={"category": "SURFACE", "safety_class": "read-only",
               **data}))

    for s in data["secret_like"]:
        rows.append(make_finding(
            tool="js-endpoints",
            title=f"Secret-like string in page source on {url}: {s[:24]}...",
            severity="medium",
            description="String berpola kredensial tertulis di sumber "
                        "halaman publik — verifikasi manual berotorisasi "
                        "diperlukan (bisa berupa dummy). LEAD, bukan klaim.",
            rec="Pindahkan kredensial ke server; jangan inline di HTML.",
            cwe="CWE-798", target_url=url,
            response=f"pattern: {s[:40]}",
            evidence_kind="request-response", finding_class="weakness",
            confidence=0.7, status="unconfirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class": "read-only"}))

    return rows, {"url": url, "requests": 0, **{k: len(v) for k, v in
                                                data.items()}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True,
                    help="HTML tersimpan (nol request)")
    ap.add_argument("--out", default="js_findings.json")
    args = ap.parse_args()
    html = Path(args.from_raw).read_text(encoding="utf-8", errors="replace")
    rows, meta = audit(args.url, html)
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    print(f"js-endpoints: {len(rows)} temuan (0 request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
