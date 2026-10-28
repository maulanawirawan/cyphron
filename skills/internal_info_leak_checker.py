"""[SAFETY: 1-request] internal-info-leak-checker — jejak infrastruktur
internal di respons API (CWE-200) — port dari deep_probe legacy
(private-ip-leak / internal-hostname-leak).

SATU GET. ZERO-FP disiplin:
  - HANYA respons NON-HTML (application/json, text/plain) — halaman HTML
    publik sering memuat contoh IP di dokumentasi = sarang FP, dilewati;
  - HANYA RFC1918 private IPv4 lengkap (10/8, 172.16/12, 192.168/16)
    dengan oktet valid — loopback 127.0.0.1 dan versi dokumentasi tidak
    dipicu karena konteks non-HTML + full-form;
  - IP dipotong (two-octet) di bukti supaya output rendah-profil.

Fail-closed: tanpa kecocokan = AMAN L0 (inventaris).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()

OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
PRIVATE_IP = re.compile(
    rf"\b(10\.{OCT}\.{OCT}\.{OCT}"
    rf"|192\.168\.{OCT}\.{OCT}"
    rf"|172\.(?:1[6-9]|2\d|3[01])\.{OCT}\.{OCT})\b")
HTML_TYPES = ("text/html", "application/xhtml")


def probe(url: str, timeout: float = 20.0) -> dict:
    """SATU GET; return {status, content_type, body}."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "content_type": (r.headers.get("Content-Type") or ""),
                    "body": r.read(64_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code,
                "content_type": (e.headers.get("Content-Type") or "")
                if e.headers else "",
                "body": (e.read(4096) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"status": None, "error": f"{type(exc).__name__}: {exc}",
                "content_type": "", "body": ""}


def audit(url: str, result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    ctype = (result.get("content_type") or "").lower()
    body = result.get("body", "")
    if result.get("status") is None:
        rows.append(make_finding(
            tool="internal-info-leak-checker",
            title=f"Fetch failed on {url}", severity="info",
            description=str(result.get("error"))[:300],
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "1-request"}))
        return rows, {"url": url, "error": True}
    is_html = any(t in ctype for t in HTML_TYPES)
    # zero-FP: konteks non-HTML saja (dokumentasi HTML = sarang FP)
    hits: list[str] = [] if is_html else \
        [m.group(0) for m in PRIVATE_IP.finditer(body)]
    uniq = sorted(set(hits))
    if uniq:
        redacted = ", ".join(ip.rsplit(".", 2)[0] + ".x.x"
                             for ip in uniq)[:300]
        rows.append(make_finding(
            tool="internal-info-leak-checker",
            title=f"Internal IP leak via API response on {url}",
            severity="low",
            description=f"Respons {ctype.split(';')[0] or 'non-HTML'} "
                        f"memuat {len(uniq)} alamat IP privat RFC1918 "
                        "(topologi jaringan internal terbaca publik — "
                        "lead; dipotong di bukti).",
            recommendation="Jangan sertakan alamat internal di respons "
                           "API; proxy/reverse-proxy yang menyuntik "
                           "header internal juga diperiksa.",
            cwe="CWE-200",
            target_url=url,
            response=f"private ips (redacted): {redacted}",
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "EXPOSURE", "safety_class": "1-request",
                   "count": len(uniq)}))
    else:
        rows.append(make_finding(
            tool="internal-info-leak-checker",
            title=f"No internal IP leak on {url}", severity="info",
            description=("Konteks HTML — tidak diaudit (anti-FP)."
                         if is_html else
                         "Tidak ada IP privat RFC1918 di respons "
                         "(AMAN, inventaris)."),
            target_url=url,
            response=f"content-type: {ctype or 'none'}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "1-request",
                   "html_skip": is_html}))
    return rows, {"url": url, "requests": 1, "hits": len(uniq),
                  "html_skip": is_html}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="internal_info_leak_findings.json")
    args = ap.parse_args()
    result = probe(args.url)
    rows, meta = audit(args.url, result)
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    # meta TIDAK selalu bawa 'hits' (jalur fetch gagal) — jangan crash
    print(f"internal-info-leak-checker: {len(rows)} temuan "
          f"({meta.get('hits', 0)} hit) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
