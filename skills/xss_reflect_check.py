"""[SAFETY: bounded-requests + scope-ack] xss-reflect-check — deteksi
refleksi mentah input ke konteks HTML (CWE-79, kelas HTML injection).

Padanan VDP-friendly untuk tahap "dalfox" gaya recon klasik: BUKAN
fuzzer — SATU request per parameter dengan marker teks benign unik
(tanpa eksekusi apa pun). Zero-FP: temuan hanya bila respons
text/html DAN marker muncul MENTAH (tanpa encoding) DAN varian
escaped TIDAK ada. Refleksi mentah = L2 lead untuk verifikasi manual
dalam scope program (L3+/PoC butuh bukti eksekusi — jalur playbook).

Fail-closed: tanpa --scope-ack ditolak. Operator menyatakan sadar
rules program yang dilaporkan mengizinkan pengujian ini (VDP umumnya
melarang scanner otomatis — marker tunggal per param = pengujian
manual-ekuivalen, tetap wajib cek rules).

Pemakaian:
  python skills/xss_reflect_check.py --url https://host/search \
      --param q --param page --scope-ack --out f.json
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
MAX_PARAMS = 8


def probe(url: str, params: list[str], marker: str,
          timeout: float = 20.0) -> dict:
    """SATU request per parameter (maks MAX_PARAMS). Return per-param."""
    out: dict = {}
    for p in params[:MAX_PARAMS]:
        q = urllib.parse.urlencode({p: f"<{marker}>"})
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(f"{url}{sep}{q}",
                                     headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out[p] = {"status": r.status,
                          "content_type": r.headers.get("Content-Type") or "",
                          "body": r.read(64_000).decode("utf-8", "replace")}
        except urllib.error.HTTPError as e:
            out[p] = {"status": e.code,
                      "content_type": (e.headers.get("Content-Type") or "")
                      if e.headers else "",
                      "body": (e.read(64_000) or b"").decode("utf-8",
                                                             "replace")}
        except Exception as exc:
            out[p] = {"status": None,
                      "error": f"{type(exc).__name__}: {exc}",
                      "content_type": "", "body": ""}
    return out


def audit(url: str, param_results: dict, marker: str) \
        -> tuple[list[dict], dict]:
    rows: list[dict] = []
    raw = f"<{marker}>"
    escaped = f"&lt;{marker}"
    reflected: list[str] = []
    for param, res in param_results.items():
        ctype = (res.get("content_type") or "").lower()
        body = res.get("body", "")
        is_html = "text/html" in ctype or "application/xhtml" in ctype
        ok = (res.get("status") == 200 and is_html
              and raw in body and escaped not in body)
        if ok:
            reflected.append(param)
            rows.append(make_finding(
                tool="xss-reflect-check",
                title=f"Raw HTML reflection on {url} param '{param}'",
                severity="medium",
                description=f"Parameter '{param}' direfleksikan MENTAH ke "
                            "konteks HTML (marker benign muncul tanpa "
                            "encoding; varian escaped tidak ada) — kelas "
                            "HTML injection/XSS reflected. L2 lead: butuh "
                            "verifikasi konteks eksekusi manual dalam "
                            "scope program sebelum dilaporkan; marker "
                            "tidak melakukan apa pun.",
                recommendation="Output-encode konteks-HTML untuk semua "
                               "input; CSP pembatas inline script.",
                cwe="CWE-79",
                target_url=url,
                response=f"param '{param}' -> {res['status']} "
                         f"{ctype.split(';')[0]}; marker mentah terlihat",
                evidence_kind="request-response", finding_class="weakness",
                confidence=1.0, status="confirmed", verdict=2,
                extra={"category": "INJECTION",
                       "safety_class": "bounded-requests",
                       "param": param, "marker": marker}))
        elif res.get("status") is None:
            rows.append(make_finding(
                tool="xss-reflect-check",
                title=f"Probe failed on {url} param '{param}'",
                severity="info",
                description=str(res.get("error"))[:300],
                target_url=url, evidence_kind="request-response",
                finding_class="posture", status="unconfirmed", verdict=1,
                extra={"category": "MISC",
                       "safety_class": "bounded-requests"}))
    rows.append(make_finding(
        tool="xss-reflect-check",
        title=f"XSS reflection posture on {url}",
        severity="info",
        description=(f"{len(reflected)} dari {len(param_results)} param "
                     f"refleksi mentah: {reflected}" if reflected else
                     f"Tidak ada refleksi mentah pada "
                     f"{len(param_results)} param (AMAN/inventaris)."),
        target_url=url, response=json.dumps(
            {p: r.get("status") for p, r in param_results.items()})[:300],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=1 if reflected else 0,
        extra={"category": "INJECTION" if reflected else "AMAN",
               "safety_class": "bounded-requests",
               "reflected": reflected, "checked": len(param_results)}))
    return rows, {"url": url, "requests": len(param_results),
                  "reflected": reflected, "marker": marker}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", action="append", required=True)
    ap.add_argument("--out", default="xss_reflect_findings.json")
    ap.add_argument("--scope-ack", action="store_true",
                    help="operator menyatakan rules program mengizinkan")
    args = ap.parse_args()
    import os
    if not args.scope_ack and os.environ.get("SCOPE_ACK") != "1":
        print("DITOLAK: butuh --scope-ack / SCOPE_ACK=1 (pengujian aktif "
              "puluhan host — verifikasi rules program dulu, fail-closed)",
              file=sys.stderr)
        return 3
    marker = f"xss-canary-{secrets.token_hex(6)}"
    results = probe(args.url, args.param, marker)
    rows, meta = audit(args.url, results, marker)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests",
                                    "scope_ack": True})
    print(f"xss-reflect-check: {len(rows)} temuan "
          f"({len(meta.get('reflected', []))} refleksi, {meta.get('requests', 0)} "
          f"request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
