"""[SAFETY: bounded-requests] antibot-posture — posisi pertahanan anti-bot
situs (dilihat seperti bot melihat): sinyal tantangan edge, header
rate-limit, dan determinisme respons. Bahan audit situs SENDIRI; pada
target pihak ketiga hanya sah bila ada otorisasi.

Maks 3 GET (halaman utama 2x identik + /login 1x GET tanpa kredensial).
Yang diukur (faktual, zero-FP — semua sinyal diambil dari respons nyata):
  1. Vendor anti-bot/WAF di edge: marker header/cookie/script yang jelas
     (cf-mitigated, __cf_bm, datadome, _abck/ak_bm, Incap_ses, x-kpsdk,
     recaptcha/turnstile/hcaptcha SDK di HTML).
  2. Header rate-limit standar: ratelimit-* / x-ratelimit-* / retry-after.
  3. Determinisme: 2 GET identik — body persis sama DAN set nama cookie
     sama = respons dapat diprediksi untuk replay (lead, bukan klaim
     kerentanan).
Verdict: lead maksimum L1 (inventaris pertahanan); vendor terdeteksi =
baris AMAN/inventaris. Kegagalan jaringan = unconfirmed (tanpa klaim).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()

# marker vendor anti-bot/WAF: (nama vendor, sinyal header, sinyal cookie,
# sinyal body) — hanya sinyal yang TEPAT (multi-kata/tepat-kunci)
VENDORS = [
    ("cloudflare", ("cf-mitigated",), ("__cf_bm", "cf_clearance"),
     ("checking your browser", "cf-browser-verification",
      "cf_chl_prog")),
    ("datadome", ("x-datadome",), ("datadome",),
     ("datadome",)),
    ("akamai", ("x-akamai-transformed",), ("_abck", "ak_bm", "bm_sv"),
     ("access denied",)),
    ("imperva", ("x-iinfo",), ("incap_ses", "visid_incap"),
     ("request unsuccessful. incapsula",)),
    ("kasada", ("x-kpsdk-ct",), ("kpsdk_ct",), ("kpsdk",)),
    ("aws-waf", ("x-amzn-waf-action",), ("awsalb", "aws-waf-token"),
     ()),
    ("recaptcha", (), (), ("recaptcha/api.js", "www.google.com/recaptcha")),
    ("hcaptcha", (), (), ("hcaptcha.com/1/api.js",)),
    ("turnstile", (), (), ("challenges.cloudflare.com/turnstile",)),
]
RATE_LIMIT_HEADERS = ("ratelimit-limit", "ratelimit-remaining",
                      "ratelimit-reset", "x-ratelimit-limit",
                      "x-ratelimit-remaining", "x-ratelimit-reset",
                      "retry-after")
MAX_GETS = 3


def _get(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "headers": {k.lower(): v
                                for k, v in r.headers.items()},
                    "body": r.read(64_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code,
                "headers": {k.lower(): v for k, v in e.headers.items()},
                "body": (e.read(32_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"status": None, "headers": {}, "body": "",
                "error": type(exc).__name__}


def probe(base_url: str, check_login: bool = True) -> dict:
    """Maks 3 GET: utama 2x (determinisme) + /login 1x (opsional)."""
    base = base_url.rstrip("/")
    r1 = _get(base + "/")
    r2 = _get(base + "/")
    out = {"main": r1, "main_repeat": r2, "login": None, "gets": 2}
    if check_login and r1.get("status") is not None:
        out["login"] = _get(base + "/login")
        out["gets"] = 3
    return out


def _vendors_seen(result: dict) -> list[str]:
    seen = []
    h = result.get("headers", {})
    body = (result.get("body", "") or "").lower()
    cookies = "; ".join(v for k, v in h.items()
                        if k == "set-cookie").lower()
    for name, headers, cookies_, bodies in VENDORS:
        hit = (any(x in h for x in headers)
               or any(x in cookies for x in cookies_)
               or any(x in body for x in bodies))
        if hit:
            seen.append(name)
    return seen


def _rate_headers(result: dict) -> list[str]:
    h = result.get("headers", {})
    return [k for k in RATE_LIMIT_HEADERS if k in h]


def _deterministic(r1: dict, r2: dict) -> bool | None:
    """True bila 2 GET identik persis (body + nama cookie)."""
    if r1.get("status") is None or r2.get("status") is None:
        return None
    c1 = sorted(k for k in r1.get("headers", {}) if k == "set-cookie")
    c2 = sorted(k for k in r2.get("headers", {}) if k == "set-cookie")
    return r1.get("body") == r2.get("body") and c1 == c2


def audit(base_url: str, results: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    main = results.get("main", {})
    if main.get("status") is None:
        rows.append(make_finding(
            tool="antibot-posture",
            title=f"Anti-bot posture on {base_url} — tidak dapat dinilai",
            severity="info",
            description=(f"Request gagal ({main.get('error')}) — postur "
                         "anti-bot tidak dinilai (tanpa klaim, "
                         "fail-closed)."),
            target_url=base_url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "bounded-requests"}))
        return rows, {"url": base_url, "error": True}

    vendors = _vendors_seen(main)
    if results.get("login"):
        vendors += [v for v in _vendors_seen(results["login"])
                    if v not in vendors]
    rate_h = _rate_headers(main)
    det = _deterministic(main, results.get("main_repeat", {}))

    # 1. vendor anti-bot terdeteksi = pertahanan ADA (inventaris AMAN)
    if vendors:
        rows.append(make_finding(
            tool="antibot-posture",
            title=f"Anti-bot/WAF edge detected on {base_url}: "
                  f"{', '.join(vendors)}",
            severity="info",
            description="Sinyal pertahanan edge teramati dari respons "
                        "(header/cookie/script yang spesifik): "
                        f"{vendors} — lapisan pertama terpasang "
                        "(AMAN/inventaris).",
            target_url=base_url,
            response=json.dumps({"vendors": vendors,
                                 "status": main.get("status")})[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "vendors": vendors}))

    # 2. rate-limit headers
    if rate_h:
        rows.append(make_finding(
            tool="antibot-posture",
            title=f"Rate-limit headers present on {base_url}",
            severity="info",
            description=f"Header pembatasan laju teramati: {rate_h} — "
                        "sinyal throttling terpasang (AMAN/inventaris).",
            target_url=base_url,
            response=json.dumps({k: main["headers"][k][:40]
                                 for k in rate_h})[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "headers": rate_h}))
    else:
        rows.append(make_finding(
            tool="antibot-posture",
            title=f"No rate-limit headers on {base_url}",
            severity="low",
            description="Tidak ada header ratelimit-*/x-ratelimit-*/"
                        "retry-after pada respons — sinyal throttling "
                        "tidak teramati di edge (lead inventaris; bisa "
                        "saja throttle jalan tanpa header, tetapi "
                        "klien yang baik tidak diberi petunjuk).",
            recommendation="Terbitkan header rate-limit standar + "
                           "throttle per identitas, bukan hanya per IP.",
            cwe="CWE-770",
            target_url=base_url,
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "BOT-DEFENSE",
                   "safety_class": "bounded-requests"}))

    # 3. determinisme 2 GET identik
    if det is True:
        rows.append(make_finding(
            tool="antibot-posture",
            title=f"Responses deterministic across repeated GETs on "
                  f"{base_url}",
            severity="low",
            description="Dua GET identik mengembalikan body dan set "
                        "cookie yang PERSIS sama — tidak ada nonce/"
                        "varian per-request yang teramati. Respons yang "
                        "dapat diprediksi memudahkan replay dan "
                        "otomasi massal (lead inventaris, bukan klaim "
                        "kerentanan).",
            recommendation="Suntikkan nonce/per-request variance + "
                           "kaitkan token ke sesi (lihat blueprint "
                           "L1-L2).",
            cwe="CWE-330",
            target_url=base_url,
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "BOT-DEFENSE",
                   "safety_class": "bounded-requests"}))
    elif det is None:
        rows.append(make_finding(
            tool="antibot-posture",
            title=f"Anti-bot posture on {base_url} — determinisme tidak "
                  f"dapat diukur",
            severity="info",
            description="Salah satu dari 2 GET identik gagal — "
                        "determinisme tidak dinilai (tanpa klaim).",
            target_url=base_url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC",
                   "safety_class": "bounded-requests"}))

    if not rows:
        rows.append(make_finding(
            tool="antibot-posture",
            title=f"Anti-bot posture on {base_url}",
            severity="info",
            description="Tidak ada sinyal anti-bot yang teramati dan "
                        "tidak ada temuan lain (inventaris).",
            target_url=base_url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))
    return rows, {"url": base_url, "vendors": vendors,
                  "rate_headers": rate_h, "deterministic": det,
                  "requests": results.get("gets", 2)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="antibot_findings.json")
    ap.add_argument("--no-login", action="store_true",
                    help="lewati GET /login (maks request jadi 2)")
    args = ap.parse_args()
    results = probe(args.url, check_login=not args.no_login)
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"antibot-posture: vendors={meta.get('vendors', [])} "
          f"rate_headers={len(meta.get('rate_headers', []))} "
          f"deterministic={meta.get('deterministic', '-')} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
