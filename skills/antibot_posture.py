"""[SAFETY: bounded-requests] antibot-posture — posisi pertahanan anti-bot
situs (dilihat seperti bot melihat): sinyal tantangan edge, header
rate-limit, determinisme respons, dan (opt-in) N-trial throttling.
Bahan audit situs SENDIRI; pada target pihak ketiga hanya sah bila ada
otorisasi.

Default maks 3 GET (halaman utama 2x identik + /login 1x GET tanpa
kredensial). Flag opsional --ntrial N (3..10) menambah N GET berurutan
ke path utama = pengukuran throttling terukur (pola F59):
  - 429 / retry-after teramati pada trial ke-k = pertahanan TERBUKTI
    berjalan (baris AMAN, verdict 0);
  - semua trial sukses tanpa sinyal throttling = "tidak ada throttling
    pada N request" TEREPRODUKSI — baris naik L2 (reproduced, semua
    kode respons + timing tersimpan di bukti), menggantikan lead L1
    absensi-header;
  - trial gagal jaringan / path non-2xx3xx = inkonklusif — kembali ke
    lead L1 absensi-header (fail-closed).
Yang diukur (faktual, zero-FP — semua sinyal diambil dari respons nyata):
  1. Vendor anti-bot/WAF di edge: marker header/cookie/script yang jelas
     (cf-mitigated, __cf_bm, datadome, _abck/ak_bm, Incap_ses, x-kpsdk,
     recaptcha/turnstile/hcaptcha SDK di HTML).
  2. Header rate-limit standar: ratelimit-* / x-ratelimit-* / retry-after.
  3. Determinisme: 2 GET identik — body persis sama DAN set nama cookie
     sama = respons dapat diprediksi untuk replay (lead, bukan klaim
     kerentanan).
  4. N-trial (opt-in): lihat di atas; timing dicatat SEBAGAI BUKTI saja
     (tanpa keputusan dari timing — disiplin anti-FP sqli-time).
Verdict default lead maksimum L1; dgn --ntrial jalur unthrottled bisa L2
(reproduced). Vendor terdeteksi = baris AMAN/inventaris. Kegagalan
jaringan = unconfirmed (tanpa klaim).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
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
NTRIAL_MIN = 3
NTRIAL_MAX = 10
THROTTLE_STATUS = (429,)


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


def probe(base_url: str, check_login: bool = True,
          ntrial_n: int = 0, timeout: float = 15.0) -> dict:
    """Default maks 3 GET: utama 2x (determinisme) + /login 1x.

    ntrial_n (3..10) = opt-in pengukuran throttling: N GET berurutan ke
    path utama SETELAH pasangan determinisme (total request tetap
    bounded, dicatat di meta.gets).
    """
    base = base_url.rstrip("/")
    r1 = _get(base + "/", timeout=timeout)
    r2 = _get(base + "/", timeout=timeout)
    out: dict = {"main": r1, "main_repeat": r2, "login": None, "gets": 2,
                 "ntrial": None}
    if check_login and r1.get("status") is not None:
        out["login"] = _get(base + "/login", timeout=timeout)
        out["gets"] = 3
    if ntrial_n:
        n = max(NTRIAL_MIN, min(NTRIAL_MAX, int(ntrial_n)))
        path = base + "/"
        trials: list[dict] = []
        for i in range(n):
            t0 = time.monotonic()
            r = _get(path, timeout=timeout)
            trials.append({"i": i + 1,
                           "status": r.get("status"),
                           "retry_after": (r.get("headers") or {})
                                          .get("retry-after"),
                           "elapsed_s": round(time.monotonic() - t0, 3),
                           "error": r.get("error")})
        out["ntrial"] = {"path": "/", "n": n, "trials": trials,
                         "gets": n}
        out["gets"] = out.get("gets", 2) + n
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


def _ntrial_verdict(nt: dict) -> dict:
    """Klasifikasi N-trial — deterministik, NOL keputusan dari timing
    (timing hanya bukti; disiplin anti-FP sqli-time).

    throttled    = 429 ATAU retry-after teramati di trial manapun.
    unthrottled  = semua trial 2xx/3xx, tanpa sinyal throttle.
    error/empty/inconclusive = tanpa klaim (kembali ke lead absensi).
    """
    trials = nt.get("trials") or []
    if not trials:
        return {"outcome": "empty"}
    for t in trials:
        if t.get("status") is None:
            return {"outcome": "error", "at": t.get("i")}
    for t in trials:
        st = t.get("status")
        ra = t.get("retry_after")
        if (isinstance(st, int) and st in THROTTLE_STATUS) or \
                ra is not None:
            return {"outcome": "throttled", "at": t.get("i"),
                    "status": st, "retry_after": ra}
    if all(isinstance(t.get("status"), int)
           and 200 <= t["status"] < 400 for t in trials):
        return {"outcome": "unthrottled"}
    return {"outcome": "inconclusive"}


def _ntrial_evidence(nt: dict) -> tuple[str, str]:
    """Bukti N-trial ringkas utk kolom request/response (tersimpan)."""
    trials = nt.get("trials") or []
    request = (f"{len(trials)}x GET {nt.get('path', '/')} berurutan "
               f"(N-trial, tanpa kredensial)")
    response = json.dumps({
        "statuses": [t.get("status") for t in trials],
        "retry_after": [t.get("retry_after") for t in trials],
        "elapsed_s": [t.get("elapsed_s") for t in trials],
    }, separators=(",", ":"))
    return request, response[:300]


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
        ntv = _ntrial_verdict(results["ntrial"]) \
            if results.get("ntrial") else None
        if ntv and ntv.get("outcome") == "throttled":
            # pertahanan TERBUKTI berjalan — 429/retry-after nyata
            n_total = len((results.get("ntrial") or {})
                          .get("trials") or [])
            req, resp = _ntrial_evidence(results["ntrial"])
            rows.append(make_finding(
                tool="antibot-posture",
                title=f"Throttling behavior observed on {base_url} "
                      f"(trial {ntv.get('at')}/{n_total})",
                severity="info",
                description=f"Pembatasan laju TERBUKTI berjalan di edge: "
                            f"status {ntv.get('status')} / retry-after "
                            f"teramati pada trial ke-{ntv.get('at')} "
                            "(kode respons + timing tersimpan di bukti) "
                            "— AMAN/inventaris pertahanan.",
                target_url=base_url, request=req, response=resp,
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=0,
                extra={"category": "AMAN",
                       "safety_class": "bounded-requests",
                       "ntrial": {"outcome": "throttled",
                                  "at": ntv.get("at"),
                                  "n": (results.get("ntrial") or {})
                                        .get("n")}}))
        elif ntv and ntv.get("outcome") == "unthrottled" and not vendors:
            # N-trial reproduced — TANPA vendor anti-bot (bila vendor
            # terdeteksi, klaim unthrottled kontradiktif: tetap L1)
            ntr = results["ntrial"]
            req, resp = _ntrial_evidence(ntr)
            rows.append(make_finding(
                tool="antibot-posture",
                title=f"No throttling across {ntr.get('n')} sequential "
                      f"GETs on {base_url}",
                severity="low",
                description=f"{ntr.get('n')} GET berurutan semua "
                            "2xx/3xx tanpa 429/retry-after — tidak ada "
                            "throttling teramati di edge pada path ini "
                            "(TEREPRODUKSI: kode respons + timing "
                            "per-trial tersimpan di bukti). Lebih kuat "
                            "dari absensi header; throttle bisa saja "
                            "jalan di jalur/lapisan lain (mis. POST "
                            "login, per-akun) — verifikasi manual bila "
                            "relevan.",
                recommendation="Throttle per identitas + terbitkan "
                               "header rate-limit standar.",
                cwe="CWE-770", target_url=base_url,
                request=req, response=resp,
                evidence_kind="request-response",
                finding_class="weakness", confidence=1.0,
                status="confirmed", verdict=2,
                extra={"category": "BOT-DEFENSE",
                       "safety_class": "bounded-requests",
                       "ntrial": {"outcome": "unthrottled",
                                  "n": ntr.get("n"),
                                  "path": ntr.get("path")}}))
        else:
            rows.append(make_finding(
                tool="antibot-posture",
                title=f"No rate-limit headers on {base_url}",
                severity="low",
                description="Tidak ada header ratelimit-*/x-ratelimit-*/"
                            "retry-after pada respons — sinyal throttling "
                            "tidak teramati di edge (lead inventaris; bisa "
                            "saja throttle jalan tanpa header, tetapi "
                            "klien yang baik tidak diberi petunjuk)."
                            + ("" if not results.get("ntrial") else
                               " N-trial tidak konklusif ("
                               f"{ntv.get('outcome') if ntv else '?'}) — "
                               "kembali ke lead absensi (fail-closed)."),
                recommendation="Terbitkan header rate-limit standar + "
                               "throttle per identitas, bukan hanya per IP.",
                cwe="CWE-770",
                target_url=base_url,
                evidence_kind="request-response", finding_class="weakness",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "BOT-DEFENSE",
                       "safety_class": "bounded-requests",
                       **({"ntrial": ntv} if ntv else {})}))

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
                  "ntrial": (_ntrial_verdict(results["ntrial"])
                       if results.get("ntrial") else None),
                  "requests": results.get("gets", 2)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="antibot_findings.json")
    ap.add_argument("--no-login", action="store_true",
                    help="lewati GET /login (maks request jadi 2)")
    ap.add_argument("--ntrial", type=int, default=0,
                    help="opt-in: N GET berurutan utk ukur throttling "
                         f"(3..{NTRIAL_MAX} — naikkan maks request)")
    args = ap.parse_args()
    if args.ntrial and not (NTRIAL_MIN <= args.ntrial <= NTRIAL_MAX):
        ap.error(f"--ntrial harus {NTRIAL_MIN}..{NTRIAL_MAX} (bounded)")
    results = probe(args.url, check_login=not args.no_login,
                    ntrial_n=args.ntrial)
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"antibot-posture: vendors={meta.get('vendors', [])} "
          f"rate_headers={len(meta.get('rate_headers', []))} "
          f"deterministic={meta.get('deterministic', '-')} "
          f"ntrial={meta.get('ntrial', '-')} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
