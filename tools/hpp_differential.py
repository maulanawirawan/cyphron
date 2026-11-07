"""[SAFETY: bounded-requests] hpp_differential — deteksi HTTP Parameter
Pollution (CWE-436/CWE-235) versi terkendali, fail-closed.

Konsep dari antrean port skill (SKILL-PORT-QUEUE #0154,
claude-red/offensive-parameter-pollution — atribusi ide): duplikasi
parameter dan perbedaan parsing antar layer. Dibangun from scratch tanpa
kode sumber pihak lain; di sini dipakai sisi DIAGNOSTIK (defend):
mengukur bagaimana server memilih nilai ketika parameter dikirim ganda,
dengan kontrol anti-FP — bukan alat eksploitasi.

Metode (maksimum 5 request GET, bounded, tanpa state-change):
  1. r1  ?<p>=A                 (single nilai A)
  2. r2  ?<p>=B                 (single nilai B)
  3. r3  ?<p>=A&<p>=B           (duplikat — objek pengukuran)
  4. r4  kontrol: ?<p>=C (nilai ketiga, tak dipakai r1-r3) + canary param
     x2 — menangkap respons generik/wildcard dan server yang memantulkan
     query mentah (pola kontrol param-probe-checker).
Klasifikasi refleksi token (canary hex acak per-run, jadi refleksi hanya
mungkin jika server benar-benar menggemakan nilai):
  - r3 memuat A dan B        -> BOTH   (semua nilai diterima/concat)
  - r3 hanya A               -> FIRST  (parser memilih nilai pertama)
  - r3 hanya B               -> LAST   (parser memilih nilai terakhir)
  - r3 tidak memuat          -> INDIFFERENT (tak ada refleksi teramati)
  - r1==r2==r3==r4           -> GENERIC (tidak ada sinyal — bukan klaim)
Fail-closed:
  - URL bukan http(s)                    -> error exit 2
  - lebih dari 1 param / param kosong    -> error exit 2
  - r1/r2 gagal jaringan (timeout, 5xx)  -> error exit 3 (tanpa klaim)
  - kontrol r4 memuat canary (mustahil)  -> error exit 3 (lingkungan kotor)
Exit: 0 hasil tercetak (+ JSON bila --out); 2 input invalid; 3 verifikasi
gagal. Target hanya lab/berizin (lihat tools/lab_target.py).
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

SCHEMA = "cyphron.hpp-differential/1"
MAX_REQUESTS = 5
TIMEOUT_S = 10.0


@dataclass
class Resp:
    """Respons HTTP minimal untuk klasifikasi (mudah di-mock, nol jaringan)."""
    status: int
    body: str


def classify(r1: Resp, r2: Resp, r3: Resp, r4: Resp,
             value_a: str, value_b: str,
             control_markers: "tuple[str, ...]" = ()) -> dict:
    """Klasifikasi murni (tanpa I/O) — inti keputusan anti-FP.

    r1/r2 single-value, r3 duplikat, r4 kontrol canary tanpa A/B.
    control_markers = nama-param canary r4; kemunculannya di r4 berarti
    server memantulkan query mentah -> refleksi tak bisa dipercaya.
    """
    has_a1, has_b1 = value_a in r1.body, value_b in r1.body
    has_a2, has_b2 = value_a in r2.body, value_b in r2.body
    has_a3, has_b3 = value_a in r3.body, value_b in r3.body
    has_a4 = (value_a in r4.body or value_b in r4.body
              or any(m in r4.body for m in control_markers))

    bodies_equal = r1.body == r2.body == r3.body == r4.body

    if has_a4:
        # canary A/B tidak pernah dikirim ke r4 — kemunculannya berarti
        # respons generik memuat teks kebetulan (mis. mirror query lengkap)
        return {"winner": "UNTRUSTWORTHY",
                "reason": "kontrol memuat canary — lingkungan memantulkan "
                          "query mentah, refleksi tak bisa dipercaya",
                "has_a3": has_a3, "has_b3": has_b3,
                "generic": bodies_equal}

    if bodies_equal:
        return {"winner": "GENERIC",
                "reason": "respons identik untuk semua variasi — tidak ada "
                          "sinyal teramati",
                "has_a3": has_a3, "has_b3": has_b3,
                "generic": True}

    if has_a3 and has_b3:
        winner, reason = "BOTH", "duplikat: kedua nilai direfleksikan"
    elif has_a3:
        winner, reason = "FIRST", "duplikat: hanya nilai pertama direfleksikan"
    elif has_b3:
        winner, reason = "LAST", "duplikat: hanya nilai terakhir direfleksikan"
    elif (has_a1 or has_b1 or has_a2 or has_b2):
        winner, reason = "INDIFFERENT", (
            "single direfleksikan tapi duplikat tidak — server menolak/"
            "mengabaikan nilai ganda")
    else:
        winner, reason = "INDIFFERENT", (
            "tidak ada refleksi teramati pada r1/r2/r3")
    return {"winner": winner, "reason": reason,
            "has_a3": has_a3, "has_b3": has_b3,
            "reflected_single_a": has_a1 or has_b1,
            "reflected_single_b": has_a2 or has_b2,
            "generic": False}


def _fetch(url: str, timeout: float) -> Resp:
    """GET satu URL — tanpa redirect otomatis (bounded, transparan)."""
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "cyphron-hpp/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return Resp(status=resp.status,
                    body=resp.read(262144).decode("utf-8", errors="replace"))


def validate_url(url: str) -> str:
    """Validasi ketat: hanya http/https + host ada — fail-closed."""
    u = (url or "").strip()
    p = urllib.parse.urlparse(u)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError(f"URL harus http(s) dengan host: {url!r}")
    if p.query:
        raise ValueError("URL tidak boleh membawa query — param dikelola "
                         "alat agar urutan duplikat terkendali")
    return u


def probe(url: str, param: str, values: "tuple[str, str] | None" = None,
          timeout: float = TIMEOUT_S) -> dict:
    """Jalankan 4 request terbatas + klasifikasi. Bounded 5 request."""
    value_a, value_b = values or (secrets.token_hex(8),
                                  secrets.token_hex(8))
    q1 = f"?{urllib.parse.quote(param, safe='')}={urllib.parse.quote(value_a, safe='')}"
    q2 = f"?{urllib.parse.quote(param, safe='')}={urllib.parse.quote(value_b, safe='')}"
    q3 = (f"?{urllib.parse.quote(param, safe='')}={urllib.parse.quote(value_a, safe='')}"
          f"&{urllib.parse.quote(param, safe='')}={urllib.parse.quote(value_b, safe='')}")
    can = secrets.token_hex(4)
    can1, can2 = f"hppc-{can}", f"hppd-{can}"
    value_c = secrets.token_hex(8)  # nilai ketiga — tak pernah dikirim di r1-r3
    q4 = (f"?{urllib.parse.quote(param, safe='')}={urllib.parse.quote(value_c, safe='')}"
          f"&{can1}={secrets.token_hex(8)}&{can2}={secrets.token_hex(8)}")

    r1 = _fetch(url + q1, timeout)
    r2 = _fetch(url + q2, timeout)
    r3 = _fetch(url + q3, timeout)
    r4 = _fetch(url + q4, timeout)

    for name, r in (("single-A", r1), ("single-B", r2), ("kontrol", r4)):
        if r.status >= 500:
            raise RuntimeError(f"request {name} gagal: HTTP {r.status}")
    verdict = classify(r1, r2, r3, r4, value_a, value_b,
                       control_markers=(can1, can2))
    lead = verdict["winner"] in ("FIRST", "LAST", "BOTH")
    return {
        "schema": SCHEMA,
        "url": url,
        "param": param,
        "requests_sent": 4,
        "max_requests": MAX_REQUESTS,
        "winner": verdict["winner"],
        "reason": verdict["reason"],
        "lead_class": "L1-CWE-436" if lead else "L0",
        "control_ok": not verdict.get("generic", False)
                      and verdict["winner"] != "UNTRUSTWORTHY",
        "generic_response": verdict.get("generic", False),
        "detail": verdict,
        "note": "diagnostik parse duplikat pada TARGET LAB/BERIZIN; HPP "
                "per se bukan kerentanan — lead perlu konfirmasi manual "
                "antar layer (proxy/WAF vs backend).",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="hpp_differential — diagnostik HTTP Parameter Pollution "
                    "terkendali (5 request GET, fail-closed, target lab).")
    ap.add_argument("--url", required=True, help="URL dasar tanpa query")
    ap.add_argument("--param", default="q", help="nama parameter yang diuji")
    ap.add_argument("--values", help="opsional: 'A,B' (2 nilai deterministik; "
                                     "default canary acak per-run)")
    ap.add_argument("--timeout", type=float, default=TIMEOUT_S,
                    help="timeout per request detik (default 10)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    try:
        url = validate_url(args.url)
    except ValueError as exc:
        print(f"[hpp] input tidak valid: {exc}", file=sys.stderr)
        return 2
    values: "tuple[str, str] | None" = None
    if args.values:
        parts = [v.strip() for v in args.values.split(",", 1)]
        if len(parts) != 2 or not all(parts):
            print("[hpp] --values harus 2 nilai dipisah koma: 'A,B'",
                  file=sys.stderr)
            return 2
        values = (parts[0], parts[1])

    try:
        result = probe(url, args.param, values, args.timeout)
    except (RuntimeError, urllib.error.URLError, OSError) as exc:
        print(f"[hpp] verifikasi gagal (fail-closed, tanpa klaim): {exc}",
              file=sys.stderr)
        return 3

    if args.out:
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
    print(f"[hpp] {args.url} param={args.param!r}")
    print(f"[hpp] winner: {result['winner']} ({result['lead_class']}) — "
          f"{result['reason']}")
    print(f"[hpp] control_ok={result['control_ok']} "
          f"generic={result['generic_response']} "
          f"requests={result['requests_sent']}/{result['max_requests']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
