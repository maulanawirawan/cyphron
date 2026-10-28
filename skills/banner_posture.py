"""[SAFETY: 1-request] Banner posture audit — SATU GET ke halaman utama.

Skill v2 (produk Cyphron). Batas keras: TEPAT SATU permintaan GET ke
halaman utama host — setara satu kunjungan browser. Tidak ada bruteforce
path, tidak ada scan direktori, tidak ada probing parameter. Ini kelas
data yang dilihat siapa pun yang membuka situs di browser.

Yang dikumpulkan: header respons (server, security headers), cookie flag,
<title>, penanda produk (mis. Zimbra), dan marker versi/build di URL
resource. Versi produk yang TIDAK terekspos => pemetaan CVE TIDAK
diklaim (fail-closed, zero-FP).

Pemakaian:
  python skills/banner_posture.py --url https://mail.example.go.id/ \
      --out findings/tier0-contoh/banner_posture.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()

# Penanda produk di HTML/cookie (nama generik, bukan klaim kerentanan).
# Pencocokan pakai word-boundary regex — substring polos memicu FP
# (kasus nyata: "owa" kena di "reflowApp" pada halaman Zimbra).
PRODUCT_MARKERS = {
    "zimbra": "Zimbra Collaboration Suite",
    "roundcube": "Roundcube",
    "owa": "Outlook Web App / Exchange",
    "outlook web app": "Outlook Web App / Exchange",
    "horde": "Horde",
    "sogo": "SOGo",
    "nextcloud": "Nextcloud",
}

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("x-frame-options", "X-Frame-Options"),
    ("content-security-policy", "CSP"),
    ("x-content-type-options", "X-Content-Type-Options"),
]


def fetch_once(url: str, timeout: float = 30.0) -> dict:
    """TEPAT SATU GET. Return {status, headers, set_cookies, body}.
    Set-Cookie ganda dipertahankan (list) — dict header kehilangan duplikat.
    Tidak ada retry (retry = permintaan kedua, melanggar batas 1-request)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(256_000).decode("utf-8", errors="replace")
            set_cookies = [v for k, v in r.headers.items()
                           if k.lower() == "set-cookie"]
            headers = {k.lower(): v for k, v in r.headers.items()
                       if k.lower() != "set-cookie"}
            return {"status": r.status, "headers": headers,
                    "set_cookies": set_cookies, "body": body}
    except Exception as exc:
        return {"status": None, "headers": {}, "set_cookies": [],
                "body": f"__fetch_error__ {type(exc).__name__}: {exc}"}


def cookie_audit(url: str, set_cookies: list[str]) -> list[dict]:
    """Analisis flag keamanan per cookie (Secure/HttpOnly/SameSite)."""
    rows: list[dict] = []
    for c in set_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite")
                   if flag not in low]
        if missing:
            rows.append(make_finding(
                tool="banner-posture",
                title=f"Cookie without security flags on {url}: {name} "
                      f"missing {', '.join(m.upper() for m in missing)}",
                severity="low",
                description=f"Cookie '{name}' dikirim tanpa flag: "
                            f"{', '.join(m.upper() for m in missing)}. "
                            "Tanpa Secure bisa bocor via http; tanpa "
                            "HttpOnly bisa dicuri JS (XSS); tanpa "
                            "SameSite rawan CSRF.",
                recommendation="Setel Secure; HttpOnly; SameSite=Lax/Strict.",
                cwe="CWE-614", target_url=url,
                response=f"set-cookie: {c[:120]}",
                evidence_kind="request-response", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "MISC", "safety_class": "1-request"}))
        else:
            rows.append(make_finding(
                tool="banner-posture",
                title=f"Cookie flags OK on {url}: {name}", severity="info",
                description=f"Cookie '{name}' membawa Secure+HttpOnly+SameSite.",
                target_url=url, response=f"set-cookie: {c[:120]}",
                evidence_kind="request-response", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=0,
                extra={"category": "AMAN", "safety_class": "1-request"}))
    return rows


def audit(url: str, result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    headers = {k.lower(): v for k, v in result.get("headers", {}).items()}
    body = result.get("body", "")

    def finding(title, sev, desc, rec="", category="MISC", verdict=0,
                cwe=None, header=None):
        extra = {"category": category, "safety_class": "1-request"}
        if header:
            # tag header untuk FAO family quorum (header×3 lintas tool)
            extra["header"] = header
        rows.append(make_finding(
            tool="banner-posture", title=title, severity=sev,
            description=desc, recommendation=rec, cwe=cwe, target_url=url,
            # x-powered-by ikut direkam — sumber fakta versi utk
            # cve-matcher (mis. PHP/8.2.34 -> KB php2shell)
            response=json.dumps({k: headers.get(k) for k in
                                 ("server", "content-type",
                                  "x-powered-by")})[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=verdict,
            extra=extra))

    if result["status"] is None:
        # fail-closed: kegagalan akses dicatat, bukan dibungkam
        rows.append(make_finding(
            tool="banner-posture", title=f"Fetch failed on {url}",
            severity="info", description=body[:300],
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "1-request"}))
        return rows, {"url": url, "error": True}

    title_m = re.search(r"<title>([^<]{0,120})</title>", body, re.I)
    title = title_m.group(1).strip() if title_m else ""
    blob = body.lower() + " " + " ".join(
        f"{k}={v}" for k, v in result["headers"].items()).lower()

    # Produk dari penanda publik — word-boundary, anti-FP substring
    detected = [name for pat, name in PRODUCT_MARKERS.items()
                if re.search(rf"\b{re.escape(pat)}\b", blob)]
    if detected:
        finding(f"Product banner observed on {url}: {', '.join(detected)}",
                "info",
                f"Title halaman: \"{title}\". Produk terdeteksi dari "
                "penanda publik (halaman login/landing) — data yang "
                "terlihat oleh pengunjung biasa.",
                category="SURFACE", verdict=0)

    # Marker build/versi di URL resource (?v=..., ?version=...) — dedupe
    vm = sorted(set(re.findall(r"[?&](?:v|version|ver|build)=(\d{6,15})", body)))
    if detected and not vm:
        rows.append(make_finding(
            tool="banner-posture",
            title=f"Version not exposed on {url} (CVE mapping NOT claimed)",
            severity="info",
            description="Produk terdeteksi tetapi versi produk tidak "
                        "terekspos di halaman publik; pemetaan CVE tidak "
                        "dilakukan (fail-closed — tanpa versi, tanpa klaim).",
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="confirmed", verdict=0,
            extra={"category": "SURFACE", "safety_class": "1-request"}))

    # Header keamanan: yang ada dicatat AMAN, yang absen dicatat lead
    hsts_present = False
    for key, label in SECURITY_HEADERS:
        if key in headers:
            if key == "strict-transport-security":
                hsts_present = True
            finding(f"Security header present on {url}: {label}",
                    "info",
                    f"{headers[key][:120]}",
                    category="AMAN", verdict=0, header=key)
        else:
            finding(f"Security header absent on {url}: {label}", "low",
                    f"Respons tidak menyertakan {label} — pengerasan "
                    "header belum lengkap (lead, bukan kerentanan).",
                    rec=f"Setel header {label} di reverse proxy/app.",
                    category="MISC", verdict=1, cwe="CWE-693", header=key)
    if result["status"] == 200 and not hsts_present and url.startswith("https://"):
        finding(f"No HSTS on https host {url}", "low",
                "Host HTTPS tanpa Strict-Transport-Security: klien tanpa "
                "preferensi sebelumnya bisa diturunkan ke HTTP (lead).",
                rec="Setel Strict-Transport-Security max-age>=15768000.",
                category="MISC", verdict=1, cwe="CWE-319",
                header="strict-transport-security")

    # Cookie flags (F10) — hanya jika ada data set-cookie
    rows.extend(cookie_audit(url, result.get("set_cookies", [])))

    return rows, {
        "url": url, "status": result["status"], "title": title,
        "server": headers.get("server"), "products": detected,
        "version_markers": vm, "requests": 1,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True, help="halaman utama (SATU GET)")
    ap.add_argument("--out", default="banner_findings.json")
    ap.add_argument("--save-raw", default=None,
                    help="path opsional untuk menyimpan body mentah")
    ap.add_argument("--from-raw", default=None,
                    help="audit dari body HTML tersimpan — NOL request "
                         "ke target (mode re-run/verifikasi)")
    args = ap.parse_args()
    if args.from_raw:
        raw = Path(args.from_raw).read_text(encoding="utf-8",
                                            errors="replace")
        # header tersimpan dari run sebelumnya (<file>.headers, JSON) —
        # tanpa ini, lead "header absent" jadi FP
        hdrs = {}
        hpath = Path(args.from_raw + ".headers")
        if hpath.exists():
            try:
                hdrs = json.loads(hpath.read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"WARN: header {hpath} tidak terbaca: {exc}")
        result = {"status": 200, "headers": hdrs, "body": raw}
        requests_used = 0
    else:
        result = fetch_once(args.url)
        requests_used = 1
    if args.save_raw and not args.from_raw:
        p = Path(args.save_raw)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(result["body"], encoding="utf-8", errors="replace")
        hp = Path(str(args.save_raw) + ".headers")
        hp.write_text(json.dumps(result["headers"], indent=2), encoding="utf-8")
    rows, meta = audit(args.url, result)
    meta["requests"] = requests_used
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    aman = sum(1 for r in rows if r.get("category") == "AMAN")
    print(f"banner-posture: {len(rows)} temuan ({aman} AMAN) "
          f"({requests_used} request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
