"""[SAFETY: 1-request] egress-fingerprint-check — self-check identitas
jaringan run ini (pola "fingerprint konsisten lintas lapisan").

Mode default: NOL request ke target — audit konfigurasi egress proses
sendiri (pola ganti dari review bridge: konsistensi UA vs OS host,
proxy env vs kemampuan stack, kredensial tercatat ter-redaksi).

--target (opsional): 1 GET ke endpoint echo milik sendiri (mis.
httpbin-style /headers di lab sendiri); dibandingkan UA yang DIKIRIM
vs UA yang DILIHAT server. Target yang tidak membalik header -> info
unconfirmed (zero-FP: tidak ada klaim tanpa bukti echo).

Tidak ada spoofing fingerprint TLS/device dan tidak ada rotasi —
skill ini hanya MENGECEK apa yang sudah dikonfigurasi.
"""
from __future__ import annotations
import argparse, json, os, platform, sys, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
from findings import make_finding, write_findings
from ua import user_agent, BROWSER_UA  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from redact import redact_headers, redact_url  # noqa: E402

PROXY_KEYS = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
              "ALL_PROXY", "all_proxy")
VALID_SCHEMES = ("http://", "https://", "socks5://")

# korespondensi token platform UA -> token yang diharapkan per OS host
UA_PLATFORM_TOKENS = {
    "Windows": ("windows nt",),
    "Linux": ("linux", "x11", "android"),
    "Darwin": ("macintosh", "mac os"),
}


def active_proxies() -> dict[str, str]:
    """Proxy env aktif (kedua casing), utuh — PEMANGGIL wajib redaksi
    sebelum menulis ke output. Windows env case-insensitive: kunci
    berbeda dengan NILAI sama dideduplikasi (satu proxy = satu baris)."""
    out: dict[str, str] = {}
    for k in PROXY_KEYS:
        v = os.environ.get(k, "").strip()
        if v and v not in out.values():
            out[k] = v
    return out


def audit(target: str | None, echo_result: dict | None) -> tuple[list, dict]:
    """Rows + meta. Selalu audit konfigurasi (0 request); tambah baris
    echo bila echo_result diberikan (hasil 1 GET ke endpoint echo)."""
    rows = []
    ua = user_agent()
    os_name = platform.system()

    # 1. Inventaris identitas aktif (L0 — bukan klaim kerentanan)
    rows.append(make_finding(
        tool="egress-fingerprint-check",
        title=f"Egress UA aktif: {ua[:80]}",
        severity="info",
        description=("Identitas jaringan yang dipakai run ini (dari "
                     "skills/ua.py terpusat). Default = identitas alat "
                     "jujur; --ua mengubahnya untuk black-box testing "
                     "aset sendiri."),
        target_url=target, evidence_kind="self-check",
        finding_class="posture", confidence=1.0, status="confirmed",
        verdict=0,
        extra={"category": "EGRESS", "safety_class": "1-request",
               "ua_source": "ua.py"}))

    # 2. Konsistensi lintas lapisan: profil 'browser' vs OS host
    #    (UA bilang Windows tapi host Linux = kontradiksi yang bisa
    #    jadi penanda otomatisasi — lead, bukan klaim kerentanan)
    if ua == BROWSER_UA and os_name in UA_PLATFORM_TOKENS:
        tokens = UA_PLATFORM_TOKENS[os_name]
        if not any(t in ua.lower() for t in tokens):
            rows.append(make_finding(
                tool="egress-fingerprint-check",
                title=f"Profil UA 'browser' tidak cocok OS host ({os_name})",
                severity="low",
                description=("UA Chrome memakai token platform berbeda "
                             "dari OS host — kontradiksi lintas lapisan "
                             "(UA vs sinyal lain) yang menonjolkan "
                             "kecerdasan otomatis. Pilih profil UA yang "
                             "konsisten dengan OS host."),
                target_url=target, evidence_kind="self-check",
                finding_class="posture", confidence=0.9,
                status="confirmed", verdict=1,
                extra={"category": "EGRESS", "safety_class": "1-request",
                       "os_host": os_name}))

    # 3. Egress proxy: keberadaan, validitas, kemampuan stack
    proxies = active_proxies()
    proxy_meta = {k: redact_url(v) for k, v in proxies.items()}
    pysocks_ok = True
    try:
        __import__("socks")  # PySocks
    except ImportError:
        pysocks_ok = False
    socks_seen = False
    for k, v in sorted(proxies.items()):
        red = redact_url(v)
        if not v.lower().startswith(VALID_SCHEMES):
            rows.append(make_finding(
                tool="egress-fingerprint-check",
                title=f"Proxy env {k} scheme tidak didukung",
                severity="low",
                description=(f"Nilai {red} bukan http:// https:// atau "
                             "socks5:// — urllib mengabaikannya dan "
                             "request jalan LANGSUNG dari IP asli tanpa "
                             "kamu sadari (fail-loud diperlukan)."),
                target_url=target, evidence_kind="self-check",
                finding_class="posture", confidence=0.9,
                status="confirmed", verdict=1,
                extra={"category": "EGRESS", "safety_class": "1-request",
                       "proxy": red}))
            continue
        if v.lower().startswith("socks5://"):
            socks_seen = True
        rows.append(make_finding(
            tool="egress-fingerprint-check",
            title=f"Egress proxy aktif via {k}: {red}",
            severity="info",
            description=("Semua request skill proses ini lewat proxy "
                         "tersebut (round-robin per skill ditangani "
                         "orchestrator --proxies). Kredensial di-redaksi "
                         "di output ini."),
            target_url=target, evidence_kind="self-check",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "EGRESS", "safety_class": "1-request",
                   "proxy": red}))
    if socks_seen and not pysocks_ok:
        rows.append(make_finding(
            tool="egress-fingerprint-check",
            title="Egress socks5 tanpa PySocks — request jalan langsung",
            severity="medium",
            description=("urllib bawaan tidak mendukung socks5; tanpa "
                         "PySocks request TIDAK lewat proxy (IP asli "
                         "terpakai) — bukan diam-diam, tapi operasional "
                         "tidak sesuai rencana. pip install pysocks."),
            target_url=target, evidence_kind="self-check",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "EGRESS", "safety_class": "1-request"}))

    # 4. Echo (opsional, 1 request): UA dikirim vs UA dilihat server
    echo_meta = None
    if echo_result is not None:
        seen = echo_result.get("seen_ua")
        headers = echo_result.get("headers", {})
        status = echo_result.get("status")
        if echo_result.get("error"):
            rows.append(make_finding(
                tool="egress-fingerprint-check",
                title=f"Echo target tidak bisa diverifikasi: {target}",
                severity="info",
                description=(f"{echo_result['error']} — endpoint echo "
                             "wajib membalik header request (mis. "
                             "/headers httpbin-style di lab sendiri); "
                             "tanpa itu tidak ada klaim (zero-FP)."),
                target_url=target, evidence_kind="self-check",
                finding_class="posture", confidence=1.0,
                status="unconfirmed", verdict=1,
                extra={"category": "EGRESS", "safety_class": "1-request"}))
        elif seen is None:
            rows.append(make_finding(
                tool="egress-fingerprint-check",
                title=f"Respons target tidak memuat echo UA: {target}",
                severity="info",
                description=("Respons 200 tapi header/body tidak memuat "
                             "User-Agent yang dikirim — endpoint bukan "
                             "echo; pindahkan ke endpoint echo milik "
                             "sendiri untuk verifikasi. Tanpa klaim."),
                target_url=target, evidence_kind="self-check",
                finding_class="posture", confidence=1.0,
                status="unconfirmed", verdict=1,
                extra={"category": "EGRESS", "safety_class": "1-request",
                       "status": status}))
        elif seen == ua:
            rows.append(make_finding(
                tool="egress-fingerprint-check",
                title="Server melihat UA sama dengan yang dikirim",
                severity="info",
                description="Identitas egress sampai utuh ke server.",
                target_url=target, evidence_kind="differential",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=0,
                extra={"category": "AMAN", "safety_class": "1-request"}))
        else:
            rows.append(make_finding(
                tool="egress-fingerprint-check",
                title="UA yang sampai ke server BERBEDA dari yang dikirim",
                severity="medium",
                description=("Ada yang mengubah identitas di jalur "
                             "(proxy transparan / middleware) — "
                             "direproduksi lewat echo endpoint milik "
                             "sendiri. Periksa rantai egress."),
                target_url=target, evidence_kind="differential",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=2,
                extra={"category": "EGRESS", "safety_class": "1-request"}))
        echo_meta = {"seen_ua": (seen or "")[:120],
                     "headers": redact_headers(headers),
                     "status": status}

    meta = {"ua": ua, "os_host": os_name, "proxies": proxy_meta,
            "pysocks": pysocks_ok,
            "requests": 1 if echo_result is not None else 0}
    if echo_meta is not None:
        meta["echo"] = echo_meta
    return rows, meta


def fetch_echo(target: str, timeout: float = 20.0) -> dict:
    """1 GET ke endpoint echo milik sendiri; kembalikan UA yang server
    lihat (dari header echo atau body). TANPA retry — satu request."""
    ua = user_agent()
    try:
        req = urllib.request.Request(target, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.read(65536).decode(errors="replace")
        seen = None
        for k in ("user-agent", "x-sent-user-agent"):
            if k in headers:
                seen = headers[k]
                break
        if seen is None and ua in body:
            seen = ua
        return {"status": r.status, "headers": headers, "seen_ua": seen}
    except Exception as e:
        return {"status": None, "headers": {},
                "error": f"__error__ {type(e).__name__}: {e}"}


def main():
    ap = argparse.ArgumentParser(description="[SAFETY: 1-request] egress-fingerprint-check")
    ap.add_argument("--out", default="egress_fingerprint_check_findings.json")
    ap.add_argument("--target", default=None,
                    help="URL endpoint echo milik sendiri (opsional, 1 request)")
    args = ap.parse_args()
    target = (args.target or "").strip() or None
    echo = fetch_echo(target) if target else None
    rows, meta = audit(target, echo)
    meta["safety_class"] = "1-request"
    write_findings(args.out, rows, meta)
    n_req = meta["requests"]
    print(f"egress-fingerprint-check: {len(rows)} temuan "
          f"({n_req} request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
