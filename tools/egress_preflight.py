"""[F37] Preflight egress — cek kesehatan jalur keluar SEBELUM scan.

Masalah yang diselesaikan (dari demo live-target 2026-10-19): 4 dari 17
skill gagal murni karena lingkungan (UDP 53 diblokir VPN, CDX timeout),
dan pembaca laporan tidak punya cara membedakan "target bermasalah" dari
"jaringan lokal bermasalah". Preflight menjawabnya SEKALI di awal run:
  - DoH 443  : HTTPS ke resolver publik (jalur yang hampir selalu lolos)
  - UDP 53   : DNS klasik (sering diblokir VPN/korporat)
  - TCP 53   : jalur AXFR (dibutuhkan dns-axfr-check)
Hasil: JSON status + daftar dampak per kemampuan. NOL request ke target
— hanya ke infrastruktur resolver publik (2-3 request, bounded).

Pemakaian:
  python tools/egress_preflight.py --out findings/egress-state.json
  python tools/egress_preflight.py --text   # cetak ringkas
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import write_findings  # noqa: E402  (untuk --findings mode)
from ua import user_agent  # noqa: E402
import dns_light  # noqa: E402

UA = user_agent()
TIMEOUT = 5.0
PROBE_DOMAIN = "example.com"  # domain uji netral (RFC 2606)


def check_doh(timeout: float = TIMEOUT) -> dict:
    """DoH JSON (Cloudflare) lewat HTTPS 443."""
    url = ("https://cloudflare-dns.com/dns-query?name="
           f"{PROBE_DOMAIN}&type=A")
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": "application/dns-json"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(4096).decode("utf-8", "replace"))
        ok = data.get("Status") == 0
        return {"check": "doh-443", "ok": ok,
                "detail": f"status={data.get('Status')}",
                "elapsed_s": round(time.monotonic() - t0, 2)}
    except Exception as exc:
        return {"check": "doh-443", "ok": False,
                "detail": type(exc).__name__, "elapsed_s": 0.0}


def check_udp53(timeout: float = TIMEOUT) -> dict:
    """DNS klasik via UDP 53 (yang sering diblokir VPN/korporat)."""
    t0 = time.monotonic()
    res = dns_light.udp_query("1.1.1.1", PROBE_DOMAIN, dns_light.QTYPE_A,
                              timeout=timeout)
    return {"check": "udp-53", "ok": res is not None,
            "detail": ("rcode=%d" % res["rcode"]) if res else "timeout/blok",
            "elapsed_s": round(time.monotonic() - t0, 2)}


def check_tcp53(timeout: float = TIMEOUT) -> dict:
    """TCP 53 (jalur AXFR) — connect + query ringan, hanya ke 1.1.1.1."""
    t0 = time.monotonic()
    try:
        query = dns_light.build_query(PROBE_DOMAIN, dns_light.QTYPE_A)
        with socket.create_connection(("1.1.1.1", 53), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(struct.pack(">H", len(query)) + query)
            hdr = s.recv(2)
            ok = len(hdr) == 2
        return {"check": "tcp-53", "ok": ok,
                "detail": "jawaban diterima" if ok else "koneksi terputus",
                "elapsed_s": round(time.monotonic() - t0, 2)}
    except (OSError, ValueError):
        return {"check": "tcp-53", "ok": False,
                "detail": "timeout/blok", "elapsed_s": 0.0}


# kemampuan produk yang terdampak bila jalur tertentu mati
IMPACT = {
    "udp-53": ["baca record DNS klasik (spf-dmarc-posture)"],
    "tcp-53": ["zone transfer AXFR (dns-axfr-check)"],
    "doh-443": ["fallback DNS + sumber DoH"],
}


def run_preflight() -> dict:
    checks = [check_doh(), check_udp53(), check_tcp53()]
    blocked = [c["check"] for c in checks if not c["ok"]]
    impact: list[str] = []
    for c in checks:
        if not c["ok"]:
            impact.extend(IMPACT.get(c["check"], []))
    return {
        "checked_at_epoch": int(time.time()),
        "checks": checks,
        "all_ok": not blocked,
        "blocked": blocked,
        "impact": sorted(set(impact)),
        "note": ("semua jalur egress sehat" if not blocked else
                 f"{len(blocked)} jalur terblokir — skill yang terdampak "
                 "akan masuk section fail-closed laporan (bukan masalah "
                 "target); ulangi saat jaringan sehat"),
    }


def render_text(state: dict) -> str:
    lines = ["Preflight egress:"]
    for c in state["checks"]:
        mark = "OK " if c["ok"] else "BLOK"
        lines.append(f"  [{mark}] {c['check']:8} {c['detail']} "
                     f"({c['elapsed_s']}s)")
    if state["impact"]:
        lines.append("  dampak: " + "; ".join(state["impact"]))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=None,
                    help="tulis state JSON ke file (untuk report_pdf --egress)")
    ap.add_argument("--text", action="store_true", help="cetak ringkas")
    args = ap.parse_args()
    state = run_preflight()
    if args.text or not args.out:
        print(render_text(state))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(state, indent=1),
                                  encoding="utf-8")
        print(f"state egress -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
