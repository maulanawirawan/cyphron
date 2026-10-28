"""[SAFETY: bounded-requests] magento-surface — deteksi Adobe Commerce /
Magento dari target URL (F66d; latar Black October 2026: CVE-2026-48356
arbitrary file upload -> RCE, masuk CISA KEV 2026-10-27; headline
kampanye 'PolyShell' — detail body belum terverifikasi penuh, jadi
skill ini HANYA inventaris + fakta versi, TANPA klaim rentan).

Bounded MAKS 3 GET: /magento_version (endpoint publik resmi),
/customer/account/login/, /downloader/. Signature ketat: regex
Magento/X.Y.Z untuk versi; token 'magento' word-boundary pada halaman
login/downloader. Versi eksplisit = fakta cve-matcher + watchlist
(token magento) — lead product-level, verifikasi manual wajib.

Zero-FP: halaman generik tanpa token 'magento' tidak dihitung. Tanpa
marker = AMAN. Semua probe gagal jaringan = TANPA klaim AMAN.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 3
TIMEOUT_S = 10.0
PROBES = ("/magento_version", "/customer/account/login/", "/downloader/")
_RE_VER = re.compile(r"Magento/(\d+\.\d+(?:\.\d+)?)", re.I)
_RE_TOKEN = re.compile(r"\bmagento\b", re.I)
_CVE_NOTE = ("Black October 2026: CVE-2026-48356 (arbitrary file "
             "upload -> RCE) masuk CISA KEV 2026-10-27 — entri KEV tidak "
             "membawa version-range; lead product-level, verifikasi "
             "paparan versi manual wajib.")


def _get(base: str, path: str):
    try:
        req = urllib.request.Request(
            base + path, method="GET",
            headers={"User-Agent": "cyphron-magento-surface"})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return (r.status, r.read(64_000).decode("utf-8", "replace"),
                    dict(r.headers.items()))
    except urllib.error.HTTPError as e:
        return (e.code,
                (e.read(16_000) or b"").decode("utf-8", "replace"),
                dict(e.headers.items()) if e.headers else {})
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"[:120], {}


def _hget(headers: dict, name: str) -> str:
    lname = name.lower()
    for k, v in headers.items():
        if str(k).lower() == lname:
            return str(v)
    return ""


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): maks 3 GET -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base

    rows: list[dict] = []
    probes: list[dict] = []
    versions: list[str] = []
    for path in PROBES:
        if len(probes) >= MAX_GETS:
            break
        st, body, hdrs = _get(base, path)
        blob = body + " " + " ".join(f"{k}: {v}" for k, v in hdrs.items())
        ver = None
        m = _RE_VER.search(blob)
        if m:
            ver = m.group(1)
            versions.append(ver)
        marker = bool(_RE_TOKEN.search(blob))
        if path == "/magento_version" and ver:
            marker = True
        probes.append({"path": path, "status": st, "marker": marker,
                       "version": ver, "body_preview": body[:120]})

    detected = [p for p in probes if p.get("marker")]
    responded = [p for p in probes if p.get("status") is not None]

    if detected:
        paths = ", ".join(p["path"] for p in detected)
        ver_s = (f" versi eksplisit: {', '.join(sorted(set(versions)))}"
                 if versions else
                 " versi TIDAK eksplisit (verifikasi manual)")
        rows.append(make_finding(
            tool="magento-surface",
            title=f"Adobe Commerce/Magento terdeteksi di {base} "
                  f"({paths})",
            severity="medium",
            description=f"Token/halaman Magento eksplisit pada {paths}."
                        f"{ver_s}. {_CVE_NOTE}",
            recommendation="Verifikasi versi vs patch Adobe Commerce "
                           "(CPU Okt 2026); pastikan /magento_version "
                           "dan /downloader tidak terekspos publik.",
            cwe=None, target_url=base,
            request=f"GET {'/'.join(p['path'] for p in detected)}",
            response="marker magento" + (f" {versions[0]}"
                                         if versions else ""),
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests",
                   "probe_paths": [p["path"] for p in detected],
                   "versions": sorted(set(versions)),
                   "tech": ("magento " + versions[0]) if versions
                   else "magento"}))
        if versions:
            rows.append(make_finding(
                tool="magento-surface",
                title=f"Versi Magento ter-expose via /magento_version "
                      f"di {base} ({versions[0]})",
                severity="low",
                description=f"Magento/{versions[0]} terlihat pada "
                            "endpoint publik — memudahkan pencocokan "
                            "advisory (lead, bukan klaim rentan).",
                recommendation="Batasi akses /magento_version bila "
                               "memungkinkan; tetap update patch.",
                cwe="CWE-200", target_url=base + "/magento_version",
                request="GET /magento_version -> 200",
                response=f"Magento/{versions[0]}"[:150],
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=1,
                extra={"category": "SURFACE", "safety_class":
                       "bounded-requests", "version": versions[0]}))
    elif not responded:
        rows.append(make_finding(
            tool="magento-surface",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} semua "
                        "gagal jaringan; kegagalan koneksi BUKAN bukti "
                        "tidak-ada-instance (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests", "network_error": True}))
    else:
        rows.append(make_finding(
            tool="magento-surface",
            title=f"Tidak ada marker yang dicari pada {base} "
                  f"({len(probes)} GET)",
            severity="info",
            description="Tidak ada token 'magento' word-boundary / "
                        "Magento/X.Y.Z pada 3 probe — AMAN/inventaris, "
                        "signature ketat.",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests"}))

    meta = {"url": base, "requests": len(probes),
            "detected": bool(detected),
            "versions": sorted(set(versions))}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="magento_surface.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"magento-surface: detected={meta['detected']} "
          f"versions={meta['versions']} ({meta['requests']} GET) -> "
          f"{args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
