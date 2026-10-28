"""[SAFETY: bounded-requests] beyondtrust-posture — deteksi appliance
BeyondTrust Remote Support / Privileged Remote Access (dulu Bomgar) dari
target URL (F61d; latar: Black October 2026 — auth bypass zero-day
CVE-2026-102764 CVSS 9.3 aktif dieksploitasi, BT26-05, aktor dugaan
China-nexus "ARMORY CASTLE"; CISA imbau patch 2026-10-16; SaaS sudah
dipatch 2026-10-09, on-prem patch sendiri).

Bounded MAKS 3 GET ke path publik /login, /appliance/login, /.
Signature ketat (zero-FP): marker HANYA token eksplisit "beyondtrust"
atau "bomgar" — frasa generik "remote support" TIDAK PERNAH jadi marker.
Versi eksplisit (token bersebelahan angka x.y.z) dicatat sebagai fakta
utk cve-matcher (alias KEV BeyondTrust :: Remote Support/PRA + watchlist
seed CVE-2026-102764). TANPA entri KB: nomor versi fix BT26-05 belum
terverifikasi publik — tidak ada fabrikasi rentang (fail-closed).
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
PROBES = ("/login", "/appliance/login", "/")
_RE_MARKER = re.compile(r"beyondtrust|bomgar", re.I)
_RE_VERSION = re.compile(
    r"(?:beyondtrust|bomgar)[ /v]*(\d+\.\d+\.\d+)", re.I)

_CVE_NOTE = ("Black Oktober 2026: auth bypass zero-day CVE-2026-102764 "
             "(CVSS 9.3, BT26-05) aktif dieksploitasi; nomor versi fix "
             "belum terverifikasi publik — verifikasi manual vs "
             "advisory BT26-05 wajib.")


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): 3 GET (bounded) -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    probes: list[dict] = []
    for path in PROBES:
        if len(probes) >= MAX_GETS:
            break
        try:
            req = urllib.request.Request(
                base + path, method="GET",
                headers={"User-Agent": "cyphron-beyondtrust-posture"})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                body = r.read(32_000).decode("utf-8", "replace")
                headers = dict(r.headers.items())
                status = r.status
        except urllib.error.HTTPError as e:
            body = (e.read(16_000) or b"").decode("utf-8", "replace")
            headers = dict(e.headers.items()) if e.headers else {}
            status = e.code
        except Exception as exc:
            probes.append({"path": path, "status": None,
                           "error": f"{type(exc).__name__}: {exc}"[:120],
                           "marker": False, "version": None})
            continue
        blob = body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())
        vm = _RE_VERSION.search(blob)
        marker = bool(_RE_MARKER.search(blob))
        probes.append({"path": path, "status": status, "marker": marker,
                       "version": vm.group(1) if vm else None,
                       "body_preview": body[:200]})
    detected = [p for p in probes if p.get("marker")]
    versions = sorted({p["version"] for p in detected
                       if p.get("version")})
    responded = [p for p in probes if p.get("status") is not None]
    rows: list[dict] = []
    if detected:
        paths = ", ".join(p["path"] for p in detected)
        ver_s = (f" versi eksplisit: {', '.join(versions)}"
                 if versions else
                 " versi TIDAK terdeteksi eksplisit (verifikasi manual)")
        rows.append(make_finding(
            tool="beyondtrust-posture",
            title=f"Appliance BeyondTrust/Bomgar terdeteksi di {base} "
                  f"({paths})",
            severity="medium",
            description=f"Token eksplisit 'beyondtrust'/'bomgar' di "
                        f"respons {paths}.{ver_s}. {_CVE_NOTE} L1 lead "
                        "— verifikasi versi + paparan manual.",
            recommendation="Terapkan patch BT26-05 pada appliance "
                           "on-prem (SaaS sudah dipatch 2026-10-09); "
                           "audit akun/sesi anomali; upgrade versi "
                           "tidak-didukung.",
            cwe=None, target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests",
                   "probe_paths": [p["path"] for p in detected],
                   "versions": versions}))
        # fakta utk cve-matcher (alias KEV + watchlist BeyondTrust):
        rows.append(make_finding(
            tool="beyondtrust-posture",
            title=f"beyondtrust remote support {versions[0]} appliance "
                  f"terdeteksi di {base}"
                  if versions else
                  f"beyondtrust remote support appliance kandidat di "
                  f"{base} (versi belum eksplisit)",
            severity="info",
            description=f"beyondtrust remote support {versions[0]} "
                        "appliance"
                        if versions else
                        "beyondtrust remote support appliance (versi "
                        "tidak eksplisit)",
            target_url=base,
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests", "kind": "version-fact"}))
    elif not responded:
        # Semua probe gagal jaringan — TIDAK ADA klaim AMAN (fail-closed).
        rows.append(make_finding(
            tool="beyondtrust-posture",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} semua "
                        "gagal jaringan; kegagalan koneksi BUKAN bukti "
                        "tidak-ada-appliance (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests", "network_error": True}))
    else:
        rows.append(make_finding(
            tool="beyondtrust-posture",
            title=f"Tidak ada marker BeyondTrust/Bomgar pada {base}",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} tanpa "
                        "token eksplisit 'beyondtrust'/'bomgar' di "
                        "header/body (AMAN/inventaris, signature "
                        "ketat — frasa generik 'remote support' tidak "
                        "dihitung).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests"}))
    meta = {"url": base, "requests": len(probes),
            "detected": bool(detected), "versions": versions}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="beyondtrust_posture.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"beyondtrust-posture: detected={meta['detected']} "
          f"({meta['requests']} GET) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
