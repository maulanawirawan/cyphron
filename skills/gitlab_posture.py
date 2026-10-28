"""[SAFETY: bounded-requests] gitlab-posture — deteksi instance GitLab
self-managed dari target URL (F61c; latar: Black October 2026 — RCE
unauthenticated CVE-2026-110264 CVSS 10.0, integer overflow kompilasi
regex, ada sejak GitLab 7.0/2014; per 2026-10-25 belum masuk CISA KEV;
path traversal CVE-2026-85706 CVSS 10.0 pendampingnya dilaporkan aktif).

Bounded MAKS 3 GET ke path publik /users/sign_in, /help, /explore.
Deteksi zero-FP: L1 lead HANYA bila ada token eksplisit "gitlab" di
header ATAU body respons (tanpa token = AMAN, tanpa tebakan). Versi
eksplisit (token "gitlab" bersebelahan angka x.y.z) dicatat sebagai
fakta — baris ini menjadi sumber fakta utk cve-matcher (KB operator
multi-branch CVE-2026-110264). Bukan eksploitasi — deteksi postur
instalasi milik sendiri/program terotorisasi.
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
PROBES = ("/users/sign_in", "/help", "/explore")
_RE_MARKER = re.compile(r"gitlab", re.I)
_RE_VERSION = re.compile(r"gitlab[ /v-]*(\d+\.\d+\.\d+)", re.I)

# Rujukan tetap di deskripsi (Black October 2026):
_CVE_NOTE = ("Keluarga GitLab self-managed Black Oktober 2026: RCE "
             "unauth CVE-2026-110264 (CVSS 10.0, regex engine, fix "
             "18.11.13/19.0.10/19.1.9/19.2.9/19.3.6/19.4.3/19.5.1) + "
             "path traversal CVE-2026-85706 (CVSS 10.0, aktif).")


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
            req = urllib.request.Request(base + path, method="GET",
                                         headers={"User-Agent":
                                                  "cyphron-gitlab-posture"})
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
            tool="gitlab-posture",
            title=f"Instance GitLab terdeteksi di {base} ({paths})",
            severity="medium",
            description=f"Token eksplisit 'gitlab' di respons {paths}."
                        f"{ver_s}. {_CVE_NOTE} L1 lead — verifikasi "
                        "versi + paparan manual.",
            recommendation="Verifikasi versi GitLab secara manual; "
                           "self-managed < 18.11.13/19.0.10/19.1.9/"
                           "19.2.9/19.3.6/19.4.3/19.5.1 = patch "
                           "CVE-2026-110264 segera (advisory GitLab "
                           "19.5.1).",
            cwe=None, target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests",
                   "probe_paths": [p["path"] for p in detected],
                   "versions": versions}))
        # fakta utk cve-matcher (tool ini masuk ALLOWED_SOURCE_TOOLS):
        rows.append(make_finding(
            tool="gitlab-posture",
            title=f"gitlab {versions[0]} instance terdeteksi di {base}"
                  if versions else
                  f"gitlab instance kandidat di {base} (versi belum "
                  "eksplisit)",
            severity="info",
            description=f"gitlab {versions[0]} instance"
                        if versions else
                        "gitlab instance (versi tidak eksplisit)",
            target_url=base,
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests", "kind": "version-fact"}))
    elif not responded:
        # Semua probe gagal jaringan — TIDAK ADA klaim AMAN (fail-closed).
        rows.append(make_finding(
            tool="gitlab-posture",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} semua "
                        "gagal jaringan; kegagalan koneksi BUKAN bukti "
                        "tidak-ada-GitLab (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests", "network_error": True}))
    else:
        rows.append(make_finding(
            tool="gitlab-posture",
            title=f"Tidak ada marker GitLab pada {base}",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} tanpa "
                        "token eksplisit 'gitlab' di header/body "
                        "(AMAN/inventaris, signature ketat).",
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
    ap.add_argument("--out", default="gitlab_posture.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"gitlab-posture: detected={meta['detected']} "
          f"({meta['requests']} GET) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
