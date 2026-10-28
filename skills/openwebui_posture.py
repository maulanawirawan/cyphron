"""[SAFETY: bounded-requests] openwebui-posture — deteksi Open WebUI
(antarmuka web untuk Ollama/OpenAI-compatible) yang terbuka dari
target URL (F64b; latar: recon infra AI — Open WebUI sering ter-expose
publik membawa riwayat chat + kunci API provider di konfigurasi).

Bounded MAKS 3 GET: /api/config, /api/version, /health.
Deteksi zero-FP: L1 lead HANYA bila token eksplisit "open-webui" /
"openwebui" / "open webui" di header/body. Shape {"version":"x.y.z"}
generik TIDAK PERNAH jadi marker sendirian (dipakai Ollama/Open WebUI
— anti-FP antar-gateway). Versi eksplisit dari /api/version dicatat
sebagai fakta utk cve-matcher. Bukan eksploitasi — deteksi postur
infra AI milik sendiri/program terotorisasi.
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
PROBES = ("/api/config", "/api/version", "/health")
_RE_MARKER = re.compile(r"open[\-_ ]?webui", re.I)
_RE_VERSION = re.compile(r'[\"\']?version[\"\']?\s*:\s*'
                         r'[\"\']?(\d+\.\d+\.\d+)', re.I)


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
                headers={"User-Agent": "cyphron-openwebui-posture"})
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
    versions = sorted({p["version"] for p in probes
                       if p.get("version")}) if detected else []
    responded = [p for p in probes if p.get("status") is not None]
    rows: list[dict] = []
    if detected:
        paths = ", ".join(p["path"] for p in detected)
        ver_s = (f" versi eksplisit: {', '.join(versions)}"
                 if versions else
                 " versi TIDAK terdeteksi eksplisit (verifikasi manual)")
        rows.append(make_finding(
            tool="openwebui-posture",
            title=f"Open WebUI terdeteksi di {base} ({paths})",
            severity="medium",
            description=f"Token eksplisit 'open-webui' di respons "
                        f"{paths}.{ver_s} Open WebUI ter-expose membawa "
                        "riwayat chat multi-user + konfigurasi koneksi "
                        "ke provider LLM (kunci API di sisi server). "
                        "L1 lead — verifikasi paparan + auth manual.",
            recommendation="Jangan ekspos Open WebUI tanpa auth ke "
                           "internet (ENABLE_SIGNUP=false, auth wajib); "
                           "pantau CVE Open WebUI utk versi terpasang.",
            cwe=None, target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "AI", "safety_class": "bounded-requests",
                   "probe_paths": [p["path"] for p in detected],
                   "versions": versions}))
        # fakta utk cve-matcher (allowlist += openwebui-posture):
        rows.append(make_finding(
            tool="openwebui-posture",
            title=f"open-webui {versions[0]} terdeteksi di {base}"
                  if versions else
                  f"open-webui kandidat di {base} (versi belum eksplisit)",
            severity="info",
            description=f"open webui {versions[0]} instance"
                        if versions else
                        "open webui instance (versi tidak eksplisit)",
            target_url=base,
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AI", "safety_class": "bounded-requests",
                   "kind": "version-fact"}))
    elif not responded:
        # Semua probe gagal jaringan — TIDAK ADA klaim AMAN (fail-closed).
        rows.append(make_finding(
            tool="openwebui-posture",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} semua "
                        "gagal jaringan; kegagalan koneksi BUKAN bukti "
                        "tidak-ada-OpenWebUI (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests", "network_error": True}))
    else:
        rows.append(make_finding(
            tool="openwebui-posture",
            title=f"Tidak ada marker Open WebUI pada {base}",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} tanpa "
                        "token eksplisit 'open-webui' di header/body "
                        "(AMAN/inventaris, signature ketat — shape "
                        "version generik tidak dihitung).",
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
    ap.add_argument("--out", default="openwebui_posture.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"openwebui-posture: detected={meta['detected']} "
          f"({meta['requests']} GET) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
