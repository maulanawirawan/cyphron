"""[SAFETY: bounded-requests] vllm-posture — deteksi server vLLM yang
terbuka dari target URL (F64a; latar: recon infra AI — vLLM adalah
serving engine OpenAI-compatible paling umum; /metrics Prometheus
TERBUKA default berisi puluhan metrik "vllm:*" (info-leak + signature
kuat), /v1/models tanpa auth = inventaris model).

Bounded MAKS 3 GET: /metrics, /version, /v1/models.
Deteksi zero-FP: L1 lead HANYA bila token eksplisit "vllm" (termasuk
prefiks metrik "vllm:" di /metrics) di header/body. /v1/models
shape-generik OpenAI TIDAK PERNAH jadi marker sendirian (dipakai
litellm/vLLM/OpenAI — anti-FP antar-gateway). Versi eksplisit dari
/version dicatat sebagai fakta utk cve-matcher. Bukan eksploitasi —
deteksi postur infra AI milik sendiri/program terotorisasi.
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
PROBES = ("/metrics", "/version", "/v1/models")
_RE_MARKER = re.compile(r"\bvllm\b|vllm:", re.I)
_RE_VERSION = re.compile(r'[\"\']?version[\"\']?\s*[:=]\s*'
                         r'[\"\']?(\d+\.\d+\.\d+)', re.I)


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): 3 GET (bounded) -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    probes: list[dict] = []
    n_models = 0
    for path in PROBES:
        if len(probes) >= MAX_GETS:
            break
        try:
            req = urllib.request.Request(
                base + path, method="GET",
                headers={"User-Agent": "cyphron-vllm-posture"})
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
        if path == "/v1/models" and '"data"' in body and '"id"' in body:
            try:
                import json
                n_models = len(json.loads(body).get("data") or [])
            except Exception:  # noqa: BLE001
                n_models = 0
        probes.append({"path": path, "status": status, "marker": marker,
                       "version": vm.group(1) if vm else None,
                       "body_preview": body[:200]})
    detected = [p for p in probes if p.get("marker")]
    # Versi dari SEMUA probe sukses saat server terdeteksi.
    versions = sorted({p["version"] for p in probes
                       if p.get("version")}) if detected else []
    responded = [p for p in probes if p.get("status") is not None]
    rows: list[dict] = []
    if detected:
        paths = ", ".join(p["path"] for p in detected)
        ver_s = (f" versi eksplisit: {', '.join(versions)}"
                 if versions else
                 " versi TIDAK terdeteksi eksplisit (verifikasi manual)")
        model_s = (f" {n_models} model tersaji tanpa auth"
                   if n_models else "")
        rows.append(make_finding(
            tool="vllm-posture",
            title=f"Server vLLM terdeteksi di {base} ({paths})",
            severity="medium",
            description=f"Token eksplisit 'vllm' di respons {paths}."
                        f"{ver_s}.{model_s} /metrics Prometheus terbuka "
                        "= info-leak operasional; /v1/models tanpa auth "
                        "= inventaris model terekspos. L1 lead — "
                        "verifikasi versi + paparan manual.",
            recommendation="Jangan ekspos vLLM ke internet tanpa auth "
                           "(API-key/gateway); matikan/tutup /metrics "
                           "dari jaringan publik; pantau CVE vLLM "
                           "untuk versi terpasang.",
            cwe=None, target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "AI", "safety_class": "bounded-requests",
                   "probe_paths": [p["path"] for p in detected],
                   "versions": versions, "models_count": n_models}))
        # fakta utk cve-matcher (allowlist += vllm-posture):
        rows.append(make_finding(
            tool="vllm-posture",
            title=f"vllm {versions[0]} server terdeteksi di {base}"
                  if versions else
                  f"vllm server kandidat di {base} (versi belum "
                  "eksplisit)",
            severity="info",
            description=f"vllm {versions[0]} server"
                        if versions else
                        "vllm server (versi tidak eksplisit)",
            target_url=base,
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AI", "safety_class": "bounded-requests",
                   "kind": "version-fact"}))
    elif not responded:
        # Semua probe gagal jaringan — TIDAK ADA klaim AMAN (fail-closed).
        rows.append(make_finding(
            tool="vllm-posture",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} semua "
                        "gagal jaringan; kegagalan koneksi BUKAN bukti "
                        "tidak-ada-vLLM (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests", "network_error": True}))
    else:
        rows.append(make_finding(
            tool="vllm-posture",
            title=f"Tidak ada marker vLLM pada {base}",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} tanpa "
                        "token eksplisit 'vllm' di header/body "
                        "(AMAN/inventaris, signature ketat — shape "
                        "generik OpenAI /v1/models tidak dihitung).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests"}))
    meta = {"url": base, "requests": len(probes),
            "detected": bool(detected), "versions": versions,
            "models_count": n_models}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="vllm_posture.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"vllm-posture: detected={meta['detected']} "
          f"({meta['requests']} GET) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
