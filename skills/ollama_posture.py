"""[SAFETY: bounded-requests] ollama-posture — deteksi API Ollama
yang terbuka dari target URL (F63; latar: Probllama CVE-2024-37032
RCE path-traversal, fix 0.1.34 — Wiz/GHSA; ribuan server Ollama
ter-expose publik; CVE-2026-7482 memory-leak via GGUF crafted menyasar
server ter-expose).

Bounded MAKS 2 GET: /api/version ({"version":"x.y.z"}) + /api/tags
(inventaris model terpasang). Deteksi zero-FP: L1 lead HANYA bila ada
token eksplisit "ollama" di header/body ATAU shape eksklusif
(/api/tags JSON dengan "models"+"name"+"digest"). Versi eksplisit
dicatat sebagai fakta — baris ini jadi sumber fakta utk cve-matcher
(KB operator CVE-2024-37032: v < 0.1.34). Nama model TIDAK dimuat di
temuan (hanya jumlah — inventaris bisa sensitif). Bukan eksploitasi —
deteksi postur infra AI milik sendiri/program terotorisasi.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 2
TIMEOUT_S = 10.0
PROBES = ("/api/version", "/api/tags")
_RE_MARKER = re.compile(r"ollama", re.I)
_RE_VERSION = re.compile(r'[\"\']?version[\"\']?\s*:\s*'
                         r'[\"\']?(\d+\.\d+\.\d+)', re.I)


def _shape_ok(path: str, body: str) -> bool:
    """Shape eksklusif Ollama tanpa token: /api/tags JSON dgn
    "models" berisi item "name"+"digest" (format manifest Ollama)."""
    if path != "/api/tags":
        return False
    try:
        doc = json.loads(body)
    except Exception:  # noqa: BLE001
        return False
    if not isinstance(doc, dict):
        return False
    models = doc.get("models")
    if not isinstance(models, list) or not models:
        return False
    return all(isinstance(m, dict) and "name" in m and "digest" in m
               for m in models)


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): 2 GET (bounded) -> (rows, meta) kontrak."""
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
                headers={"User-Agent": "cyphron-ollama-posture"})
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
        marker = bool(_RE_MARKER.search(blob)) or _shape_ok(path, body)
        if path == "/api/tags":
            try:
                n_models = len(json.loads(body).get("models") or [])
            except Exception:  # noqa: BLE001
                n_models = 0
        probes.append({"path": path, "status": status, "marker": marker,
                       "version": vm.group(1) if vm else None,
                       "body_preview": body[:200]})
    detected = [p for p in probes if p.get("marker")]
    # Versi diambil dari SEMUA probe sukses saat server terdeteksi —
    # versi hidup di /api/version, marker shape di /api/tags.
    versions = sorted({p["version"] for p in probes
                       if p.get("version")}) if detected else []
    responded = [p for p in probes if p.get("status") is not None]
    rows: list[dict] = []
    if detected:
        paths = ", ".join(p["path"] for p in detected)
        ver_s = (f" versi eksplisit: {', '.join(versions)}"
                 if versions else
                 " versi TIDAK terdeteksi eksplisit (verifikasi manual)")
        model_s = (f" {n_models} model terpasang terinventarisasi"
                   if n_models else "")
        rows.append(make_finding(
            tool="ollama-posture",
            title=f"API Ollama terbuka di {base} ({paths})",
            severity="medium",
            description=f"Token eksplisit 'ollama'/shape eksklusif di "
                        f"respons {paths}.{ver_s}.{model_s} API Ollama "
                        "tanpa auth = infra AI ter-expose (Probllama "
                        "CVE-2024-37032 RCE, fix 0.1.34; CVE-2026-7482 "
                        "memory-leak menyasar server ter-expose). L1 "
                        "lead — verifikasi versi + paparan manual.",
            recommendation="Upgrade Ollama >= 0.1.34 (terbaru); jangan "
                           "ekspos 11434 ke internet; OLLAMA_HOST "
                           "127.0.0.1 + reverse-proxy ber-auth bila "
                           "perlu remote.",
            cwe=None, target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "AI", "safety_class": "bounded-requests",
                   "probe_paths": [p["path"] for p in detected],
                   "versions": versions, "models_count": n_models}))
        # fakta utk cve-matcher (allowlist += ollama-posture):
        rows.append(make_finding(
            tool="ollama-posture",
            title=f"ollama {versions[0]} API terdeteksi di {base}"
                  if versions else
                  f"ollama API kandidat di {base} (versi belum eksplisit)",
            severity="info",
            description=f"ollama {versions[0]} API"
                        if versions else
                        "ollama API (versi tidak eksplisit)",
            target_url=base,
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AI", "safety_class": "bounded-requests",
                   "kind": "version-fact"}))
    elif not responded:
        # Semua probe gagal jaringan — TIDAK ADA klaim AMAN (fail-closed).
        rows.append(make_finding(
            tool="ollama-posture",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} semua "
                        "gagal jaringan; kegagalan koneksi BUKAN bukti "
                        "tidak-ada-Ollama (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests", "network_error": True}))
    else:
        rows.append(make_finding(
            tool="ollama-posture",
            title=f"Tidak ada marker Ollama pada {base}",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} tanpa "
                        "token eksplisit 'ollama' ATAU shape eksklusif "
                        "/api/tags (AMAN/inventaris, signature ketat).",
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
    ap.add_argument("--out", default="ollama_posture.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"ollama-posture: detected={meta['detected']} "
          f"({meta['requests']} GET) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
