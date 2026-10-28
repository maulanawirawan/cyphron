"""[SAFETY: bounded-requests] litellm-posture — deteksi proxy LiteLLM
dari target URL (F56; latar: gelombang CVE LiteLLM 2026 — RCE unauth
CVE-2026-42271 masuk CISA KEV, SQLi pre-auth CVE-2026-42208 rentan
v1.81.16-<1.83.7, SSRF CVE-2026-59823, PyPI 1.82.7/1.82.8 beracun).

Bounded MAKS 3 GET ke path /version, /health/liveliness, /v1/models.
Deteksi zero-FP: L1 lead HANYA bila ada token eksplisit "litellm" di
header ATAU body respons (tanpa token = AMAN, tanpa tebakan). Versi
eksplicit (regex "version": "x.y.z") dicatat sebagai fakta — baris ini
menjadi sumber fakta utk cve-matcher (KB operator + KEV BerriAI ::
LiteLLM). Bukan eksploitasi — deteksi postur infrastruktur LLM milik
sendiri/program terotorisasi.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 3
TIMEOUT_S = 10.0
PROBES = ("/version", "/health/liveliness", "/v1/models")
_RE_MARKER = re.compile(r"litellm", re.I)
_RE_VERSION = re.compile(
    r"[\"']?version[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.I)


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
                                                  "cyphron-litellm-posture"})
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
        # marker eksplisit: token "litellm" ATAU shape endpoint /version
        # milik proxy litellm (JSON dgn status+version bersama) —
        # kombinasi keduanya = kandidat kuat, tetap L1 (verifikasi manual)
        shape_ok = (path == "/version" and '"status"' in body
                    and '"version"' in body and vm)
        marker = bool(_RE_MARKER.search(blob)) or shape_ok
        probes.append({"path": path, "status": status, "marker": marker,
                       "version": vm.group(1) if vm else None,
                       "body_preview": body[:200]})
    detected = [p for p in probes if p.get("marker")]
    versions = sorted({p["version"] for p in detected
                       if p.get("version")})
    rows: list[dict] = []
    if detected:
        paths = ", ".join(p["path"] for p in detected)
        ver_s = (f" versi eksplisit: {', '.join(versions)}"
                 if versions else
                 " versi TIDAK terdeteksi eksplisit (verifikasi manual)")
        rows.append(make_finding(
            tool="litellm-posture",
            title=f"Proxy LiteLLM terdeteksi di {base} ({paths})",
            severity="medium",
            description=f"Token eksplisit 'litellm' di respons "
                        f"{paths}.{ver_s}. Keluarga LiteLLM 2026 punya "
                        "CVE aktif: RCE unauth CVE-2026-42271 (CISA "
                        "KEV), SQLi pre-auth CVE-2026-42208 (<1.83.7), "
                        "SSRF CVE-2026-59823; PyPI 1.82.7/1.82.8 "
                        "beracun. L1 lead — verifikasi versi + paparan "
                        "manual.",
            recommendation="Upgrade LiteLLM >= 1.83.7 (hindari "
                           "1.82.7/1.82.8), jangan ekspos proxy ke "
                           "internet tanpa auth, cek panduan KEV CISA.",
            cwe=None, target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "AI", "safety_class": "bounded-requests",
                   "probe_paths": [p["path"] for p in detected],
                   "versions": versions}))
        # fakta utk cve-matcher (tool ini ada di ALLOWED_SOURCE_TOOLS):
        rows.append(make_finding(
            tool="litellm-posture",
            title=f"litellm {versions[0]} proxy terdeteksi di {base}"
                  if versions else
                  f"litellm proxy kandidat di {base} (versi belum eksplisit)",
            severity="info",
            description=f"litellm {versions[0]} proxy"
                        if versions else
                        "litellm proxy (versi tidak eksplisit)",
            target_url=base,
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests", "kind": "version-fact"}))
    else:
        rows.append(make_finding(
            tool="litellm-posture",
            title=f"Tidak ada marker LiteLLM pada {base}",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} tanpa "
                        "token eksplisit 'litellm' di header/body "
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
    ap.add_argument("--out", default="litellm_posture.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"litellm-posture: detected={meta['detected']} "
          f"({meta['requests']} GET) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
