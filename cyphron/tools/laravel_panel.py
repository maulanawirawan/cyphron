"""laravel_panel — Laravel Telescope / Horizon / Ignition exposure (HIGH).

Konteks lapangan (BINUS BB-003): target Laravel dengan APP_DEBUG=true.
Layar debug bukan satu-satunya permukaan: /telescope (request inspector),
/horizon (queue dashboard), dan /_ignition/health-check (Ignition aktif —
CVE-2021-3129 RCE class pada versi rentan). Semua cukup 1 GET untuk
memastikan keterbukaan — DETEKSI SAJA, tanpa eksploitasi.

FP-guard:
  - Telescope: halaman harus memuat marker "Telescope" + laravel route,
    bukan sekadar 200;
  - Horizon: marker "Horizon dashboard";
  - Ignition health-check: HTTP 200 + body "ok"/"READY" — 404 = tidak ada;
  - semua request GET, nol POST, nol eksploitasi CVE.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

# FP lapangan 2026-09: regex longgar ("up" match "Sign up", "ok" match
# catch-all GitLab) menghasilkan 12 FP — fingerprint WAJIB ketat:
# title-tag spesifik utk Telescope/Horizon; Ignition body EXACT "READY".
_CHECKS = (
    ("/telescope", re.compile(r"<title>[^<]*Telescope", re.I),
     "Laravel Telescope", "inspector request/database terbuka publik"),
    ("/horizon", re.compile(r"<title>[^<]*Horizon", re.I),
     "Laravel Horizon", "dashboard queue/failed jobs terbuka publik"),
    ("/_ignition/health-check", re.compile(r"^\s*READY\s*$"),
     "Laravel Ignition", "error-page service aktif — pada versi lama membuka "
     "CVE-2021-3129 (RCE via log poisoning)"),
)


class LaravelPanelTool(Tool):
    name = "laravel_panel"
    description = ("Laravel Telescope/Horizon/Ignition exposure check — "
                   "GET-only, deteksi saja tanpa eksploitasi CVE.")
    risk_tags = {"active"}
    source_skill = "manual-bb-16"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        data: dict = {"host": host, "checks": []}
        findings: list[Finding] = []
        for path, pattern, product, impact in _CHECKS:
            if ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(
                    urljoin(base + "/", path.lstrip("/")), timeout=ctx.timeout_s,
                    follow_redirects=False)
            except Exception as e:
                data["checks"].append({"path": path, "error": type(e).__name__})
                continue
            ctx.world.request_count += 1
            # FP-guard: redirect/catch-all/cross-host tidak dihitung exposed
            if not isinstance(st, int) or st in (301, 302, 303, 307, 308, 401,
                                                 403, 404):
                data["checks"].append({"path": path, "status": st,
                                       "exposed": False})
                continue
            hit = bool(re.search(pattern, body or ""))
            data["checks"].append({"path": path, "status": st, "exposed": hit})
            if not hit:
                continue
            severity = "high" if product != "Laravel /up route" else "info"
            findings.append(Finding(
                tool=self.name,
                title=f"Laravel debug tool exposed: {product} on {host}{path}",
                severity=severity, cwe="CWE-489",
                description=(
                    f"{product} dapat diakses publik di {host}{path} (HTTP {st}, "
                    f"fingerprint cocok) — {impact}. Penduga framework Laravel "
                    f"membuat permukaan ini layak diperiksa tim: satu-satunya "
                    f"perlindungan yang lazim untuk alat debug adalah mematikan "
                    f"di produksi."),
                recommendation=(
                    "Matikan/misahkan alat debug di produksi: Telescope="
                    "false, Horizon hanya di jaringan internal, Ignition "
                    "dinonaktifkan (APP_DEBUG=false) dan framework "
                    "diperbarui."),
                target_url=base,
                request=f"GET {path}",
                response=f"HTTP {st}; fingerprint '{product}' cocok",
                confidence=0.95, source_skill=self.source_skill,
                status="confirmed", evidence_kind="header"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
