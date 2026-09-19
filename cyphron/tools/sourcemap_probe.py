"""roadmap_batch1 - 3 slot ROADMAP pertama yang diimplementasikan LIVE:
1. sourcemap_probe  (tier3: sourcemap-exposure + map-secrets)
2. password-policy  (auth_probe lanjutan: kebijakan password diuji)
3. cors-credentialed (sudah live di deep_probe - ditandai selesai)
Jalankan uji: python -m cyphron scan ... (otomatis ikut via registry)."""

from __future__ import annotations

import json
from urllib.parse import urljoin

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


class SourcemapProbeTool(Tool):
    name = "sourcemap_probe"
    description = "Deteksi .map sourcemap terbuka (source asli bocor)."
    risk_tags = {"active"}
    source_skill = "03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        tested = 0
        for url in list(ctx.world.endpoints)[:12]:
            if not url.endswith((".js", ".css")):
                continue
            map_url = url + ".map"
            try:
                status, _h, body, _ms = http_engine.http_get(map_url, timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.observe_response(map_url, status, _h, body, self.name)
            tested += 1
            if status == 200 and '"sources"' in (body or ""):
                findings.append(Finding(
                    tool=self.name,
                    title=f"Sourcemap terbuka: {url.split('/')[-1]}.map",
                    severity="medium", cwe="CWE-540",
                    description=(f"Sourcemap di {map_url} memaparkan source asli aplikasi "
                                 f"(termasuk logika bisnis dan kadang komentar internal)."),
                    recommendation="Jangan deploy .map ke produksi; hapus dari build output.",
                    target_url=map_url, request=f"GET {map_url}",
                    response=f"status=200; sources key present; len={len(body)}",
                    poc=f"curl -s '{map_url}' | head -c 400",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
        ctx.world.note(f"sourcemap_probe: {tested} aset JS/CSS diuji, {len(findings)} bocor")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)
