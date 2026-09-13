"""server_banner_soft — Server/X-Powered-By tanpa utilitas serangan
(CWE-200, info posture higienis).

Roadmap: "Server/X-Powered-By tanpa versi (higienis)". Banner HANYA dicatat
bila mengandung versi produk eksplisit (nginx/1.24, PHP/8.2.1) — banner
generik tanpa versi = postur biasa (note). 1 GET per run.
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                   "x-aspnetmvc-version", "x-generator")
_VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")


class ServerBannerSoftTool(Tool):
    name = "server_banner_soft"
    description = ("Banner server dengan VERSI eksplisit = info posture; "
                   "banner generik/hilang = note.")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        ctx.throttle()
        st, hd, _b, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        banners = {k: v for k, v in (hd or {}).items()
                   if k.lower() in _BANNER_HEADERS and v}
        data = {"banners": banners, "versioned": {}}
        for k, v in banners.items():
            m = _VERSION_RE.search(v)
            if m:
                data["versioned"][k] = v[:60]
        if not data["versioned"]:
            data["note"] = ("banner generik/absen — postur biasa, bukan "
                            "temuan")
            return ToolResult(tool=self.name, ok=True, data=data)
        versioned = "; ".join(f"{k}: {v}" for k, v in
                              data["versioned"].items())
        findings = [Finding(
            tool=self.name,
            title=f"Server banner discloses product version "
                  f"({', '.join(data['versioned'])})",
            severity="info", cwe="CWE-200",
            description=(f"Header respons memaparkan versi produk "
                         f"({versioned}) — mempermudah pencarian CVE pasif "
                         f"oleh penyerang. Higienis: qualifying atau tidak "
                         f"mengikuti rules program (umumnya non-claim). "
                         f"finding_class=posture."),
            recommendation=("Sembunyikan/normalisasi banner (server_tokens "
                            "off, expose_php off, remove X-Powered-By)."),
            target_url=url, request=f"GET {url}",
            response=versioned,
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="header",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
