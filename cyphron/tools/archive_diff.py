"""archive_wayback_diff — endpoint terlupakan dari arsip yang masih HIDUP
sekarang (CWE-775-class, info->medium surface).

Roadmap: "wayback URL yang 200 sekarang vs dulu (endpoint terlupakan)".
Input: daftar URL dari wayback CDX (pengguna jalankan WaybackTool dulu).
Engine: 1 GET per URL arsip (maks 6) ->
  - 200 = endpoint lama masih hidup (lead: fitur lama tidak diaudit);
  - 404/410 = sudah dibersihkan (postur baik);
  - redirect = dicatat sebagai info.
Guard: hanya URL dari args; konten TIDAK disimpan (excerpt 80 char
redacted); hasil = surface (non-claim umum); cease-on-data tidak berlaku
karena tiap URL independen — tapi berhenti di max_requests.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding


class ArchiveDiffTool(Tool):
    name = "archive_wayback_diff"
    description = ("Cek URL arsip wayback yang masih 200 sekarang (endpoint "
                   "terlupakan). Surface intel; konten tidak disimpan.")
    risk_tags = {"external", "passive"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        urls = [str(u) for u in (args.get("urls") or [])][:6]
        if not urls:
            return ToolResult(tool=self.name, ok=False,
                              error="args.urls (dari wayback CDX) wajib")
        data: dict = {"checked": 0, "results": []}
        findings: list[Finding] = []
        for u in urls:
            if ctx.world.request_count >= ctx.max_requests:
                break
            host = (urlsplit(u).hostname or "").lower()
            if not host:
                continue
            try:
                ctx.throttle()
                st, _h, body, _ms = http_engine.http_get(
                    u, timeout=ctx.timeout_s)
            except Exception as e:
                data["results"].append({"url": u,
                                        "error": type(e).__name__})
                continue
            ctx.world.request_count += 1
            data["checked"] += 1
            verdict = {200: "live", 404: "gone", 410: "gone"}.get(
                st, f"status-{st}")
            data["results"].append({"url": u, "status": st,
                                    "verdict": verdict})
            if verdict == "live":
                findings.append(Finding(
                    tool=self.name,
                    title=f"Archived endpoint still live: {u}",
                    severity="info", cwe="CWE-775",
                    description=(
                        f"URL yang terarsip wayback masih merespons 200 — "
                        f"endpoint lama yang mungkin terlewat dari audit "
                        f"(fitur deprecated, autentikasi lama). Lead untuk "
                        f"diperiksa manual; surface non-claim umum; konten "
                        f"tidak disimpan (cease-on-data)."),
                    recommendation=("Inventaris endpoint; matikan route lama "
                                    "(410); audit authz versi lama."),
                    target_url=u,
                    request=f"GET {u}",
                    response=f"status=200; excerpt={redact((body or '')[:80])!r}",
                    confidence=0.7, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response",
                    finding_class="surface"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
