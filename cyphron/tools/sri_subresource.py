"""sri_missing_subresource — skrip PIHAK KETIGA tanpa SRI (CWE-827, low
posture). Lanjutan sri_audit (fokus: subresource eksternal lintas-origin).

Guard: hanya <script src> lintas-host yang dinilai; same-origin/relative
dikecualikan; integrity= (SRI) yang ada = sehat; 1 GET per run.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_SCRIPT_TAG_RE = re.compile(
    r"<script[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.I)
_INTEGRITY_RE = re.compile(r"integrity\s*=", re.I)
_CDN_HOSTS = ("googleapis", "gstatic", "jsdelivr", "unpkg", "cloudflare",
              "cdnjs", "bootstrapcdn", "js.", "cdn.")


class SriSubresourceTool(Tool):
    name = "sri_missing_subresource"
    description = ("Skrip pihak ketiga (CDN/lintas-host) tanpa integrity="
                   " — posture low; same-origin dikecualikan.")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        host = (urlsplit(url).hostname or "").lower()
        ctx.throttle()
        st, _h, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        missing: list[str] = []
        with_sri = 0
        for match in _SCRIPT_TAG_RE.finditer(body or ""):
            full_tag, tag = match.group(0), match.group(1)
            src_host = (urlsplit(tag if "//" in tag else
                                 f"http://{tag}").hostname or "").lower()
            if not src_host or src_host == host or src_host.endswith(
                    "." + host):
                continue  # same-origin: bukan domain SRI
            if _INTEGRITY_RE.search(full_tag):
                with_sri += 1
                continue
            missing.append(src_host)
        data = {"status": st, "third_party_scripts": len(missing) + with_sri,
                "missing_hosts": sorted(set(missing))[:8],
                "with_sri": with_sri}
        if not missing:
            data["note"] = "semua subresource pihak ketiga ber-SRI (atau kosong)"
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"{len(missing)} third-party script(s) without SRI "
                  f"({', '.join(sorted(set(missing))[:3])})",
            severity="low", cwe="CWE-827",
            description=(f"Skrip dari host pihak ketiga "
                         f"({', '.join(sorted(set(missing))[:5])}) dimuat "
                         f"TANPA integrity= — kompromi CDN/host itu "
                         f"(atau DNS/hijack) langsung menjadi eksekusi "
                         f"skrip di halaman target. finding_class=posture."),
            recommendation=("Tambah integrity + crossorigin untuk semua "
                            "subresource lintas-origin; self-host skrip "
                            "kritis."),
            target_url=url, request=f"GET {url}",
            response=f"missing SRI hosts={sorted(set(missing))[:5]}",
            confidence=0.9, source_skill=self.source_skill,
            status="confirmed", evidence_kind="file",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
