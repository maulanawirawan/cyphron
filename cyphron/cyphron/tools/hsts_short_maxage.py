"""hsts_short_maxage — HSTS ada tapi max-age pendek (<30 hari) atau tanpa
includeSubDomains pada apex (CWE-319, low posture).

Guard: HSTS hilang total = note (missing header non-claim umum — wilayah
tls_audit); max-age >= 30 hari = sehat; 1 GET per run; posture.
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_MIN_MAXAGE = 30 * 24 * 3600  # 30 hari


class HstsShortMaxageTool(Tool):
    name = "hsts_short_maxage"
    description = ("HSTS max-age < 30 hari / tanpa includeSubDomains — "
                   "sub-syarat posture; HSTS hilang = note (wilayah tls_audit).")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        ctx.throttle()
        st, hd, _b, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        hsts = (hd or {}).get("Strict-Transport-Security", "")
        data = {"status": st, "hsts": hsts or None}
        if not hsts:
            data["note"] = ("HSTS tidak diset — missing header non-claim "
                            "umum; wilayah tls_audit")
            return ToolResult(tool=self.name, ok=True, data=data)
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if not m:
            data["note"] = "max-age tidak bisa diparse"
            return ToolResult(tool=self.name, ok=True, data=data)
        maxage = int(m.group(1))
        data["max_age"] = maxage
        issues: list[str] = []
        if maxage < _MIN_MAXAGE:
            issues.append(f"max-age {maxage}s < 30 hari")
        if "includesubdomains" not in hsts.lower() and \
                args.get("expect_subdomains"):
            issues.append("includeSubDomains tidak ada pada apex")
        data["issues"] = issues
        if not issues:
            data["note"] = "HSTS sehat"
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"HSTS short max-age: {issues[0]}",
            severity="low", cwe="CWE-319",
            description=(f"HSTS {hsts!r} di {url}: {'; '.join(issues)} — "
                         f"window downgrade-SSL terbuka lebih panjang dari "
                         f"perlu. finding_class=posture."),
            recommendation=("Naikkan max-age >= 31536000 bertahap; tambahkan "
                            "includeSubDomains bila semua subdomain aman."),
            target_url=url, request=f"GET {url}",
            response=f"Strict-Transport-Security: {hsts}",
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="header",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
