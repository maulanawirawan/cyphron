"""referrer_policy_loose — Referrer-Policy longgar: unsafe-url /
no-referrer-when-downgrade (CWE-693, low posture).

Guard: nilai ketat (no-referrer, same-origin, strict-origin*) = sehat;
header hilang = note saja (missing header non-claim umum); 1 GET per run.
"""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_LOOSE = {"unsafe-url": "URL penuh (termasuk path+query) bocor ke pihak "
                        "ketiga",
          "no-referrer-when-downgrade": "path/query tetap bocor pada "
                                        "same-origin navigasi ke origin lain",
          "origin-when-cross-origin": "path/query tetap bocor same-origin"}


class ReferrerPolicyLooseTool(Tool):
    name = "referrer_policy_loose"
    description = ("Referrer-Policy longgar (unsafe-url / "
                   "no-referrer-when-downgrade) — posture; hilang = note.")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        ctx.throttle()
        st, hd, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        policy = (hd or {}).get("Referrer-Policy", "").strip().lower()
        meta_policy = ""
        for line in (body or "").lower().splitlines():
            if "referrer" in line and "content=" in line:
                meta_policy = line
                break
        data = {"status": st, "policy": policy or None}
        value = policy or (meta_policy and policy)
        effective = policy or ("meta-detected" if meta_policy else "")
        if not effective:
            data["note"] = ("Referrer-Policy tidak diset — missing header "
                            "non-claim umum; intel saja")
            return ToolResult(tool=self.name, ok=True, data=data)
        issue = _LOOSE.get(policy)
        if not issue:
            data["note"] = "policy ketat"
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"Referrer-Policy loose: {policy}",
            severity="low", cwe="CWE-693",
            description=(f"Referrer-Policy '{policy}' di {url}: {issue} "
                         f"(token/token sesi di URL ikut bocor ke referer). "
                         f"finding_class=posture."),
            recommendation=("Set Referrer-Policy: strict-origin-when-cross-"
                            "origin (atau no-referrer); hindari token "
                            "sensitif di URL."),
            target_url=url, request=f"GET {url}",
            response=f"Referrer-Policy: {policy}",
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="header",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
