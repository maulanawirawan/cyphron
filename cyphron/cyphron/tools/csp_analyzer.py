"""csp_analyzer — parse Content-Security-Policy: script-src unsafe-inline /
unsafe-eval / wildcard (CWE-693, medium posture).

FP-guard:
  - yang dihitung hanya script-src / default-src AKTIF (Report-Only = note);
  - CSP hilang total = note saja (missing header = non-claim umum di
    banyak program — engine tidak menggurui program untuk membayar);
  - nonce/hash di script-src menetralkan unsafe-inline (bypass klasik
    $-script-src nonce lama TIDAK dianggap vuln tanpa bukti).
1 GET per run.
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_DIRECTIVE_RE = re.compile(r"(script-src(?:-elem)?|default-src)([^;]*)")


class CspAnalyzerTool(Tool):
    name = "csp_analyzer"
    description = ("Analisis CSP aktif: unsafe-inline/eval/wildcard pada "
                   "script-src. CSP hilang = note (bukan temuan).")
    risk_tags = {"passive"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        ctx.throttle()
        st, hd, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        csp = hd.get("Content-Security-Policy", "")
        csp_ro = hd.get("Content-Security-Policy-Report-Only", "")
        data: dict = {"status": st, "csp_present": bool(csp),
                      "report_only": bool(csp_ro)}
        if csp_ro and not csp:
            data["note"] = ("CSP hanya Report-Only — belum aktif "
                            "(catatan, bukan temuan)")
        if not csp:
            data.setdefault("note", "CSP tidak ada — non-claim umum; catat "
                                    "sebagai intel saja")
            return ToolResult(tool=self.name, ok=True, data=data)

        issues: list[str] = []
        directives = _DIRECTIVE_RE.findall(csp)
        script_dir = next((v for k, v in directives
                           if k.startswith("script-src")), None)
        default_dir = next((v for k, v in directives
                            if k == "default-src"), None)
        target = script_dir if script_dir is not None else default_dir
        data["script_src"] = (script_dir or default_dir or "").strip() or None
        if target is None:
            data["note"] = "script-src dan default-src tidak ditentukan"
            return ToolResult(tool=self.name, ok=True, data=data)
        has_nonce = "nonce-" in target or "'strict-dynamic'" in target
        if "'unsafe-inline'" in target and not has_nonce:
            issues.append("script-src unsafe-inline (nonce/strict-dynamic "
                          "tidak menetralkan)")
        if "'unsafe-eval'" in target:
            issues.append("script-src unsafe-eval")
        if "*" in target or "http:" in target.split()[0:1]:
            issues.append("sumber script wildcard/kembar tanpa pembatas")
        data["issues"] = issues
        if not issues:
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"CSP weakened: {issues[0].split(' (')[0]}",
            severity="medium", cwe="CWE-693",
            description=(f"CSP aktif di {url} melemahkan proteksi XSS: "
                         f"{'; '.join(issues)}. finding_class=posture — "
                         f"qualifying atau tidak mengikuti rules program "
                         f"(banyak program menaruh ini non-claim)."),
            recommendation=("Gunakan nonce/strict-dynamic; hapus "
                            "unsafe-inline/eval; batasi host script."),
            target_url=url, request=f"GET {url}",
            response=f"CSP: {data['script_src']}",
            confidence=0.7, source_skill=self.source_skill,
            status="confirmed", evidence_kind="header",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
