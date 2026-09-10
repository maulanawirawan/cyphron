"""method_audit — HTTP method exposure check (OPTIONS/TRACE/PUT/DELETE/PATCH)
on the target. Bounded, non-destructive: bodies are tiny; a 2xx on stateful
methods is reported, never repeated."""

from __future__ import annotations

import difflib
import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

# Nilai yang berubah per-request: sentry-trace, request-id, nonce, csrf, dll.
_DYNAMIC_RE = re.compile(
    r'(sentry-trace"\s+content=")[^"]*(")'
    r'|((?:csrf|nonce|request-?id|x-request-id|trace-?id|baggage)'
    r'[="\s:]+[A-Za-z0-9_\-/+=]{8,})',
    re.I)


def _norm_dynamic(text: str) -> str:
    def _sub(m):
        if m.group(1):
            return m.group(1) + m.group(2)
        return m.group(3) + "<dyn>"
    return _DYNAMIC_RE.sub(_sub, text or "")


def _page_similarity(a: str, b: str) -> float:
    """Similarity dua halaman SETELAH nilai dinamis dinormalisasi."""
    return difflib.SequenceMatcher(None, _norm_dynamic(a)[:8000],
                                   _norm_dynamic(b)[:8000]).ratio()


class MethodAuditTool(Tool):
    name = "method_audit"
    description = "Check exposed/unsafe HTTP methods on a URL."
    risk_tags = {"active"}
    source_skill = "16"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        findings: list[Finding] = []
        allowed: list[str] = []

        status, headers, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s, method="OPTIONS")
        ctx.world.observe_response(url, status, headers, body, self.name)
        allow = headers.get("allow") or headers.get("Allow") or ""
        if allow:
            allowed = [m.strip().upper() for m in allow.split(",")]
            ctx.world.note(f"method_audit: OPTIONS {url} -> Allow: {allow}")

        checks = [
            ("TRACE", "Cross-Site Tracing (XST)"),
            ("PUT", "unauthenticated file/resource creation"),
            ("DELETE", "unauthenticated resource deletion"),
        ]
        for method, impact in checks:
            if allowed and method not in allowed:
                continue
            status, headers, body, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, method=method,
                data=b"cyphron-probe", headers={"Content-Type": "text/plain"})
            ctx.world.observe_response(url, status, headers, body, self.name)
            if method == "TRACE" and status == 200 and "cyphron-probe" in (body or ""):
                findings.append(Finding(
                    tool=self.name, title="TRACE method enabled (Cross-Site Tracing)",
                    severity="medium", cwe="CWE-693",
                    description=f"TRACE at {url} echoed the request body; enables XST against cookies.",
                    recommendation="Disable TRACE at the web server/framework.",
                    target_url=url, request=f"TRACE {url}", response=f"status={status} body echoed probe",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
            elif method in ("PUT", "DELETE") and status < 300:
                # Self-critique: a 2xx alone proves nothing — many app servers
                # answer ANY method with the normal page. Compare with GET
                # after normalizing per-request values (sentry-trace, nonce, dst.).
                get_status, _gh, get_body, _gm = http_engine.http_get(url, timeout=ctx.timeout_s)
                ctx.world.observe_response(url, get_status, _gh, get_body, self.name)
                sim = _page_similarity(body or "", get_body or "")
                if sim >= 0.95:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Method {method} answered with the normal page (no side-effect evidence)",
                        severity="info", cwe="CWE-650",
                        description=(f"{method} {url} returned {status} but the body matches a "
                                     f"plain GET response (similarity {sim:.0%} after normalizing "
                                     f"per-request IDs), so the method is very likely a no-op of "
                                     f"the page handler rather than a real write path."),
                        recommendation=("Verify in the framework whether the method is routed anywhere; "
                                        "explicitly return 405 for unimplemented methods."),
                        target_url=url, request=f"{method} {url}",
                        response=f"status={status}; body similarity to GET: {sim:.0%}",
                        confidence=0.3, source_skill=self.source_skill,
                        status="unconfirmed", evidence_kind="probe-pair"))
                elif sim >= 0.7:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Method {method} returned a near-identical page (needs manual check)",
                        severity="info", cwe="CWE-650",
                        description=(f"{method} {url} returned {status} with body similarity "
                                     f"{sim:.0%} to GET — ambiguous (dynamic page vs no-op). "
                                     f"Butuh konfirmasi manual sebelum diklaim vuln."),
                        recommendation="Verify framework routing for this method; return 405 "
                                       "for unimplemented methods.",
                        target_url=url, request=f"{method} {url}",
                        response=f"status={status}; similarity {sim:.0%}",
                        confidence=0.3, source_skill=self.source_skill,
                        status="unconfirmed", evidence_kind="probe-pair"))
                else:
                    findings.append(Finding(
                        tool=self.name, title=f"DANGEROUS method {method} accepted (HTTP {status})",
                        severity="critical", cwe="CWE-650",
                        description=f"{method} {url} returned {status} with a materially different "
                                    f"response than GET (similarity {sim:.0%}); "
                                    f"{impact} may be possible.",
                        recommendation="Disable write methods on public resources; require explicit auth.",
                        target_url=url, request=f"{method} {url}", response=f"status={status}; "
                                     f"similarity {sim:.0%}",
                        confidence=0.8, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response"))
        return ToolResult(tool=self.name, ok=True, data={"url": url, "allow": allowed},
                          findings=findings)
