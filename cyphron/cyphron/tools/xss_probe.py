"""xss_probe — Cyphron's own reflected XSS detector (context-aware markers).

Injects a unique marker; if the marker reflects back inside an unencoded
<script> tag (or raw <svg onallow-ish construct) the finding is confirmed
with request/response evidence. Plain reflection without tag execution is
reported as unconfirmed (verifier will not let it masquerade as confirmed).
Active: requires a valid in-scope authorization document."""

from __future__ import annotations

import uuid
from html import escape
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(k, value if k == param else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


class XssProbeTool(Tool):
    name = "xss_probe"
    description = "Probe one URL+param for reflected XSS with unique markers."
    risk_tags = {"active"}
    source_skill = "03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url, param = str(args["url"]), str(args["param"])
        marker = "cx" + uuid.uuid4().hex[:10] + "z"
        payloads = [
            (f"<script>{marker}</script>", "tag"),
            (f'"><svg onload=alert("{marker}")>', "attribute-break"),
        ]
        findings: list[Finding] = []
        # baseline encodes the marker so we know the app escapes by default
        baseline_url = _with_param(url, param, escape(marker))
        _s, _h, baseline_body, _ms = http_engine.http_get(baseline_url, timeout=ctx.timeout_s)
        ctx.world.observe_response(baseline_url, _s, _h, baseline_body, self.name)

        for payload, kind in payloads:
            probe_url = _with_param(url, param, payload)
            status, _h, body, _ms = http_engine.http_get(probe_url, timeout=ctx.timeout_s)
            ctx.world.observe_response(probe_url, status, _h, body, self.name)
            if marker not in body:
                continue
            raw_tag = (f"<script>{marker}</script>" in body) if kind == "tag" else \
                (f'<svg onload=alert("{marker}")>' in body)
            if raw_tag and marker in baseline_body.replace(escape(marker), ""):
                pass
            if raw_tag:
                idx = body.find("<script>" if kind == "tag" else "<svg")
                context = body[max(0, idx - 80): idx + len(payload) + 80]
                findings.append(Finding(
                    tool=self.name,
                    title=f"Reflected XSS ({kind}) via parameter '{param}'",
                    severity="high", cwe="CWE-79",
                    description=(
                        f"Payload injected into parameter `{param}` is reflected into the HTML response "
                        f"WITHOUT encoding: the marker appears as executable markup. An attacker can craft "
                        f"a link that executes script in a victim's browser session."
                    ),
                    recommendation=(
                        "HTML-encode the value on output for its context (element body vs attribute vs JS), "
                        "add a Content-Security-Policy, and prefer safe templating autoescape. "
                        "See .kimchi/knowledge/remediation-playbook.md (XSS) and secure-patterns.md."
                    ),
                    target_url=url, param=param,
                    request=f"GET {probe_url}",
                    response=f"reflected unencoded; context excerpt: {context!r}",
                    poc=f"curl -g '{probe_url}'   # response contains {payload!r} verbatim",
                    confidence=0.85, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response",
                ))
                break
            # plain reflection (no executable markup): unconfirmed candidate
            if marker in body and not findings:
                findings.append(Finding(
                    tool=self.name,
                    title=f"User input reflected unvalidated via parameter '{param}' (no tag execution observed)",
                    severity="low", cwe="CWE-79",
                    description=(
                        f"The marker is reflected in the response but not as executable markup; "
                        f"context may still be exploitable (attribute/JS/body differs per endpoint)."
                    ),
                    recommendation="Encode output per context and validate input; re-test with context-specific payloads.",
                    target_url=url, param=param,
                    request=f"GET {probe_url}",
                    response=f"marker reflected; excerpt: {body[max(0, body.find(marker)-80):body.find(marker)+80]!r}",
                    confidence=0.35, source_skill=self.source_skill,
                    status="unconfirmed", evidence_kind="request-response",
                ))
        return ToolResult(tool=self.name, ok=True, data={"url": url, "param": param},
                          findings=findings)
