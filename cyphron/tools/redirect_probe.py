"""redirect_probe — open redirect detection for discovered query parameters.
Active: requires authorization. Payload domains are documentation-only."""

from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

CANARY_HOST = "cx-redirect-test.example.test"
PARAM_HINTS = ("url", "next", "redirect", "redirect_uri", "redirect_url", "goto",
               "return", "returnto", "return_to", "link", "dest", "destination",
               "continue", "callback", "target", "r", "u", "out")


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(k, value if k == param else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


class RedirectProbeTool(Tool):
    name = "redirect_probe"
    description = "Probe URL params for open redirect using a canary host."
    risk_tags = {"active"}
    source_skill = "68"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        param = str(args["param"])
        findings: list[Finding] = []
        if param.lower() not in PARAM_HINTS:
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": f"param '{param}' not redirect-like"})
        for payload in (f"//{CANARY_HOST}/", f"https://{CANARY_HOST}/"):
            probe_url = _with_param(url, param, payload)
            status, headers, body, _ms = http_engine.http_get(probe_url, timeout=ctx.timeout_s)
            ctx.world.observe_response(probe_url, status, headers, body, self.name)
            location = headers.get("location") or headers.get("Location") or ""
            if status in (301, 302, 303, 307, 308) and CANARY_HOST in location:
                findings.append(Finding(
                    tool=self.name, title=f"Open redirect via parameter '{param}'",
                    severity="medium", cwe="CWE-601",
                    description=(f"Parameter `{param}` on {url} redirects (HTTP {status}) to an "
                                 f"external canary host ({location}). Attackers can abuse it for "
                                 f"phishing that appears to originate from your domain."),
                    recommendation=("Whitelist redirect destinations against known-good paths/hosts; "
                                    "never take raw URLs from request parameters."),
                    target_url=url, param=param,
                    request=f"GET {probe_url}", response=f"status={status}; Location={location}",
                    poc=f"curl -sI '{probe_url}'   # Location -> {location}",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
                break
        return ToolResult(tool=self.name, ok=True, data={"url": url, "param": param},
                          findings=findings)
