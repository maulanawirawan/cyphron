"""security_headers — audits security response headers and cookie flags.
Passive; produces low/info findings with header evidence."""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_REQUIRED = [
    ("content-security-policy", "medium", "CWE-693",
     "Content-Security-Policy header missing",
     "Add a CSP policy (e.g. default-src 'self') to mitigate XSS and injection of third-party content."),
    ("x-content-type-options", "low", "CWE-430",
     "X-Content-Type-Options header missing",
     "Send `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing."),
    ("x-frame-options", "low", "CWE-1021",
     "X-Frame-Options header missing",
     "Send `X-Frame-Options: DENY` (or frame-ancestors via CSP) to prevent clickjacking."),
    ("referrer-policy", "info", "CWE-693",
     "Referrer-Policy header missing",
     "Send `Referrer-Policy: strict-origin-when-cross-origin`."),
    ("permissions-policy", "info", "CWE-693",
     "Permissions-Policy header missing",
     "Send a Permissions-Policy restricting sensitive browser features."),
]


class SecurityHeadersTool(Tool):
    name = "security_headers"
    description = "Audit security headers and cookie flags on one URL."
    risk_tags = {"passive"}
    source_skill = "14"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        status, headers, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.observe_response(url, status, headers, body, self.name)
        lower = {k.lower(): v for k, v in headers.items()}
        findings: list[Finding] = []
        for header, sev, cwe, title, fix in _REQUIRED:
            if header not in lower and not (header == "strict-transport-security"):
                findings.append(Finding(
                    tool=self.name, title=title, severity=sev, cwe=cwe,
                    description=f"Response from {url} does not include the `{header}` header.",
                    recommendation=fix, target_url=url,
                    evidence_kind="header", confidence=1.0,
                    source_skill=self.source_skill, status="confirmed",
                    response=f"response headers: {sorted(lower.keys())}",
                ))
        if url.lower().startswith("https://") and "strict-transport-security" not in lower:
            findings.append(Finding(
                tool=self.name, title="Strict-Transport-Security header missing",
                severity="medium", cwe="CWE-319",
                description=f"HTTPS response from {url} lacks HSTS.",
                recommendation="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
                target_url=url, evidence_kind="header", confidence=1.0,
                source_skill=self.source_skill, status="confirmed",
                response=f"response headers: {sorted(lower.keys())}",
            ))
        for cookie in _cookies(lower.get("set-cookie", "")):
            flags = cookie["flags"]
            missing: set[str] = set()
            if "httponly" not in flags:
                missing.add("httpOnly")
            if "samesite" not in flags:
                missing.add("samesite")
            if url.lower().startswith("https://") and "secure" not in flags:
                missing.add("secure")
            if missing:
                findings.append(Finding(
                    tool=self.name, title=f"Cookie '{cookie['name']}' missing flags: {', '.join(sorted(missing))}",
                    severity="low", cwe="CWE-1004",
                    description=f"Set-Cookie for {cookie['name']} at {url} lacks {', '.join(sorted(missing))}.",
                    recommendation="Set HttpOnly, Secure, and SameSite=Lax/Strict on session cookies.",
                    target_url=url, evidence_kind="header", confidence=1.0,
                    source_skill=self.source_skill, status="confirmed",
                    response=cookie["raw"][:200],
                ))
        return ToolResult(tool=self.name, ok=True, data={"url": url, "status": status},
                          findings=findings, raw_excerpt=str(headers)[:800])


def _cookies(header_value: str) -> list[dict]:
    out: list[dict] = []
    for part in header_value.split(","):
        if "=" not in part:
            continue
        name_value, *flag_parts = part.strip().split(";")
        name = name_value.strip().split("=", 1)[0]
        flags = [f.strip().split("=", 1)[0].lower() for f in flag_parts]
        out.append({"name": name, "flags": flags, "raw": part.strip()})
    return out
