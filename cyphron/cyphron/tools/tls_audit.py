"""tls_audit — TLS/certificate audit using the stdlib ssl module: certificate
expiry, negotiated protocol, SAN coverage. Passive."""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


class TlsAuditTool(Tool):
    name = "tls_audit"
    description = "Audit TLS certificate validity, protocol version, SAN."
    risk_tags = {"passive"}
    source_skill = "05"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        parsed = urlparse(url)
        if parsed.scheme != "https":
            ctx.world.note("tls_audit skipped: target is not HTTPS")
            return ToolResult(tool=self.name, ok=True, data={"skipped": "not-https"})
        host, port = parsed.hostname, parsed.port or 443
        findings: list[Finding] = []
        data: dict = {"host": host, "port": port}
        try:
            ctx.throttle()
            ctx_cb = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=ctx.timeout_s) as sock:
                with ctx_cb.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert() or {}
                    data["protocol"] = ss.version()
                    data["cipher"] = ss.cipher()[0] if ss.cipher() else None
        except ssl.SSLCertVerificationError as exc:
            findings.append(Finding(
                tool=self.name, title="TLS certificate verification fails",
                severity="high", cwe="CWE-295",
                description=f"TLS handshake with {host}:{port} fails verification: {exc.verify_message}",
                recommendation="Renew/fix the certificate chain; never disable verification in clients.",
                target_url=url, request=f"TLS handshake to {host}:{port}",
                response=str(exc.verify_message), confidence=1.0,
                source_skill=self.source_skill, status="confirmed",
                evidence_kind="probe-pair"))
            ctx.world.observe_response(url, None, {}, "", self.name)
            return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
        except OSError as exc:
            return ToolResult(tool=self.name, ok=False, error=f"TLS connect failed: {exc}")

        not_after = cert.get("notAfter")
        if not_after:
            import calendar
            expiry = calendar.timegm(time.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
            days_left = int((expiry - time.time()) / 86400)
            data["notAfter"] = not_after
            data["days_left"] = days_left
            if days_left < 0:
                sev, title = "critical", "TLS certificate EXPIRED"
            elif days_left < 14:
                sev, title = "high", f"TLS certificate expires in {days_left} days"
            elif days_left < 30:
                sev, title = "medium", f"TLS certificate expires in {days_left} days"
            else:
                sev, title = None, None
            if sev:
                findings.append(Finding(
                    tool=self.name, title=title, severity=sev, cwe="CWE-298",
                    description=f"Certificate for {host} expires {not_after} ({days_left} days left).",
                    recommendation="Renew the certificate before expiry; automate renewal.",
                    target_url=url, request=f"TLS handshake to {host}:{port}",
                    response=f"notAfter={not_after}; days_left={days_left}",
                    confidence=1.0, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="probe-pair"))
        proto = data.get("protocol")
        if proto and proto in ("TLSv1", "TLSv1.0", "TLSv1.1"):
            findings.append(Finding(
                tool=self.name, title=f"Outdated TLS protocol negotiated: {proto}",
                severity="high", cwe="CWE-327",
                description=f"Server negotiated {proto}, which is deprecated.",
                recommendation="Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
                target_url=url, response=f"negotiated={proto}", confidence=1.0,
                source_skill=self.source_skill, status="confirmed",
                evidence_kind="probe-pair"))
        san = [v for kind, v in cert.get("subjectAltName", []) if kind == "DNS"]
        data["san_count"] = len(san)
        ctx.world.note(f"tls_audit: {proto}, cert days_left={data.get('days_left')}, SAN={len(san)}")
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
