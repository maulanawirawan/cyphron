"""security_txt — RFC 9116 /.well-known/security.txt posture probe.

Teknik lapangan (2026-09, UMS): institusi besar kerap belum punya kanal
pelaporan kerentanan resmi. security.txt yang valid = positif (tidak ada
temuan); hilang/invalid = posture info yang menjadi pemicu percakapan VDP.

FP-guard:
  - respons 200 tapi Content-Type HTML = catch-all soft-404 -> dianggap
    TIDAK ADA (bukan security.txt valid);
  - file tanpa field "Contact:" = invalid (RFC 9116 mensyaratkan Contact).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_PATHS = ("/.well-known/security.txt", "/security.txt")


class SecurityTxtTool(Tool):
    name = "security_txt"
    description = ("RFC 9116 security.txt posture: valid file (text/plain + "
                   "Contact:) = positif; missing/invalid = posture info.")
    risk_tags = {"active"}
    source_skill = "manual-bb-08"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        data: dict = {"host": host}
        found_valid = False
        seen: list[dict] = []

        for path in _PATHS:
            if ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(
                    urljoin(base + "/", path.lstrip("/")), timeout=ctx.timeout_s)
            except Exception as e:
                seen.append({"path": path, "error": type(e).__name__})
                continue
            ctx.world.request_count += 1
            ctype = ""
            for k, v in (hd or {}).items():
                if k.lower() == "content-type":
                    ctype = v
                    break
            is_plain = ctype.strip().lower().startswith("text/plain")
            has_contact = "Contact:" in (body or "")
            seen.append({"path": path, "status": st, "content_type": ctype,
                         "valid": bool(st == 200 and is_plain and has_contact)})
            if st == 200 and is_plain and has_contact:
                found_valid = True
                break

        data["security_txt"] = seen
        if found_valid:
            ctx.world.note(f"security_txt: valid di {host} — postur baik")
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"No valid security.txt (RFC 9116) on {host}",
            severity="info", cwe=None, finding_class="posture",
            description=(
                "Tidak ditemukan /.well-known/security.txt atau /security.txt "
                "yang valid (HTTP 200, text/plain, memuat field Contact). "
                "Peneliti keamanan yang menemukan kerentanan tidak memiliki "
                "kanal pelaporan resmi — risiko disclosure liar dan insiden "
                "tanpa koordinasi."),
            recommendation=(
                "Terbitkan /.well-known/security.txt berisi Contact:, Expires, "
                "dan Preferred-Languages; cukup file statis."),
            target_url=host, confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="header")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
