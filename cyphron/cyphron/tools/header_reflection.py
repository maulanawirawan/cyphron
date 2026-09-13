"""header_reflection_double — input tercermin di RESPONSE HEADER (bukan
body) (CWE-113, info posture).

Roadmap: "-> info". Engine menguji 1 param dengan nilai marker aman
(TANPA CRLF — ini bukan tes smuggling; CRLF nyata dilarang doktrin).
Bila marker muncul di response header -> server menaruh input mentah ke
header (bahan phishing header/cache-key; kalau sanitasi CRLF lemah di
middleware lain, bisa jadi splitting).

Guard: marker murni alfanumerik-dash; baseline tanpa param wajib; hanya
HEADER yang dihitung (body diabaikan); maks 2 request; finding_class=
posture, severity info.
"""

from __future__ import annotations

from urllib.parse import quote as _q, urljoin

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_MARKER = "cyphron-refl-77k"


class HeaderReflectionTool(Tool):
    name = "header_reflection_double"
    description = ("Input ter-echo di response header (bukan body) — intel "
                   "posture, info; tanpa CRLF (bukan tes smuggling).")
    risk_tags = {"active"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("url") or "")
        param = str(args.get("param") or "")
        if not base or not param:
            return ToolResult(tool=self.name, ok=False,
                              error="args.url + args.param wajib")
        url_b = urljoin(base, ("&" if "?" in base else "?") + f"{param}=baseline")
        ctx.throttle()
        s_b, h_b, _bd, _m = http_engine.http_get(url_b, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        url_i = urljoin(base, ("&" if "?" in base else "?") +
                        f"{param}={_q(_MARKER, safe='')}")
        ctx.throttle()
        s_i, h_i, body_i, _m = http_engine.http_get(url_i, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        hdr_hits = [k for k, v in (h_i or {}).items()
                    if _MARKER in str(v) and k.lower() not in
                    ("referer", "user-agent")]
        in_baseline_headers = any(_MARKER in str(v)
                                  for v in (h_b or {}).values())
        data = {"param": param, "marker": _MARKER,
                "reflected_headers": hdr_hits,
                "marker_in_body": _MARKER in (body_i or "")}
        if not hdr_hits or in_baseline_headers:
            data.setdefault("note", "tidak ada refleksi header (atau marker "
                                    "memang selalu ada)")
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"Input reflected in response header(s): {', '.join(hdr_hits)}",
            severity="info", cwe="CWE-113",
            description=(
                f"Nilai parameter '{param}' dipindahkan server ke response "
                f"header ({', '.join(hdr_hits)}) tanpa encode. Refleksi "
                f"header adalah bahan untuk cache-key confusion/phishing "
                f"header; bila filter CRLF middleware lain lemah, bisa "
                f"menjadi response splitting. TANPA CRLF dikirim di sini "
                f"(doktrin). finding_class=posture."),
            recommendation=("Encode/strip CRLF dan karakter kontrol; jangan "
                            "menaruh input mentah ke header; allowlist nilai."),
            target_url=base, param=param,
            request=f"GET ...?{param}={_MARKER}",
            response=f"headers: {[(k, str((h_i or {}).get(k))[:60]) for k in hdr_hits]}",
            confidence=0.7, source_skill=self.source_skill,
            status="confirmed", evidence_kind="header",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
