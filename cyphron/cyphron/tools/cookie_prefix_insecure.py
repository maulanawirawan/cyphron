"""cookie_prefix_insecure — prefix __Host- / __Secure- disalahgunakan
(CWE-1004, low posture).

Aturan (RFC 6265bis):
  - __Host-  : HARUS Secure, Path=/, dan TANPA Domain attr;
  - __Secure-: HARUS Secure.
Guard: parse RAW Set-Cookie (bukan cookiejar); prefix dipedulikan pada
nama persisnya; 1 GET per run; posture.
"""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


class CookiePrefixInsecureTool(Tool):
    name = "cookie_prefix_insecure"
    description = ("Prefix cookie __Host-/__Secure- yang melanggar syarat "
                   "Secure/Path/Domain (parse RAW Set-Cookie).")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        ctx.throttle()
        st, _h, _b, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        raw = list(http_engine.LAST_RAW_HEADERS or [])
        set_cookies = [v for k, v in raw if k.lower() == "set-cookie"]
        data = {"set_cookie_count": len(set_cookies), "violations": []}
        findings: list[Finding] = []
        for sc in set_cookies:
            first = sc.split(";", 1)[0]
            name = first.split("=", 1)[0].strip()
            attrs = {}
            for part in sc.split(";")[1:]:
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                else:
                    k, v = part.strip(), ""
                attrs[k.lower()] = v
            violations: list[str] = []
            if name.startswith("__Host-"):
                if "secure" not in attrs:
                    violations.append("__Host- tanpa Secure")
                if attrs.get("path", "/") != "/":
                    violations.append(f"__Host- Path={attrs.get('path')!r} "
                                      f"(harus /)")
                if attrs.get("domain"):
                    violations.append(f"__Host- punya Domain={attrs['domain']!r} "
                                      f"(dilarang)")
            elif name.startswith("__Secure-") and "secure" not in attrs:
                violations.append("__Secure- tanpa Secure")
            if not violations:
                continue
            data["violations"].append({"name": name,
                                       "violations": violations})
            findings.append(Finding(
                tool=self.name,
                title=f"Cookie prefix misused: {name} "
                      f"({violations[0]})",
                severity="low", cwe="CWE-1004",
                description=(f"Cookie '{name}' memakai prefix proteksi tetapi "
                             f"melanggar syaratnya: {'; '.join(violations)}. "
                             f"Browser modern bisa MENOLAK cookie ini "
                             f"(fitur diam-diam rusak) atau prefix jadi "
                             f"dekoratif. finding_class=posture."),
                recommendation=("Penuhi syarat prefix (Secure, Path=/, tanpa "
                                "Domain utk __Host-) atau hapus prefix."),
                target_url=url, param=name,
                request=f"GET {url}",
                response=f"Set-Cookie raw: {sc[:120]}",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="header",
                finding_class="posture"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
