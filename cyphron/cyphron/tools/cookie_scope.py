"""cookie_scope — Domain/Path overbroad pada cookie NON-SESSION
(CWE-1004, low-medium posture).

Guard inti (pelajaran cookiejar salah baca HttpOnly -> selalu parse RAW
Set-Cookie dari LAST_RAW_HEADERS, bukan dict yang menelan duplikat):
  - hanya cookie NON-SENSITIF (bukan session/auth/token/csrf) yang
    dinilai; session cookie memang pantas scope luas;
  - temuan = Domain leading-dot (kirim ke SEMUA subdomain) pada host
    non-apex, atau Path yang lebih luas dari kebutuhan nyata;
  - Secure/HttpOnly pada cookie non-session tidak wajib (bukan temuan).
1 GET per run; finding_class=posture.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_SENSITIVE = ("session", "sess", "sid", "auth", "token", "csrf", "jwt",
              "remember", "login")


class CookieScopeTool(Tool):
    name = "cookie_scope"
    description = ("Scope cookie non-session: Domain leading-dot / Path "
                   "overbroad. Parse RAW Set-Cookie (bukan cookiejar).")
    risk_tags = {"passive"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            return ToolResult(tool=self.name, ok=False,
                              error="host tidak bisa diparse")
        ctx.throttle()
        st, _hd, _body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        raw = list(http_engine.LAST_RAW_HEADERS or [])
        set_cookies = [v for k, v in raw
                       if k.lower() == "set-cookie"]
        data: dict = {"status": st, "set_cookie_count": len(set_cookies),
                      "cookies": []}
        findings: list[Finding] = []
        for sc in set_cookies:
            first = sc.split(";", 1)[0]
            name = first.split("=", 1)[0].strip()
            attrs = {}
            for part in sc.split(";")[1:]:
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                else:
                    k, v = part.strip().lower(), ""
                attrs[k.lower()] = v
            info = {"name": name, "domain": attrs.get("domain"),
                    "path": attrs.get("path", "/")}
            data["cookies"].append(info)
            if any(s in name.lower() for s in _SENSITIVE):
                continue  # session-like: scope luas memang wajar
            dom = attrs.get("domain", "")
            if dom.startswith("."):
                apex = host.rsplit(".", 2)[-2] if host.count(".") >= 2 else host
                findings.append(Finding(
                    tool=self.name,
                    title=f"Cookie '{name}' scoped to Domain={dom} "
                          f"(non-session)",
                    severity="medium", cwe="CWE-1004",
                    description=(
                        f"Cookie non-sensitif '{name}' memakai Domain leading-"
                        f"dot '{dom}' sehingga terkirim ke SEMUA subdomain "
                        f"(termasuk subdomain pihak ketiga/XSS-lama di host "
                        f"apex '{apex}'). finding_class=posture; nilai temuan "
                        f"final dari rules program."),
                    recommendation=("Kurangi scope: set Domain hanya host "
                                    "yang butuh; hindari leading-dot untuk "
                                    "cookie aplikasi."),
                    target_url=url, param=name,
                    request=f"GET {url}",
                    response=f"Set-Cookie raw: {sc[:120]}",
                    confidence=0.6, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="header",
                    finding_class="posture"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
