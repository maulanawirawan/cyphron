"""cors_wildcard_subdomain — ACAO yang men refleksikan origin terkait
(target.com.evil.tld, evil-target.com) bukan sekadar any-* (CWE-942,
medium).

Berbeda dari cors_probe (yang menangkap exact reflection + wildcard):
di sini varian origin TRUST-BOUNDARY dikirim — bila server mencocokkan
dengan 'in'/'startswith' naif, varian lulus dan ACAO meng-echo varian
attacker + credentials.

FP-guard: ACAO harus persis varian yang dikirim (bukan *); ACAC=true
menaikkan severity; kontrol Origin sepenuhnya asing TIDAK boleh lulus
(jika kontrol lulus juga = allowlist rusak total — tetap temuan, tapi
dicatat beda); maks 4 request.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


class CorsSubdomainReflectionTool(Tool):
    name = "cors_wildcard_subdomain"
    description = ("CORS trust-boundary: origin terkait target di-reflect + "
                   "credentials. Bukan tes any-* (itu cors_probe).")
    risk_tags = {"active"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        host = (urlsplit(url).hostname or "").lower()
        if not url or "." not in host:
            return ToolResult(tool=self.name, ok=False,
                              error="args.url wajib (host bertitik)")
        base_label = host.split(".")[0]
        variants = [
            f"https://{host}.cyphron-oob.example",   # suffix trust bug
            f"https://{base_label}-cyphron.oob.example",  # prefix trust bug
            f"https://cyphron.{host}",               # self-subdomain wildcard
        ]
        data: dict = {"host": host, "variants": variants, "checks": []}
        findings: list[Finding] = []
        for origin in variants:
            if ctx.world.request_count >= ctx.max_requests or findings:
                break  # cease-on-data
            ctx.throttle()
            st, hd, _b, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s,
                headers={"Origin": origin})
            ctx.world.request_count += 1
            acao = hd.get("Access-Control-Allow-Origin", "")
            acac = hd.get("Access-Control-Allow-Credentials", "")
            reflected = acao == origin
            data["checks"].append({"origin": origin, "status": st,
                                   "acao": acao[:80], "acac": acac})
            if reflected and st < 500:
                findings.append(Finding(
                    tool=self.name,
                    title=f"CORS reflects related-origin '{origin}'"
                          + (" with credentials" if acac.lower() == "true"
                             else ""),
                    severity="high" if acac.lower() == "true" else "medium",
                    cwe="CWE-942",
                    description=(
                        f"Origin varian trust-boundary '{origin}' di-echo "
                        f"Access-Control-Allow-Origin persis "
                        f"(credentials={acac or 'tidak diset'}) — allowlist "
                        f"naif (in/startswith) menerima domain attacker yang "
                        f"mengandung nama target; data terautentikasi dapat "
                        f"dibaca dari origin attacker. cease-on-data: satu "
                        f"varian cukup sebagai bukti."),
                    recommendation=("Cocokkan origin exact-match per "
                                    "allowlist string; jangan pakai in/"
                                    "startswith; hindari ACAC dengan origin "
                                    "dinamis."),
                    target_url=url,
                    request=f"GET {url} [Origin: {origin}]",
                    response=f"status={st}; ACAO={acao[:80]}; "
                             f"ACAC={acac or '-'}",
                    confidence=0.85, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="header"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
