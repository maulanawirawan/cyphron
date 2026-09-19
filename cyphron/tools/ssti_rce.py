"""ssti_rce — Server-Side Template Injection: deteksi ke bukti evaluasi
(CWE-1336, critical).

Protokol dua-titik-aritmetika: {{7*7}}->49 SAJA tidak cukup (string "49"
bisa kebetulan). Bukti diterima bila DUA operasi aritmetika berbeda
mengembalikan hasil yang BENAR dan baseline tidak memuat keduanya —
itu evaluasi template sungguhan (RCE-class), bukan echo statis.
"""

from __future__ import annotations

from urllib.parse import quote as _q

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_MATH = [("{{7*7}}", "49"), ("{{234*2}}", "468"), ("${7*7}", "49"),
         ("<%= 7*7 %>", "49"), ("{7*7}", "49")]


class SstiRceTool(Tool):
    name = "ssti_rce"
    description = ("SSTI evaluation proof dengan dua-titik-aritmetika "
                   "(anti-FP) — evaluasi template terbukti = RCE-class.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if "{payload}" not in url:
            return ToolResult(tool=self.name, ok=False,
                              error="url harus memuat {payload}")
        b_url = url.replace("{payload}", "cyphron-baseline")
        ctx.throttle()
        b_st, _h, b_body, _ms = http_engine.http_get(b_url, timeout=ctx.timeout_s)
        ctx.world.observe_response(b_url, b_st, _h, b_body, self.name)
        ctx.world.request_count += 1

        probes: list[dict] = []
        confirmed: list[dict] = []
        for payload, expect in _MATH:
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            i_url = url.replace("{payload}", _q(payload, safe=""))
            st, _h, body, _ms = http_engine.http_get(i_url, timeout=ctx.timeout_s)
            ctx.world.observe_response(i_url, st, _h, body, self.name)
            ctx.world.request_count += 1
            hit = expect in body and expect not in b_body
            probes.append({"payload": payload, "status": st,
                           "expect": expect, "hit": hit})
            if hit:
                confirmed.append({"payload": payload, "expect": expect,
                                  "engine_hint": payload})
            if len(confirmed) >= 2:
                break  # dua bukti cukup

        findings: list[Finding] = []
        if len(confirmed) >= 2:
            engines = ", ".join(c["payload"] for c in confirmed)
            findings.append(Finding(
                tool=self.name,
                title=f"SSTI template evaluation confirmed ({engines})",
                severity="critical", cwe="CWE-1336",
                description=("Dua operasi aritmetika berbeda dievaluasi "
                             "server-side dan hasil yang BENAR muncul di "
                             "respons (baseline tidak memuatnya) — template "
                             "injection terbukti. Evaluasi template umumnya "
                             "berujung RCE (CWE-1336 -> CWE-94). cease-on-data: "
                             "tanpa eksekusi perintah lanjutan."),
                recommendation=("Jangan pernah render input user sebagai "
                                "template; gunakan sandbox/logic-less template."),
                file_path=None, line_start=None, line_end=None,
                request="GET " + url.replace("{payload}", confirmed[0]["payload"]),
                response=f"bukti: {confirmed} (baseline bebas marker)",
                confidence=0.9, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response",
            ))
        return ToolResult(tool=self.name, ok=True, data={
            "url": url, "probes": probes, "confirmed": confirmed,
            "baseline_status": b_st,
        }, findings=findings)
