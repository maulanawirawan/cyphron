"""sqli_extract — SQLi dari deteksi ke BUKTI EKSTRKASI (CWE-89, critical).

Rantai: baseline request -> injeksi payload evidence-safe (union version)
-> bukti = marker muncul di respons INJECTED dan TIDAK ADA di baseline
(pelajaran marker statis != dinamis). cease-on-data: berhenti di bukti
pertama; TIDAK ada dumping tabel/data user — versi DB saja sebagai bukti.
"""

from __future__ import annotations

import re

from urllib.parse import quote as _q

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding
from ..payloads import SQLI_EXTRACT


class SqliExtractTool(Tool):
    name = "sqli_extract"
    description = ("SQLi exploitation-to-evidence: union/boolean extraction "
                   "dengan differential baseline — bukti versi DB, tanpa "
                   "dumping data. cease-on-data.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        param = str(args.get("param") or "")
        if "{payload}" not in url or not param:
            return ToolResult(tool=self.name, ok=False,
                              error="url harus memuat {payload} dan args.param "
                                    "diisi (param yang tervuln dari sqli_probe)")
        baseline_payload = args.get("baseline_value", "1")
        b_url = url.replace("{payload}", _q(baseline_payload, safe=""))
        ctx.throttle()
        b_st, _h, b_body, _ms = http_engine.http_get(b_url, timeout=ctx.timeout_s)
        ctx.world.observe_response(b_url, b_st, _h, b_body, self.name)
        ctx.world.request_count += 1

        probes: list[dict] = []
        findings: list[Finding] = []
        for p in SQLI_EXTRACT:
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            i_url = url.replace("{payload}", _q(p.payload, safe=""))
            st, _h, body, _ms = http_engine.http_get(i_url, timeout=ctx.timeout_s)
            ctx.world.observe_response(i_url, st, _h, body, self.name)
            ctx.world.request_count += 1
            hit = bool(p.evidence) and p.evidence.lower() in body.lower()
            in_baseline = bool(p.evidence) and p.evidence.lower() in b_body.lower()
            probes.append({"payload": p.name, "status": st, "marker_hit": hit,
                           "marker_in_baseline": in_baseline})
            if hit and not in_baseline:
                m = re.search(r"[\w.\- ]{6,60}", body)
                excerpt = redact(m.group(0)) if m else "(excerpt tersensor)"
                findings.append(Finding(
                    tool=self.name,
                    title=f"SQLi data extraction confirmed via {p.name}",
                    severity=p.severity, cwe="CWE-89",
                    description=(f"Injeksi {p.name} pada parameter '{param}' "
                                 f"mengekstrak nilai database ({excerpt}) yang "
                                 f"TIDAK ada di respons baseline — union-based "
                                 f"extraction terbukti. cease-on-data: tidak ada "
                                 f"dumping tabel/data lanjutan."),
                    recommendation=("Prepared statements/ORM; validasi tipe "
                                    "parameter; least-privilege DB user."),
                    file_path=None, line_start=None, line_end=None,
                    request=f"GET {i_url}",
                    response=f"status={st}; marker='{p.evidence}' "
                             f"(tidak ada di baseline); excerpt: {excerpt}",
                    confidence=0.85, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response",
                ))
                break  # cease-on-data
        return ToolResult(tool=self.name, ok=True, data={
            "url": url, "param": param, "baseline_status": b_st,
            "probes": probes, "note": "cease-on-data aktif — tidak ada dumping",
        }, findings=findings)
