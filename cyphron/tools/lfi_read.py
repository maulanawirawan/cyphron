"""lfi_read — Local File Inclusion/Path Traversal: deteksi ke bukti baca
(CWE-22, high->critical).

Differential: marker bukti harus ada di respons INJECTED dan tidak ada di
baseline. cease-on-data ketat: cukup SATU baris bukti (root: atau hostname)
— isi file penuh TIDAK disimpan, tidak ada chaining ke file lain.
"""

from __future__ import annotations

import re

from urllib.parse import quote as _q

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding
from ..payloads import LFI_READ


class LfiReadTool(Tool):
    name = "lfi_read"
    description = ("LFI/path traversal exploitation-to-evidence dengan "
                   "cease-on-data: 1 baris bukti, tanpa dumping file.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if "{payload}" not in url:
            return ToolResult(tool=self.name, ok=False,
                              error="url harus memuat {payload}")
        b_url = url.replace("{payload}", "cyphron.txt")
        ctx.throttle()
        b_st, _h, b_body, _ms = http_engine.http_get(b_url, timeout=ctx.timeout_s)
        ctx.world.observe_response(b_url, b_st, _h, b_body, self.name)
        ctx.world.request_count += 1

        probes: list[dict] = []
        findings: list[Finding] = []
        for p in LFI_READ:
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            i_url = url.replace("{payload}", _q(p.payload, safe=""))
            st, _h, body, _ms = http_engine.http_get(i_url, timeout=ctx.timeout_s)
            ctx.world.observe_response(i_url, st, _h, body, self.name)
            ctx.world.request_count += 1
            hit = bool(p.evidence) and p.evidence.lower() in body.lower()
            in_baseline = bool(p.evidence) and p.evidence.lower() in b_body.lower()
            first_line = ""
            if hit:
                # cease-on-data: simpan SATU baris bukti saja, redacted
                line = next((l for l in body.splitlines()
                             if p.evidence.lower() in l.lower()), "")
                first_line = redact(line[:80])
            probes.append({"payload": p.name, "status": st, "marker_hit": hit,
                           "marker_in_baseline": in_baseline})
            if hit and not in_baseline:
                severity = p.severity
                findings.append(Finding(
                    tool=self.name,
                    title=f"LFI arbitrary file read confirmed via {p.name}",
                    severity=severity, cwe="CWE-22",
                    description=(f"Parameter yang tervuln membaca file arbitrer "
                                 f"({p.name}): baris bukti '{first_line}' hadir "
                                 f"di respons dan tidak ada di baseline. "
                                 f"cease-on-data: isi file TIDAK disimpan dan "
                                 f"tidak ada pembacaan lanjutan."),
                    recommendation=("Whitelist path; resolve+chroot; blok "
                                    "traversal sequence dan wrapper di layer "
                                    "aplikasi."),
                    file_path=None, line_start=None, line_end=None,
                    request=f"GET {i_url}",
                    response=f"status={st}; bukti (1 baris, redacted): {first_line}",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response",
                ))
                break  # cease-on-data
        return ToolResult(tool=self.name, ok=True, data={
            "url": url, "probes": probes, "baseline_status": b_st,
        }, findings=findings)
