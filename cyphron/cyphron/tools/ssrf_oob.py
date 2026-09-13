"""ssrf_oob — generic SSRF probe via URL-ish parameters (CWE-918, HIGH).

Teknik (pola BB-004): parameter yang menerima URL diisi endpoint capture
milik peneliti (webhook.site); konfirmasi HANYA lewat capture out-of-band.
Tanpa oob_check yang mengonfirmasi, status tetap LEAD (tidak pernah
dilaporkan sebagai temuan — jangan overclaim).

FP-guard:
  - tanpa oob_url + oob_check_url → hanya lead (data, bukan finding);
  - temuan WAJIB berdasarkan capture OOB, bukan status HTTP/status code
    respons (banyak server selalu 200);
  - maksimal 6 parameter per run; 1 request per parameter.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_URL_PARAMS = ("url", "uri", "dest", "destination", "redirect", "next", "site",
               "html", "val", "validate", "domain", "callback", "return",
               "page", "feed", "host", "port", "to", "out", "view", "dir",
               "show", "navigation", "open", "file", "document", "img",
               "image", "download", "read", "render", "source", "fetch",
               "proxy", "target", "link")


class SsrfOobTool(Tool):
    name = "ssrf_oob"
    description = ("Generic SSRF via URL-ish params + OOB capture confirm. "
                   "Tanpa capture = LEAD (bukan finding).")
    risk_tags = {"active"}
    source_skill = "manual-bb-13"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        path = str(args.get("path") or "/")
        oob_url = str(args.get("oob_url") or "").strip()
        oob_check = str(args.get("oob_check_url") or "").strip()
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        params = [p for p in (args.get("params") or _URL_PARAMS)][:6]
        data: dict = {"host": host, "path": path, "params": params,
                      "oob": bool(oob_url and oob_check), "probes": []}

        fired = []
        for p in params:
            if ctx.world.request_count >= ctx.max_requests:
                break
            probe_target = oob_url or "https://webhook.site/unconfirmed-lead"
            url = urljoin(base + "/", path.lstrip("/")) + \
                ("&" if "?" in path else "?") + f"{p}={probe_target}"
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
            except Exception as e:
                data["probes"].append({"param": p, "error": type(e).__name__})
                continue
            ctx.world.request_count += 1
            fired.append(p)
            data["probes"].append({"param": p, "status": st})
        data["fired_params"] = fired

        if not (oob_url and oob_check):
            data["lead"] = ("UNCONFIRMED — probe terkirim ke param " +
                            ", ".join(fired) +
                            "; sediakan oob_url + oob_check_url (webhook.site) "
                            "untuk konfirmasi out-of-band")
            return ToolResult(tool=self.name, ok=True, data=data)

        # konfirmasi OOB
        try:
            ctx.throttle()
            st, _hd, body, _ms = http_engine.http_get(oob_check, timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            hits = json.loads(body or "{}")
        except Exception as e:
            data["oob_check_error"] = type(e).__name__
            return ToolResult(tool=self.name, ok=True, data=data)
        count = int(hits.get("count") or len(hits.get("data") or []) or 0)
        data["oob_capture_count"] = count
        data["oob_detail"] = [
            {"ip": h.get("ip"), "ua": (h.get("user_agent") or "")[:80]}
            for h in (hits.get("data") or [])[:3]
        ]
        if count <= 0:
            return ToolResult(tool=self.name, ok=True, data=data)

        findings = [Finding(
            tool=self.name,
            title=f"SSRF via parameter '{fired[0] if fired else '?'}' confirmed "
                  f"out-of-band on {host}",
            severity="high", cwe="CWE-918",
            description=(
                f"Parameter '{fired[0] if fired else '?'}' membuat server produksi "
                f"melakukan request HTTP ke URL pilihan attacker — terbukti lewat "
                f"capture out-of-band ({count} hit dari IP server). Server dapat "
                f"dipakai memindai/menjangkau layanan internal. Pengujian berhenti "
                f"pada bukti pertama (cease-on-data); tidak ada probing internal."),
            recommendation=(
                "Validasi/allowlist URL tujuan (deny RFC1918 + link-local + "
                "metadata), matikan redirect follow, dan jangan fetch URL dari "
                "input mentah."),
            target_url=base, param=fired[0] if fired else None,
            request=f"GET {path}?{fired[0] if fired else 'param'}=<capture-url>",
            response=f"OOB capture: {count} hit" +
                     (f"; detail: {json.dumps(data['oob_detail'])}" if data["oob_detail"] else ""),
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="probe-pair")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
