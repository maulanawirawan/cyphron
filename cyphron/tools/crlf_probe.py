"""crlf — CRLF / HTTP response header injection via parameter (CWE-93, MEDIUM-HIGH).

Teknik: param diuji dengan payload %0d%0aX-<marker>: cyphron; temuan hanya
bila header marker MUNCUL PERSIS di response headers — bukan di body
(cegah FP dari halaman yang meng-echo input).

FP-guard:
  - header harus muncul di BAGIAN HEADERS respons (bukan body);
  - marker unik per run (cyphron-crlf-<rand>) sehingga echo body tak bisa
    dipakai sebagai bukti;
  - maksimal 3 parameter.
"""

from __future__ import annotations

import secrets
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_PAYLOAD_PARAMS = ("id", "page", "url", "path", "next", "redirect", "q", "view")


class CrlfProbeTool(Tool):
    name = "crlf"
    description = ("CRLF header injection via parameter (marker header unik "
                   "per run; body-echo tidak dihitung).")
    risk_tags = {"active"}
    source_skill = "manual-bb-14"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        path = str(args.get("path") or "/")
        params = [p for p in (args.get("params") or _PAYLOAD_PARAMS)][:3]
        if not host or not params:
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "no-host-or-params"})
        marker = f"cyphron-crlf-{secrets.token_hex(4)}"
        header_name = f"X-{marker}"
        data: dict = {"host": host, "marker": header_name, "probes": []}
        findings: list[Finding] = []

        for p in params:
            if ctx.world.request_count >= ctx.max_requests:
                break
            payload = f"1%0d%0a{header_name}:cyphron"  # tanpa spasi: spasi mentah di request line bikin 400
            url = urljoin(base + "/", path.lstrip("/")) + \
                ("&" if "?" in path else "?") + f"{p}={payload}"
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
            except Exception as e:
                data["probes"].append({"param": p, "error": type(e).__name__})
                continue
            ctx.world.request_count += 1
            injected = any(k.lower() == header_name.lower() for k in (hd or {}))
            data["probes"].append({"param": p, "status": st, "header_injected": injected})
            if injected:
                findings.append(Finding(
                    tool=self.name,
                    title=f"CRLF header injection via parameter '{p}' on {host}",
                    severity="medium", cwe="CWE-93",
                    description=(
                        f"Parameter '{p}' menerima CRLF (%0d%0a) dan header "
                        f"respons baru '{header_name}' muncul persis di response "
                        f"headers. Attacker dapat menyuntik header arbitrer: "
                        f"session fixation, cache poisoning, XSS via header."),
                    recommendation=(
                        "Sanitasi CRLF (%0d/%0a) dari semua input yang masuk ke "
                        "header/logika respons; batasi panjang nilai."),
                    target_url=base, param=p,
                    request=f"GET {urlsplit(url).path}?{p}=1%0d%0a{header_name}:cyphron",
                    response=f"HTTP {st}; header '{header_name}' terinjeksi",
                    confidence=1.0, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="header"))
                break
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
