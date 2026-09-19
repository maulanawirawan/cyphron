"""cors — CORS misconfig probe: arbitrary Origin reflection + credentials
(CWE-942).

Teknik: satu GET dengan Origin dari domain kontrol; kalau server membalas
Access-Control-Allow-Origin yang MEMANTULKAN origin itu persis sambil
Access-Control-Allow-Credentials: true, situs mana pun bisa membaca respons
terotentikasi korban — kombinasi yang tidak boleh terjadi.

FP-guard:
  - ACAO `*` TIDAK dilaporkan (browser menolak kredensial pada wildcard —
    bukan exploitable untuk pencurian respons terotentikasi);
  - refleksi HARUS persis origin kontrol kita (allowlist origin sah milik
    aplikasi tidak memantulkan origin asing);
  - hanya GET read-only, nol kredensial, satu request.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_PROBE_ORIGIN = "https://cyphron-probe.invalid"


def _hdr(hd: dict, name: str) -> str:
    for k, v in (hd or {}).items():
        if k.lower() == name.lower():
            return v or ""
    return ""


class CorsProbeTool(Tool):
    name = "cors"
    description = ("CORS misconfig: arbitrary-Origin reflection with "
                   "Allow-Credentials. 1 read-only GET, exact-match guard.")
    risk_tags = {"active"}
    source_skill = "manual-bb-09"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        try:
            ctx.throttle()
            st, hd, body, _ms = http_engine.http_get(
                base + "/", headers={"Origin": _PROBE_ORIGIN},
                timeout=ctx.timeout_s)
        except Exception as e:
            return ToolResult(tool=self.name, ok=True,
                              data={"error": type(e).__name__},
                              error=f"fetch failed: {type(e).__name__}")
        ctx.world.request_count += 1
        ctx.world.observe_response(base + "/", st, hd, body, self.name)

        acao = _hdr(hd, "Access-Control-Allow-Origin").strip()
        acac = _hdr(hd, "Access-Control-Allow-Credentials").strip().lower()
        data = {"host": host, "acao": acao, "acac": acac, "probe_origin": _PROBE_ORIGIN}

        if acao == _PROBE_ORIGIN and acac == "true" and isinstance(st, int) and st < 500:
            findings = [Finding(
                tool=self.name,
                title=f"CORS reflects arbitrary Origin with credentials on {host}",
                severity="medium", cwe="CWE-942",
                description=(
                    f"Server memantulkan Origin asing ({_PROBE_ORIGIN}) ke "
                    f"Access-Control-Allow-Origin bersama "
                    f"Access-Control-Allow-Credentials: true. Situs pihak ketiga "
                    f"dapat membaca respons terotentikasi korban (cookie-based "
                    f"session) lintas origin — termasuk endpoint data pribadi."),
                recommendation=(
                    "Jangan pantulkan Origin sembarang; allowlist origin sah "
                    "secara eksplisit, dan jangan set Allow-Credentials bersama "
                    "refleksi dinamis."),
                target_url=base,
                request=f"GET / dengan Origin: {_PROBE_ORIGIN}",
                response=f"ACAO={acao}; ACAC={acac}; HTTP {st}",
                poc=f"curl -sI -H 'Origin: {_PROBE_ORIGIN}' {base}/ — lihat ACAO memantulkan",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="header")]
            return ToolResult(tool=self.name, ok=True, data=data, findings=findings)

        if acao == "*":
            data["note"] = ("ACAO wildcard — tidak exploitable untuk kredensial, "
                            "tidak dilaporkan")
        return ToolResult(tool=self.name, ok=True, data=data)
