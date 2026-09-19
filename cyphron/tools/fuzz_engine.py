"""fuzz_engine — zero-day hunting untuk SISTEM SENDIRI (differential fuzzing).

Slot CRITICAL-30 (tierpack2). Menguji parameter yang ditemukan dengan kelas
mutasi berbahaya secara logis (bukan destruktif): type confusion, format
string, oversized, null-byte, unicode. Anomali terdeteksi = 5xx crash, error
signature baru, deviasi body ekstrem — lalu DIREPRODUKSI (dikirim ulang)
sebelum dilaporkan. Hasil = kandidat zero-day untuk review manual, bukan
klaim eksploitasi. Active: butuh otorisasi; budget keras."""

from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

MUTATIONS = [
    ("type-confusion-array", "cx[]"),
    ("type-confusion-object", "[object Object]"),
    ("format-string", "%s%s%s%s%d"),
    ("oversized-4k", "A" * 4000),
    ("null-byte", "cx\x00cx"),
    ("unicode-mixed", "сx\uffff\u0000d"),
]
ERROR_SIGNATURES = ("Traceback (most recent call last)", "at Object.", "Exception:",
                    "at line", "System.Exception", "panic:", "ReferenceError",
                    "TypeError:", "Segmentation fault")


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(k, value if k == param else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


class FuzzEngineTool(Tool):
    name = "fuzz_engine"
    description = "Zero-day hunt: differential fuzzing on discovered parameters."
    risk_tags = {"active"}
    source_skill = "70"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        findings: list[Finding] = []
        total = 0
        for ep in ctx.world.param_endpoints(limit=6):
            for param in ep.params[:3]:
                # baseline
                s0, _h0, b0, _m0 = http_engine.http_get(ep.url, timeout=ctx.timeout_s)
                ctx.world.observe_response(ep.url, s0, _h0, b0, self.name)
                total += 1
                base_len = len(b0 or "")
                for label, payload in MUTATIONS:
                    if ctx.world.request_count >= int(args.get("max_requests", 80)):
                        ctx.world.note(f"fuzz_engine: budget habis di {ep.url}#{param}")
                        return ToolResult(tool=self.name, ok=True,
                                          data={"requests": total}, findings=findings)
                    u = _with_param(ep.url, param, payload)
                    try:
                        status, _h, body, _ms = http_engine.http_get(u, timeout=ctx.timeout_s)
                    except Exception:
                        status, body = 0, ""
                    ctx.world.observe_response(u, status, _h, body, self.name)
                    total += 1

                    crash = status >= 500
                    err_sig = next((sig for sig in ERROR_SIGNATURES if sig in (body or "")), None)
                    huge_diff = abs(len(body or "") - base_len) > base_len * 9 and base_len > 100

                    if crash or err_sig or huge_diff:
                        # ---- REPRODUCE (truth guard: kirim ulang) ----
                        r_status, _rh, r_body, _rm = http_engine.http_get(u, timeout=ctx.timeout_s)
                        ctx.world.observe_response(u, r_status, _rh, r_body, self.name)
                        total += 1
                        reproduced = (crash and r_status >= 500) or \
                                     (err_sig and err_sig in (r_body or "")) or \
                                     (huge_diff and abs(len(r_body or "") - base_len) > base_len * 9)
                        if not reproduced:
                            continue  # satu kali kebetulan -> bukan temuan
                        kind = ("crash (5xx reproduced)" if crash else
                                f"error signature {err_sig!r} (reproduced)" if err_sig else
                                "extreme body deviation (reproduced)")
                        findings.append(Finding(
                            tool=self.name,
                            title=f"Fuzz anomaly via parameter '{param}' ({label}) — {kind}",
                            severity="high", cwe="CWE-20",
                            description=(f"Mutation '{label}' on `{param}` produced a reproduced "
                                         f"anomaly ({kind}). Ini KANDIDAT zero-day pada sistem "
                                         f"milik sendiri: butuh analisis manual untuk menentukan "
                                         f"dampak penuh (DoS/leak/RCE) sebelum diklaim."),
                            recommendation="Capture the payload+trace for internal engineering review; add regression test.",
                            target_url=ep.url, param=param,
                            request=f"GET {u}",
                            response=f"run1: status={status} len={len(body or '')}; "
                                     f"repro: status={r_status} len={len(r_body or '')}; baseline={base_len}",
                            poc=f"curl -g '{u}'   # reproduced on resend",
                            confidence=0.7, source_skill=self.source_skill,
                            status="confirmed", evidence_kind="probe-pair"))
                        break  # early stop per param: satu anomali cukup
        ctx.world.note(f"fuzz_engine: {total} requests, {len(findings)} reproduced anomalies")
        return ToolResult(tool=self.name, ok=True, data={"requests": total}, findings=findings)
