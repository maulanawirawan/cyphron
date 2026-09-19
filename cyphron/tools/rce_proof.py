"""rce_proof — command injection dari deteksi ke BUKTI eksekusi (CWE-78,
critical).

Teknik: payload aritmetika (CMD_ARITH) — server yang mengeksekusi perintah
akan MENGHITUNG 1234+1111 -> "2345" muncul di respons. Marker murni hasil
perhitungan, bukan string yang dikirim (echo input tidak bisa menghasilkan
"2345" dari "1234+1111" tanpa evaluasi).

FP-guard:
  - differential: "2345" TIDAK boleh ada di body baseline (angka kebetulan);
  - payload echo-safe: marker tidak termuat dalam payload mentah;
  - cease-on-data: bukti pertama berhenti; tidak ada perintah destruktif /
    enumerasi file / network command — hanya aritmetika;
  - maks 4 payload, 1 request per payload.
"""

from __future__ import annotations

from urllib.parse import quote as _q, urljoin

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding
from ..payloads import CMD_ARITH


class RceProofTool(Tool):
    name = "rce_proof"
    description = ("Command injection bukti eksekusi via aritmetika shell "
                   "(1234+1111 -> 2345) dengan differential baseline — "
                   "cease-on-data, tanpa perintah destruktif.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("url") or "")
        param = str(args.get("param") or "")
        baseline_value = str(args.get("baseline_value", "1"))
        if not base or not param:
            return ToolResult(tool=self.name, ok=False,
                              error="args.url + args.param wajib (param "
                                    "kandidat dari rce/param_miner)")

        def probe_for(value: str) -> str:
            if "{payload}" in base:
                return base.replace("{payload}", _q(value, safe=""))
            return urljoin(base + "/", ("&" if "?" in base else "?") +
                           f"{param}={_q(value, safe='')}")

        ctx.throttle()
        b_st, _h, b_body, _ms = http_engine.http_get(
            probe_for(baseline_value), timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        data: dict = {"param": param, "baseline_status": b_st, "probes": []}
        if "2345" in b_body:
            data["note"] = ("baseline sudah memuat '2345' — differential "
                            "tidak bisa dipercaya untuk param ini; skip")
            return ToolResult(tool=self.name, ok=True, data=data)

        findings: list[Finding] = []
        for pl in CMD_ARITH:
            if ctx.world.request_count >= ctx.max_requests or findings:
                break  # cease-on-data
            ctx.throttle()
            i_url = probe_for(baseline_value + pl.payload)
            try:
                st, _h, body, _ms = http_engine.http_get(i_url,
                                                         timeout=ctx.timeout_s)
            except Exception as e:
                data["probes"].append({"payload": pl.name,
                                       "error": type(e).__name__})
                continue
            ctx.world.request_count += 1
            hit = pl.evidence.lower() in body.lower()
            data["probes"].append({"payload": pl.name, "status": st,
                                   "marker_hit": hit})
            if hit and pl.evidence not in b_body:
                findings.append(Finding(
                    tool=self.name,
                    title=f"Command injection confirmed via {pl.name} "
                          f"on param '{param}'",
                    severity="critical", cwe="CWE-78",
                    description=(
                        f"Payload aritmetika '{pl.name}' pada parameter "
                        f"'{param}' dievaluasi server: respons memuat hasil "
                        f"hitung 1234+1111=2345 yang TIDAK ada di baseline "
                        f"dan tidak mungkin berasal dari echo input. Eksekusi "
                        f"perintah terbukti. cease-on-data: pengujian berhenti "
                        f"di bukti pertama; tidak ada command destruktif atau "
                        f"ekstraksi data."),
                    recommendation=(
                        "Jangan gabungkan input ke shell; pakai API/exec array "
                        "tanpa shell=True; validasi ketat karakter parameter; "
                        "least-privilege user service."),
                    target_url=base, param=param,
                    request=f"GET ...{param}={baseline_value!r}{pl.payload}",
                    response=f"status={st}; marker '2345' dihitung server "
                             f"(tidak ada di baseline)",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="probe-pair"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
