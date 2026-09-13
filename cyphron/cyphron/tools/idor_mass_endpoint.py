"""idor_mass_endpoint — pemetaan object-level authz di BANYAK endpoint
dengan SATU id asing per endpoint (CWE-639, high).

Berbeda dari error_oracle (1 endpoint, analisis error channel mendalam):
di sini endpoint list dari args (dari crawl/api_surface) diuji dangkal —
1 request own_id (baseline harus sukses) + 1 request foreign_id per
endpoint, cease-on-data di bukti pertama.

Guard: allow_foreign_probe=True wajib eksplisit; foreign_id HARUS dari
args (id akun kedua milik peneliti / id yang sudah ada di wilayah uji),
BUKAN enumerasi id massal; respons asing yang memuat data tidak disimpan
(redact, nilai redacted); endpoint yang baseline-nya gagal dilewati;
maks 12 endpoint x 2 request.
"""

from __future__ import annotations

import json

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_PII_KEYS = ("email", "phone", "name", "address", "nik", "ktp")


def _looks_like_data(body: str) -> bool:
    low = body.lower()
    if any(k in low for k in _PII_KEYS):
        return True
    try:
        j = json.loads(body)
    except Exception:
        return False
    return isinstance(j, (dict, list)) and bool(j)


class IdorMassEndpointTool(Tool):
    name = "idor_mass_endpoint"
    description = ("Pemetaan IDOR massal dangkal: 1 id asing per endpoint "
                   "(dari args), baseline own id wajib, cease-on-data, "
                   "redaksi nilai asing.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("base_url") or "").rstrip("/")
        endpoints = [str(e).lstrip("/") for e in (args.get("endpoints") or [])
                     if str(e).strip()][:12]
        id_template = str(args.get("id_template") or "/{id}")
        own_id = str(args.get("own_id") or "")
        foreign_id = str(args.get("foreign_id") or "")
        if not base or not endpoints or not own_id:
            return ToolResult(tool=self.name, ok=False,
                              error="base_url + endpoints + own_id wajib")
        if not args.get("allow_foreign_probe"):
            return ToolResult(
                tool=self.name, ok=False,
                error="uji id asing butuh allow_foreign_probe=True + foreign_id "
                      "MILIK WILAYAH UJI (akun kedua peneliti), bukan id massal")
        if not foreign_id:
            return ToolResult(tool=self.name, ok=False,
                              error="foreign_id wajib (id akun kedua milik "
                                    "peneliti — bukan enumerasi)")

        def get(path: str):
            url = base + "/" + path.lstrip("/")
            ctx.throttle()
            st, _h, body, _ms = http_engine.http_get(url,
                                                     timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            return st, body

        data: dict = {"endpoints": endpoints, "results": [],
                      "cease_on_data": True}
        findings: list[Finding] = []
        for ep in endpoints:
            if ctx.world.request_count >= ctx.max_requests or findings:
                break  # cease-on-data
            o_st, o_body = get(ep + id_template.replace("{id}", own_id))
            if o_st >= 400:
                data["results"].append({"endpoint": ep,
                                        "baseline": f"skip({o_st})"})
                continue  # endpoint bukan wilayah akun sendiri -> lewati
            f_st, f_body = get(ep + id_template.replace("{id}", foreign_id))
            leaked = f_st < 400 and _looks_like_data(f_body) and \
                f_body != o_body
            data["results"].append({"endpoint": ep, "own_status": o_st,
                                    "foreign_status": f_st,
                                    "foreign_leak": leaked})
            if leaked:
                findings.append(Finding(
                    tool=self.name,
                    title=f"IDOR confirmed on '{ep}' (object-level authz "
                          f"missing)",
                    severity="high", cwe="CWE-639",
                    description=(
                        f"Endpoint '{ep}' mengembalikan data object milik id "
                        f"asing ({foreign_id}) tanpa otorisasi object-level "
                        f"(baseline id sendiri {o_st}=ok; id asing "
                        f"{f_st}=data). cease-on-data: SATU id asing "
                        f"(wilayah uji peneliti) per endpoint; nilai data "
                        f"tidak disimpan; tidak ada enumerasi id lain."),
                    recommendation=(
                        "Enforce otorisasi object-level per request (owner "
                        "check di layer data); jangan percaya id dari klien; "
                        "uji dengan test suite authz otomatis."),
                    target_url=base, param=ep,
                    request=f"GET /{ep}{id_template.replace('{id}', foreign_id)}",
                    response=f"own={o_st}(ok) vs foreign={f_st}(data asing "
                             f"kembali; nilai redacted)",
                    confidence=0.85, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="probe-pair"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
