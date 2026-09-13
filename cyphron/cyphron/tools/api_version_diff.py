"""api_version_diff — fitur yang sudah di-deprecate di v2 masih terbuka di
v1 (CWE-1233, medium).

Differential: SATU sample path (dari args, bukan sweep) diuji pada v1 dan
v2:
  - v2 menolak (404/410/403) tapi v1 masih 200 = endpoint deprecated tetap
    hidup -> temuan medium (permukaan lama tak diaudit);
  - keduanya 200 = "masih aktif dua-duanya" (note, bukan temuan);
  - keduanya gagal / v1 juga menolak = postur baik.
Guard: maks 2 path per run; respons v1 TIDAK disimpan penuh (excerpt
redacted 80 char); 1 request per versi per path.
"""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding


class ApiVersionDiffTool(Tool):
    name = "api_version_diff"
    description = ("Differential v1 vs v2: endpoint yang ditolak di v2 tapi "
                   "masih hidup di v1 = permukaan deprecated.")
    risk_tags = {"active"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url_v1 = str(args.get("url_v1") or "")
        url_v2 = str(args.get("url_v2") or "")
        paths = [str(p).strip("/") for p in (args.get("paths") or [])][:2]
        if not url_v1 or not url_v2 or not paths:
            return ToolResult(tool=self.name, ok=False,
                              error="url_v1 + url_v2 + paths wajib")
        data: dict = {"paths": paths, "results": []}
        findings: list[Finding] = []
        for p in paths:
            if ctx.world.request_count >= ctx.max_requests or findings:
                break  # cease-on-data
            ctx.throttle()
            s1, _h1, b1, _m1 = http_engine.http_get(
                f"{url_v1.rstrip('/')}/{p}", timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            ctx.throttle()
            s2, _h2, b2, _m2 = http_engine.http_get(
                f"{url_v2.rstrip('/')}/{p}", timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            v1_ok = s1 < 400
            v2_rejected = s2 in (403, 404, 410) or s2 >= 500
            data["results"].append({"path": p, "v1_status": s1,
                                    "v2_status": s2})
            if v1_ok and v2_rejected:
                excerpt = redact(b1[:80]) if b1 else "(kosong)"
                findings.append(Finding(
                    tool=self.name,
                    title=f"Deprecated API version still live: v1 '{p}' "
                          f"(rejected on v2)",
                    severity="medium", cwe="CWE-1233",
                    description=(
                        f"Endpoint '{p}' DITOLAK di v2 (status {s2}) tetapi "
                        f"masih merespons 200 di v1 — versi lama yang sudah "
                        f"tidak diaudit tetap menyajikan data/fitur. "
                        f"cease-on-data: satu sample path; isi respons tidak "
                        f"disimpan."),
                    recommendation=("Matikan/rute v1 ke 410 Gone dengan "
                                    "sunset header; samakan policy authz "
                                    "antara versi."),
                    target_url=url_v1, param=p,
                    request=f"GET v1/{p} vs GET v2/{p}",
                    response=f"v1={s1} (hidup; excerpt: {excerpt!r}); "
                             f"v2={s2} (ditolak)",
                    confidence=0.8, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="probe-pair"))
        if not findings:
            data.setdefault("note", "tidak ada divergensi v1/v2 pada sample")
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
