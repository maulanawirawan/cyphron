"""auth_bypass_matrix — matriks bypass authz pada path terproteksi
(CWE-288/862, high->critical).

Baseline WAJIB ditolak (401/403); kalau path sudah terbuka -> skip (tidak
ada yang di-bypass). Matriks: header internal (X-Original-URL family),
ACL-IP, dan varian path (normalisasi proxy vs app). Bukti bypass:
status turun ke 2xx/redirect-berisi DAN body berbeda signifikan dari
baseline DAN bukan halaman login (pelajaran dir_probe: admin 200 bisa
cuma login page -> candidate info).
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding
from ..payloads import AUTH_BYPASS_HEADERS, AUTH_BYPASS_PATHS

_LOGIN_HINT = re.compile(r"<form[^>]*>|log\s?in|masuk|password", re.I)


class AuthBypassMatrixTool(Tool):
    name = "auth_bypass_matrix"
    description = ("Matriks bypass authz (header internal + varian path) "
                   "pada path terproteksi — bukti differential vs baseline "
                   "401/403, anti-FP login-page.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("url") or "").rstrip("/")
        if not base:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        path = "/" + base.split("://", 1)[-1].split("/", 1)[-1]

        ctx.throttle()
        b_st, _h, b_body, _ms = http_engine.http_get(base, timeout=ctx.timeout_s)
        ctx.world.observe_response(base, b_st, _h, b_body, self.name)
        ctx.world.request_count += 1
        if b_st < 400:
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": f"baseline {b_st} (path sudah terbuka — "
                           f"tidak ada yang di-bypass)"})
        b_len = len(b_body)

        attempts: list[dict] = []
        findings: list[Finding] = []
        cases: list[tuple[str, str, dict[str, str]]] = []
        for p in AUTH_BYPASS_HEADERS:
            header, _, value = p.payload.partition(": ")
            cases.append((p.name, base, {header: value.replace("{path}", path.strip("/"))}))
        for p in AUTH_BYPASS_PATHS:
            origin = base.split("://", 1)[0] + "://" + base.split("://", 1)[-1].split("/", 1)[0]
            cases.append((p.name, origin + p.payload.replace("{path}", path.strip("/")), {}))

        for name, url, extra in cases:
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            st, _h, body, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, headers=extra or None)
            ctx.world.observe_response(url, st, _h, body, self.name)
            ctx.world.request_count += 1
            is_login = bool(_LOGIN_HINT.search(body or ""))
            different = abs(len(body or "") - b_len) > 64 or (body or "") != b_body
            bypassed = st < 400 and different
            attempts.append({"case": name, "url": url, "status": st,
                             "bypassed": bypassed, "login_page": is_login})
            if bypassed:
                severity = "critical" if not is_login else "medium"
                findings.append(Finding(
                    tool=self.name,
                    title=f"Auth bypass via {name}: {path} -> {st}"
                          + (" (login page - candidate)" if is_login else ""),
                    severity=severity, cwe="CWE-288",
                    description=(f"Baseline {b_st} pada {base}; varian '{name}' "
                                 f"menghasilkan {st} dengan konten berbeda."
                                 + (" Body berupa halaman login — bukti akses "
                                    "fungsi terlarang belum lengkap (candidate)."
                                    if is_login else
                                    " Konten NON-login terbuka tanpa kredensial "
                                    "— bypass terbukti.")),
                    recommendation=("Konsistenkan kebijakan authz di app-layer "
                                    "untuk SEMUA varian path/header; blok header "
                                    "internal di edge."),
                    file_path=None, line_start=None, line_end=None,
                    request=f"GET {url}" + (f" | extra={extra}" if extra else ""),
                    response=f"baseline={b_st}; bypass={st}; login_page={is_login}; "
                             f"len {b_len}->{len(body or '')}",
                    confidence=0.55 if is_login else 0.85,
                    source_skill=self.source_skill,
                    status="unconfirmed" if is_login else "confirmed",
                    evidence_kind="request-response",
                ))
                break  # satu bukti cukup; sisa matriks tidak perlu
        return ToolResult(tool=self.name, ok=True, data={
            "url": base, "baseline_status": b_st,
            "attempts": attempts,
        }, findings=findings)
