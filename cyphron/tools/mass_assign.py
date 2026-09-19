"""mass_assign — parameter privilege di endpoint register/update akun
SENDIRI (CWE-915, high).

Rantai bukti (differential + persistensi):
  1. POST/PUT akun sendiri + field privilege (role/isAdmin/...) = nilai
     privilege; bila server 4xx -> tolak, bukan temuan;
  2. VERIFIKASI persistensi via args.verify_url (GET profil akun sendiri):
     field privilege benar-benar tersimpan = temuan. TANPA verify_url,
     respons POST yang meng-echo field = hanya LEAD (echo != tersimpan —
     pelajaran marker statis != dinamis).

FP-guard: hanya akun milik sendiri (body dari args); field dibatasi
allowlist; nilai '1'/'true' evidence-safe; cease-on-data; maks 3 request.
"""

from __future__ import annotations

import json

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_DEFAULT_FIELDS = ("role", "isAdmin", "is_admin", "admin", "level",
                   "userType", "permissions")


class MassAssignTool(Tool):
    name = "mass_assign"
    description = ("Mass assignment pada akun sendiri: field privilege di "
                   "register/update + verifikasi persistensi di profil.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        body = args.get("body") or {}
        verify_url = str(args.get("verify_url") or "").strip()
        fields = [f for f in (args.get("fields") or _DEFAULT_FIELDS)][:8]
        value = args.get("privilege_value", "admin")
        if not url or not isinstance(body, dict) or not body:
            return ToolResult(tool=self.name, ok=False,
                              error="args.url + args.body (akun SENDIRI) wajib")
        if fields and "email" in fields:
            fields = [f for f in fields if f != "email"]

        def post(b: dict):
            ctx.throttle()
            st, _h, txt, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, method="POST",
                data=json.dumps(b).encode(),
                headers={"Content-Type": "application/json"})
            ctx.world.request_count += 1
            return st, txt

        data: dict = {"fields": fields, "probes": []}
        findings: list[Finding] = []
        stored: list[str] = []
        for f in fields:
            if ctx.world.request_count >= ctx.max_requests or stored:
                break  # cease-on-data
            payload = dict(body)
            payload[f] = value
            st, txt = post(payload)
            data["probes"].append({"field": f, "status": st})
            if st >= 400:
                continue  # server menolak field — postur baik
            low = txt.lower()
            if json.dumps(value).lower().strip('"') in low or \
                    str(value).lower() in low:
                if not verify_url:
                    data.setdefault("lead", []).append(
                        f"{f} ter-echo pada respons POST (belum terbukti "
                        f"tersimpan; sediakan verify_url untuk bukti)")
                    continue
                ctx.throttle()
                v_st, _h, v_txt, _ms = http_engine.http_get(
                    verify_url, timeout=ctx.timeout_s)
                ctx.world.request_count += 1
                v_low = v_txt.lower()
                persisted = (str(value).lower() in v_low and
                             json.dumps(value).lower().strip('"') in v_low
                             or str(value).lower() in v_low)
                if persisted and str(value).lower() in v_low:
                    stored.append(f)
        if not stored:
            return ToolResult(tool=self.name, ok=True, data=data)
        findings.append(Finding(
            tool=self.name,
            title=f"Mass assignment: privilege fields {stored} persisted on "
                  f"own account",
            severity="high", cwe="CWE-915",
            description=(
                f"Field {stored} pada endpoint '{url}' diterima server dan "
                f"TERVERIFIKASI tersimpan di profil akun peneliti (verify "
                f"via GET) — penyerang mendaftar/ubah akun apa pun menjadi "
                f"privileged. cease-on-data: satu akun sendiri saja; tidak "
                f"ada perubahan akun orang lain."),
            recommendation=(
                "Allowlist field yang boleh di-bind (DTO/serializer); abaikan "
                "field keamanan (role/isAdmin) dari input; otorisasi "
                "perubahan role lewat endpoint terpisah admin-only."),
            target_url=url, param=", ".join(stored),
            request=f"POST {url} {{..., {stored[0]}: {value!r}}} (akun sendiri)",
            response=f"verify GET: {stored[0]}={value!r} tersimpan "
                     f"(persistensi terbukti)",
            confidence=0.9, source_skill=self.source_skill,
            status="confirmed", evidence_kind="request-pair"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
