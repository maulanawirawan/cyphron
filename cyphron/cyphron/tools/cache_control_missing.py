"""cache_control_missing — respons PERSONAL tanpa Cache-Control (CWE-524,
low posture, intel).

Guard penting (pelajaran: non-claim umum):
  - hanya relevan bila respons membawa jejak personalisasi (Set-Cookie
    session-like / body memuat email terdeteksi kasar) — halaman statis
    publik tanpa cookie wajar dicache;
  - Cache-Control no-store/private/no-cache = postur baik;
  - hasil surface; alamat yang kebetulan terlihat di-mask.
1 GET per run.
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)
_SESSION_HINTS = ("session", "sid", "auth", "token", "csrf")


def _mask(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


class CacheControlMissingTool(Tool):
    name = "cache_control_missing"
    description = ("Respons personal (Set-Cookie session-like / konten "
                   "personal) tanpa Cache-Control no-store — intel posture.")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        ctx.throttle()
        st, hd, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        cc = (hd or {}).get("Cache-Control", "").lower()
        set_cookies = [v for k, v in (http_engine.LAST_RAW_HEADERS or [])
                       if k.lower() == "set-cookie"]
        session_cookie = any(any(h in sc.lower() for h in _SESSION_HINTS)
                             for sc in set_cookies)
        personal_email = re.search(_EMAIL_RE, body or "")
        data = {"status": st, "cache_control": cc or None,
                "personal_signals": bool(session_cookie or personal_email)}
        if cc and any(t in cc for t in ("no-store", "private", "no-cache")):
            data["note"] = "postur baik"
            return ToolResult(tool=self.name, ok=True, data=data)
        if not data["personal_signals"]:
            data["note"] = ("respons terlihat non-personal — tidak dinilai "
                            "(halaman publik wajar dicache)")
            return ToolResult(tool=self.name, ok=True, data=data)
        detail = (f"Set-Cookie session-like ({len(set_cookies)})" if
                  session_cookie else
                  f"konten personal ({_mask(personal_email.group(0))})")
        findings = [Finding(
            tool=self.name,
            title=f"Personalized response without Cache-Control on {url}",
            severity="low", cwe="CWE-524",
            description=(f"Respons memuat sinyal personal ({detail}) tetapi "
                         f"tanpa Cache-Control no-store/private — shared/"
                         f"browser cache bisa menyimpan halaman personal "
                         f"(contoh: tombol back setelah logout). "
                         f"finding_class=posture, non-claim umum."),
            recommendation=("Set Cache-Control: no-store pada semua respons "
                            "terautentikasi/personal."),
            target_url=url, request=f"GET {url}",
            response=f"Cache-Control={cc or '(tidak ada)'}; sinyal={detail}",
            confidence=0.6, source_skill=self.source_skill,
            status="confirmed", evidence_kind="header",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
