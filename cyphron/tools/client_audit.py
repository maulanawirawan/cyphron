"""client_audit — teknik manual agent (2026-09-08) yang dipromosikan ke engine.

Dua pemeriksaan postur berbasis FAKTA header/konten (bukan heuristik, nol FP
karena yang dilaporkan adalah isi respons itu sendiri):

1. cookie_audit - atribut keamanan tiap Set-Cookie pada surface anonim
   (HttpOnly / Secure / SameSite). Cookie kedaluwarsa/hapus diabaikan.
2. sri_audit    - skrip pihak ketiga (<script src=http...>) tanpa atribut
   integrity pada halaman utama. Same-host dan inline dikecualikan.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE)
_SESSION_HINTS = ("session", "auth", "token", "sid", "jwt", "login")
_DELETED_HINTS = ("deleted", "expired", "epoch", "1970")


def _hdr_all_raw() -> list[tuple[str, str]]:
    """Set-Cookie asli (termasuk duplikat) dari respons terakhir http_engine."""
    return [(k, v) for k, v in http_engine.LAST_RAW_HEADERS
            if k.lower() == "set-cookie"]


def _cookie_issues(cookie: str) -> list[str]:
    low = cookie.lower()
    if any(h in low for h in _DELETED_HINTS):
        return []  # FP-guard: cookie penghapus sesi bukan masalah atribut
    flags = []
    if "httponly" not in low:
        flags.append("HttpOnly-missing")
    if "secure" not in low:
        flags.append("Secure-missing")
    if "samesite" not in low:
        flags.append("SameSite-missing")
    return flags


class CookieAuditTool(Tool):
    name = "cookie_audit"
    description = ("Audit atribut keamanan semua Set-Cookie pada surface anonim "
                   "(fakta header, bukan heuristik).")
    risk_tags = {"active"}
    source_skill = "agent-manual-2026-09"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        problems: list[tuple[str, str, list[str]]] = []
        raw_seen: list[str] = []
        checked = 0
        for path in ("/", "/login"):
            try:
                ctx.throttle()
                st, _h, _b, _m = http_engine.http_get(base + path,
                                                      timeout=ctx.timeout_s,
                                                      follow_redirects=False)
            except Exception:
                continue
            ctx.world.request_count += 1
            checked += 1
            if not isinstance(st, int) or st >= 500:
                continue  # FP-guard: hanya respons layak yang diaudit
            for _name, cookie in _hdr_all_raw():
                cname = cookie.split("=", 1)[0].strip()
                if cookie in raw_seen:
                    continue
                raw_seen.append(cookie)
                flags = _cookie_issues(cookie)
                if flags:
                    problems.append((path, cname, flags))
        findings: list[Finding] = []
        if problems:
            risky = any(any(h in cname.lower() for h in _SESSION_HINTS)
                        and ("Secure-missing" in flags or "HttpOnly-missing" in flags)
                        for _p, cname, flags in problems)
            detail = "; ".join(f"{p} {c!r}: {','.join(f)}"
                               for p, c, f in problems[:10])
            findings.append(Finding(
                tool=self.name,
                title=(f"Cookie tanpa atribut keamanan lengkap: "
                       f"{len(problems)} cookie ({'sesi berisiko' if risky else 'non-sesi'})"),
                severity="medium" if risky else "low",
                cwe="CWE-1004",
                description=(f"Audit header Set-Cookie pada surface anonim menemukan "
                             f"cookie tanpa atribut keamanan lengkap (fakta header, "
                             f"bukan heuristik): {detail}. Cookie sesi tanpa "
                             f"HttpOnly/Secure dapat dibaca skrip atau terkirim "
                             f"tanpa enkripsi; tanpa SameSite terbuka CSRF lintas "
                             f"situs."),
                recommendation=("Tambahkan HttpOnly; Secure; SameSite=Lax (atau "
                                "Strict) pada semua cookie sesi, dan pertimbangkan "
                                "atribut yang sama untuk cookie fungsional lain."),
                target_url=base, request="GET / dan /login (Set-Cookie audit)",
                response=detail,
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="header",
                finding_class="posture"))
        ctx.world.note(f"cookie_audit: {checked} halaman, {len(problems)} cookie "
                       f"bermasalah, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True,
                          data={"pages": checked, "problems": len(problems)},
                          findings=findings)


class SriAuditTool(Tool):
    name = "sri_audit"
    description = ("Skrip pihak ketiga tanpa Subresource Integrity pada halaman "
                   "utama (fakta konten).")
    risk_tags = {"active"}
    source_skill = "agent-manual-2026-09"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = (urlsplit(base).hostname or "").lower()
        try:
            ctx.throttle()
            st, _h, body, _m = http_engine.http_get(base, timeout=ctx.timeout_s,
                                                    follow_redirects=False)
        except Exception as exc:
            ctx.world.note(f"sri_audit: halaman utama tidak terjangkau "
                           f"({type(exc).__name__})")
            return ToolResult(tool=self.name, ok=True,
                              data={"error": type(exc).__name__})
        ctx.world.request_count += 1
        if not isinstance(st, int) or st >= 400 or not body:
            ctx.world.note(f"sri_audit: respons {st} - tidak dinilai")
            return ToolResult(tool=self.name, ok=True, data={"status": st})
        missing: list[str] = []
        for m in _SCRIPT_RE.finditer(body):
            tag, src = m.group(0), m.group(1)
            if not src.lower().startswith(("http://", "https://")):
                continue  # inline/relatif: bukan subresource lintas-origin
            src_host = urlsplit(src).hostname or ""
            if src_host == host or host.endswith("." + src_host):
                continue  # same-origin/parent-domain: SRI tidak berlaku wajar
            if re.search(r"integrity\s*=", tag, re.IGNORECASE):
                continue
            if src not in missing:
                missing.append(src)
        findings: list[Finding] = []
        if missing:
            shown = "; ".join(missing[:8])
            findings.append(Finding(
                tool=self.name,
                title=f"Skrip pihak ketiga tanpa Subresource Integrity: {len(missing)}",
                severity="info", cwe="CWE-351",
                description=(f"Halaman utama memuat {len(missing)} skrip lintas-origin "
                             f"tanpa atribut integrity: {shown}. Bila CDN/sumber "
                             f"ketiga disusupi, kode yang diubah akan dieksekusi di "
                             f"halaman ini tanpa penahan SRI. Fakta konten halaman, "
                             f"bukan heuristik."),
                recommendation=("Tambahkan atribut integrity (hash SRI) pada skrip "
                                "pihak ketiga yang statis. Skrip dinamis/iklan yang "
                                "tidak mendukung SRI sebaiknya diisolasi ke origin "
                                "terpisah (sandbox iframe / CSP script-src)."),
                target_url=base, request="GET / (script[src] audit)",
                response=shown,
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="file",
                finding_class="posture"))
        ctx.world.note(f"sri_audit: {len(missing)} skrip eksternal tanpa integrity")
        return ToolResult(tool=self.name, ok=True, data={"missing": len(missing)},
                          findings=findings)
