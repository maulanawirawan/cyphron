"""debug_page — verbose error / debug-mode exposure check (CWE-209, CWE-489).

Teknik dari lapangan (2026-09): produksi dengan APP_DEBUG=true /
error_reporting penuh membalas request rusak dengan halaman debug framework
(Laravel Ignition, Whoops, Django traceback) yang membocorkan path internal,
versi framework, dan source code.

Trigger yang diuji (benign, GET):
  1. /?page=abc   - tipe salah pada paginator/query umum
  2. /?id=abc     - variasi konversi tipe

FP-guard (wajib sebelum predikat "debug page"):
  - WAJIB ada marker KUAT: "Ignition", "Whoops", "vendor/laravel",
    "vendor/swiftmailer", "Stack trace", "Traceback (most recent call last)",
    "WP_DEBUG" — kata "Exception"/"error" saja TIDAK cukup (halaman normal
    sering memuat kata itu);
  - status >= 500 diperkuat, tetapi 2xx dengan marker kuat juga sah
    (kasus nyata: debug page dirender pada request POST sukses-gagal);
  - versi framework/PHP diekstrak dan dilaporkan bila ada (bukan wajib).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_STRONG = re.compile(
    r"Ignition|Whoops|vendor[/\\]laravel|vendor[/\\]swiftmailer|"
    r"Stack trace|Traceback \(most recent call last\)|WP_DEBUG|"
    r"ErrorException|Fatal error", re.I)
_VERSIONS = re.compile(
    r"Laravel version[^0-9]{0,4}(\d+\.\d+\.\d+)|"
    r"PHP version[^0-9]{0,4}(\d+\.\d+\.\d+)", re.I)


class DebugPageTool(Tool):
    name = "debug_page"
    description = ("Verbose error/debug-mode exposure: halaman debug framework "
                   "(Ignition/Whoops/traceback) pada request rusak ringan + "
                   "ekstraksi versi framework/PHP.")
    risk_tags = {"active"}
    source_skill = "manual-bb-03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        probes = ["/?page=abc", "/?id=abc"]
        evidence: list[tuple[str, int, str]] = []
        for p in probes:
            if ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                st, _hd, body, _ms = http_engine.http_get(urljoin(base + "/", p.lstrip("/")),
                                                          timeout=ctx.timeout_s,
                                                          max_body=120_000)
            except Exception:
                continue
            ctx.world.request_count += 1
            if not isinstance(st, int) or not body:
                continue
            ctx.world.observe_response(urljoin(base + "/", p.lstrip("/")),
                                       st, _hd, body, self.name)
            m = _STRONG.search(body)
            if m and (st >= 500 or re.search(r"vendor[/\\]|Stack trace|Ignition|Whoops",
                                             body, re.I)):
                evidence.append((p, st, body))

        if not evidence:
            ctx.world.note(f"debug_page: {host} - tidak ada halaman debug terdeteksi")
            return ToolResult(tool=self.name, ok=True, data={"debug_page": "not-detected"})

        path, st, body = evidence[0]
        versions = [v for pair in _VERSIONS.findall(body) for v in pair if v]
        ver_text = (f" Versi terungkap: {'; '.join(versions[:2])}." if versions else "")
        findings = [Finding(
            tool=self.name,
            title=f"Verbose debug/error page exposed in production on {host}",
            severity="medium", cwe="CWE-209",
            description=(
                f"Request rusak ringan ({path}) dibalas HTTP {st} dengan halaman "
                f"debug framework (marker kuat: "
                f"{'; '.join(sorted(set(re.findall(r'Ignition|Whoops|Stack trace|'
                r'vendor[/\\\\]laravel|vendor[/\\\\]swiftmailer|ErrorException|'
                r'Fatal error', body, re.I)))[:3]) or 'stack trace'}). Halaman ini "
                f"membocorkan detail internal ke setiap pengunjung.{ver_text} "
                f"Status predikat: CONFIRMED - marker kuat + status terukur; "
                f"tidak ada eksploitasi lanjutan yang dilakukan."),
            recommendation=(
                "Matikan debug mode di produksi (APP_DEBUG=false / display_errors=off); "
                "kembalikan halaman error generik; catat exception ke log server; "
                "naikkan versi framework/runtime yang end-of-life bila terungkap."),
            target_url=urljoin(base + "/", path.lstrip("/")),
            request=f"GET {path}",
            response=f"HTTP {st}; debug markers terdeteksi (detail di video/screenshot)",
            poc=f"curl -i \"{'https://' + host + path}\"",
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="request-response")]
        ctx.world.note(f"debug_page: {host} - DEBUG PAGE TERDETEKSI pada {path} "
                       f"(HTTP {st})")
        return ToolResult(tool=self.name, ok=True,
                          data={"debug_page": "detected", "probe": path, "status": st,
                                "versions": versions[:2]},
                          findings=findings)
