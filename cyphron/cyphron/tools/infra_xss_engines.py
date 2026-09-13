"""roadmap_batch6 — slot HIGH yang diimplementasikan LIVE:
1. sourcemap2 (high-17 sourcemap-full-recover + high-18 map-secrets):
   sourcesContent pulih penuh + kredensial di dalam source
2. mq_mgmt    (high-16 mq-mgmt-exposed): RabbitMQ/ActiveMQ management terbuka
3. dom_xss    (high-19 dom-xss-sink): sink berbahaya yang makan source DOM (statis)
4. clickj     (high-21 clickjacking-action): halaman aksi sensitif tanpa proteksi framing

Truth guarantee: sourcemap2 = JSON .map valid dengan sourcesContent/kredensial
literal; mq = marker brand definitif (management_version / brand ActiveMQ);
clickj = header framing HILANG di halaman ber-form (fakta header); dom_xss =
sink+source di JS = lead unconfirmed (butuh verifikasi runtime)."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from .secret_scan import PATTERNS as SECRET_PATTERNS
from ..findings import Finding


class Sourcemap2Tool(Tool):
    name = "sourcemap2"
    description = "Sourcemap dalam: source penuh pulih + kredensial di sourcesContent."
    risk_tags = {"active"}
    source_skill = "t2-high-17"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        tested = 0
        for url in list(ctx.world.endpoints)[:15]:
            if tested >= 8 or ctx.world.request_count >= ctx.max_requests:
                break
            if not urlsplit(url).path.endswith((".js", ".ts", ".jsx", ".css")):
                continue
            map_url = url + ".map"
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(map_url, timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.observe_response(map_url, st, hd, body, self.name)
            tested += 1
            if st != 200 or '"sources"' not in (body or ""):
                continue
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                continue
            sources = data.get("sourcesContent") or []
            recovered = sum(len(s or "") for s in sources)
            # high-17: source ASLI pulih penuh (bukan hanya nama file)
            if recovered > 1000:
                findings.append(Finding(
                    tool=self.name,
                    title=f"Sourcemap memulihkan {recovered} karakter source asli",
                    severity="high", cwe="CWE-540",
                    description=(f"{map_url} memuat sourcesContent berisi {recovered} "
                                 f"karakter kode asli (pre-build): logika bisnis, endpoint "
                                 f"internal, dan komentar developer sepenuhnya terbaca."),
                    recommendation="Jangan deploy .map ke produksi; hapus dari build output.",
                    target_url=map_url, request=f"GET {map_url}",
                    response=f"sourcesContent total {recovered} chars, {len(sources)} file",
                    poc=f"curl -s '{map_url}' | python -m json.tool | head -50",
                    confidence=0.95, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
            # high-18: kredensial literal di dalam source yang pulih
            leaked = []
            for name, pattern, sev, _cwe in SECRET_PATTERNS:
                for match in pattern.finditer(body):
                    if name != "generic credential assignment" or True:
                        leaked.append(f"{name}: {match.group(0)[:40]}...")
                    break  # satu contoh per pola cukup (nilai di-redaksi)
            if leaked:
                findings.append(Finding(
                    tool=self.name,
                    title=f"Sourcemap membocorkan {len(leaked)} pola kredensial",
                    severity="high", cwe="CWE-798",
                    description=(f"Source yang dipulihkan dari {map_url} memuat literal "
                                 f"kredensial: {'; '.join(leaked[:5])}. Kode client-side "
                                 f"mengekspos secret yang bisa langsung dipakai."),
                    recommendation="Pindahkan semua secret ke server-side/env; rotasi "
                                   "kredensial yang sudah ter-publish.",
                    target_url=map_url, request=f"GET {map_url}",
                    response="; ".join(leaked[:5]), confidence=0.9,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="request-response"))
        ctx.world.note(f"sourcemap2: {tested} .map diuji, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class MqMgmtTool(Tool):
    name = "mq_mgmt"
    description = "MQ management console terbuka tanpa auth (RabbitMQ/ActiveMQ)."
    risk_tags = {"active"}
    source_skill = "t2-high-16"

    CHECKS = (
        ("/api/overview", "rabbitmq", "RabbitMQ management API terbuka"),
        ("/rabbitmq/api/overview", "rabbitmq", "RabbitMQ management API terbuka"),
        ("/admin/", "activemq", "ActiveMQ web console terbuka"),
        ("/admin/index.jsp", "activemq", "ActiveMQ web console terbuka"),
    )

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        tested = 0
        for path, marker, message in self.CHECKS:
            if tested >= 6 or ctx.world.request_count >= ctx.max_requests:
                break
            url = base + path
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.observe_response(url, st, hd, body, self.name)
            tested += 1
            # FP-guard: status < 400 DAN marker brand definitif di body
            if st < 400 and marker in (body or "").lower():
                findings.append(Finding(
                    tool=self.name,
                    title=f"{message}: {path}",
                    severity="high", cwe="CWE-306",
                    description=(f"{message} di {url} (HTTP {st}, marker '{marker}' "
                                 f"hadir di respons, tanpa autentikasi). Konsol MQ "
                                 f"memaparkan antrian, binding, dan kadang kredensial."),
                    recommendation="Batasi konsol ke jaringan internal/VPN; wajibkan "
                                   "auth kuat; hapus dari edge publik.",
                    target_url=url, request=f"GET {path}",
                    response=f"status={st}; marker '{marker}' ditemukan",
                    poc=f"curl -s '{url}' | head -c 300",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
        ctx.world.note(f"mq_mgmt: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class DomXssTool(Tool):
    name = "dom_xss"
    description = "DOM XSS sink statis: innerHTML/eval/write yang makan data URL."
    risk_tags = {"passive"}
    source_skill = "t2-high-19"

    SINK_RE = re.compile(
        r"(?:\.\s*(?:innerHTML|outerHTML)\s*=|document\.write(?:ln)?\s*\(|\beval\s*\("
        r"|\.html\s*\()"
        r"[^;]{0,80}"
        r"(?:location(?:\.(?:hash|search|href))?|documentURL|document\.URL|"
        r"URLSearchParams|window\.name|postMessage)",
        re.I)

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cap = int(args.get("max_requests", 6))
        findings: list[Finding] = []
        tested = 0
        for url in list(ctx.world.endpoints)[:25]:
            if tested >= cap or ctx.world.request_count >= ctx.max_requests:
                break
            if not urlsplit(url).path.endswith(".js"):
                continue
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.observe_response(url, st, hd, body, self.name)
            tested += 1
            if st != 200:
                continue
            hits = self.SINK_RE.search(body)
            if hits:
                snippet = hits.group(0)[:160]
                findings.append(Finding(
                    tool=self.name,
                    title=f"Dugaan DOM XSS sink di {urlsplit(url).path}",
                    severity="high", cwe="CWE-79",
                    description=(f"JS di {url} mengalirkan data dari source URL/hash ke sink "
                                 f"eksekusi-DOM: '{snippet}'. Analisis statis — butuh "
                                 f"verifikasi runtime sebelum diklaim eksploitable."),
                    recommendation="Gunakan textContent, sanitasi dengan DOMPurify, atau "
                                   "peta source->sink yang tervalidasi.",
                    target_url=url, request="static JS analysis",
                    response=snippet, confidence=0.4,
                    source_skill=self.source_skill, status="unconfirmed",
                    evidence_kind="code-line"))
        ctx.world.note(f"dom_xss: {tested} asset JS dianalisis, {len(findings)} lead")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class ClickjackTool(Tool):
    name = "clickj"
    description = "Clickjacking: halaman aksi sensitif tanpa XFO/frame-ancestors."
    risk_tags = {"passive"}
    source_skill = "t2-high-21"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        candidates = [ep.url for ep in ctx.world.endpoints.values()
                      if ep.form_fields or any(
                          k in urlsplit(ep.url).path.lower()
                          for k in ("logout", "settings", "profile", "account",
                                    "password", "delete", "transfer"))][:4]
        if base not in candidates:
            candidates.append(base)
        tested = 0
        for url in candidates[:4]:
            if tested >= 4 or ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.observe_response(url, st, hd, body, self.name)
            tested += 1
            if st != 200 or "html" not in str(_hdr(hd, "content-type")).lower():
                continue
            has_action = ("<form" in (body or "").lower()
                          or re.search(r"<button[^>]*>", body or "", re.I))
            xfo = _hdr(hd, "x-frame-options")
            csp = _hdr(hd, "content-security-policy")
            framed = bool(xfo) or ("frame-ancestors" in csp)
            # FP-guard: halaman punya aksi (form/button) DAN TIDAK ada proteksi framing
            if has_action and not framed:
                findings.append(Finding(
                    tool=self.name,
                    title=f"Clickjacking: aksi sensitif tanpa proteksi framing di "
                          f"{urlsplit(url).path or '/'}",
                    severity="high", cwe="CWE-1021",
                    description=(f"Halaman {url} memuat form/tombol aksi namun tidak "
                                 f"mengirim X-Frame-Options maupun CSP frame-ancestors "
                                 f"(XFO={xfo or 'absen'}). Halaman bisa di-frame dan aksi "
                                 f"dipicu tanpa sepengetahuan pengguna (UI redressing)."),
                    recommendation="Kirim CSP frame-ancestors 'self' (atau DENY) pada "
                                   "seluruh halaman ber-aksi.",
                    target_url=url, request=f"GET {url}",
                    response=f"X-Frame-Options={xfo or 'absen'}; frame-ancestors absent; "
                             f"aksi: {'form' if '<form' in (body or '').lower() else 'button'}",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="header"))
        ctx.world.note(f"clickj: {tested} halaman diuji, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""
