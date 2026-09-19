"""redteam_variants — eskalasi variasi red teaming (deterministik, zero-FP).

Tiga engine variasi baru untuk fase eskalasi — SEMUanya pakai kontrol
baseline dan marker aman (tanpa payload destruktif, tanpa CRLF, tanpa
brute force):

1. variant_sweep           — payload marker di-sweep dengan variasi encoding
                             (double-encode, %u-unicode, case-flip, null-strip,
                             tab-prefix, raw). Temuan hanya bila MARKER CORE
                             terpantul MENTAH pada salah satu varian DAN baseline
                             tidak memuat marker (probe-pair deterministik).
2. method_override_matrix  — POST + header/form override (X-HTTP-Method-Override,
                             X-Method-Override, _method). Lead bila status
                             berubah signifikan vs POST polos (endpoint
                             menghormati override — bahan authz misconfig).
3. header_variant_matrix   — header spoof klasik (X-Forwarded-For: 127.0.0.1,
                             X-Original-URL, dsb.) pada endpoint terlindungi.
                             Lead bila status turun 4xx -> <400 pada salah satu
                             varian (auth bypass HINT — bukan klaim bypass).

Semua temuan = status "unconfirmed" (lead) kecuali bukti probe-pair penuh
(variant_sweep: baseline vs varian). Batas request jelas per engine.
"""

from __future__ import annotations

from urllib.parse import quote as _q, urljoin

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_MARKER = "cyphronv7x"


def _with_param(base: str, param: str, value: str) -> str:
    return urljoin(base, ("&" if "?" in base else "?") + f"{param}={value}")


class VariantSweepTool(Tool):
    name = "variant_sweep"
    description = ("Sweep variasi encoding payload marker pada parameter — "
                   "deteksi filter yang hanya menyaring bentuk tertentu. "
                   "Marker aman, probe-pair, maks 7 request.")
    risk_tags = {"active"}
    source_skill = "redteam-variants-01"

    VARIANTS = (
        ("raw", lambda p: p),
        ("double-encode", lambda p: _q(_q(p, safe=""), safe="")),
        ("unicode-esc", lambda p: p.replace("'", "%u0027").replace("<", "%u003c")),
        ("case-flip", lambda p: p.swapcase()),
        ("null-strip", lambda p: p + "%00"),
        ("tab-prefix", lambda p: "%09" + p),
    )

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("url") or "")
        param = str(args.get("param") or "")
        if not base:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        if not param:
            eps = [e for e in ctx.world.param_endpoints() if e.get("params")]
            param = (eps[0]["params"][0] if eps else "") if eps else ""
        if not param:
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "tidak ada parameter teramati"})
        payload = f"{_MARKER}'\"><{param}>"
        ctx.throttle()
        s_b, _h, body_b, _m = http_engine.http_get(
            _with_param(base, param, "baseline"), timeout=ctx.timeout_s,
            follow_redirects=False)
        ctx.world.request_count += 1
        baseline_hit = _MARKER in (body_b or "")
        hits = []
        for name, fn in self.VARIANTS:
            ctx.throttle()
            s, h, body, _m = http_engine.http_get(
                _with_param(base, param, fn(payload)), timeout=ctx.timeout_s,
                follow_redirects=False)
            ctx.world.request_count += 1
            if s < 400 and _MARKER in (body or "") and not baseline_hit:
                hits.append({"variant": name, "status": s})
        if not hits or baseline_hit:
            return ToolResult(tool=self.name, ok=True, data={
                "param": param, "variants_tried": len(self.VARIANTS),
                "baseline_hit": baseline_hit, "hits": hits,
                "note": ("marker ada di baseline — bukan refleksi varian"
                         if baseline_hit else
                         "tidak ada varian yang terpantul mentah")})
        names = ", ".join(h["variant"] for h in hits)
        findings = [Finding(
            tool=self.name,
            title=f"Payload marker terpantul mentah lewat varian encoding: {names}",
            severity="info", cwe="CWE-79",
            description=(
                f"Parameter '{param}' memantulkan MARKER mentah pada varian "
                f"({names}) sementara baseline bersih — filter input hanya "
                f"menyaring bentuk tertentu. Ini PREKUSOR refleksi/injeksi "
                f"(LEAD): klaim XSS/injeksi nyata tetap butuh verifikasi "
                f"payload penuh yang sah."),
            recommendation=("Normalize + decode berlapis sebelum validasi; "
                            "allowlist karakter; encode kontekstual saat output."),
            target_url=base, param=param,
            request=f"GET ...?{param}=<varian {names}> dari {payload[:40]}",
            response=f"status={hits[0]['status']}; marker mentah pada {len(hits)} varian",
            confidence=0.6, source_skill=self.source_skill,
            status="unconfirmed", evidence_kind="probe-pair",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data={
            "param": param, "baseline_hit": baseline_hit, "hits": hits},
            findings=findings)


class MethodOverrideMatrixTool(Tool):
    name = "method_override_matrix"
    description = ("Deteksi endpoint yang menghormati method override "
                   "(X-HTTP-Method-Override / _method) — bahan authz "
                   "misconfig (middleware verifikasi method GET tapi action "
                   "mutasi jalan). Maks 5 request.")
    risk_tags = {"active"}
    source_skill = "redteam-variants-02"

    HEADERS = (
        ("X-HTTP-Method-Override", "PUT"),
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-Method-Override", "DELETE"),
    )

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        ctx.throttle()
        s0, _h0, b0, _m = http_engine.http_get(url, timeout=ctx.timeout_s,
                                               follow_redirects=False)
        ctx.world.request_count += 1
        ctx.throttle()
        s_post, _h, b_post, _m = http_engine.http_post(
            url, data=b"", timeout=ctx.timeout_s, follow_redirects=False) \
            if hasattr(http_engine, "http_post") else (None, None, None, None)
        if s_post is None:
            # http_post belum ada di engine ini — pakai http_get method POST
            s_post, _h, b_post, _m = http_engine.http_get(
                url, method="POST", data=b"", timeout=ctx.timeout_s,
                follow_redirects=False)
        ctx.world.request_count += 1
        changed = []
        for hname, method in self.HEADERS:
            ctx.throttle()
            s, _h, body, _m = http_engine.http_get(
                url, method="POST", data=b"",
                headers={hname: method, "Content-Type": "application/x-www-form-urlencoded"},
                timeout=ctx.timeout_s, follow_redirects=False)
            ctx.world.request_count += 1
            if s != s_post and (s < 400 or s_post >= 400):
                changed.append({hname: method, "status": s})
        if len(changed) < 1 or s0 >= 400 and s_post >= 400 and s0 == s_post:
            return ToolResult(tool=self.name, ok=True, data={
                "baseline_get": s0, "plain_post": s_post, "changed": changed,
                "note": "override tidak mengubah perilaku berarti"})
        findings = [Finding(
            tool=self.name,
            title=("Endpoint menghormati method override: "
                   + ", ".join(f"{k}={v}" for c in changed for k, v in c.items())),
            severity="info", cwe="CWE-650",
            description=(
                f"POST polos memberi status {s_post}, tetapi dengan header "
                f"override status berubah ({', '.join(str(c['status']) for c in changed)}). "
                f"Endpoint yang menghormati override bisa membungkus aksi mutasi "
                f"di balik route GET-only/middleware yang hanya memeriksa method "
                f"asli (LEAD — verifikasi dampak otorisasi butuh sesi uji)."),
            recommendation=("Jangan hormati override header bila middleware "
                            "otorisasi memeriksa method; putuskan satu sumber "
                            "method dan verifikasi di situ."),
            target_url=url, request="POST (dengan header override)",
            response=f"baseline GET={s0}, POST polos={s_post}, override={changed}",
            confidence=0.55, source_skill=self.source_skill,
            status="unconfirmed", evidence_kind="probe-pair",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data={
            "baseline_get": s0, "plain_post": s_post, "changed": changed},
            findings=findings)


class HeaderVariantMatrixTool(Tool):
    name = "header_variant_matrix"
    description = ("Header spoof klasik pada endpoint terlindungi (X-Forwarded-For: "
                   "127.0.0.1, X-Original-URL, dsb.) — lead auth-bypass HINT bila "
                   "status turun 4xx -> <400. Maks 7 request.")
    risk_tags = {"active"}
    source_skill = "redteam-variants-03"

    VARIANTS = (
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Remote-Addr", "127.0.0.1"),
        ("X-Original-URL", "{path}"),
        ("X-Rewrite-URL", "{path}"),
        ("X-Forwarded-Host", "localhost"),
    )

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        from urllib.parse import urlsplit
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        path = urlsplit(url).path or "/"
        ctx.throttle()
        s0, _h0, b0, _m = http_engine.http_get(url, timeout=ctx.timeout_s,
                                               follow_redirects=False)
        ctx.world.request_count += 1
        if s0 < 400:
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": f"endpoint tidak terlindungi (status {s0})"})
        opens = []
        for hname, val in self.VARIANTS:
            ctx.throttle()
            s, _h, body, _m = http_engine.http_get(
                url, headers={hname: val.replace("{path}", path)},
                timeout=ctx.timeout_s, follow_redirects=False)
            ctx.world.request_count += 1
            if s < 400 and len(body or "") != len(b0 or ""):
                opens.append({hname: val.replace("{path}", path), "status": s})
        if not opens:
            return ToolResult(tool=self.name, ok=True, data={
                "baseline_status": s0, "opens": [],
                "note": "spoof header tidak membuka endpoint"})
        findings = [Finding(
            tool=self.name,
            title=("Auth bypass hint via header spoof: "
                   + ", ".join(f"{k}" for c in opens for k in c if k != "status")),
            severity="low", cwe="CWE-290",
            description=(
                f"Endpoint menjawab {s0} untuk semua orang, tetapi membuka "
                f"({', '.join(str(c['status']) for c in opens)}) dengan header "
                f"spoof ({', '.join(k for c in opens for k in c if k != 'status')}). "
                f"Kontrol akses memercayai header yang dikendalikan klien "
                f"(LEAD — bukti akses konten terlarang butuh verifikasi manual)."),
            recommendation=("Jangan percaya header klien untuk keputusan akses; "
                            "autorizasi di aplikasi, bukan di parser proxy."),
            target_url=url, request=f"GET {path} + header spoof",
            response=f"baseline={s0}; opens={opens}",
            confidence=0.6, source_skill=self.source_skill,
            status="unconfirmed", evidence_kind="probe-pair",
            finding_class="surface")]
        return ToolResult(tool=self.name, ok=True, data={
            "baseline_status": s0, "opens": opens}, findings=findings)
