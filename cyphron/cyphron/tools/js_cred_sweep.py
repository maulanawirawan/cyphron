"""js_cred_sweep — hardcoded credential sweep pada aset JS frontend.

Teknik dari lapangan (2026-09): bundle JavaScript publik sering
membawa kredensial statis (Basic auth, API key, password literal) yang
membuka akses API tanpa akun. Engine ini:
  1. ambil halaman utama + kumpulkan <script src> same-host (cap 8),
  2. fetch tiap JS + (maks 2) sourcemap .map -> sourcesContent,
  3. scan pola kredensial dengan filter FP agresi.

FP-guard (pelajaran sweep nyata):
  - literal Firebase (AIzaSy/authDomain) dikecualikan: memang dirancang publik;
  - enum library OAuth/MSAL (ACCESS_TOKEN=, CLIENT_ASSERTION, DEVICE_CODE,
    XMS_CC, LOGOUT_HINT, httpSuccess) dikecualikan — itu konstanta kode;
  - Basic auth HANYA confirmed bila base64-nya ter-decode ke bentuk
    "user:pass" (dua sisi non-kosong); gagal decode = lead unconfirmed 0.4;
  - jwt-literal TIDAK dilaporkan (hampir selalu session-handling kode) —
    cukup world.note;
  - semua bukti lewat redact() sebelum masuk log/laporan;
  - dedup per (kind, match) — satu baris kode tidak jadi 5 temuan.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_JS_CAP = 8
_MAP_CAP = 2
_MAX_BODY = 400_000
_MAX_REQUESTS = 13

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("basic-auth-header", re.compile(
        r"""Authorization['"]?\s*[:=]\s*['"]Basic\s+[A-Za-z0-9+/=]{8,}""", re.I)),
    ("basic-raw", re.compile(r"""Basic\s+[A-Za-z0-9+/]{16,}={0,2}""")),
    ("btoa-literal", re.compile(r"""btoa\(\s*['"][^'"]{6,}['"]""")),
    ("url-creds", re.compile(
        r"""[a-z][a-z0-9+.-]*://[A-Za-z0-9._%-]+:[^@\s/'"]{3,}@""", re.I)),
    ("password-literal", re.compile(
        r"""(?:password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{4,}['"]""", re.I)),
    ("api-key", re.compile(
        r"""(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{8,}['"]""", re.I)),
    ("aws-akia", re.compile(r"""AKIA[0-9A-Z]{16}""")),
    ("admin-cred", re.compile(r"""['"]admin['"]\s*:\s*['"][^'"\s]{3,}['"]""", re.I)),
]

# Nilai/penanda yang TIDAK boleh jadi temuan (public-by-design / kode library).
PLACEHOLDER = re.compile(
    r"process\.env|import\.meta|YOUR_|xxxx|example|dummy|placeholder|"
    r"<[^>]+>|\$\{|\{\{|lorem|todo|sample|env\.|config\.|opts\.|params\.|"
    r"options\.|this\.|window\.|__|AIzaSy|firebaseapp|ACCESS_TOKEN=|"
    r"ID_TOKEN=|REFRESH_TOKEN=|CLIENT_ASSERTION|DEVICE_CODE|LOGOUT_HINT|"
    r"XMS_CC|httpSuccess|console\.", re.I)

_B64 = re.compile(r"(?:Basic\s+|\")([A-Za-z0-9+/=]{16,})")


def decode_basic(match_text: str) -> str | None:
    """Decode kredensial Basic secara LOKAL. Valid bila bentuk 'user:pass'
    (dua sisi non-kosong, tanpa spasi). Return None bila gagal/invalid."""
    m = _B64.search(match_text or "")
    if not m:
        return None
    try:
        decoded = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4),
                                   validate=False).decode("utf-8", "replace")
    except Exception:
        return None
    if re.fullmatch(r"[^\s:]+:[^\s:]+", decoded):
        return decoded
    return None


def scan_text(text: str) -> list[tuple[str, str, str]]:
    """Return daftar (kind, match, snippet) yang lolos filter FP."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for kind, rx in PATTERNS:
        for m in rx.finditer(text or ""):
            snip = (text[max(0, m.start() - 60):m.end() + 60] or "").replace("\n", " ")
            if PLACEHOLDER.search(snip):
                continue
            key = (kind, m.group(0)[:80])
            if key in seen:
                continue
            seen.add(key)
            out.append((kind, m.group(0)[:160], snip[:220]))
    return out


def script_srcs(html: str, host: str) -> list[str]:
    srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html or "", re.I)
    out: list[str] = []
    for s in srcs:
        u = s if s.startswith("http") else urljoin("https://" + host + "/", s)
        if host in (urlsplit(u).hostname or ""):
            out.append(urlsplit(u).path)
    return list(dict.fromkeys(out))[:_JS_CAP]


class JsCredSweepTool(Tool):
    name = "js_cred_sweep"
    description = ("Sweep hardcoded credentials di aset JS frontend (Basic auth/"
                   "api-key/password literal) + sourcemap; Basic auth hanya "
                   "CONFIRMED bila base64 ter-decode ke user:pass.")
    risk_tags = {"active"}
    source_skill = "manual-bb-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        findings: list[Finding] = []
        try:
            ctx.throttle()
            st, _hd, body, _ms = http_engine.http_get(base, timeout=ctx.timeout_s,
                                                      max_body=_MAX_BODY)
        except Exception as exc:
            ctx.world.note(f"js_cred_sweep: halaman utama gagal ({type(exc).__name__})")
            return ToolResult(tool=self.name, ok=True, data={"error": "fetch-failed"})
        if not isinstance(st, int) or st >= 400 or not body:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-page"})
        ctx.world.observe_response(base, st, _hd, body, self.name)
        ctx.world.request_count += 1

        hits: list[tuple[str, str, str]] = scan_text(body)
        js_paths = script_srcs(body, host)
        maps = 0
        for jp in js_paths:
            if ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                jst, _jh, jbody, _m = http_engine.http_get(
                    urljoin(base + "/", jp.lstrip("/")), timeout=ctx.timeout_s,
                    max_body=_MAX_BODY)
            except Exception:
                continue
            ctx.world.request_count += 1
            if not isinstance(jst, int) or jst >= 400 or not jbody:
                continue
            hits.extend((k, m, s) for k, m, s in scan_text(jbody))
            if maps < _MAP_CAP and re.search(
                    r"(main|app|index|runtime|vendor|bundle|chunk)", jp):
                maps += 1
                try:
                    ctx.throttle()
                    mst, _mh, mbody, _m2 = http_engine.http_get(
                        urljoin(base + "/", jp.lstrip("/") + ".map"),
                        timeout=ctx.timeout_s, max_body=_MAX_BODY)
                except Exception:
                    continue
                ctx.world.request_count += 1
                if isinstance(mst, int) and mst < 400 and mbody.lstrip().startswith("{"):
                    try:
                        import json
                        md = json.loads(mbody)
                        srcs = " ".join(str(s) for s in (md.get("sourcesContent") or []))
                        if srcs:
                            hits.extend((k, m, s) for k, m, s in scan_text(srcs))
                    except Exception:
                        pass

        # dedup lintas sumber + klasifikasi
        confirmed = 0
        leads = 0
        seen: set[tuple[str, str]] = set()
        for kind, match, snip in hits:
            key = (kind, match[:80])
            if key in seen:
                continue
            seen.add(key)
            if kind in ("basic-auth-header", "basic-raw"):
                decoded = decode_basic(match)
                if decoded:
                    user = decoded.split(":", 1)[0]
                    confirmed += 1
                    findings.append(Finding(
                        tool=self.name,
                        title=(f"Hardcoded Basic auth credential in frontend JS: "
                               f"{host} (user '{user}')"),
                        severity="high", cwe="CWE-798",
                        description=(
                            f"JavaScript yang dilayani publik oleh {host} memuat "
                            f"kredensial Basic auth statis ({kind}). Decode base64 "
                            f"lokal menghasilkan bentuk 'user:pass' yang valid "
                            f"(user: {user}). Siapa pun yang membuka aset ini dapat "
                            f"memakai kredensial tersebut tanpa akun. Kredensial "
                            f"TIDAK digunakan lebih lanjut selama pengujian."),
                        recommendation=(
                            f"Rotasi/revoke kredensial '{user}'; pindahkan pertukaran "
                            f"kredensial ke sisi server; jangan pernah menanam secret "
                            f"di bundle klien; audit log API untuk pemakaian identitas ini."),
                        target_url=base, request=f"GET {base} + aset JS",
                        response=redact(snip)[:200],
                        poc="Buka aset JS di browser -> cari 'Basic ' -> decode base64 lokal.",
                        confidence=0.95, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response"))
                else:
                    leads += 1
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Basic auth literal (gagal decode) di JS frontend: {host}",
                        severity="low", cwe="CWE-798",
                        description=("Literal Basic auth terdeteksi pada aset JS "
                                     "publik tetapi base64-nya tidak ter-decode ke "
                                     "bentuk user:pass. Kandidat - verifikasi manual "
                                     "sebelum diklaim."),
                        recommendation="Verifikasi manual nilai literal; rotasi bila terbukti kredensial.",
                        target_url=base, request=f"GET {base}",
                        response=redact(snip)[:200], confidence=0.4,
                        source_skill=self.source_skill, status="unconfirmed",
                        evidence_kind="request-response"))
            else:
                leads += 1
                findings.append(Finding(
                    tool=self.name,
                    title=f"Kredensial-shaped literal ({kind}) di JS frontend: {host}",
                    severity="low", cwe="CWE-798",
                    description=("Literal berpola kredensial terdeteksi pada aset JS "
                                 "publik. SUDAH difilter dari pola public-by-design "
                                 "(Firebase/MSAL) tetapi tetap butuh verifikasi manual "
                                 "sebelum diklaim sebagai kredensial valid."),
                    recommendation="Verifikasi manual nilai literal terhadap API terkait sebelum diklaim.",
                    target_url=base, request=f"GET {base}",
                    response=redact(snip)[:200], confidence=0.4,
                    source_skill=self.source_skill, status="unconfirmed",
                    evidence_kind="request-response"))

        ctx.world.note(f"js_cred_sweep: {len(js_paths)} JS diuji - "
                       f"{confirmed} confirmed, {leads} leads")
        return ToolResult(tool=self.name, ok=True,
                          data={"js_checked": len(js_paths), "maps": maps,
                                "confirmed": confirmed, "leads": leads},
                          findings=findings)
