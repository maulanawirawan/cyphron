"""session_probe — authenticated session analysis (grey-box).

Requires a live session cookie (set via grey-box --account login).
Checks, with low-false-positive predicates:
1. Cookie composition & entropy estimate (definitive math).
2. JWT structure: decode header/payload (no verification offline); flag
   missing expiry and dangerous claims (definitive facts).
3. JWT alg:none tamper test (bounded 2 requests): replace signature with
   empty and elevate role claim; hit only if the tampered token yields a
   materially different response than an unauthenticated request.
4. Admin-path authorization diff: unauthenticated vs authenticated response
   on discovered admin/dashboard routes (definitive status diff)."""

from __future__ import annotations

import base64
import json
import math
from urllib.parse import urljoin

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

ADMIN_MARKERS = ("admin", "dashboard", "manage", "users")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _entropy_bits(value: str) -> float:
    if not value:
        return 0.0
    charset = 10
    if any(c.isalpha() for c in value):
        charset += 52
    if any(not c.isalnum() for c in value):
        charset += 32
    return round(len(value) * math.log2(charset), 1)


def _fetch(ctx, url, cookie: str | None):
    headers = {"Cookie": cookie} if cookie else {"Cookie": ""}
    return http_engine.http_get(url, timeout=ctx.timeout_s, headers=headers)


class SessionProbeTool(Tool):
    name = "session_probe"
    description = "Analyze the authenticated session: cookie entropy, JWT structure, alg:none, authz diff."
    risk_tags = {"active"}
    source_skill = "06"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cookie = http_engine.get_cookie_header()
        if not cookie:
            ctx.world.note("session_probe skipped: no session cookie (grey-box login required)")
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-session"})
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        data: dict = {"cookie_names": [p.split("=", 1)[0] for p in cookie.split("; ")]}

        # ---- 1. JWT structure analysis ----
        jwt_token = None
        for pair in cookie.split("; "):
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            segments = value.split(".")
            if len(segments) == 3 and all(segments):
                jwt_token = (name, value, segments)
                data["jwt_cookie"] = name
                header = json.loads(_b64url_decode(segments[0]) or b"{}")
                payload = json.loads(_b64url_decode(segments[1]) or b"{}")
                data["jwt_header"] = header
                data["jwt_claims"] = list(payload.keys())
                if header.get("alg") == "none":
                    findings.append(Finding(
                        tool=self.name, title="JWT uses alg=none (unsigned token accepted at issue)",
                        severity="critical", cwe="CWE-347",
                        description=f"Session JWT for {name} is issued with alg=none — tokens are not signed.",
                        recommendation="Sign tokens with a strong algorithm (HS256+/RS256) and reject unsigned tokens.",
                        target_url=base, response=f"header={header}", confidence=1.0,
                        source_skill=self.source_skill, status="confirmed",
                        evidence_kind="request-response"))
                if "exp" not in payload:
                    findings.append(Finding(
                        tool=self.name, title="JWT has no expiry (exp) claim",
                        severity="medium", cwe="CWE-613",
                        description=f"Session JWT for {name} carries no exp claim — a stolen token is valid forever.",
                        recommendation="Set short-lived exp and implement refresh rotation.",
                        target_url=base, response=f"claims={list(payload.keys())}", confidence=1.0,
                        source_skill=self.source_skill, status="confirmed",
                        evidence_kind="request-response"))

                # ---- 3. alg:none tamper test (bounded: 1 request + 1 baseline) ----
                role_claim = next((k for k in payload if k.lower() in ("role", "roles", "isadmin", "is_admin")), None)
                test_url = str(args.get("test_url") or urljoin(base, "/admin"))
                base_status, _h, base_body, _ms = _fetch(ctx, test_url, cookie=None)
                tampered_payload = dict(payload)
                if role_claim:
                    tampered_payload[role_claim] = "admin" if isinstance(payload[role_claim], str) else True
                forged = (base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
                          .rstrip(b"=").decode() + "." +
                          base64.urlsafe_b64encode(json.dumps(tampered_payload).encode())
                          .rstrip(b"=").decode() + ".")
                t_status, _th, t_body, _tm = _fetch(ctx, test_url, cookie=f"{name}={forged}")
                ctx.world.observe_response(test_url, t_status, _th, t_body, self.name)
                escalated = (t_status == 200 and base_status in (301, 302, 303, 307, 308, 401, 403, 404)
                             and len(t_body or "") > 500)
                if escalated:
                    findings.append(Finding(
                        tool=self.name,
                        title="JWT alg:none tampering grants access (authentication bypass)",
                        severity="critical", cwe="CWE-347",
                        description=(f"A forged unsigned JWT (alg=none"
                                     + (f", {role_claim}=admin" if role_claim else "")
                                     + f") was ACCEPTED at {test_url} (HTTP 200) while the unauthenticated "
                                     f"request was denied ({base_status}). The server trusts token claims "
                                     f"without verifying signatures — full authentication bypass."),
                        recommendation="Reject alg=none tokens; verify signatures server-side on every request; use a hardened JWT library.",
                        target_url=test_url,
                        request=f"GET {test_url} with forged alg:none token",
                        response=f"unauthenticated={base_status}; tampered={t_status}",
                        confidence=0.85, source_skill=self.source_skill,
                        status="unconfirmed",  # manual confirmation before exploit claims
                        evidence_kind="probe-pair"))
                break  # analyze the first JWT-shaped cookie only

        if not jwt_token:
            # ---- session cookie entropy (non-JWT) ----
            for pair in cookie.split("; "):
                if "=" not in pair:
                    continue
                name, value = pair.split("=", 1)
                if any(k in name.lower() for k in ("session", "sid", "token", "auth")):
                    bits = _entropy_bits(value)
                    data.setdefault("session_entropy", []).append({"cookie": name, "bits": bits})
                    if bits < 100:
                        findings.append(Finding(
                            tool=self.name,
                            title=f"Session token '{name}' has low entropy (~{bits} bits)",
                            severity="medium", cwe="CWE-330",
                            description=(f"Session value is ~{bits} bits of entropy (length {len(value)}); "
                                         f"modern session tokens should exceed ~100 bits of randomness."),
                            recommendation="Generate session ids with a CSPRNG at >=128 bits.",
                            target_url=base, response=f"len={len(value)}; entropy~{bits} bits",
                            confidence=0.8, source_skill=self.source_skill,
                            status="confirmed", evidence_kind="request-response"))

        # ---- 4. Admin-path authorization diff ----
        for path in ("/admin", "/dashboard", "/api/admin/users"):
            url = urljoin(base, path)
            if url not in ctx.world.endpoints:
                continue
            if not (args.get("budget_left", True)):
                break
            un_status, _uh, un_body, _um = _fetch(ctx, url, cookie=None)
            au_status, _ah, au_body, _am = _fetch(ctx, url, cookie=cookie)
            ctx.world.observe_response(url, au_status, _ah, au_body, self.name)
            if un_status in (301, 302, 303, 307, 308, 401, 403, 404) and au_status == 200:
                marker = next((m for m in ADMIN_MARKERS if m in (au_body or "").lower()), None)
                ctx.world.note(f"session_probe: {path} auth-gated (unauth {un_status} -> auth {au_status})")
                if marker:
                    data.setdefault("authz_gated", []).append(path)
            elif au_status == 200 and un_status == 200 and len(au_body or "") == len(un_body or ""):
                findings.append(Finding(
                    tool=self.name,
                    title=f"Sensitive route {path} served identically without authentication",
                    severity="high", cwe="CWE-306",
                    description=(f"{url} returns the same 200 response with and without a session — "
                                 f"the route appears to skip server-side authorization. Confirm the "
                                 f"rendered data is not privileged before treating as exploitable."),
                    recommendation="Enforce authorization checks server-side on every sensitive route (default-deny).",
                    target_url=url,
                    request=f"GET {url} (unauth vs authenticated)",
                    response=f"unauth={un_status} len={len(un_body or '')}; auth={au_status} len={len(au_body or '')}",
                    confidence=0.6, source_skill=self.source_skill,
                    status="unconfirmed", evidence_kind="probe-pair"))

        ctx.world.note(f"session_probe: cookie={data.get('cookie_names')}, "
                       f"{len(findings)} findings, early-stop semantics respected")
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
