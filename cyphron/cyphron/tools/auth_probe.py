"""auth_probe — authentication-surface testing (bounded, non-destructive).

Discovers login endpoints, tests username enumeration, lockout/rate-limit
behavior, and a TINY default-credential check that only ever targets a
cyphron-probe user (never real accounts). Active: requires authorization.
Hard bounds: <= 12 POSTs per run, no brute-force campaigns, no DoS."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from .crawler import _PageParser
from ..findings import Finding

LOGIN_PATHS = ["/login", "/signin", "/sign-in", "/auth/login", "/masuk", "/account/login"]
REGISTER_PATHS = ["/register", "/signup", "/sign-up", "/daftar", "/auth/register"]

# Bounded spray — only against the cyphron-probe user, never real accounts.
PROBE_USER = "cyphron-probe-9f3x@example.test"
SPRAY_PAIRS = [
    (PROBE_USER, "admin123"),
    (PROBE_USER, "password123"),
    (PROBE_USER, "cyphron-probe"),
]


def _post_form(url: str, fields: dict, ctx: ToolContext):
    from urllib.parse import urlencode
    body = urlencode(fields).encode()
    # auth tests MUST run unauthenticated: an active grey-box session would
    # turn every login page response into the logged-in state (false hits)
    return http_engine.http_get(url, timeout=ctx.timeout_s, method="POST", data=body,
                                headers={"Content-Type": "application/x-www-form-urlencoded",
                                         "Cookie": ""})


def _get(ctx, url, headers=None):
    # auth surface tests are anonymous by definition: never send the grey-box
    # session, or the "already logged in" page hides the login form entirely
    hdrs = {"Cookie": ""}
    if headers:
        hdrs.update(headers)
    return http_engine.http_get(url, timeout=ctx.timeout_s, headers=hdrs)


def _looks_like_error_page(body: str) -> bool:
    low = (body or "").lower()
    return any(k in low for k in ("invalid", "salah", "wrong password", "not found",
                                  "gagal", "credentials", "login failed", "password"))


class AuthProbeTool(Tool):
    name = "auth_probe"
    description = "Bounded authentication testing: discovery, enumeration, lockout, spray."
    risk_tags = {"active"}
    source_skill = "06"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        data: dict = {"login_url": None, "attempts": 0}

        # --- 1. Discovery: forms found by the crawler, else common paths ---
        login_url, user_field, pass_field = self._discover(base, ctx, data)
        if not login_url:
            ctx.world.note("auth_probe: no login endpoint discovered (bounded paths)")
            return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
        data["login_url"] = login_url
        ctx.world.note(f"auth_probe: login endpoint = {login_url} (fields: {user_field}/{pass_field})")

        # --- 2. Registration availability (detection only, no signup) ---
        for path in REGISTER_PATHS:
            status, _h, body, _ms = http_engine.http_get(urljoin(base, path), timeout=ctx.timeout_s)
            ctx.world.observe_response(urljoin(base, path), status, _h, body, self.name)
            if status == 200 and body and ("password" in body.lower() and
                                           ("<form" in body.lower() or "button" in body.lower())):
                ctx.world.note(f"auth_probe: open registration detected at {path}")
                data["register_url"] = urljoin(base, path)
                break

        def post_fields(pwd: str):
            user_key = "email" if user_field.startswith("input[type=") else user_field
            return {user_key: pwd}

        # --- 3. Username enumeration: compare two nonexistent-format logins ---
        s1, _h1, b1, ms1 = _post_form(login_url, {**post_fields(PROBE_USER), "password": "cx-wrong-1"}, ctx)
        ctx.world.observe_response(login_url, s1, _h1, b1, self.name); data["attempts"] += 1
        s2, _h2, b2, ms2 = _post_form(login_url, {**post_fields("cyphron-probe-a81z@example.test"),
                                                  "password": "cx-wrong-1"}, ctx)
        ctx.world.observe_response(login_url, s2, _h2, b2, self.name); data["attempts"] += 1
        if s1 == 403 and s2 == 403:
            ctx.world.note("auth_probe: auth POSTs rejected at the edge (403) — "
                           "app-level login behavior not assessable from outside the edge")
            findings.append(Finding(
                tool=self.name, title="Authentication API blocked at the edge (403) — protective control",
                severity="info", cwe="CWE-693",
                description=(f"POST attempts to the login endpoint ({login_url}) are uniformly rejected "
                             f"with 403 before reaching the application, so enumeration/lockout "
                             f"behavior cannot be assessed from outside. This indicates an edge-level "
                             f"protective control (WAF/allowlist) is active on the auth surface."),
                recommendation=("Keep the edge protection; verify app-level lockout separately from an "
                                "allowlisted internal position or with an authorized test account."),
                target_url=login_url,
                request=f"POST {login_url} (probe account, wrong password)",
                response=f"case A: status={s1}; case B: status={s2} (identical edge rejection)",
                confidence=0.9, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-pair"))
            data["attempts"] += 0
            return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
        sig1 = (s1, len(b1), _looks_like_error_page(b1))
        sig2 = (s2, len(b2), _looks_like_error_page(b2))
        if sig1 != sig2 and s1 < 400 and s2 < 400:
            findings.append(Finding(
                tool=self.name, title="Username enumeration via differentiated login responses",
                severity="low", cwe="CWE-204",
                description=(f"Login at {login_url} returns materially different responses for "
                             f"different unknown accounts (status {s1}/{s2}, body {len(b1)}/{len(b2)} "
                             f"bytes), allowing attackers to map valid accounts."),
                recommendation=("Return an identical generic failure for unknown user and wrong "
                                "password; equalize status, body, and response timing."),
                target_url=login_url,
                request=f"POST {login_url} (two unknown accounts)\nPOST {login_url} (control)",
                response=f"case A: status={s1} len={len(b1)}; case B: status={s2} len={len(b2)}",
                confidence=0.7, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-pair"))

        # --- 4. Lockout / rate-limit behavior: 6 consecutive bad passwords ---
        # Semantik jujur: HTTP 200 saja TIDAK membuktikan tanpa throttle.
        # Sinyal yang dicek: 429/423/403, kata CAPTCHA/lockout di body,
        # dan delay progresif (attempt akhir jauh lebih lambat dari baseline).
        statuses: list[int] = []
        delays: list[int] = []
        bodies: list[str] = []
        for i in range(6):
            s, _h, _b, ms = _post_form(login_url, {**post_fields(PROBE_USER),
                                                   "password": f"cx-wrong-{i}"}, ctx)
            ctx.world.observe_response(login_url, s, _h, _b, self.name)
            statuses.append(s); delays.append(ms)
            bodies.append((_b or "").lower()); data["attempts"] += 1
        throttled = any(s in (429, 423) or s == 403 for s in statuses[3:])
        captcha_text = any(k in b for b in bodies[3:]
                           for k in ("captcha", "too many", "locked", "try again later",
                                     "rate limit", "terlalu banyak", "diblokir"))
        base = sorted(delays[:3])[1] if len(delays) >= 3 else 0
        progressive = any(d > max(2 * base, base + 800) for d in delays[3:]) if base else False
        signal = throttled or captcha_text or progressive
        if not signal and all(s < 500 for s in statuses):
            findings.append(Finding(
                tool=self.name,
                title="No lockout/rate-limit signal in 6 failed logins (no 429/423/403, no CAPTCHA text, no progressive delay)",
                severity="medium", cwe="CWE-307",
                description=(f"Six consecutive failed logins at {login_url} were all processed "
                             f"(statuses {statuses}; median response {base:.0f} ms; slowest "
                             f"late attempt {max(delays[3:]) if len(delays) > 3 else max(delays):.0f} ms) "
                             f"with zero throttle signals: no 429/423/403, no CAPTCHA/lockout wording, "
                             f"no progressive slowdown. Within this tested envelope, unthrottled "
                             f"password guessing is possible. Thresholds above six attempts or "
                             f"invisible behavioral throttling cannot be excluded without a longer run."),
                recommendation=("Apply progressive throttling or temporary lockout per account/IP, "
                                "and return 429 once the threshold is exceeded."),
                target_url=login_url,
                request=f"POST {login_url} x6 (wrong passwords, single probe account)",
                response=(f"statuses={statuses}; delays_ms={delays}; "
                          f"captcha_text=false; progressive_delay=false"),
                confidence=0.7, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-pair"))

        # --- 5. Bounded default-credential check (probe account only) ---
        # Differential guard: a "hit" must differ from the known-failure
        # response for the same account, otherwise it is page coincidence.
        ref_status, _rh, ref_body, _rm = _post_form(
            login_url, {**post_fields(PROBE_USER), "password": "cx-definitely-wrong-xyz"}, ctx)
        data["attempts"] += 1
        for user, pwd in SPRAY_PAIRS:
            s, _h, b, _ms = _post_form(login_url, {**post_fields(user), "password": pwd}, ctx)
            ctx.world.observe_response(login_url, s, _h, b, self.name); data["attempts"] += 1
            same_as_failure = (s == ref_status and len(b or "") == len(ref_body or ""))
            if not same_as_failure and (
                    s in (301, 302, 303, 307, 308)
                    or (s == 200 and not _looks_like_error_page(b) and b and len(b) > 500)):
                findings.append(Finding(
                    tool=self.name, title=f"Weak/default credential accepted for probe account '{user}'",
                    severity="critical", cwe="CWE-521",
                    description=(f"Login at {login_url} succeeded with weak credential for the probe "
                                 f"account (HTTP {s}). If this account exists, it uses a guessable "
                                 f"password."),
                    recommendation="Enforce a password policy and MFA; remove seeded default accounts.",
                    target_url=login_url, request=f"POST {login_url} (probe account)",
                    response=f"status={s}", confidence=0.6,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="request-response"))
                break
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)

    def _discover(self, base: str, ctx: ToolContext, data: dict):
        # (a) forms the crawler already saw
        for url, ep in ctx.world.endpoints.items():
            if ep.form_fields and any("password" in f.lower() for f in ep.form_fields):
                return url, (ep.form_fields[0] or "email"), ("password" if "password" in
                          [f.lower() for f in ep.form_fields] else ep.form_fields[-1])
        # (b) common paths: GET page, parse the form
        for path in LOGIN_PATHS:
            url = urljoin(base, path)
            status, _h, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
            ctx.world.observe_response(url, status, _h, body, self.name)
            if status != 200 or not body:
                continue
            parser = _PageParser()
            try:
                parser.feed(body)
            except Exception:
                continue
            for form in parser.forms:
                if any("password" in f.lower() for f in form["fields"]):
                    action = urljoin(url, form["action"] or url)
                    fields = [f for f in form["fields"] if "password" not in f.lower()]
                    user_field = fields[0] if fields else "email"
                    return action, user_field, "password"
        return None, None, None
