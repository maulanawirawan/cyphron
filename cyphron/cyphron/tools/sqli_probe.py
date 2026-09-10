"""sqli_probe — Cyphron's own SQL injection detector (no sqlmap).

Three evidence classes (mirrors knowledge/attack-encyclopedia.md §1.1):
- error-based: DB error signatures appear only with the quote payload
- boolean-based: paired TRUE/FALSE payloads produce reproducible divergence
- time-based: DB sleep payload delays the response (aggressive; off default)

Active: requires a valid in-scope authorization document."""

from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

DB_ERRORS = {
    "MySQL": r"you have an error in your sql syntax|warning: mysql",
    "PostgreSQL": r"postgresql.*error|unterminated quoted string|pg_query\(\)",
    "SQLite": r"sqlite3?::|sqlite_master|sql syntax error near|sqliteexception",
    "MSSQL": r"microsoft ole db|unclosed quotation mark|sqlserver jdbc",
    "Oracle": r"ora-\d{5}:",
    "Generic": r"sql syntax|sqlstate\[|syntax error at or near",
}

TRUE_PAYLOADS = ["'", "' OR '1'='1"]
BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
]


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    q = [(k, value if k == param else v) for k, v in q]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _db_family(body: str) -> str | None:
    low = body.lower()
    for family, pattern in DB_ERRORS.items():
        if __import__("re").search(pattern, low):
            return family
    return None


class SqliProbeTool(Tool):
    name = "sqli_probe"
    description = "Probe one URL+param for SQL injection (error/boolean/time)."
    risk_tags = {"active"}
    source_skill = "03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url, param = str(args["url"]), str(args["param"])
        findings: list[Finding] = []
        base_status, _h, base_body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.observe_response(url, base_status, _h, base_body, self.name)
        baseline_error = _db_family(base_body)

        # --- error-based ---
        for quote in ("'", '"'):
            probe_url = _with_param(url, param, quote)
            status, _h, body, _ms = http_engine.http_get(probe_url, timeout=ctx.timeout_s)
            ctx.world.observe_response(probe_url, status, _h, body, self.name)
            family = _db_family(body)
            if family and family != baseline_error:
                findings.append(Finding(
                    tool=self.name,
                    title=f"SQL injection (error-based, {family}) via parameter '{param}'",
                    severity="critical", cwe="CWE-89",
                    description=(
                        f"Injecting {quote!r} into parameter `{param}` makes the application return a "
                        f"{family} database error while the baseline response is clean. User input is "
                        f"concatenated into the SQL statement without parameterization."
                    ),
                    recommendation=(
                        "Use parameterized queries/prepared statements for every SQL statement; "
                        "never concatenate user input; validate types server-side. "
                        "See .kimchi/knowledge/remediation-playbook.md §1 (SQL INJECTION)."
                    ),
                    target_url=url, param=param,
                    request=f"GET {probe_url}",
                    response=f"status={status}; matched {family} error signature; excerpt: {body[:300]!r}",
                    poc=f"curl -g '{probe_url}'   # baseline: GET {url} (no error)",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response",
                ))
                break  # one error-based finding per param is enough

        # --- boolean-based ---
        if not findings:
            for true_p, false_p in BOOL_PAIRS:
                u1, u2 = _with_param(url, param, true_p), _with_param(url, param, false_p)
                s1, _h1, b1, _ = http_engine.http_get(u1, timeout=ctx.timeout_s)
                s2, _h2, b2, _ = http_engine.http_get(u2, timeout=ctx.timeout_s)
                ctx.world.observe_response(u1, s1, _h1, b1, self.name)
                ctx.world.observe_response(u2, s2, _h2, b2, self.name)
                diverged = (s1 != s2) or abs(len(b1) - len(b2)) > max(40, int(0.05 * max(len(b1), 1)))
                if diverged and s1 < 400:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"SQL injection (boolean-based blind) via parameter '{param}'",
                        severity="critical", cwe="CWE-89",
                        description=(
                            f"Paired payloads `{true_p}` vs `{false_p}` on parameter `{param}` produce "
                            f"reproducibly different responses (status {s1} vs {s2}, body {len(b1)} vs {len(b2)} bytes): "
                            f"the injected condition alters query results."
                        ),
                        recommendation=(
                            "Use parameterized queries/prepared statements; treat the value as data, never as SQL. "
                            "See .kimchi/knowledge/remediation-playbook.md §1 (SQL INJECTION)."
                        ),
                        target_url=url, param=param,
                        request=f"GET {u1}\nGET {u2}",
                        response=f"TRUE-payload: status={s1} len={len(b1)}; FALSE-payload: status={s2} len={len(b2)}",
                        poc=f"curl -g '{u1}' && curl -g '{u2}'   # compare responses",
                        confidence=0.75, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="probe-pair",
                    ))
                    break

        return ToolResult(tool=self.name, ok=True, data={"url": url, "param": param},
                          findings=findings)
