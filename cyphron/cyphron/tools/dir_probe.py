"""dir_probe — lightweight path exposure discovery (no dirb/ffuf).
Small curated list, 404-baseline heuristic. Active: needs authorization."""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

PATHS = [
    # intel (info, tidak jadi temuan tapi diambil untuk lead)
    ("robots.txt", "info", "robots.txt present — review for disclosed private paths"),
    ("sitemap.xml", "info", "sitemap.xml present"),
    ("humans.txt", "info", "humans.txt present"),
    (".well-known/security.txt", "info", "security.txt present"),
    ("README.md", "info", "README exposed"),
    ("CHANGELOG.md", "info", "CHANGELOG exposed — version disclosure"),
    ("package.json", "info", "package.json exposed — dependency disclosure"),
    # secrets & source
    (".env", "high", ".env file exposed — environment secrets downloadable"),
    (".env.local", "high", ".env.local exposed"),
    (".env.production", "critical", ".env.production exposed — production secrets"),
    (".git/HEAD", "critical", ".git directory exposed — full source/history may be recoverable"),
    (".git/config", "high", ".git/config exposed"),
    (".svn/entries", "high", ".svn metadata exposed"),
    (".DS_Store", "low", ".DS_Store exposed — directory listing disclosure"),
    (".htaccess", "medium", ".htaccess exposed"),
    ("web.config", "medium", "web.config exposed"),
    ("Dockerfile", "medium", "Dockerfile exposed"),
    ("docker-compose.yml", "high", "docker-compose.yml exposed — service/credential layout"),
    ("Jenkinsfile", "medium", "Jenkinsfile exposed — CI pipeline disclosure"),
    (".github/workflows/ci.yml", "low", "GitHub Actions workflow exposed"),
    (".npmrc", "high", ".npmrc exposed — may contain registry tokens"),
    (".netrc", "high", ".netrc exposed"),
    ("id_rsa", "critical", "private SSH key exposed"),
    (".ssh/id_rsa", "critical", "private SSH key exposed (.ssh)"),
    (".aws/credentials", "critical", "AWS credentials file exposed"),
    # backups & dumps
    ("backup.zip", "high", "backup archive exposed"),
    ("backup.tar.gz", "high", "backup archive exposed"),
    ("site.tar.gz", "high", "site archive exposed"),
    ("dump.sql", "high", "SQL dump exposed"),
    ("db.sqlite3", "high", "SQLite database file exposed"),
    ("database.sqlite", "high", "SQLite database file exposed"),
    ("config.php.bak", "medium", "config backup file exposed"),
    ("wp-config.php.bak", "high", "WordPress config backup exposed"),
    # server state
    ("server-status", "medium", "Apache server-status exposed"),
    ("server-info", "medium", "Apache server-info exposed"),
    ("phpinfo.php", "high", "phpinfo exposed — full environment disclosure"),
    ("info.php", "medium", "info.php exposed"),
    ("cgi-bin/", "low", "cgi-bin path present"),
    # panels & admin
    ("admin/", "low", "admin path present (200) — verify authentication"),
    ("administrator/", "low", "administrator path present — verify authentication"),
    ("phpmyadmin/", "medium", "phpMyAdmin panel exposed"),
    ("wp-admin/", "low", "WordPress admin present"),
    ("wp-login.php", "info", "WordPress login present"),
    ("debug/", "medium", "debug path present"),
    ("console/", "medium", "console path present"),
    # API surface
    ("swagger.json", "low", "swagger.json exposed — API surface disclosure"),
    ("openapi.json", "low", "openapi.json exposed — API surface disclosure"),
    ("api-docs", "low", "API docs path present"),
    ("graphql", "medium", "GraphQL endpoint present — verify introspection/auth"),
    ("graphiql", "medium", "GraphiQL IDE exposed"),
    ("actuator/health", "low", "Spring actuator exposed"),
    ("actuator/env", "critical", "Spring actuator env endpoint exposed — configuration leak"),
    # app surface
    ("uploads/", "low", "uploads directory listing possible"),
    ("files/", "low", "files directory possible"),
    ("tmp/", "medium", "tmp directory exposed"),
    ("static/", "info", "static assets path present"),
    ("assets/", "info", "assets path present"),
    ("_next/static", "info", "Next.js static assets present"),
]


class DirProbeTool(Tool):
    name = "dir_probe"
    description = "Probe common sensitive paths on the target host."
    risk_tags = {"active"}
    source_skill = "03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        # baseline: a path that must not exist, to learn the 404 shape
        marker = "/cx-zz-not-a-real-path-" + str(ctx.world.request_count)
        miss_status, _h, miss_body, _ms = http_engine.http_get(base + marker, timeout=ctx.timeout_s)
        ctx.world.observe_response(base + marker, miss_status, _h, miss_body, self.name)
        misses = {miss_status, 404}
        miss_len = len(miss_body)
        hits = 0
        for path, severity, message in PATHS:
            url = f"{base}/{path}"
            status, _h, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
            ctx.world.observe_response(url, status, _h, body, self.name)
            soft404 = (
                miss_body.strip() == body.strip()
                or ("not found" in body.lower() and "not found" in miss_body.lower())
            )
            if status < 400 and status not in misses and not soft404:
                hits += 1
                # /admin* yang hidup BELUM bukti kerentanan: bisa halaman login,
                # SPA shell, atau redirect JS. Kandidat dulu - bukti konten
                # terlarang dibutuhkan sebelum boleh disebut exposed.
                if path.lower().startswith(("admin", "administrator", "manager")):
                    body_l = (body or "").lower()
                    is_login = ("<form" in body_l and "password" in body_l) or "login" in body_l
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Admin surface reachable without auth: /{path} (candidate)",
                        severity="info", cwe=None,
                        description=(f"HTTP {status} pada /{path} tanpa autentikasi. "
                                     + ("Body berupa halaman login - belum ada bukti akses "
                                        "ke fungsi/data terlarang. Uji lanjutan butuh kredensial "
                                        "uji untuk membuktikan bypass."
                                        if is_login else
                                        "Konten halaman perlu diverifikasi manual apakah "
                                        "memuat fungsi/data terlarang sebelum naik level "
                                        "temuan. Belum ada bukti akses terlarang pada pengujian ini.")),
                        recommendation=("Pastikan panel admin meminta otentikasi kuat di level "
                                        "server; sembunyikan dari index/publik bila tidak dipakai."),
                        target_url=f"{base}/{path}", request=f"GET /{path}",
                        response=f"status={status}; login_page={is_login}; excerpt: {body[:160]!r}",
                        confidence=0.35, source_skill=self.source_skill,
                        status="unconfirmed", evidence_kind="request-response",
                        finding_class="surface"))
                    continue
                session_note = ""
                from . import http_engine as _he
                if _he.get_cookie_header():
                    # a grey-box session is active: a 200 here may simply be the
                    # authenticated view, not anonymous exposure
                    session_note = " [under authenticated session - verify anonymous access separately]"
                if severity != "info":
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Sensitive path exposed: /{path}{session_note}",
                        severity="info" if session_note else severity, cwe="CWE-538",
                        description=f"{message}. HTTP {status} at {url} (404 baseline is {miss_status}).{session_note}",
                        recommendation=(
                            "Block public access to internal/sensitive paths at the web server or "
                            "application router; return 404 (not 403) for anything not intended to be public. "
                            "See .kimchi/skills/14-security-hardening-config.md."
                        ),
                        target_url=url, request=f"GET {url}",
                        response=f"status={status}; len={len(body)}; excerpt: {body[:200]!r}",
                        poc=f"curl -i '{url}'",
                        confidence=0.4 if session_note else 0.7,
                        source_skill=self.source_skill,
                        status="unconfirmed" if session_note else "confirmed",
                        evidence_kind="request-response",
                    ))
                if "index of /" in body.lower():
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Directory listing enabled: /{path}",
                        severity="medium", cwe="CWE-548",
                        description=f"{url} renders a directory index (autoindex) — file names/structure are exposed.",
                        recommendation="Disable autoindex on the web server for user-accessible directories.",
                        target_url=url, request=f"GET {url}",
                        response=f"status={status}; 'Index of /' marker present",
                        poc=f"curl -s '{url}' | grep -i 'index of'",
                        confidence=0.9, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response",
                    ))
        return ToolResult(tool=self.name, ok=True, data={"base": base, "hits": hits},
                          findings=findings)
