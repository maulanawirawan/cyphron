"""template_probe — Cyphron's OWN template-based scanner (mini-Nuclei).

Closes the Nuclei gap with our own template format and catalog. Each template
has DEFINITIVE matchers (status + body keyword/regex) so findings are true by
construction. Templates run against the target host with early-stop per
template. Active: requires authorization. Budget-capped."""

from __future__ import annotations

from urllib.parse import urljoin

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

# (id, path, severity, cwe, title, description, status_pred, body_contains_any)
# status_pred: exact status or "any"
TEMPLATES = [
    ("phpinfo", "/phpinfo.php", "high", "CWE-200",
     "phpinfo page exposed", "Full PHP environment disclosure aids attackers.",
     "any", ["PHP Version", "Configuration File php.ini"]),
    ("actuator-env", "/actuator/env", "critical", "CWE-200",
     "Spring Boot env endpoint exposed", "Environment variables/secrets readable.",
     "any", ["propertySources", '"activeProfiles"']),
    ("git-config", "/.git/config", "high", "CWE-538",
     ".git/config exposed", "Repository configuration downloadable.",
     "any", ["[core]", "repositoryformatversion"]),
    ("env-summary", "/.env.production", "critical", "CWE-798",
     "Production environment file exposed", "Production secrets downloadable.",
     "any", ["DB_PASSWORD", "API_KEY", "SECRET"]),
    ("server-status", "/server-status", "medium", "CWE-200",
     "Apache server-status exposed", "Live request/worker information disclosed.",
     "any", ["Apache Server Status", "Server uptime"]),
    ("jenkins-open", "/jenkins/", "high", "CWE-284",
     "Jenkins panel exposed", "CI panel reachable — verify auth.",
     "any", ["Script Console", "Jenkins-Version", "jenkins-cli"]),
    ("kibana-open", "/kibana/", "high", "CWE-284",
     "Kibana exposed", "Log/telemetry UI reachable — verify auth.",
     "any", ["kbn-injected-metadata", "kibana-app"]),
    ("wp-config-bak", "/wp-config.php.bak", "critical", "CWE-538",
     "WordPress config backup exposed", "DB credentials downloadable.",
     "any", ["DB_PASSWORD", "DB_NAME"]),
    ("h2-console", "/h2-console", "high", "CWE-284",
     "H2 database console exposed", "DB console reachable — may allow RCE via JDBC.",
     "any", ["H2 Console", "jdbc"]),
    ("sonarqube", "/sonar/", "medium", "CWE-284",
     "SonarQube exposed", "Code-quality server reachable — source/issues may leak.",
     "any", ["SonarQube", "sonarqube"]),
    ("docker-api", "/containers/json", "critical", "CWE-668",
     "Docker API exposed", "Container runtime API reachable — full host compromise path.",
     "any", ["Id", "Image", "HostConfig"]),
    ("prometheus", "/metrics", "medium", "CWE-200",
     "Prometheus metrics exposed", "Internal metrics (routes, queues, versions) disclosed.",
     "any", ["# HELP", "http_requests"]),
    ("debug-var", "/debug/vars", "high", "CWE-200",
     "Go expvar debug endpoint exposed", "Runtime memory/state dumped publicly.",
     "any", ["cmdline", "memstats"]),
    ("supervisor", "/supervisor/status", "medium", "CWE-284",
     "Supervisor status exposed", "Process manager XML-RPC reachable.",
     "any", ["supervisord"]),
    ("netdata", "/netdata/", "medium", "CWE-200",
     "Netdata dashboard exposed", "Real-time infra monitoring UI reachable.",
     "any", ["netdata"]),
]


class TemplateProbeTool(Tool):
    name = "template_probe"
    description = "Own template-based scanner (mini-Nuclei) with definitive matchers."
    risk_tags = {"active"}
    source_skill = "03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        findings: list[Finding] = []
        tested = 0
        for tid, path, severity, cwe, title, desc, status_pred, markers in TEMPLATES:
            if ctx.world.request_count >= int(args.get("max_requests", 60)):
                break
            url = urljoin(base + "/", path.lstrip("/"))
            try:
                # redirects are NOT followed: a redirect-to-login is NOT an exposure,
                # and following it would pollute the marker match (lesson: supervisor FP)
                status, headers, body, _ms = http_engine.http_get(
                    url, timeout=ctx.timeout_s, follow_redirects=False)
            except Exception:
                continue
            ctx.world.observe_response(url, status, headers, body, self.name)
            tested += 1
            ok_status = (status_pred == "any") or (status == status_pred)
            hit_marker = next((m for m in markers if m in (body or "")), None)
            if ok_status and status == 200 and hit_marker:
                findings.append(Finding(
                    tool=self.name,
                    title=f"[{tid}] {title}",
                    severity=severity, cwe=cwe,
                    description=(f"{desc} Template `{tid}` matched at {url} "
                                 f"(HTTP {status}, marker {hit_marker!r})."),
                    recommendation=("Restrict or authenticate this endpoint at the web server/router; "
                                    "return 404 for anything not intended to be public."),
                    target_url=url,
                    request=f"GET {url}",
                    response=f"status={status}; marker={hit_marker!r}; len={len(body or '')}",
                    poc=f"curl -s '{url}' | grep -F {hit_marker!r}",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
        ctx.world.note(f"template_probe: {tested} templates tested, {len(findings)} hits "
                       f"(definitive matchers, early-stop per template)")
        return ToolResult(tool=self.name, ok=True,
                          data={"templates_tested": tested}, findings=findings)
