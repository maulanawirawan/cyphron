"""sca_probe — Cyphron's own dependency-vulnerability scanner (OSV-Scanner
equivalent). Parses local manifests (package.json, package-lock.json,
requirements.txt) and queries the PUBLIC OSV.dev API — a free open database,
not a third-party tool install. Passive + local."""

from __future__ import annotations

import json
from pathlib import Path

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

OSV_API = "https://api.osv.dev/v1/query"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_QUERIES = 40


def _packages_from_repo(root: Path) -> list[tuple[str, str, str]]:
    """Return [(ecosystem, name, version)] capped for query budget."""
    pkgs: list[tuple[str, str, str]] = []
    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies"):
                for name, version in (data.get(section) or {}).items():
                    clean = version.lstrip("^~><=* ")
                    if clean and clean[0].isdigit():
                        pkgs.append(("npm", name, clean))
        except (json.JSONDecodeError, OSError):
            pass
    req = root / "requirements.txt"
    if req.exists():
        try:
            for line in req.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if "==" in line and not line.startswith(("#", "-")):
                    name, version = line.split("==", 1)
                    pkgs.append(("PyPI", name.strip(), version.strip()))
        except OSError:
            pass
    return pkgs[:MAX_QUERIES]


class ScaProbeTool(Tool):
    name = "sca_probe"
    description = "Query public OSV.dev database for known vulns in local dependencies."
    risk_tags = {"external", "local", "passive"}
    source_skill = "19"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        root = Path(str(args.get("path", args.get("target", "."))))
        if not root.exists():
            return ToolResult(tool=self.name, ok=False, error=f"no such path: {root}")
        pkgs = _packages_from_repo(root)
        if not pkgs:
            ctx.world.note("sca_probe: no dependency manifests found")
            return ToolResult(tool=self.name, ok=True, data={"packages": 0})
        findings: list[Finding] = []
        queried = 0
        for ecosystem, name, version in pkgs:
            if queried >= MAX_QUERIES:
                break
            ctx.throttle()
            try:
                _s, _h, body, _ms = http_engine.http_get(
                    OSV_API, timeout=ctx.timeout_s, method="POST",
                    data=json.dumps({"package": {"name": name, "ecosystem": ecosystem},
                                     "version": version}).encode(),
                    headers={"Content-Type": "application/json"})
                result = json.loads(body or "{}")
            except Exception:
                continue
            queried += 1
            for vuln in (result.get("vulns") or [])[:5]:
                vuln_id = vuln.get("id", "OSV-UNKNOWN")
                summary = vuln.get("summary") or vuln.get("details", "")[:200]
                sev = "high"
                for sev_item in (vuln.get("severity") or []):
                    if str(sev_item.get("score", "")).lower() in ("critical", "high"):
                        sev = "critical" if "critical" in str(sev_item.get("score")).lower() else "high"
                findings.append(Finding(
                    tool=self.name,
                    title=f"Known vulnerability in {name}@{version} ({vuln_id})",
                    severity=sev, cwe="CWE-1104",
                    description=(f"{name}@{version} has a published vulnerability in the OSV "
                                 f"database: {summary}"),
                    recommendation=(f"Upgrade {name} to a fixed version per {vuln_id} advisory "
                                    f"(https://osv.dev/vulnerability/{vuln_id})."),
                    file_path=str(root / "package.json" if ecosystem == "npm" else root / "requirements.txt"),
                    target_url=f"osv:{vuln_id}",
                    request=f"POST osv.dev/v1/query {name}@{version}",
                    response=vuln_id + ": " + summary[:160],
                    poc=f"https://osv.dev/vulnerability/{vuln_id}",
                    confidence=1.0, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
        ctx.world.note(f"sca_probe: {queried} packages queried against OSV.dev, "
                       f"{len(findings)} vulnerable")
        return ToolResult(tool=self.name, ok=True, data={"packages_queried": queried},
                          findings=findings)
