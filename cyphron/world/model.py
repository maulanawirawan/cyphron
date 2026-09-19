"""World model — structured state updated throughout the run: target info,
discovered endpoints/params, technologies, and event history."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Endpoint:
    url: str
    status: int | None = None
    params: list[str] = field(default_factory=list)
    method: str = "GET"
    form_fields: list[str] = field(default_factory=list)
    discovered_by: str = ""
    probed: bool = False


@dataclass
class WorldModel:
    target: str = ""
    mode: str = "read-only"
    technologies: dict[str, str] = field(default_factory=dict)  # tech -> evidence header/source
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    request_count: int = 0
    hypotheses: list[dict] = field(default_factory=list)  # planner reasoning trail
    # FAZ 2 adaptive state (diisi planner/orchestrator):
    findings_seen: list[dict] = field(default_factory=list)   # temuan ringkas dari orchestrator
    replan_events: list[dict] = field(default_factory=list)   # {"trigger_finding","hypothesis_id","claim","steps"}
    budget_ledger: dict[str, dict] = field(default_factory=dict)  # dari planner

    def has_tech(self, key: str) -> bool:
        return any(key in k.lower() for k in self.technologies)

    def has_graphql(self) -> bool:
        import urllib.parse as _up
        return any("graphql" in _up.urlparse(e.url).path.lower()
                   and (e.status or 0) not in (404, 405, 410)
                   for e in self.endpoints.values())

    def has_jwt(self) -> bool:
        return any("jwt" in k.lower() for k in self.technologies)

    def has_param(self, names) -> bool:
        wanted = {n.lower() for n in names}
        return any(p.lower() in wanted for e in self.endpoints.values() for p in e.params)

    def observe_target(self, target: str, mode: str) -> None:
        self.target = target
        self.mode = mode
        self.notes.append(f"scan started in {mode} mode")

    def observe_response(self, url: str, status: int | None, headers: dict[str, str] | None,
                         body: str | None, discovered_by: str) -> None:
        ep = self.endpoints.setdefault(url, Endpoint(url=url, discovered_by=discovered_by))
        ep.status = status
        if headers:
            for name, value in headers.items():
                lower = name.lower()
                if lower in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
                    self.technologies.setdefault(f"{name}: {value}", f"header on {urlparse(url).path or '/'}")
                if lower == "set-cookie":
                    self.technologies.setdefault("session cookie", value.split("=", 1)[0])
                    import base64 as _b64, json as _json
                    v = value.split("=", 1)[1].split(";")[0]
                    segs = v.split(".")
                    if len(segs) == 3 and len(v) > 20:
                        try:
                            pad = "=" * (-len(segs[0]) % 4)
                            hdr = _json.loads(_b64.urlsafe_b64decode(segs[0] + pad))
                            if isinstance(hdr, dict) and "alg" in hdr:
                                self.technologies.setdefault(
                                    "jwt token detected", f"alg={hdr.get('alg')}")
                        except Exception:
                            pass
        if body:
            m = _GENERATOR_RE.search(body)
            if m:
                self.technologies.setdefault(f"generator: {m.group(1)}", f"meta tag on {urlparse(url).path or '/'}")
        self.request_count += 1

    def observe_endpoint(self, url: str, params: list[str], method: str = "GET",
                         form_fields: list[str] | None = None, discovered_by: str = "") -> Endpoint:
        ep = self.endpoints.setdefault(url, Endpoint(url=url, discovered_by=discovered_by))
        for p in params:
            if p not in ep.params:
                ep.params.append(p)
        if form_fields:
            for f in form_fields:
                if f not in ep.form_fields:
                    ep.form_fields.append(f)
        ep.method = method
        return ep

    def note(self, text: str) -> None:
        self.notes.append(text)

    def param_endpoints(self, limit: int = 25) -> list[Endpoint]:
        eps = [e for e in self.endpoints.values() if e.params]
        eps.sort(key=lambda e: -len(e.params))
        return eps[:limit]

    def snapshot(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "technologies": self.technologies,
            "endpoint_count": len(self.endpoints),
            "param_endpoints": [e.url for e in self.param_endpoints()],
            "notes": self.notes,
            "request_count": self.request_count,
            "hypotheses": self.hypotheses,
            "findings_seen": self.findings_seen,
            "replan_events": self.replan_events,
            "budget_ledger": self.budget_ledger,
        }

    def summarize(self, max_chars: int = 2500) -> str:
        """Compact prompt-ready summary (token-budgeted by chars)."""
        lines = [f"Target: {self.target}", f"Mode: {self.mode}",
                 f"Requests sent: {self.request_count}"]
        if self.technologies:
            lines.append("Technologies: " + "; ".join(list(self.technologies)[:8]))
        lines.append(f"Endpoints known: {len(self.endpoints)}")
        for ep in self.param_endpoints(8):
            lines.append(f"  - {ep.url} params={ep.params} status={ep.status}")
        if self.notes:
            lines.append("Notes: " + " | ".join(self.notes[-6:]))
        text = "\n".join(lines)
        return text[:max_chars]


_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
