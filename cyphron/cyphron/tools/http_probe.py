"""http_probe — fingerprint the target: status, headers, technologies,
cookie flags. Passive (read-only): allowed without an authorization doc."""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult


class HttpProbeTool(Tool):
    name = "http_probe"
    description = "Fetch the target, record status/headers/technologies."
    risk_tags = {"passive"}
    source_skill = "03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        status, headers, body, elapsed = http_engine.http_get(
            url, timeout=ctx.timeout_s)
        ctx.world.observe_response(url, status, headers, body, self.name)
        return ToolResult(
            tool=self.name, ok=True,
            data={"status": status, "elapsed_ms": elapsed,
                  "headers": headers, "technologies": dict(ctx.world.technologies)},
            raw_excerpt=body[:2000],
        )
