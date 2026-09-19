"""rate_header_graceful — inti: CATAT postur rate-limit server (intel).
Roadmap: "Retry-After/X-RateLimit info (intel, non-claim umum)".

Engine TIDAK membuat finding (non-claim) — hasil masuk data + world.note:
  - 2 GET berurutan pada 1 endpoint; bila respons memuat 429/Retry-After/
    X-RateLimit-* -> server "graceful" (ada sinyal limit);
  - tanpa sinyal = "no-signal" (jangan diperbandingkan sebagai temuan).
Guard: MAKS 3 request total — ini bukan stress test (no-DoS doktrin);
jeda rate-limit ctx tetap jalan.
"""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult

_SIGNAL_HEADERS = ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
                   "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining",
                   "x-rate-limit")


class RateLimitGracefulTool(Tool):
    name = "rate_header_graceful"
    description = ("Intel postur rate-limit (429/Retry-After/X-RateLimit). "
                   "NON-CLAIM: tidak pernah menghasilkan finding; maks 3 req.")
    risk_tags = {"passive"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        signals: list[dict] = []
        statuses: list[int] = []
        for i in range(2):
            if ctx.world.request_count >= min(ctx.max_requests, 3):
                break
            ctx.throttle()
            st, hd, _b, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            statuses.append(st)
            sig = {k: v for k, v in (hd or {}).items()
                   if k.lower() in _SIGNAL_HEADERS}
            if sig or st == 429:
                signals.append({"req": i + 1, "status": st, "headers": sig})
        data = {"url": url, "statuses": statuses,
                "posture": "graceful" if signals else "no-signal",
                "signals": signals}
        ctx.world.note(f"[{self.name}] rate-limit postur "
                       f"{data['posture']} pada {url} (non-claim intel)")
        return ToolResult(tool=self.name, ok=True, data=data)
