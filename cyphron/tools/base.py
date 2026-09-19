"""Tool layer: every network/filesystem action goes through here.

Guards enforced in code, in order: kill switch -> authorization gate
(scope + restrictions) -> rate limit -> request budget -> timeout.
Evidence is redacted before it ever lands in logs or reports."""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..findings import Finding
from ..guardrails.authorization import (
    AuditLog,
    AuthorizationGate,
    host_port_of,
    is_local_path,
)
from ..licensing import gate_engine
from ..world.model import WorldModel

_REDACT_RE = re.compile(
    r"(?i)((?:api[_-]?key|secret|token|password|passwd|authorization)\s*[:=]\s*)(\S{4})\S+"
)


def redact(text: str | None) -> str | None:
    if text is None:
        return None
    return _REDACT_RE.sub(r"\1\2***[redacted]", text)


@dataclass
class ToolContext:
    gate: AuthorizationGate
    audit: AuditLog
    world: WorldModel
    timeout_s: float = 8.0
    rate_limit_s: float = 0.05
    max_requests: int = 400
    license_path: Path | None = None
    _last_request_ts: float = 0.0
    kill_switch: bool = False
    errors: list[str] = field(default_factory=list)
    sessions: dict[str, str] = field(default_factory=dict)  # user -> cookie (god mode)
    # kuota token (trial/lisensi ber-kuota): credit_gate(tool, risk_tags) ->
    # (ok, reason); credit_spend(tool, risk_tags) dipanggil setelah sukses.
    credit_gate: object = None
    credit_spend: object = None
    report_mode: str = "full"  # full | redacted (trial)

    def throttle(self) -> None:
        now = time.monotonic()
        wait = self.rate_limit_s - (now - self._last_request_ts)
        if wait > 0:
            time.sleep(wait)
        self._last_request_ts = time.monotonic()

    def host_scope(self, host: str, port: int = 443):
        """Per-destination scope check for hosts an engine discovers itself
        (sibling subdomains, MX hosts). Engines MUST call this before any
        DNS resolution or HTTP to such a host; out-of-scope hosts get zero
        queries and are downgraded to passive OSINT leads."""
        return self.gate.evaluate_host(host, port)


@dataclass
class ToolResult:
    tool: str
    ok: bool
    data: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    raw_excerpt: str | None = None


class Tool(ABC):
    name: str = "tool"
    description: str = ""
    risk_tags: set[str] = set()  # passive | active | local | aggressive | dos | ...
    source_skill: str = ""  # .kimchi skill id that governs this tool

    @abstractmethod
    def run(self, args: dict, ctx: ToolContext) -> ToolResult: ...


class ToolRegistry:
    def __init__(self, ctx: ToolContext):
        self.ctx = ctx
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def execute(self, name: str, args: dict) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(tool=name, ok=False, error=f"unknown tool: {name}")
        ctx = self.ctx
        # ---- TIER GATE (lisensi, kode-enforced — tidak bisa dilewati dari UI) ----
        lic_ok, lic_reason, _lic = gate_engine(name, ctx.license_path)
        if not lic_ok:
            ctx.audit.append({"kind": "license-refusal", "tool": name,
                              "reason": lic_reason})
            return ToolResult(tool=name, ok=False, error=f"license: {lic_reason}")
        if ctx.kill_switch:
            ctx.audit.append({"kind": "tool-blocked", "tool": name, "reason": "kill switch"})
            return ToolResult(tool=name, ok=False, error="kill switch engaged")
        if ctx.world.request_count >= ctx.max_requests:
            ctx.audit.append({"kind": "tool-blocked", "tool": name, "reason": "request budget exhausted"})
            return ToolResult(tool=name, ok=False, error="request budget exhausted")
        if ctx.credit_gate is not None:
            tok_ok, tok_reason = ctx.credit_gate(name, set(tool.risk_tags))
            if not tok_ok:
                ctx.audit.append({"kind": "tool-blocked", "tool": name,
                                  "reason": f"token: {tok_reason}"})
                return ToolResult(tool=name, ok=False, error=f"token: {tok_reason}")
        # Per-step scope: evaluasi URL/PATH yang BENAR-BENAR diprobe step ini,
        # bukan selalu world.target (planner memakai key url/base_url/path).
        step_target = str(args.get("url") or args.get("base_url")
                          or args.get("target") or ctx.world.target)
        if step_target.startswith("/") and not is_local_path(str(ctx.world.target)):
            step_target = str(ctx.world.target).rstrip("/") + step_target
        if is_local_path(step_target):
            # local filesystem tools: no network scope to check; passive/local only
            decision_ok, decision_mode, decision_reason = True, "read-only", "local target"
            if "active" in tool.risk_tags or "aggressive" in tool.risk_tags:
                gate_decision = ctx.gate.evaluate("localhost", 0, tool.risk_tags | {"active"})
                decision_ok, decision_mode, decision_reason = (
                    gate_decision.allowed, gate_decision.mode, gate_decision.reason)
        else:
            host, port = host_port_of(step_target)
            if not host:
                # URL tak lengkap → evaluasi terhadap target utama
                host, port = host_port_of(str(ctx.world.target))
            gate_decision = ctx.gate.evaluate(host, port, tool.risk_tags)
            decision_ok, decision_mode, decision_reason = (
                gate_decision.allowed, gate_decision.mode, gate_decision.reason)
        if not decision_ok:
            ctx.audit.append({
                "kind": "authorization-refusal", "tool": name,
                "target": step_target,
                "reason": decision_reason, "risk_tags": sorted(tool.risk_tags),
            })
            return ToolResult(tool=name, ok=False, error=f"refused: {decision_reason}")
        ctx.audit.append({
            "kind": "tool-run", "tool": name, "args": {
                k: redact(str(v)) for k, v in args.items()
            },
            "mode": decision_mode, "risk_tags": sorted(tool.risk_tags),
        })
        try:
            ctx.throttle()
            result = tool.run(args, ctx)
        except Exception as exc:  # engines must never crash the loop
            ctx.errors.append(f"{name}: {exc}")
            return ToolResult(tool=name, ok=False, error=f"{type(exc).__name__}: {exc}")
        if ctx.credit_spend is not None:
            try:
                ctx.credit_spend(name, set(tool.risk_tags))
            except Exception:
                pass  # pembukuan gagal jangan kunci hasil engine
        result.raw_excerpt = redact(result.raw_excerpt)
        for f in result.findings:
            f.request = redact(f.request)
            f.response = redact(f.response)
        ctx.audit.append({
            "kind": "tool-done", "tool": name, "ok": result.ok,
            "findings": len(result.findings), "error": result.error,
        })
        return result
