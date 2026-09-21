"""Orchestrator — the Cyphron agent loop.

observe (world) -> plan (deterministic planner) -> act (tool registry, gated)
-> update world -> repeat until budget/fixpoint -> verify -> report.
Every decision is traced (JSONL) and every tool call is audit-chained."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config, load
from .findings import Finding, dedupe
from .tools import http_engine
from .tools.crawler import _PageParser
from .guardrails.authorization import (
    AuditLog,
    AuthorizationDocument,
    AuthorizationGate,
    host_port_of,
    is_local_path,
)
from .planner import DeterministicPlanner
from .skills.registry import SkillRegistry
from .tools import build_default_registry
from .tools.base import ToolContext
from .verifier import finalize
from . import chaining as _chaining
from . import quorum as _quorum
from .world.model import WorldModel


@dataclass
class ScanOptions:
    target: str
    auth_path: Path | None = None
    kimchi_dir: Path | None = None
    max_steps: int = 40
    max_requests: int = 400
    timeout_s: float = 8.0
    rate_limit_s: float = 0.05
    max_time_s: float = 15 * 60
    crawl_pages: int = 15
    crawl_depth: int = 2
    account: str | None = None  # grey-box: "user:password" for authenticated testing
    accounts: list[str] | None = None  # god mode: ["userA:pass", "userB:pass", ...]
    license_path: Path | None = None  # tier gate: license.json (basic/pro/business/god)
    kill_switch: bool = False


@dataclass
class ScanSummary:
    target: str
    mode: str
    auth_id: str | None = None
    steps_executed: int = 0
    refused_actions: int = 0
    confirmed: list[Finding] = field(default_factory=list)
    unconfirmed: list[Finding] = field(default_factory=list)
    skills_used: list[str] = field(default_factory=list)
    audit_verified: bool = False
    audit_note: str = ""
    elapsed_s: float = 0.0
    scope: dict | None = None  # scope AKTUAL dari dokumen otorisasi (untuk laporan)
    attack_chains: list[dict] = field(default_factory=list)  # Attack Chain Composer
    quorum_summary: dict = field(default_factory=dict)       # Independent Validator Quorum
    escalation: dict = field(default_factory=dict)           # fase eskalasi adaptif (U2)

    def counts_by_severity(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.confirmed:
            out[f.severity] += 1
        return out


@dataclass
class ScanRun:
    summary: ScanSummary
    world: WorldModel
    audit: AuditLog
    report_mode: str = "full"


def run_scan(opts: ScanOptions, verbose: bool = True) -> ScanRun:
    started = time.monotonic()
    config: Config = load(opts.kimchi_dir)
    registry_skills = SkillRegistry(config)
    audit = AuditLog()

    doc = None
    if opts.auth_path is not None:
        doc = AuthorizationDocument.load(opts.auth_path)
        audit.append({"kind": "authorization-loaded", "auth_id": doc.id,
                      "expires_at": doc.expires_at.isoformat(),
                      "authorized_by": doc.authorized_by})
    gate = AuthorizationGate(doc)

    world = WorldModel()
    host, port = ("", 0) if is_local_path(opts.target) else host_port_of(opts.target)
    initial = gate.evaluate(host, port, {"active"})
    mode = initial.mode
    # U10: bukti kepemilikan domain — bila dokumen menuntutnya (fail-closed)
    if doc is not None and mode == "offensive" \
            and bool(doc.raw.get("require_ownership")) \
            and not is_local_path(opts.target):
        from .ownership import verify_ownership
        ok, detail = verify_ownership(
            opts.target, doc,
            channel=str(doc.raw.get("ownership_channel") or "auto"))
        audit.append({"kind": "ownership-check", "ok": ok,
                      "host": detail.get("host"), "method": detail.get("method"),
                      "channel": detail.get("channel")})
        if ok:
            world.note(f"ownership proof OK via {detail.get('method')} "
                       f"({detail.get('host')})")
        else:
            mode = "read-only"
            initial = type(initial)(allowed=False, mode=mode,
                                    reason="ownership proof gagal (fail-closed)",
                                    auth_id=doc.id)
            world.note("ownership proof GAGAL — mode ofensif ditolak, "
                       "lanjut read-only")
    world.observe_target(opts.target, mode)
    audit.append({"kind": "scan-start", "target": opts.target, "mode": mode,
                  "reason": initial.reason})
    if doc is not None and not initial.allowed:
        audit.append({"kind": "authorization-refusal", "tool": "(all-active)",
                      "target": opts.target, "reason": initial.reason,
                      "risk_tags": ["active"]})
    if verbose:
        print(f"[cyphron] mode: {mode} — {initial.reason}")

    ctx = ToolContext(
        gate=gate, audit=audit, world=world,
        timeout_s=opts.timeout_s, rate_limit_s=opts.rate_limit_s,
        max_requests=opts.max_requests, license_path=opts.license_path,
        kill_switch=opts.kill_switch,
    )
    # kuota token (trial/token_limit): habis = REFUSED di ToolRegistry
    from .licensing import License
    from .credits import CreditLedger
    lic_info = License(opts.license_path)
    if lic_info.valid and lic_info.token_limit is not None:
        ledger = CreditLedger(lic_info.licensee, mode=mode)
        ctx.credit_gate = (
            lambda tool, tags: ledger.can_spend(tags, lic_info.token_limit))
        ctx.credit_spend = (
            lambda tool, tags: ledger.spend(tool, tags))
        ctx.report_mode = lic_info.kind  # trial → report redacted
    tools = build_default_registry(ctx)
    planner = DeterministicPlanner(offensive_allowed=(mode == "offensive"),
                                   crawl_pages=opts.crawl_pages,
                                   crawl_depth=opts.crawl_depth,
                                   request_budget=opts.max_requests,
                                   known_tools={t.name for t in tools.all()})

    # Grey-box / god-mode: authenticate before probing so cookie-protected
    # surface is in scope. `--account` = satu sesi; `--accounts` = multi-sesi.
    if (opts.account or opts.accounts) and not is_local_path(opts.target):
        from .tools.auth_login import login
        creds = list(opts.accounts or [])
        if opts.account:
            creds.insert(0, opts.account)
        logged_in = False
        for cred in creds[:4]:
            if ":" not in cred:
                ctx.world.note("credentials dilewati (format wajib user:pass)")
                continue
            user, pwd = cred.split(":", 1)
            cookie = login(opts.target, user, pwd, timeout=opts.timeout_s)
            if cookie:
                ctx.sessions[user] = cookie
                logged_in = True
                if len(ctx.sessions) == 1:
                    # sesi pertama jadi cookie global: crawler/browser memakainya
                    http_engine.set_cookie_header(cookie)
                audit.append({"kind": "greybox-session", "user": user,
                              "set_cookie_attrs": cookie[:200]})
            audit.append({"kind": "greybox-login", "user": user, "success": bool(cookie)})
            world.note(f"grey-box login as {user!r}: "
                       f"{'SUCCESS - session cookie active' if cookie else 'FAILED'}")
        if not logged_in:
            world.note("grey-box login: semua kredensial gagal — lanjut tanpa sesi")
    planner.authenticated = bool(ctx.sessions)
    planner.account_count = len(ctx.sessions)

    candidates: list[Finding] = []
    steps_executed = 0
    refused = 0
    done_tool_runs: set[tuple] = set()

    # FAZ 2 adaptive loop: re-plan before EVERY step so the next action always
    # reflects the freshest world state; a step that yields findings triggers
    # observe_findings (confidence update + reactive hypotheses) and an
    # immediate re-plan. Termination: planner `_once` dedup + done_tool_runs
    # + max_steps + max_time.
    while steps_executed < opts.max_steps and (time.monotonic() - started) < opts.max_time_s:
        steps = planner.plan(world)
        step = next((s for s in steps
                     if (s.tool, json.dumps(s.args, sort_keys=True)) not in done_tool_runs),
                    None)
        if step is None:
            break  # fixpoint: planner has nothing new under current authority
        key = (step.tool, json.dumps(step.args, sort_keys=True))
        done_tool_runs.add(key)
        result = tools.execute(step.tool, step.args)
        steps_executed += 1
        if not result.ok and str(result.error or "").startswith("refused"):
            refused += 1
        if result.ok:
            candidates.extend(result.findings)
            for f in result.findings:
                audit.append({"kind": "finding-candidate", "tool": f.tool,
                              "title": f.title, "severity": f.severity,
                              "status": f.status, "id": f.id})
        if result.ok and result.findings:
            # (a) mirror compact findings into the world model
            for f in result.findings:
                world.findings_seen.append({"tool": f.tool, "title": f.title,
                                            "severity": f.severity,
                                            "status": f.status, "id": f.id,
                                            "target_url": f.target_url or "",
                                            "param": f.param or ""})
            # (b) planner updates confidence and opens reactive hypotheses
            new_hyps = planner.observe_findings(result.findings)
            # (c) trace every newly opened hypothesis (audit + replan event)
            for h in new_hyps:
                audit.append({"kind": "hypothesis-opened", "id": h["id"],
                              "claim": h["claim"],
                              "trigger_finding": h.get("opened_by", "")})
                if h["id"] not in {e.get("hypothesis_id")
                                   for e in world.replan_events}:
                    world.replan_events.append({
                        "trigger_finding": h.get("opened_by", ""),
                        "hypothesis_id": h["id"], "claim": h["claim"],
                        "steps": h.get("steps", [])})
            # (d) re-plan immediately: fresh evidence may re-order pending steps
            continue
        if result.ok and not result.findings:
            # clean probe: let the planner demote CONFIRMED hypotheses it serves
            planner.observe_findings([], clean_tools=[step.tool])
        if verbose:
            status = "ok" if result.ok else f"err: {result.error}"
            suffix = f" (+{len(result.findings)} findings)" if result.findings else ""
            print(f"[cyphron] step {steps_executed:>2} {step.tool:<17} {status}{suffix}")

    confirmed, unconfirmed = finalize(candidates)
    confirmed = dedupe(confirmed)
    unconfirmed = dedupe(unconfirmed)
    # fingerprint tidak memuat status → kandidat ber-id sama bisa hidup di dua
    # bucket; confirmed MENANG (deterministik) supaya verdict quorum tak
    # tertimpa salinan unconfirmed dan laporan tidak dobel
    confirmed_ids = {f.id for f in confirmed}
    unconfirmed = [f for f in unconfirmed if f.id not in confirmed_ids]

    # Intelligence Fabric: quorum verdicts (provenance ke evidence ledger)
    # + attack chain composition (impact gabungan, bukan per-temuan).
    verdicts = _quorum.adjudicate(confirmed + unconfirmed)
    # id unik di kedua bucket (dedupe silang di atas) → pemetaan deterministik
    verdict_by_id = {v.finding_id: v for v in verdicts}
    for f in confirmed + unconfirmed:
        v = verdict_by_id.get(f.id)
        if v is not None:
            f.attach_evidence("quorum", v.to_dict())
    chains = _chaining.compose(confirmed)
    # skills that governed the run (retrieved from world state)
    skills_used = [s.summary() for s, _score in
                   registry_skills.retrieve(f"pentest {world.target} web vulnerabilities owasp", top_k=5)]
    ok, note = audit.verify()

    scope_summary = None
    if doc is not None:
        scope_summary = {"targets": list(doc.scope.targets),
                         "excluded": list(doc.scope.excluded),
                         "cidr": list(doc.scope.cidr),
                         "ports": list(doc.scope.ports)}
    summary = ScanSummary(
        target=opts.target, mode=mode, auth_id=(doc.id if doc else None),
        steps_executed=steps_executed,
        refused_actions=refused, confirmed=confirmed, unconfirmed=unconfirmed,
        skills_used=skills_used, audit_verified=ok, audit_note=note,
        elapsed_s=round(time.monotonic() - started, 2),
        scope=scope_summary,
        attack_chains=[c.to_dict() for c in chains],
        quorum_summary=_quorum.summarize(verdicts),
        escalation=dict(getattr(planner, "escalation_state", {}) or {}),
    )
    audit.append({"kind": "scan-end", "confirmed": len(confirmed),
                  "unconfirmed": len(unconfirmed), "steps": steps_executed})
    return ScanRun(summary=summary, world=world, audit=audit,
                   report_mode=getattr(ctx, "report_mode", "full"))
