"""load_probe — BOUNDED capacity/availability measurement (finite-quota).

This is NOT a DoS tool and must never become one. Hard ceilings are built in:
- total requests <= max_total (default 190 quick / 750 capacity profile)
- concurrency <= 10
- a FIXED stage ladder; intensity is never raised mid-run even if the target
  looks healthy (escalate-until-down is out of scope by design)
- automatic stop: 3 consecutive transport errors, or 5xx rate > 30% in a stage

Two profiles:
- "quick"    : stages (5,6)(5,12)(5,20)   -> 190 requests, concurrency 5
- "capacity" : stages (10,5)(10,10)(10,20)(10,40) -> 750 requests, concurrency 10
               with capacity-knee detection (2x baseline p95 or error onset)

Every stage records UTC start/end timestamps so server-side (VPS) logs can be
correlated with client-side measurements."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

QUICK_STAGES = [(5, 6), (5, 12), (5, 20)]            # 30 + 60 + 100
CAPACITY_STAGES = [(10, 5), (10, 10), (10, 20), (10, 40)]  # 50 + 100 + 200 + 400


class LoadProbeTool(Tool):
    name = "load_probe"
    description = "Finite-quota capacity/availability measurement with hard ceilings."
    risk_tags = {"active", "load"}
    source_skill = "70"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        profile = str(args.get("profile", "quick"))
        stages = CAPACITY_STAGES if profile == "capacity" else QUICK_STAGES
        max_total = int(args.get("max_total", 750 if profile == "capacity" else 190))
        max_conc = 10
        findings: list[Finding] = []
        stage_reports: list[dict] = []
        stop = threading.Event()
        total_sent = 0
        consecutive_errors = 0
        lock = threading.Lock()

        def run_stage(conc: int, rounds: int) -> list[tuple[int, int]]:
            nonlocal total_sent, consecutive_errors
            results: list[tuple[int, int]] = []
            stage_budget = min(conc * rounds, max_total - total_sent)
            sent_in_stage = [0]

            def worker():
                nonlocal total_sent, consecutive_errors
                taken = 0
                per_worker = stage_budget // max(conc, 1) + 1
                while not stop.is_set() and taken < per_worker:
                    with lock:
                        if sent_in_stage[0] >= stage_budget or total_sent >= max_total:
                            return
                        sent_in_stage[0] += 1
                        total_sent += 1
                        taken += 1
                    try:
                        _s, _h, _b, elapsed = http_engine.http_get(url, timeout=ctx.timeout_s)
                        with lock:
                            results.append((_s, elapsed))
                            consecutive_errors = 0
                    except Exception:
                        with lock:
                            results.append((0, 0))
                            consecutive_errors += 1
                            if consecutive_errors >= 3:
                                stop.set()
                    time.sleep(0.03)

            workers = [threading.Thread(target=worker) for _ in range(min(conc, max_conc))]
            for t in workers:
                t.start()
            for t in workers:
                t.join()
            return results

        for stage_no, (conc, rounds) in enumerate(stages, start=1):
            if stop.is_set():
                break
            started_at = datetime.now(timezone.utc).isoformat()
            results = run_stage(conc, rounds)
            ended_at = datetime.now(timezone.utc).isoformat()
            if not results:
                break
            statuses = [s for s, _ in results]
            latencies = sorted(e for _s, e in results if e)
            err = sum(1 for s in statuses if s == 0)
            s5xx = sum(1 for s in statuses if s >= 500)
            s429 = sum(1 for s in statuses if s == 429)
            ok = sum(1 for s in statuses if 200 <= s < 400)
            p50 = latencies[len(latencies) // 2] if latencies else 0
            p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0
            stage_reports.append({
                "stage": stage_no, "concurrency": min(conc, max_conc),
                "requests": len(statuses), "ok": ok, "err": err,
                "5xx": s5xx, "429": s429, "p50_ms": p50, "p95_ms": p95,
                "started_at": started_at, "ended_at": ended_at,
            })
            ctx.world.note(f"load_probe[{profile}] stage {stage_no}: {len(statuses)} req "
                           f"(conc {conc}), ok={ok}, 429={s429}, 5xx={s5xx}, p95={p95}ms, "
                           f"window={started_at[11:19]}Z-{ended_at[11:19]}Z")
            if len(statuses) and s5xx / len(statuses) > 0.30:
                stop.set()  # never push a struggling target further

        data = {"url": url, "profile": profile, "total_requests": total_sent,
                "stages": stage_reports,
                "note": ("finite-quota measurement; the stage ladder is fixed and hard-capped "
                         "by design — no escalate-until-failure")}

        all_429 = sum(r["429"] for r in stage_reports)
        all_5xx = sum(r["5xx"] for r in stage_reports)
        all_err = sum(r["err"] for r in stage_reports)

        # capacity-knee detection (measurement, not an attack verdict)
        knee = None
        if len(stage_reports) >= 2:
            baseline_p95 = max(stage_reports[0]["p95_ms"], 200)
            for r in stage_reports[1:]:
                err_rate = (r["5xx"] + r["err"]) / r["requests"] if r["requests"] else 0
                if r["p95_ms"] > 2 * baseline_p95 or err_rate > 0.02:
                    knee = r
                    break

        if knee:
            findings.append(Finding(
                tool=self.name,
                title=(f"Capacity knee observed at stage {knee['stage']} "
                       f"(p95 {knee['p95_ms']} ms, {knee['p95_ms'] / max(stage_reports[0]['p95_ms'], 1):.1f}x baseline)"),
                severity="info", cwe="CWE-400",
                description=(f"Within the bounded ladder ({total_sent} requests, max concurrency "
                             f"{max_conc}), latency/error degradation begins at stage "
                             f"{knee['stage']} (window {knee['started_at']} - {knee['ended_at']}). "
                             f"Correlate this window with server-side CPU/RAM/app logs."),
                recommendation=("If the knee is below business-grade traffic, scale the origin "
                                "(workers/cache/db pool) and re-run the same ladder to move it."),
                target_url=url, request=f"GET {url} x{total_sent} (staged ladder)",
                response=f"knee stage={knee['stage']}; stages={stage_reports}",
                confidence=0.9, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-pair"))
        elif stage_reports:
            last = stage_reports[-1]
            findings.append(Finding(
                tool=self.name,
                title=("No degradation within the bounded measurement envelope "
                       f"({total_sent} requests, max concurrency {max_conc})"),
                severity="info", cwe="CWE-400",
                description=(f"All {total_sent} staged requests completed; final stage p95 "
                             f"{last['p95_ms']} ms, errors {all_err + all_5xx}, 429 {all_429}. "
                             f"This describes the measured envelope only - it is NOT a statement "
                             f"about true maximum capacity, which requires load generation from "
                             f"owned infrastructure."),
                recommendation=("For true capacity certification, run an owned load generator "
                                "(e.g. k6 on a staging VPS) against a non-production clone with "
                                "the same ladder and server-side monitoring."),
                target_url=url, request=f"GET {url} x{total_sent} (staged ladder)",
                response=f"stages={stage_reports}", confidence=1.0,
                source_skill=self.source_skill, status="confirmed",
                evidence_kind="probe-pair"))

        if all_429:
            findings.append(Finding(
                tool=self.name, title="Edge rate-limiting engaged under bounded load (429 observed)",
                severity="info", cwe="CWE-770",
                description=f"Edge returned 429 on {all_429} of {total_sent} bounded requests.",
                recommendation="Keep the edge limit; document its threshold for capacity planning.",
                target_url=url, request=f"GET {url} x{total_sent}",
                response=f"429 count={all_429}", confidence=1.0,
                source_skill=self.source_skill, status="confirmed",
                evidence_kind="probe-pair"))
        if all_5xx or all_err:
            findings.append(Finding(
                tool=self.name, title="Errors/5xx observed under bounded load",
                severity="medium", cwe="CWE-400",
                description=f"During the bounded measurement ({total_sent} requests), "
                            f"{all_5xx} responses were 5xx and {all_err} transport errors occurred.",
                recommendation="Investigate origin capacity/error logs for the measured windows.",
                target_url=url, request=f"GET {url} x{total_sent}",
                response=f"stages={stage_reports}", confidence=0.8,
                source_skill=self.source_skill, status="confirmed",
                evidence_kind="probe-pair"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
