"""Deterministic planner — Cyphron's reasoning core, v0.4 (FAZ 2 adaptive).

Rule-based policy over the world model with a discovery loop: observe ->
plan -> act -> update world -> re-plan, until every one-shot phase has been
scheduled and no new parameter leads remain (fixpoint) or the budget runs
out. One-shot phases are tracked by the planner itself (`_emitted`), NOT by
endpoint markers, so a phase that yields no new endpoints can never stall
the loop.

FAZ 2 — adaptive planning (deterministic, no LLM):
- Every Step carries `cost` (estimated requests charged against the
  hypothesis budget) and `hypothesis_id` (the claim the step serves).
  Untagged steps (discovery / passive audit) keep cost 1 and stay outside
  the hypothesis budget ledger.
- plan() returns the whole pending schedule ordered by expected value
  EV = impact * confidence / max(cost, 1), descending, with a stable
  tie-break on the original schedule order — so the next executed step
  always reflects the evidence gathered by the previous one.
- Budget allocation: each round the remaining request budget (minus a small
  reserve so re-plan rounds opened by findings stay fundable) is split over
  the hypotheses that still have newly-emitted steps, proportional to
  impact * confidence, minimum 1 while capacity remains. Engines taking a
  `max_requests` argument are scaled to clamp(int(share), 6, default).
- observe_findings() updates hypothesis confidence from fresh findings
  (confirmed finding on a related hypothesis -> +0.2 capped at 0.95; a
  probe that finished clean on a CONFIRMED hypothesis -> confidence * 0.3,
  applied once per (tool, hypothesis)), opens reactive hypotheses
  ("H-react-*") when a finding opens a new attack surface, and returns the
  newly opened hypothesis dicts (world.hypotheses format plus "opened_by"
  and "steps" keys).

Impact taxonomy (aligned with finding_class): 4=exploitable, 3=weakness,
2=posture, 1=surface.

LLM PLANNER SLOT (deliberately unplugged):
    When the team picks a model/provider, implement `plan()` with the same
    signature and pass it to `run_scan(planner=...)`. The orchestrator,
    gate, verifier and audit log are independent of that choice.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import escalation as _escalation
from . import graph as _knowledge_graph
from .guardrails.authorization import is_local_path
from .world.model import WorldModel


def urlsplit_path(url: str) -> str:
    return urlsplit(url).path


@dataclass
class Step:
    tool: str
    args: dict
    rationale: str
    phase: str  # recon | passive-audit | discovery | active-testing
    cost: int = 1  # estimated requests this step burns (hypothesis budget)
    hypothesis_id: str = ""  # hypothesis this step serves ("" = general)


# Impact per hypothesis id (taxonomy: 4=exploitable, 3=weakness, 2=posture,
# 1=surface). Reactive ids are mapped at open time.
_HYP_IMPACT = {
    "H-graphql": 4, "H-jwt": 4, "H-params": 3, "H-idor": 4,
    "H-pagination": 3, "H-sortinject": 3, "H-jsassets": 2,
    "H-graphql-discovery": 1, "H-exposure": 2, "H-infra": 3,
    "H-stale": 1, "H-next": 3, "H-wpdata": 3, "H-login": 3,
    "H-escalate": 3,
}
# Initial confidence for PENDING hypotheses, by evidence strength
# (discovery-only 0.3; param-backed surfaces such as H-react-params 0.5).
_PENDING_CONF = {"H-graphql-discovery": 0.3, "H-exposure": 0.3, "H-infra": 0.3,
                 "H-stale": 0.4, "H-next": 0.5, "H-wpdata": 0.4, "H-login": 0.4}
# EV weight fallback for untagged steps, by phase.
_PHASE_WEIGHT = {"recon": (2, 1.0), "discovery": (3, 0.95),
                 "passive-audit": (2, 0.9), "active-testing": (3, 0.85)}
_PROBE_TOOLS = ("sqli_probe", "xss_probe", "redirect_probe")
# tool -> primary hypothesis it can confirm (used by observe_findings).
_TOOL_HYP = {
    "sqli_probe": "H-params", "xss_probe": "H-params", "redirect_probe": "H-params",
    "fuzz_engine": "H-params", "param_miner": "H-params", "json_inj": "H-params",
    "css_inj": "H-params", "proto_c": "H-params", "cache_dec": "H-params",
    "id_seq": "H-idor", "bola": "H-idor", "priv_matrix": "H-idor",
    "authz_bypass": "H-idor", "session_probe": "H-jwt",
    "jwt_jku": "H-jwt", "jwt_crack": "H-jwt",
    "gql_batch": "H-graphql-discovery", "gql_depth": "H-graphql",
    "gql_alias": "H-graphql", "pagin": "H-pagination", "sort_inj": "H-sortinject",
    "sourcemap2": "H-jsassets", "dom_xss": "H-jsassets", "clobber": "H-jsassets",
    "dir_probe": "H-exposure", "deep_probe": "H-exposure",
    "template_probe": "H-exposure", "method_audit": "H-infra",
    "smuggle": "H-infra", "api_ver": "H-infra", "ct_conf": "H-infra",
    "verb_over": "H-infra", "mq_mgmt": "H-infra",
    "liveness_probe": "H-stale",
    "middleware_bypass": "H-next", "next_image_proxy": "H-next",
}
_TITLE_HINTS = (("graphql", "H-graphql"), ("jwt", "H-jwt"), ("sql", "H-params"),
                ("xss", "H-params"), ("cross-site", "H-params"),
                ("redirect", "H-params"), ("pagination", "H-pagination"),
                ("sort", "H-sortinject"), ("idor", "H-idor"),
                ("sourcemap", "H-jsassets"))
# Sinkron dengan scheduler Step() di bawah (world.has_param) — jangan drift lagi.
_IDOR_PARAMS = ("id", "uid", "user_id", "userid", "order_id", "doc_id",
                "invoice_id", "account_id")
_PAGIN_PARAMS = ("limit", "first", "size", "per_page", "page_size", "count", "take")
_SORT_PARAMS = ("sort", "order", "orderby", "order_by", "filter", "sort_by",
                "sortby")


def _fget(f, name):
    """Read a field from a Finding object (or dict) tolerantly."""
    if isinstance(f, dict):
        return f.get(name)
    return getattr(f, name, None)


class DeterministicPlanner:
    def __init__(self, offensive_allowed: bool, crawl_pages: int = 15,
                 authenticated: bool = False, request_budget: int = 400,
                 known_tools: set | None = None):
        self.offensive_allowed = offensive_allowed
        self.crawl_pages = crawl_pages
        self.authenticated = authenticated
        self.request_budget = max(int(request_budget), 0)
        self.account_count = 0
        self.known_tools = ({str(t) for t in known_tools}
                            if known_tools is not None else None)
        self._emitted: set[tuple] = set()
        # ---- FAZ 2 adaptive state ----
        self._schedule: list[Step] = []   # every emitted step, in emission order
        self._hyp: dict[str, dict] = {}   # hypothesis_id -> ledger state
        self._round_steps: list[Step] = []  # steps emitted in the current round
        self._round_new: list[str] = []   # hypothesis ids with new steps (ordered)
        self._last_share: dict[str, int] = {}  # share granted in the current round
        self._allocated_total = 0
        self._probe_pairs: set[tuple] = set()  # (url, param) already probe-scheduled
        self._tool_serves: dict[str, set] = {}  # tool -> hypothesis ids it serves
        self._clean_demoted: set[tuple] = set()  # (tool, hypothesis) already demoted
        self._opened: set[str] = set()    # reactive hypotheses already opened
        self._reactive: dict[str, dict] = {}  # opened reactive hypothesis entries
        self._world: WorldModel | None = None
        self._seen_gql = False
        self._seen_jwt = False
        # ---- U2: adaptive escalation state ----
        self._escalated_patterns: set[str] = set()  # pola yang sudah di-unlock
        self._last_escalation_fase: str = ""
        self.escalation_state: dict = {}  # rencana eskalasi terakhir (laporan)

    # ----------------------------------------------------------- emission
    def _once(self, step: Step) -> list[Step]:
        """Emit a step once per run (dedup on tool+args). Newly emitted steps
        are tracked for the current round's budget allocation; param-probe
        steps register their (url, param) pair for re-plan dedup."""
        key = (step.tool, json.dumps(step.args, sort_keys=True))
        if key in self._emitted:
            return []
        self._emitted.add(key)
        self._schedule.append(step)
        self._round_steps.append(step)
        if step.hypothesis_id:
            if step.hypothesis_id not in self._round_new:
                self._round_new.append(step.hypothesis_id)
            self._tool_serves.setdefault(step.tool, set()).add(step.hypothesis_id)
        if step.tool in _PROBE_TOOLS and step.args.get("url") and step.args.get("param"):
            self._probe_pairs.add((step.args["url"], step.args["param"]))
        return [step]

    @staticmethod
    def _is_public_host(target: str) -> bool:
        h = (urlsplit(target).hostname or "").lower()
        if not h or h in ("127.0.0.1", "localhost", "::1") or h.endswith((".local", ".test")):
            return False
        if h.replace(".", "").isdigit():
            return False
        if h.startswith(("192.168.", "10.")) or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", h):
            return False
        return True

    # -------------------------------------------------------- hypotheses
    def _reconcile(self, h: dict) -> None:
        """Create/update the ledger state for a world-derived hypothesis.

        Initial confidence follows evidence strength: CONFIRMED 0.8,
        PENDING 0.3-0.5 (discovery-only 0.3, param-backed 0.5), REJECTED 0.
        Status is re-derived from the world each round; confidence only
        moves on transitions (observe_findings owns in-place updates)."""
        st = self._hyp.get(h["id"])
        if st is None:
            status = h["status"]
            if status == "CONFIRMED":
                conf = 0.8
            elif status in ("REJECTED", "DONE"):
                conf = 0.0
            else:
                conf = _PENDING_CONF.get(h["id"], 0.3)
            self._hyp[h["id"]] = {"claim": h["claim"], "confidence": conf,
                                  "impact": _HYP_IMPACT.get(h["id"], 2),
                                  "allocated": 0, "status": status}
            return
        prev = st["status"]
        st["status"] = h["status"]
        st["claim"] = h["claim"]
        if h["status"] == "CONFIRMED" and prev != "CONFIRMED" and st["confidence"] < 0.8:
            st["confidence"] = 0.8
        if h["status"] in ("REJECTED", "DONE"):
            st["confidence"] = 0.0

    def _hypotheses(self, world: WorldModel) -> None:
        """Reasoning trail deterministik: hipotesis -> bukti -> keputusan.
        Update setiap iterasi plan(); tersimpan di world + laporan. FAZ 2:
        tiap entri dilengkapi confidence/impact/budget_requests dan hipotesis
        reaktif (H-react-*) yang sudah terbuka tetap dipertahankan."""
        H = []
        gql = world.has_graphql()
        H.append({"id": "H-graphql",
                  "claim": "Endpoint GraphQL tersedia untuk serangan batch/depth/alias",
                  "evidence": ("endpoint graphql teramati" if gql
                               else "tidak ada endpoint graphql teramati"),
                  "decision": ("jadwalkan gql_depth + gql_alias" if gql
                               else "lewati seluruh uji GraphQL"),
                  "status": "CONFIRMED" if gql else "REJECTED"})
        jwt = world.has_jwt()
        H.append({"id": "H-jwt",
                  "claim": "Token JWT dipakai aplikasi -> uji tamper/weak-secret",
                  "evidence": ("token JWT terdeteksi pada cookie" if jwt
                               else "tidak ada token JWT terdeteksi"),
                  "decision": ("jadwalkan jwt_jku + jwt_crack" if jwt
                               else "lewati uji JWT"),
                  "status": "CONFIRMED" if jwt else "REJECTED"})
        params = world.param_endpoints(limit=1)
        H.append({"id": "H-params",
                  "claim": "Parameter query membuka surface (injeksi/pollution/pagination)",
                  "evidence": (f"{len(world.param_endpoints(limit=25))} endpoint berparameter"
                               if params else "belum ada endpoint berparameter"),
                  "decision": ("jadwalkan json_inj/css_inj/proto_c + uji param spesifik"
                               if params else "lewati uji berbasis parameter"),
                  "status": "CONFIRMED" if params else "REJECTED"})
        idp = world.has_param(("id", "uid", "user_id", "userid", "order_id", "doc_id"))
        H.append({"id": "H-idor",
                  "claim": "Identifier numerik bisa dihitung -> uji sekuens + lintas akun",
                  "evidence": ("param id-like teramati" if idp
                               else "tidak ada param id-like"),
                  "decision": "jadwalkan id_seq" if idp else "lewati id_seq",
                  "status": "CONFIRMED" if idp else "REJECTED"})
        pg = world.has_param(("limit", "first", "size", "per_page", "page_size", "count", "take"))
        H.append({"id": "H-pagination",
                  "claim": "Pagination bisa dipaksa dump massal",
                  "evidence": ("param limit-like teramati" if pg else "tidak ada param limit-like"),
                  "decision": "jadwalkan pagin" if pg else "lewati pagin",
                  "status": "CONFIRMED" if pg else "REJECTED"})
        si = world.has_param(("sort", "order", "orderby", "order_by", "filter", "sort_by"))
        H.append({"id": "H-sortinject",
                  "claim": "Parameter sort/filter masuk query tanpa sanitasi",
                  "evidence": ("param sort/filter teramati" if si else "tidak ada param sort/filter"),
                  "decision": "jadwalkan sort_inj" if si else "lewati sort_inj",
                  "status": "CONFIRMED" if si else "REJECTED"})
        js = any(urlsplit_path(e.url).endswith((".js", ".css"))
                 for e in world.endpoints.values())
        H.append({"id": "H-jsassets",
                  "claim": "Aset JS/CSS membuka sourcemap & DOM sink",
                  "evidence": (f"{sum(1 for e in world.endpoints.values() if urlsplit_path(e.url).endswith(('.js', '.css')))} aset teramati"
                               if js else "belum ada aset js/css teramati"),
                  "decision": ("jadwalkan sourcemap2 + dom_xss" if js
                               else "lewati sourcemap2 + dom_xss"),
                  "status": "CONFIRMED" if js else "REJECTED"})
        H.append({"id": "H-graphql-discovery",
                  "claim": "Endpoint GraphQL bisa tersembunyi di path umum",
                  "evidence": "probe discovery murah (<=6 request) tetap berjalan",
                  "decision": "gql_batch berlaku sebagai discoverer",
                  "status": "PENDING" if not gql else "DONE"})
        H.append({"id": "H-exposure",
                  "claim": "Template engine dan file sensitif terekspos publik",
                  "evidence": "probe exposure bawaan planner (tanpa bukti awal)",
                  "decision": "jadwalkan dir_probe/deep_probe/template_probe",
                  "status": "PENDING"})
        H.append({"id": "H-infra",
                  "claim": "Lapisan infrastruktur HTTP bisa dikelabui (method/verb/versi/smuggling)",
                  "evidence": "probe infra bawaan planner (tanpa bukti awal)",
                  "decision": "jadwalkan method_audit/smuggle/api_ver/ct_conf/verb_over",
                  "status": "PENDING"})
        live = bool(world.endpoints)
        wp = world.has_tech("wordpress") or any(
            "wp-json" in urlsplit_path(e.url) or "/wp-content/" in urlsplit_path(e.url)
            for e in world.endpoints.values())
        H.append({"id": "H-wpdata",
                  "claim": "WP comments/media membocorkan PII tanpa auth",
                  "evidence": ("indikasi WordPress teramati" if wp
                               else "tidak ada indikasi WordPress"),
                  "decision": "jadwalkan wp_dataexp" if wp else "lewati wp_dataexp",
                  "status": "CONFIRMED" if wp else "REJECTED"})
        login_ep = any(getattr(e, "form_fields", None)
                       or any(k in urlsplit_path(e.url).lower()
                              for k in ("login", "signin", "sign-in", "logon", "auth"))
                       for e in world.endpoints.values())
        H.append({"id": "H-login",
                  "claim": "Login tanpa lockout membuka password spraying",
                  "evidence": ("endpoint login/form teramati" if login_ep
                               else "belum ada endpoint login teramati"),
                  "decision": "jadwalkan lockout" if login_ep else "lewati lockout",
                  "status": "CONFIRMED" if login_ep else "REJECTED"})
        H.append({"id": "H-stale",
                  "claim": "Host yang merespons belum tentu menjalankan aplikasi "
                           "(server hidup = aplikasi hidup TIDAK otomatis)",
                  "evidence": ("host merespons; endpoint teramati - fingerprint "
                               "aplikasi diuji liveness_probe" if live
                               else "belum ada bukti host hidup"),
                  "decision": ("jadwalkan liveness_probe" if live
                               else "lewati liveness_probe"),
                  "status": "CONFIRMED" if live else "REJECTED"})
        nxt = any("/_next/" in urlsplit_path(e.url)
                  for e in world.endpoints.values()) or world.has_tech("next")
        H.append({"id": "H-next",
                  "claim": "Aplikasi Next.js membuka middleware bypass "
                           "(CVE-2025-29927) dan image optimizer proxy",
                  "evidence": ("aset /_next/ teramati di world model" if nxt
                               else "tidak ada bukti Next.js"),
                  "decision": ("jadwalkan middleware_bypass + next_image_proxy" if nxt
                               else "lewati probe Next.js"),
                  "status": "CONFIRMED" if nxt else "REJECTED"})
        # FAZ 3 feed: anomaly + invariant candidates jadi hipotesis riset (tanpa request)
        try:
            from .anomaly import zero_day_candidates
            for i, c in enumerate(zero_day_candidates(world), start=1):
                H.append({"id": f"H-zd-{i}", "claim": c["hypothesis"],
                          "evidence": f"source: {c['source']}",
                          "decision": "masuk antrean riset zero-day (FAZ 3)",
                          "status": "PENDING"})
        except Exception:
            pass
        # U2-integ: antrean eskalasi adaptif tampil sebagai hipotesis
        if "H-escalate" in self._hyp:
            esc = self.escalation_state or {}
            H.append({"id": "H-escalate",
                      "claim": "Eskalasi adaptif: pola attack surface terdeteksi -> "
                               "antrean engine ofensif terbuka (budget-aware)",
                      "evidence": ("pola: "
                                   + (", ".join(sorted(esc.get("patterns", {}))) or "-")
                                   + f"; fase {esc.get('fase', '-')}"),
                      "decision": "jadwalkan engine hasil unlock (dedup per pola)",
                      "status": self._hyp["H-escalate"]["status"]})
        for h in H:
            self._reconcile(h)
        # reactive hypotheses opened by observe_findings persist across rebuilds
        for hid, base in self._reactive.items():
            st = self._hyp[hid]
            H.append({**base, "status": st["status"],
                      "confidence": round(st["confidence"], 4),
                      "impact": st["impact"], "budget_requests": st["allocated"]})
        world.hypotheses = H

    # ------------------------------------------------------------ budget
    def _allocate(self) -> None:
        """Split the remaining request budget over the hypotheses that still
        have newly-emitted steps this round, proportional to
        impact * confidence (minimum 1 while capacity remains). Every
        allocation round keeps a small reserve (10%, max 40 requests) so later
        re-plan rounds opened by findings stay fundable."""
        self._last_share = {}
        eligible: list[str] = []
        for hid in self._round_new:
            st = self._hyp.get(hid)
            if not st or st["confidence"] <= 0 or st["status"] in ("REJECTED", "DONE"):
                continue
            if hid not in eligible:
                eligible.append(hid)
        if not eligible:
            return
        reserve = min(self.request_budget // 10, 40)
        cap_total = max(self.request_budget - reserve, 0)
        remaining = max(cap_total - self._allocated_total, 0)
        if self._allocated_total >= self.request_budget:
            return  # hard stop: nothing left to grant, not even the minimum
        weights = {hid: self._hyp[hid]["impact"] * self._hyp[hid]["confidence"]
                   for hid in eligible}
        total_w = sum(weights.values())
        if total_w <= 0:
            return
        for hid in eligible:
            cap = self.request_budget - self._allocated_total
            if cap <= 0:
                break
            share = min(max(1, int(remaining * weights[hid] / total_w)), cap)
            self._hyp[hid]["allocated"] += share
            self._allocated_total += share
            self._last_share[hid] = share

    def _rescale_engines(self) -> None:
        """Scale `max_requests` of newly-emitted engine steps to the serving
        hypothesis share: clamp(int(share), 6, default_engine); the step cost
        carries the same estimate."""
        for step in self._round_steps:
            if step.hypothesis_id and "max_requests" in step.args:
                default = int(step.args["max_requests"])
                share = int(self._last_share.get(step.hypothesis_id, 0))
                scaled = max(6, min(share, default))
                step.args["max_requests"] = scaled
                step.cost = scaled

    def budget_ledger(self) -> dict[str, dict]:
        """hypothesis_id -> {claim, confidence, impact, allocated, spent, status}.
        `spent` is the summed cost of every step emitted for the hypothesis."""
        spent: dict[str, int] = {}
        for s in self._schedule:
            if s.hypothesis_id:
                spent[s.hypothesis_id] = spent.get(s.hypothesis_id, 0) + s.cost
        return {hid: {"claim": st["claim"], "confidence": round(st["confidence"], 4),
                      "impact": st["impact"], "allocated": st["allocated"],
                      "spent": spent.get(hid, 0), "status": st["status"]}
                for hid, st in self._hyp.items()}

    def _sync_world_events(self, world: WorldModel) -> None:
        """Mirror reactive re-plan events into the world model (FAZ 2): one
        {trigger_finding, hypothesis_id, claim, steps} row per opened
        H-react-* hypothesis. Existing rows (appended by the orchestrator)
        are deduplicated on hypothesis id, keeping the first occurrence, so
        appends and syncs never pile up duplicate rows."""
        events: list[dict] = []
        have: set = set()
        for e in list(getattr(world, "replan_events", []) or []):
            hid = e.get("hypothesis_id")
            if hid in have:
                continue
            have.add(hid)
            events.append(e)
        for hid, base in self._reactive.items():
            if hid in have:
                continue
            events.append({"trigger_finding": base.get("opened_by", ""),
                           "hypothesis_id": hid, "claim": base.get("claim", ""),
                           "steps": list(base.get("steps", []))})
            have.add(hid)
        world.replan_events = events

    # ----------------------------------------------------------- ordering
    def _ev_key(self, step: Step) -> tuple:
        """EV = impact * confidence / max(cost, 1); negated for descending
        sort. Ties fall to deterministic secondary keys (tool, url, param)
        so two logically-identical worlds produce identical plans even when
        endpoint dict insertion order differs."""
        st = self._hyp.get(step.hypothesis_id) if step.hypothesis_id else None
        if st is not None:
            weight = st["impact"] * st["confidence"]
        else:
            impact, conf = _PHASE_WEIGHT.get(step.phase, (2, 0.9))
            weight = impact * conf
        return (-(weight / max(step.cost, 1)),
                step.tool,
                str(step.args.get("url", "")),
                str(step.args.get("param", "")))

    # ------------------------------------------------- escalation (U2-integ)
    def _escalation_phase(self, world: WorldModel) -> None:
        """Adaptive Escalation sebagai bagian otak planner: proyeksikan world
        menjadi Evidence Graph, tanyakan fase berikutnya ke escalation_plan,
        catat perubahan fase di world note, dan pada fase ESCALATE jadwalkan
        engine hasil unlock sebagai step (dedup `_once`, sekali per pola,
        budget-aware lewat hipotesis H-escalate). Tanpa otorisasi offensive
        fase berhenti di PATTERN (fail-closed)."""
        try:
            g = _knowledge_graph.build_from_world(world)
            plan = _escalation.escalation_plan(
                g, self.offensive_allowed,
                has_vuln_candidates=bool(world.findings_seen))
        except Exception:
            return
        self.escalation_state = plan
        fase = str(plan.get("fase", ""))
        if fase and fase != self._last_escalation_fase:
            world.note(
                "escalation fase: "
                + (f"{self._last_escalation_fase} -> {fase}"
                   if self._last_escalation_fase else fase)
                + f" (pola: {', '.join(sorted(plan.get('patterns', {}))) or 'belum ada'})")
            self._last_escalation_fase = fase
        if fase != _escalation.FASE_ESCALATE:
            return
        if "H-escalate" not in self._hyp:
            self._hyp["H-escalate"] = {
                "claim": "Eskalasi adaptif: pola attack surface terdeteksi -> "
                         "antrean engine ofensif terbuka (budget-aware)",
                "confidence": 0.8, "impact": _HYP_IMPACT["H-escalate"],
                "allocated": 0, "status": "CONFIRMED"}
        for pola, engines in sorted((plan.get("unlocked_by_pattern") or {}).items()):
            if pola in self._escalated_patterns:
                continue
            emitted: list[str] = []
            for eng in engines:
                if self.known_tools is not None and eng not in self.known_tools:
                    continue
                args = self._escalation_args(eng, world)
                if args is None:
                    continue
                if self._once(Step(
                        eng, args,
                        f"eskalasi adaptif: pola '{pola}' terdeteksi -> engine "
                        f"'{eng}' masuk antrian (dedup per pola, budget H-escalate)",
                        "active-testing", 6, "H-escalate")):
                    emitted.append(eng)
            if emitted:
                self._escalated_patterns.add(pola)
                world.note(f"escalation unlock: pola '{pola}' -> {', '.join(emitted)}")

    def _escalation_args(self, eng: str, world: WorldModel) -> dict | None:
        """Argumen minimum untuk engine hasil unlock; None = lewati engine
        ini (butuh konteks yang belum ada, mis. multi-sesi atau pasangan
        (url,param) konkret)."""
        if eng in ("sqli_probe", "xss_probe", "redirect_probe"):
            # probe param-pair: planner menjadwalkannya pada (url,param)
            # konkret lewat skeleton/re-plan, bukan generik tanpa param
            return None
        if eng in ("bola", "priv_matrix", "idor_mass_endpoint"):
            # uji lintas akun bermakna hanya dengan >= 2 sesi
            if self.account_count < 2:
                return None
        if eng == "idor_mass_endpoint":
            return {"base_url": world.target, "allow_foreign_probe": True}
        if eng == "param_miner":
            # samakan args dengan skeleton agar _once mendedup (bukan ganda)
            return {"url": world.target, "max_requests": 40}
        if eng == "traversal":
            params: list[str] = []
            for ep in world.param_endpoints(limit=6):
                for prm in ep.params:
                    if prm not in params:
                        params.append(prm)
                if len(params) >= 3:
                    break
            if not params:
                return None
            return {"url": world.target, "params": params[:3]}
        return {"url": world.target}

    # -------------------------------------------------------------- plan
    def plan(self, world: WorldModel) -> list[Step]:
        """Build (once per run) and return the full pending schedule,
        EV-ordered: the orchestrator executes the first step not yet run and
        re-plans, so step N+1 always reflects findings from step N."""
        self._world = world
        self._escalation_phase(world)
        self._hypotheses(world)
        target = world.target
        if is_local_path(target):
            self._once(Step("code_audit", {"path": target},
                            "white-box SAST: dangerous-pattern scan of the repository",
                            "recon"))
            self._once(Step("sca_probe", {"path": target},
                            "SCA: query OSV.dev for known dependency vulns",
                            "recon"))
            self._once(Step("secret_scan", {"path": target},
                            "local path target: scan for hardcoded secrets", "recon"))
        elif not world.endpoints:
            # entrypoint probe can fail transiently (edge 522/timeout) — retry
            # once more before declaring a fixpoint
            attempts = sum(1 for s in self._schedule if s.tool == "http_probe")
            if attempts < 2:
                self._once(Step("http_probe", {"url": target, "attempt": attempts + 1},
                                f"fingerprint the target (retry {attempts + 1} after "
                                f"failed/empty probe)", "recon"))
            self._once(Step("security_headers", {"url": target},
                            "audit security headers on the entrypoint", "passive-audit"))
            self._once(Step("tls_audit", {"url": target},
                            "audit certificate validity and TLS protocol",
                            "passive-audit"))
            self._once(Step("email_probe", {"url": target},
                            "check SPF/DMARC for the target domain",
                            "passive-audit"))
            if self._is_public_host(target):
                self._once(Step("ct_log", {"url": target},
                                "certificate transparency audit: leaked subdomains",
                                "passive-audit"))
                self._once(Step("wayback", {"url": target},
                                "wayback diff: historical routes that no longer resolve",
                                "passive-audit"))
            self._once(Step("takeover", {"url": target},
                            "subdomain takeover: CNAME dangling + provider fingerprint",
                            "passive-audit"))
            if self._is_public_host(target):
                self._once(Step("smtp_probe", {"url": target},
                                "STARTTLS check on the MX host (EHLO)",
                                "passive-audit"))
                self._once(Step("dkim_probe", {"url": target},
                                "DKIM key strength on common selectors",
                                "passive-audit"))
        else:
            self._plan_web(world, target)
        # GOD-TIER: begitu ada bukti teknologi di world, jalankan sekali
        # matcher CVE pasif (nol request; no-op aman bila KB belum sinkron)
        if world.technologies:
            self._once(Step("cve_matcher", {},
                            "pasif: fingerprint teknologi -> KB NVD lokal "
                            "(lead CVE exposure, tanpa request)",
                            "passive-audit"))
        self._allocate()
        self._rescale_engines()
        # round bookkeeping is cleared AFTER allocation so follow-up steps
        # emitted by observe_findings() between two plan() calls are funded
        # by the next allocation round instead of being dropped
        self._round_steps = []
        self._round_new = []
        ordered = sorted(self._schedule, key=self._ev_key)
        # sync world-facing hypothesis rows with the latest ledger state
        for h in world.hypotheses:
            st = self._hyp.get(h.get("id"))
            if st:
                h["confidence"] = round(st["confidence"], 4)
                h["impact"] = st["impact"]
                h["budget_requests"] = st["allocated"]
                h["status"] = st["status"]
        world.budget_ledger = self.budget_ledger()
        self._sync_world_events(world)
        return ordered

    def _plan_web(self, world: WorldModel, target: str) -> None:
        """Full web skeleton: discovery -> offensive testing (evidence-gated).
        Every step is tagged with the hypothesis it serves."""
        self._once(Step("crawler", {"url": target, "max_pages": self.crawl_pages},
                        f"deep crawl (up to {self.crawl_pages} pages) with sitemap/"
                        "robots/security.txt lead ingestion", "discovery"))
        self._once(Step("browser_engine", {"url": target, "max_pages": 5},
                        "render key pages with headless browser (SPA surface)",
                        "discovery"))
        self._once(Step("browser_scout", {"url": target, "max_pages": 5},
                        "CDP headless scout: DOM/trafik/cookie halaman "
                        "JS-heavy dalam scope (profil terisolasi, bounded, "
                        "request pihak ketiga diblokir di dalam browser)",
                        "discovery"))
        if not self.offensive_allowed:
            return
        self._once(Step("liveness_probe", {"url": target},
                        "app-liveness classification: distinguish server-alive from "
                        "application-alive (stale/orphaned surface candidate)",
                        "active-testing", 8, "H-stale"))
        self._once(Step("cookie_audit", {"url": target},
                        "security-attribute audit of every anonymous Set-Cookie",
                        "active-testing", 2))
        self._once(Step("sri_audit", {"url": target},
                        "third-party scripts without Subresource Integrity on /",
                        "active-testing", 1))
        self._once(Step("debug_page", {"url": target},
                        "verbose error/debug-mode exposure on malformed requests "
                        "(Ignition/Whoops/traceback)", "active-testing", 2))
        self._once(Step("wp_probe", {"url": target},
                        "WordPress hardening: REST user enumeration (2 path), "
                        "debug.log, xmlrpc posture", "active-testing", 4))
        self._once(Step("xmlrpc_probe", {"url": target},
                        "XML-RPC audit: method exposure, multicall amplification "
                        "(protocol-level), pingback SSRF (oob-confirmed only)",
                        "active-testing", 4))
        if world.has_tech("wordpress") or any(
                "wp-json" in urlsplit_path(e.url)
                or "/wp-content/" in urlsplit_path(e.url)
                for e in world.endpoints.values()):
            self._once(Step("wp_dataexp", {"url": target},
                            "WP comments/media PII exposure sweep (email/phone, "
                            "masked, cease-on-data) bila WordPress terdeteksi",
                            "active-testing", 3, "H-wpdata"))
        if world.has_tech("next") or any("/_next/" in urlsplit_path(e.url)
                                         for e in world.endpoints.values()):
            self._once(Step("middleware_bypass", {"url": target},
                            "CVE-2025-29927 Next.js middleware bypass (3-gate "
                            "differential)", "active-testing", 20, "H-next"))
            self._once(Step("next_image_proxy", {"url": target},
                            "/_next/image open-proxy check (external URL fetch)",
                            "active-testing", 2, "H-next"))
        self._once(Step("method_audit", {"url": target},
                        "check exposed HTTP methods on the entrypoint",
                        "active-testing", 1, "H-infra"))
        self._once(Step("dir_probe", {"url": target},
                        "expanded sensitive-path discovery", "active-testing",
                        1, "H-exposure"))
        self._once(Step("auth_probe", {"url": target},
                        "bounded authentication testing: login discovery, "
                        "enumeration, lockout behavior, probe-account spray",
                        "active-testing"))
        self._once(Step("deep_probe", {"url": target},
                        "additional attack techniques (traversal/SSTI/cmdi/CORS/"
                        "host-header/GraphQL/API-auth) with early-stop-on-hit",
                        "active-testing", 1, "H-exposure"))
        self._once(Step("template_probe", {"url": target, "max_requests": 60},
                        "own template scanner: 15 definitive exposure checks",
                        "active-testing", 60, "H-exposure"))
        self._once(Step("fuzz_engine", {"url": target, "max_requests": 80},
                        "zero-day hunt: differential fuzzing on discovered params "
                        "(reproduce-before-report)", "active-testing", 80, "H-params"))
        for ep in world.param_endpoints(limit=12):
            for param in ep.params[:4]:
                for tool, what in (("sqli_probe", "SQL injection"),
                                   ("xss_probe", "reflected XSS"),
                                   ("redirect_probe", "open redirect")):
                    self._once(Step(tool, {"url": ep.url, "param": param},
                                    f"probe param '{param}' for {what}",
                                    "active-testing", 1, "H-params"))
        if getattr(self, "authenticated", False):
            self._once(Step("session_probe", {"url": target},
                            "authenticated session analysis: entropy, JWT "
                            "structure/tamper, admin authorization diff",
                            "active-testing", 1, "H-jwt"))
        if world.has_param(("id", "uid", "user_id", "userid", "order_id", "doc_id", "invoice_id", "account_id")):
            self._once(Step("id_seq", {"url": target},
                            "sequential-id enumeration with failing control value",
                            "active-testing", 1, "H-idor"))
            self._once(Step("authz_bypass", {"url": target, "max_requests": 30},
                            "401/403 bypass matrix (path tricks, X-Original-URL)",
                            "active-testing", 30, "H-idor"))
        if bool(world.param_endpoints(limit=1)):
            self._once(Step("cache_dec", {"url": target},
                            "web cache deception on protected paths (.css variant)",
                            "active-testing", 1, "H-params"))
        self._once(Step("oauth", {"url": target},
                        "OAuth/OIDC authorize audit: state, redirect_uri, nonce",
                        "active-testing"))
        self._once(Step("puzzle", {"url": target},
                        "session puzzling: string vs array parameter confusion",
                        "active-testing"))
        if bool(world.param_endpoints(limit=1)):
            self._once(Step("json_inj", {"url": target},
                            "JSON injection with unique-marker verification",
                            "active-testing", 1, "H-params"))
        self._once(Step("smuggle", {"url": target, "max_requests": 6},
                        "request smuggling clue: controlled CL/TE timing divergence",
                        "active-testing", 6, "H-infra"))
        if any(e.method == "POST" for e in world.endpoints.values()):
            self._once(Step("ct_conf", {"url": target},
                            "content-type confusion on POST endpoints",
                            "active-testing", 1, "H-infra"))
            self._once(Step("verb_over", {"url": target},
                            "X-HTTP-Method-Override bypass check",
                            "active-testing", 1, "H-infra"))
        self._once(Step("api_ver", {"url": target},
                        "API version downgrade: v1 open vs v2 protected",
                        "active-testing", 1, "H-infra"))
        self._once(Step("gql_batch", {"url": target},
                        "GraphQL batching check (array-of-queries)",
                        "active-testing", 1, "H-graphql-discovery"))
        if world.has_graphql():
            self._once(Step("gql_depth", {"url": target},
                            "GraphQL query cost limit check (500 aliases)",
                            "active-testing", 1, "H-graphql"))
            self._once(Step("gql_alias", {"url": target},
                            "GraphQL alias duplication check",
                            "active-testing", 1, "H-graphql"))
        if world.has_param(("limit", "first", "size", "per_page", "page_size", "count", "take")):
            self._once(Step("pagin", {"url": target},
                            "pagination unbounded: limit=10000 accepted?",
                            "active-testing", 1, "H-pagination"))
        if world.has_param(("sort", "order", "orderby", "order_by", "filter", "sort_by", "sortby")):
            self._once(Step("sort_inj", {"url": target},
                            "sort/filter parameter SQL injection",
                            "active-testing", 1, "H-sortinject"))
        if world.has_jwt():
            self._once(Step("jwt_jku", {"url": target},
                            "JWT jku/x5u attacker-header tamper-replay",
                            "active-testing", 1, "H-jwt"))
            self._once(Step("jwt_crack", {"url": target},
                            "offline JWT HMAC weak-secret guess",
                            "active-testing", 1, "H-jwt"))
        if bool(world.param_endpoints(limit=1)):
            self._once(Step("proto_c", {"url": target},
                            "client-side prototype pollution via query",
                            "active-testing", 1, "H-params"))
        self._once(Step("proto_s", {"url": target},
                        "server-side prototype pollution via JSON merge",
                        "active-testing"))
        if any(urlsplit_path(e.url).endswith((".js", ".css"))
               for e in world.endpoints.values()):
            self._once(Step("clobber", {"url": target},
                            "DOM clobbering static lead analysis",
                            "active-testing", 1, "H-jsassets"))
        if bool(world.param_endpoints(limit=1)):
            self._once(Step("css_inj", {"url": target},
                            "CSS injection with style-breakout marker",
                            "active-testing", 1, "H-params"))
        if any(urlsplit_path(e.url).endswith((".js", ".css")) for e in world.endpoints.values()):
            self._once(Step("sourcemap2", {"url": target},
                            "sourcemap deep: full source recovery + embedded secrets",
                            "active-testing", 1, "H-jsassets"))
            self._once(Step("js_cred_sweep", {"url": target},
                            "hardcoded credential sweep on frontend JS assets "
                            "(Basic auth decode-gated, FP-filtered)",
                            "active-testing", 10, "H-jsassets"))
        self._once(Step("mq_mgmt", {"url": target},
                        "MQ management console exposure (RabbitMQ/ActiveMQ)",
                        "active-testing", 1, "H-infra"))
        if any(urlsplit_path(e.url).endswith(".js") for e in world.endpoints.values()):
            self._once(Step("dom_xss", {"url": target},
                            "static DOM XSS sink analysis on JS assets",
                            "active-testing", 1, "H-jsassets"))
        self._once(Step("clickj", {"url": target},
                        "clickjacking: sensitive action pages without framing protection",
                        "active-testing"))
        if any(getattr(e, "form_fields", None)
               or any(k in urlsplit_path(e.url).lower()
                      for k in ("login", "signin", "sign-in", "logon", "auth"))
               for e in world.endpoints.values()):
            self._once(Step("lockout", {"url": target},
                            "bounded login lockout/rate-limit check (max 6 "
                            "failed attempts, statis-vs-dinamis marker guard, "
                            "no valid credentials)",
                            "active-testing", 6, "H-login"))
        self._once(Step("exploitability", {"url": target},
                        "exploitability verifier: does missing CSP leave a real primitive?",
                        "active-testing"))
        self._once(Step("param_miner", {"url": target, "max_requests": 40},
                        "hidden parameter mining via response diff",
                        "active-testing", 40, "H-params"))
        self._once(Step("llm_probe", {"url": target},
                        "AI/LLM endpoint policy-compliance canary probe",
                        "active-testing"))
        if getattr(self, "account_count", 0) >= 2:
            self._once(Step("bola", {"url": target},
                            "cross-account object access (BOLA/IDOR, >=2 sessions)",
                            "active-testing", 1, "H-idor"))
            self._once(Step("priv_matrix", {"url": target},
                            "privilege matrix: user sees admin panel?",
                            "active-testing", 1, "H-idor"))
            self._once(Step("identity_matrix", {"url": target},
                            "matriks multi-identitas: expected-behavior "
                            "anonymous/A/B per endpoint, deviasi differential "
                            "= weakness (GET-only)",
                            "active-testing", 1, "H-idor"))
        self._once(Step("business_logic", {"url": target},
                        "logika bisnis IDENTITY x OBJECT x ACTION x STATE: "
                        "validasi transisi teramati vs tabel legalitas "
                        "(pasif, tanpa request state-changing)",
                        "passive-audit"))
        # fixed capacity ladder, hard caps, no escalation — cost is a ladder estimate
        self._once(Step("load_probe", {"url": target, "profile": "capacity",
                                       "max_total": 750},
                        "finite-quota capacity profiling (fixed ladder, hard caps, "
                        "knee detection, no escalation)", "active-testing", 30))

    # --------------------------------------------------- observe / re-plan
    def _ensure_hyp(self, hid: str) -> dict | None:
        """Ledger entry for a hypothesis matched by a finding (before the next
        plan() rebuild); a finding implies the evidence exists."""
        st = self._hyp.get(hid)
        if st is None and hid in _HYP_IMPACT:
            st = {"claim": hid, "confidence": 0.8, "impact": _HYP_IMPACT[hid],
                  "allocated": 0, "status": "CONFIRMED"}
            self._hyp[hid] = st
        return st

    def _matching_hyps(self, f) -> list[str]:
        """Hypotheses related to a finding: by tool, then by title hint, then
        by the parameter name the finding points at."""
        matched: list[str] = []
        add = lambda hid: hid not in matched and matched.append(hid) is None
        hid = _TOOL_HYP.get(str(_fget(f, "tool") or ""))
        if hid:
            add(hid)
        title = str(_fget(f, "title") or "").lower()
        for hint, h2 in _TITLE_HINTS:
            if hint in title:
                add(h2)
        param = str(_fget(f, "param") or "").lower()
        if param:
            if param in _IDOR_PARAMS:
                add("H-idor")
            if param in _PAGIN_PARAMS:
                add("H-pagination")
            if param in _SORT_PARAMS:
                add("H-sortinject")
        return matched

    def _unprobed_pairs(self, seed: list[tuple], limit: int,
                        family: str | None = None, all_params: bool = False) -> list[tuple]:
        """(url, param) pairs not yet probe-scheduled: the seed first, then
        world param endpoints (optionally restricted to the same host family)."""
        out: list[tuple] = []
        for pair in seed:
            if pair not in self._probe_pairs and pair not in out:
                out.append(pair)
            if len(out) >= limit:
                return out
        w = self._world
        fam = urlsplit(str(family or "")).netloc if family else ""
        if w is not None:
            for ep in w.param_endpoints(limit=12):
                if fam and urlsplit(ep.url).netloc != fam:
                    continue
                for p in (ep.params if all_params else ep.params[:4]):
                    pair = (ep.url, p)
                    if pair not in self._probe_pairs and pair not in out:
                        out.append(pair)
                    if len(out) >= limit:
                        return out
        return out

    def _open_reactive(self, hid: str, claim: str, evidence: str, decision: str,
                       status: str, conf: float, impact: int, opened_by: str,
                       step_descs: list[str]) -> dict | None:
        """Open a reactive hypothesis once; returns the world.hypotheses-shaped
        dict (plus "opened_by" and "steps") or None when already open."""
        if hid in self._opened:
            return None
        self._opened.add(hid)
        self._hyp[hid] = {"claim": claim, "confidence": conf, "impact": impact,
                          "allocated": 0, "status": status}
        entry = {"id": hid, "claim": claim, "evidence": evidence,
                 "decision": decision, "status": status, "confidence": conf,
                 "impact": impact, "budget_requests": 0, "opened_by": opened_by,
                 "steps": list(step_descs)}
        self._reactive[hid] = dict(entry)
        if self._world is not None:
            self._world.hypotheses.append(dict(entry))
        return dict(entry)

    def _react_new_params(self, findings: list) -> dict | None:
        """Rule 1: a finding exposes an unprobed (url, param) pair ->
        H-react-params with sqli/xss/redirect probes for up to 6 pairs."""
        pairs: list[tuple] = []
        for f in findings:
            u, prm = _fget(f, "target_url"), _fget(f, "param")
            if u and prm:
                pair = (str(u), str(prm))
                if pair not in self._probe_pairs and pair not in pairs:
                    pairs.append(pair)
        if not pairs:
            return None
        follow = self._unprobed_pairs(seed=pairs, limit=6)
        if not follow:
            return None
        desc = [f"{t}({u}#{p})" for (u, p) in follow
                for t in ("sqli_probe", "xss_probe", "redirect_probe")]
        entry = self._open_reactive(
            "H-react-params",
            claim="Temuan membuka parameter baru -> uji injeksi pada pasangan "
                  "(url,param) yang belum pernah diprobe",
            evidence=(f"{len(follow)} pasangan (url,param) belum-probe: "
                      + ", ".join(f"{u}#{p}" for u, p in follow[:3])
                      + ("; ..." if len(follow) > 3 else "")),
            decision="jadwalkan sqli_probe/xss_probe/redirect_probe pada param baru",
            status="PENDING", conf=0.5, impact=3,
            opened_by=str(_fget(findings[0], "title") or "-"),
            step_descs=desc)
        for (u, p) in follow:
            for tool, what in (("sqli_probe", "SQL injection"),
                               ("xss_probe", "reflected XSS"),
                               ("redirect_probe", "open redirect")):
                self._once(Step(tool, {"url": u, "param": p},
                                f"re-plan follow-up: newly surfaced param '{p}' "
                                f"probed for {what}", "active-testing", 1,
                                "H-react-params"))
        return entry

    def _react_deep(self, findings: list) -> list[dict]:
        """Rule 2: confirmed high/critical from sqli_probe/xss_probe ->
        H-react-deep-<tool>: probe up to 4 remaining unprobed params on the
        same endpoint host family."""
        out: list[dict] = []
        for f in findings:
            tool = _fget(f, "tool")
            if tool not in ("sqli_probe", "xss_probe"):
                continue
            if _fget(f, "status") != "confirmed" or _fget(f, "severity") not in ("high", "critical"):
                continue
            hid = f"H-react-deep-{tool}"
            follow = self._unprobed_pairs(seed=[], limit=4,
                                          family=_fget(f, "target_url"),
                                          all_params=True)
            desc = [f"{tool}({u}#{p})" for (u, p) in follow]
            entry = self._open_reactive(
                hid,
                claim=f"Kerentanan {tool} terkonfirmasi (severity "
                      f"{_fget(f, 'severity')}) -> perdalam uji pada param tersisa "
                      f"keluarga endpoint yang sama",
                evidence=f"temuan terkonfirmasi: {_fget(f, 'title')}",
                decision=f"jadwalkan {tool} pada maks 4 param belum-probe di keluarga sama",
                status="CONFIRMED", conf=0.8, impact=4,
                opened_by=str(_fget(f, "title") or "-"),
                step_descs=desc)
            for (u, p) in follow:
                self._once(Step(tool, {"url": u, "param": p},
                                f"re-plan follow-up: deep probe param '{p}' after "
                                f"confirmed {tool} hit", "active-testing", 1, hid))
            if entry:
                out.append(entry)
        return out

    def _react_exploit(self, findings: list) -> dict | None:
        """Rule 5: confirmed finding with severity >= high -> H-react-exploit:
        make sure an exploitability step is scheduled (or re-tagged so EV
        ordering prioritizes the pending one)."""
        trig = None
        for f in findings:
            if _fget(f, "status") == "confirmed" and _fget(f, "severity") in ("high", "critical"):
                trig = f
                break
        if trig is None:
            return None
        target = self._world.target if self._world else ""
        emitted = self._once(Step("exploitability", {"url": target},
                                  "re-plan: exploitability verification after a "
                                  "confirmed high/critical finding", "active-testing",
                                  1, "H-react-exploit"))
        if not emitted:
            for s in self._schedule:
                if s.tool == "exploitability":
                    s.hypothesis_id = "H-react-exploit"
                    if "diprioritaskan re-plan" not in s.rationale:
                        s.rationale += (" (diprioritaskan re-plan: temuan "
                                        "high/critical terkonfirmasi)")
                    break
        return self._open_reactive(
            "H-react-exploit",
            claim="Temuan high/critical terkonfirmasi -> verifikasi exploitability "
                  "wajib dijadwalkan dan diprioritaskan",
            evidence=f"temuan terkonfirmasi: {_fget(trig, 'title')}",
            decision="jadwalkan (atau prioritaskan) step exploitability",
            status="CONFIRMED", conf=0.85, impact=4,
            opened_by=str(_fget(trig, "title") or "-"),
            step_descs=[f"exploitability({target})"])

    def observe_findings(self, findings: list, clean_tools: list[str] | None = None) -> list[dict]:
        """FAZ 2 re-plan hook, called by the orchestrator after every step.

        - confirmed findings on related hypotheses raise confidence by +0.2
          (capped at 0.95) and confirm the hypothesis at >= 0.8;
        - a clean probe (tool finished without findings) on a CONFIRMED
          hypothesis it serves cuts confidence x0.3 (once per pair);
        - GraphQL/JWT evidence newly present confirms H-graphql/H-jwt at 0.9;
        - reactive hypotheses (H-react-*) are opened when findings open a new
          attack surface (offensive mode only).

        Returns the newly opened hypotheses (world.hypotheses format plus
        "opened_by" and "steps"); empty list means no new hypothesis."""
        # (a) confidence updates from findings
        for f in findings:
            if _fget(f, "status") != "confirmed":
                continue
            for hid in self._matching_hyps(f):
                st = self._ensure_hyp(hid)
                if not st or st["status"] in ("REJECTED", "DONE"):
                    continue
                st["confidence"] = round(min(0.95, st["confidence"] + 0.2), 4)
                if st["confidence"] >= 0.8:
                    st["status"] = "CONFIRMED"
        # (b) clean-probe demotion (CONFIRMED hypotheses only, offensive mode)
        if self.offensive_allowed:
            for tool in sorted({str(t) for t in (clean_tools or [])}):
                for hid in sorted(self._tool_serves.get(tool, ())):
                    st = self._hyp.get(hid)
                    if not st or st["status"] != "CONFIRMED":
                        continue
                    if (tool, hid) in self._clean_demoted:
                        continue
                    self._clean_demoted.add((tool, hid))
                    st["confidence"] = round(st["confidence"] * 0.3, 4)
        # (c) graphql/jwt evidence newly present (rules 3 and 4)
        w = self._world
        if w is not None:
            gql = w.has_graphql()
            if gql and not self._seen_gql:
                st = self._hyp.get("H-graphql")
                if st:
                    st["confidence"] = 0.9
                    st["status"] = "CONFIRMED"
            self._seen_gql = gql
            jwt = w.has_jwt()
            if jwt and not self._seen_jwt:
                st = self._hyp.get("H-jwt")
                if st:
                    st["confidence"] = 0.9
                    st["status"] = "CONFIRMED"
            self._seen_jwt = jwt
        # (d) reactive hypotheses (offensive mode only)
        opened: list[dict] = []
        if self.offensive_allowed and findings:
            entry = self._react_new_params(findings)
            if entry:
                opened.append(entry)
            opened.extend(self._react_deep(findings))
            entry = self._react_exploit(findings)
            if entry:
                opened.append(entry)
        if w is not None:
            w.budget_ledger = self.budget_ledger()
            self._sync_world_events(w)
        return opened
