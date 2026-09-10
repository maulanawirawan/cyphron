"""Adversarial validation FAZ 2 — independent pass (fresh eyes).

File ini TIDAK mengulang cakupan test_planner_v2.py / test_faz2_acceptance.py;
ia mengadu batas-batas yang belum teruji:

1.  Termination: temuan reaktif baru terus-menerus (planner + orchestrator)
    tidak boleh membuat loop tak berujung; max_steps & max_time dipatuhi.
2.  Budget invarian ekstrem: request_budget 1/3/0/negatif — tanpa crash,
    tanpa alokasi negatif, Sigma allocated <= budget, tanpa division-by-zero.
3.  observe_findings idempoten: temuan identik berulang tidak membuka
    hipotesis H-react-* duplikat dan tidak menduplikasi replan_events.
4.  Finding aneh (dict tanpa validasi skema): severity tak dikenal, param/
    target_url kosong, judul sangat panjang, dict kosong — tidak crash;
    unconfirmed/medium TIDAK membuka H-react-deep/H-react-exploit.
5.  Konsistensi ledger: planner.budget_ledger() == world.budget_ledger
    setelah plan() maupun observe_findings(); snapshot() memuat 3 field FAZ 2.
6.  Reporting 03/03b: 3 event -> 3 baris; hipotesis legacy 5-key -> fallback
    "-"; event tanpa key -> placeholder, tanpa crash (plus 1 temuan ter-
    dokumentasi via expectedFailure).
7.  Orchestrator re-plan nyata: bukti urutan audit — langkah follow-up
    H-react-* dieksekusi SETELAH finding pemicunya.
8.  Regresi EV-order: plan() 3x identik (termasuk setelah state tumbuh);
    EV-desc tetap terjaga saat urutan insert dict endpoint diubah (plus 1
    temuan ketergantungan urutan-insert, terdokumentasi via expectedFailure).

Semua test offline, deterministik, tanpa jaringan (target mati 127.0.0.1:9,
fake registry), total < 5 detik.
"""

from __future__ import annotations

import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import reporting
from cyphron.findings import Finding
from cyphron.guardrails.authorization import AuditLog
from cyphron.orchestrator import ScanOptions, ScanSummary, run_scan
from cyphron.planner import DeterministicPlanner, Step
from cyphron.tools.base import Tool, ToolRegistry, ToolResult
from cyphron.world.model import Endpoint, WorldModel

BASE = "https://lab.example.test"
DEAD_TARGET = "http://127.0.0.1:9/"  # port mati; tidak ada koneksi nyata
BUDGET = 400

# fallback EV weight per fase (harus konsisten dengan planner.py:77-78)
_PHASE_WEIGHT = {"recon": (2, 1.0), "discovery": (3, 0.95),
                 "passive-audit": (2, 0.9), "active-testing": (3, 0.85)}


# ---------------------------------------------------------------- helpers ---

def _world(six_params: bool = False) -> WorldModel:
    """World offensive sintetis. six_params: endpoint dengan 6 param sehingga
    plan awal hanya memrobe params[:4] dan rule-2 (deep) punya pasangan
    tersisa untuk follow-up."""
    w = WorldModel(target=BASE + "/", mode="offensive")
    if six_params:
        w.observe_endpoint(
            BASE + "/item",
            ["id", "uid", "user_id", "order_id", "invoice_id", "account_id"],
            discovered_by="crawler")
    else:
        w.observe_endpoint(BASE + "/", ["id", "limit", "sort"],
                           discovered_by="crawler")
    return w


def _finding(status="confirmed", severity="critical", url=f"{BASE}/?id=1",
             param="id", tool="sqli_probe",
             title="SQL injection (error-based)") -> Finding:
    return Finding(tool=tool, title=title, severity=severity,
                   description="bukti sintetis", recommendation="perbaiki",
                   target_url=url, param=param, confidence=0.95, status=status,
                   evidence_kind="request-response",
                   request=f"GET {url}?{param}=1' HTTP/1.1",
                   response="HTTP/1.1 500 SQLiteException")


def _ev_of(step: Step, ledger: dict) -> float:
    st = ledger.get(step.hypothesis_id) if step.hypothesis_id else None
    if st:
        weight = st["impact"] * st["confidence"]
    else:
        impact, conf = _PHASE_WEIGHT.get(step.phase, (2, 0.9))
        weight = impact * conf
    return weight / max(step.cost, 1)


def _step_key(s: Step) -> tuple:
    return (s.tool, json.dumps(s.args, sort_keys=True))


AUTH_DOC = {
    "id": "AUTH-ADV-1",
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2030-01-01T00:00:00Z",
    "target": {"name": "fixture-adversarial"},
    "scope": {"targets": ["localhost", "127.0.0.1"], "excluded": [],
              "cidr": ["127.0.0.0/8"], "ports": []},
    "authorized_by": {"name": "tester"},
    "restrictions": ["no_dos", "no_data_exfiltration", "no_persistence"],
    "signature": "test-sig",
}


class _SeedingProbe(Tool):
    """Fake http_probe: menanam endpoint berparam ke world (tanpa jaringan)."""

    name = "http_probe"
    risk_tags = {"passive"}

    def run(self, args, ctx):
        ctx.world.observe_response(ctx.world.target or DEAD_TARGET, 200, {},
                                   "<html>fixture</html>", "http_probe")
        ctx.world.observe_endpoint(DEAD_TARGET + "?id=1", ["id"],
                                   discovered_by="http_probe")
        return ToolResult(tool=self.name, ok=True, data={"status": 200})


class _SqliHit(Tool):
    """Fake sqli_probe: finding critical terkonfirmasi pada pasangan argumenya."""

    name = "sqli_probe"
    risk_tags = {"active"}

    def run(self, args, ctx):
        f = _finding(url=args.get("url") or DEAD_TARGET,
                     param=args.get("param") or "id")
        return ToolResult(tool=self.name, ok=True, findings=[f], data={"hits": 1})


class _EndlessSqli(Tool):
    """Fake sqli_probe yang MENGARSKAN param baru yang belum pernah dilihat
    planner pada setiap eksekusi — mensimulasikan temuan reaktif tak berujung."""

    name = "sqli_probe"
    risk_tags = {"active"}

    def __init__(self):
        self.counter = 0

    def run(self, args, ctx):
        self.counter += 1
        prm = f"inject_{self.counter}"
        url = args.get("url") or DEAD_TARGET
        f = Finding(tool="sqli_probe", title=f"SQL injection ({prm})",
                    severity="critical",
                    description="fixture temuan reaktif tanpa henti",
                    target_url=f"{url}?{prm}=1", param=prm,
                    confidence=0.95, status="confirmed",
                    evidence_kind="request-response",
                    request=f"GET {url}?{prm}=1' HTTP/1.1",
                    response="HTTP/1.1 500 SQLiteException")
        return ToolResult(tool=self.name, ok=True, findings=[f], data={"hits": 1})


def _fake_registry(tools: list[Tool]):
    def factory(ctx):
        reg = ToolRegistry(ctx)
        for t in tools:
            reg.register(t)
        return reg
    return factory


class _OrchestratorMixin:
    """Menjalankan run_scan offline dengan dokumen otorisasi + fake registry."""

    def _run(self, tools: list[Tool], max_steps: int = 60, max_time_s: float = 30.0,
             max_requests: int = BUDGET) -> "object":
        with tempfile.TemporaryDirectory() as td:
            auth_path = Path(td) / "auth.json"
            auth_path.write_text(json.dumps(AUTH_DOC), encoding="utf-8")
            opts = ScanOptions(target=DEAD_TARGET, auth_path=auth_path,
                               rate_limit_s=0.0, max_steps=max_steps,
                               max_requests=max_requests, max_time_s=max_time_s,
                               timeout_s=0.2, crawl_pages=3)
            with mock.patch("cyphron.orchestrator.build_default_registry",
                            _fake_registry(tools)), \
                 mock.patch("cyphron.tools.auth_login.login", return_value=None):
                return run_scan(opts, verbose=False)


def _section(doc: dict, no: str) -> dict:
    return next(s for s in doc["sections"] if s.get("no") == no)


def _report_doc(w: WorldModel) -> dict:
    opts = ScanOptions(target=BASE + "/")
    s = ScanSummary(target=BASE + "/", mode="read-only", steps_executed=1,
                    elapsed_s=0.1)
    audit = AuditLog()
    blocks = reporting._build_blocks(opts, s, w, audit)
    return reporting._build_doc(opts, s, w, audit, blocks)


# ------------------------------------------------------------------ tests ---


class TestTermination(_OrchestratorMixin, unittest.TestCase):
    """Butir 1: temuan reaktif baru terus-menerus TIDAK boleh infinite loop."""

    def test_planner_endless_reactive_findings_stay_bounded(self):
        """60 putaran observe(plan baru dengan param baru terus) harus berhenti,
        Sigma allocated terkunci di request_budget (hard stop), dan id H-react-*
        tidak terduplikasi."""
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world()
        p.plan(w)
        for i in range(60):
            f = {"tool": "param_miner", "title": f"Hidden parameter #{i}",
                 "severity": "low", "status": "unconfirmed",
                 "target_url": f"{BASE}/e{i}", "param": f"p{i}"}
            p.observe_findings([f])
            steps = p.plan(w)  # harus selalu kembali (tidak menggantung)
            self.assertTrue(steps)
        total = sum(e["allocated"] for e in p.budget_ledger().values())
        self.assertLessEqual(total, BUDGET)
        react = [h["id"] for h in w.hypotheses if h["id"].startswith("H-react-")]
        self.assertEqual(len(react), len(set(react)),
                         "id hipotesis reaktif tidak boleh duplikat")
        self.assertLessEqual(len(react), 4)  # params + deep-<tool> + exploit

    def test_run_scan_terminates_with_endless_new_param_findings(self):
        """Fake tool yang selalu menemukan param BARU: run_scan harus selesai
        pada max_steps (bukan menggantung), ledger tetap <= budget."""
        run = self._run([_SeedingProbe(), _EndlessSqli()], max_steps=40,
                        max_time_s=20.0)
        self.assertLessEqual(run.summary.steps_executed, 40)
        self.assertGreater(run.summary.steps_executed, 0)
        total = sum(v["allocated"] for v in run.world.budget_ledger.values())
        self.assertLessEqual(total, BUDGET)
        hids = [e["hypothesis_id"] for e in run.world.replan_events]
        self.assertEqual(len(hids), len(set(hids)),
                         "replan_events tidak boleh menduplikasi hypothesis_id")
        ok, note = run.audit.verify()
        self.assertTrue(ok, note)

    def test_run_scan_max_time_guard_stops_the_loop(self):
        """max_time_s=0 harus menghentikan loop SEBELUM langkah pertama; dengan
        max_time_s normal run yang sama mengeksekusi langkah — membuktikan
        guard waktu benar-benar yang menghentikan, bukan kondisi lain."""
        run_zero = self._run([_SeedingProbe(), _SqliHit()], max_steps=500,
                             max_time_s=0.0)
        self.assertEqual(run_zero.summary.steps_executed, 0,
                         "max_time_s=0 harus mencegah seluruh eksekusi langkah")
        run_norm = self._run([_SeedingProbe(), _SqliHit()], max_steps=500,
                             max_time_s=30.0)
        self.assertGreater(run_norm.summary.steps_executed, 0)


class TestBudgetExtremes(unittest.TestCase):
    """Butir 2: budget ekstrem — valid, tanpa negatif, tanpa division-by-zero."""

    def _invariants(self, p: DeterministicPlanner, steps: list[Step], budget: int):
        ledger = p.budget_ledger()
        for hid, e in ledger.items():
            self.assertGreaterEqual(e["allocated"], 0,
                                    f"alokasi negatif pada {hid}")
            self.assertGreaterEqual(e["spent"], 0)
            self.assertTrue(math.isfinite(e["confidence"]))
            self.assertTrue(0.0 <= e["confidence"] <= 1.0)
        total = sum(e["allocated"] for e in ledger.values())
        self.assertLessEqual(total, budget)
        for s in steps:
            self.assertGreaterEqual(s.cost, 1,
                                    "cost step tidak boleh 0/negatif setelah rescale")
        return total

    def test_tiny_budget_three_requests(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=3)
        steps = p.plan(_world())
        self.assertTrue(steps, "plan() harus tetap mengembalikan langkah valid")
        total = self._invariants(p, steps, 3)
        self.assertGreaterEqual(total, 1, "kapasitas tersisa harus dialokasikan")

    def test_budget_one(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=1)
        steps = p.plan(_world())
        self.assertTrue(steps)
        self.assertEqual(self._invariants(p, steps, 1), 1)

    def test_zero_budget_graceful(self):
        """request_budget=0 (perilaku terdokumentasi): plan() tetap penuh,
        seluruh alokasi 0 — tidak crash, tidak ada alokasi minimal paksa."""
        p = DeterministicPlanner(offensive_allowed=True, request_budget=0)
        steps = p.plan(_world())
        self.assertTrue(steps)
        total = self._invariants(p, steps, 0)
        self.assertEqual(total, 0)

    def test_negative_budget_clamped_to_zero(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=-5)
        steps = p.plan(_world())
        self.assertTrue(steps)
        self.assertEqual(self._invariants(p, steps, 0), 0)

    def test_no_eligible_hypothesis_no_division_by_zero(self):
        """Read-only: tidak ada langkah ber-tag hipotesis -> eligible kosong;
        jalur Sigma-EV=0 (planner.py:315) tidak boleh crash."""
        p = DeterministicPlanner(offensive_allowed=False, request_budget=0)
        steps = p.plan(_world())
        self.assertTrue(steps)
        ledger = p.budget_ledger()
        self.assertEqual(sum(e["allocated"] for e in ledger.values()), 0)
        self.assertEqual(p.observe_findings([_finding(url=f"{BASE}/x", param="y")]),
                         [])

    def test_extreme_budget_survives_replan_rounds(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=3)
        w = _world()
        p.plan(w)
        for i in range(5):
            p.observe_findings([{"tool": "param_miner",
                                 "title": f"Hidden parameter #{i}",
                                 "severity": "low", "status": "unconfirmed",
                                 "target_url": f"{BASE}/e{i}",
                                 "param": f"p{i}"}])
            steps = p.plan(w)
            self._invariants(p, steps, 3)


class TestObserveFindingsDedup(unittest.TestCase):
    """Butir 3: temuan IDENTIK berulang — tanpa hipotesis/event duplikat."""

    def test_identical_findings_twice_no_duplicate_reactive_ids(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        f = _finding(url=f"{BASE}/item?id=1", param="id")
        first = p.observe_findings([f])
        self.assertTrue(first)
        second = p.observe_findings([f])
        third = p.observe_findings([f])
        self.assertEqual(second, [])
        self.assertEqual(third, [])
        hids = [h["id"] for h in w.hypotheses]
        self.assertEqual(len(hids), len(set(hids)),
                         "world.hypotheses tidak boleh memuat id duplikat")
        events = [e["hypothesis_id"] for e in w.replan_events]
        self.assertEqual(len(events), len(set(events)))
        self.assertEqual(sorted(events), sorted(h["id"] for h in first))

    def test_manual_duplicate_event_row_is_deduped_by_plan(self):
        """Simulasi orchestrator append ganda: baris replan_events dengan
        hypothesis_id sama tidak boleh menumpuk setelah plan()."""
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        p.observe_findings([_finding(url=f"{BASE}/item?id=1", param="id")])
        before = len(w.replan_events)
        w.replan_events.append(dict(w.replan_events[0]))  # duplikat manual
        p.plan(w)
        hids = [e["hypothesis_id"] for e in w.replan_events]
        self.assertEqual(len(hids), len(set(hids)))
        self.assertEqual(len(w.replan_events), before)

    def test_ledger_spent_matches_emitted_reactive_steps(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        p.observe_findings([_finding(url=f"{BASE}/item?id=1", param="id")])
        p.plan(w)
        ledger = p.budget_ledger()
        for hid, e in ledger.items():
            self.assertEqual(
                e["spent"],
                sum(s.cost for s in p._schedule if s.hypothesis_id == hid),
                f"spent[{hid}] harus = akumulasi cost step ter-emit")


class TestWeirdFindings(unittest.TestCase):
    """Butir 4: finding aneh (dict, di luar validasi skema Finding) — tidak
    crash, dan reaktif hanya dari temuan bermakna sesuai desain."""

    def test_weird_dict_findings_do_not_crash(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world()
        p.plan(w)
        weird = [
            {"tool": "sqli_probe", "title": "x" * 10000,
             "severity": "apocalyptic", "status": "unconfirmed",
             "target_url": "", "param": ""},
            {"tool": "", "title": "", "severity": None, "status": "weird",
             "target_url": None, "param": None},
            {},
            {"tool": "dir_probe", "title": "directory listing",
             "severity": "unknown-sev", "status": "confirmed",
             "target_url": BASE + "/", "param": ""},
        ]
        opened = p.observe_findings(weird)  # tidak boleh raise
        self.assertEqual([h["id"] for h in opened if h["id"].startswith("H-react-deep")
                          or h["id"] == "H-react-exploit"], [],
                         "severity tak dikenal/unconfirmed tidak boleh membuka "
                         "hipotesis deep/exploit")
        for e in p.budget_ledger().values():
            self.assertTrue(0.0 <= e["confidence"] <= 1.0)

    def test_unconfirmed_critical_never_opens_deep_or_exploit(self):
        """Desain: rule deep/exploit hanya dari temuan CONFIRMED high/critical.
        'critical' tapi unconfirmed tidak boleh membukanya."""
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        f = _finding(status="unconfirmed", severity="critical",
                     url=f"{BASE}/item?id=1", param="id")
        opened = p.observe_findings([f])
        ids = {h["id"] for h in opened}
        self.assertNotIn("H-react-deep-sqli_probe", ids)
        self.assertNotIn("H-react-exploit", ids)
        steps = p.plan(w)
        self.assertNotIn("H-react-deep-sqli_probe",
                         {s.hypothesis_id for s in steps})

    def test_confirmed_medium_does_not_open_deep_or_exploit(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        f = _finding(status="confirmed", severity="medium",
                     url=f"{BASE}/item?id=1", param="id")
        opened = p.observe_findings([f])
        ids = {h["id"] for h in opened}
        self.assertNotIn("H-react-deep-sqli_probe", ids)
        self.assertNotIn("H-react-exploit", ids)


class TestLedgerWorldConsistency(unittest.TestCase):
    """Butir 5: ledger planner vs world + snapshot."""

    def test_world_ledger_matches_planner_after_plan_and_observe(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        self.assertEqual(w.budget_ledger, p.budget_ledger())
        p.observe_findings([_finding(url=f"{BASE}/item?id=1", param="id")])
        # observe_findings juga menyinkronkan ledger ke world (planner.py:855-857)
        self.assertEqual(w.budget_ledger, p.budget_ledger())
        p.plan(w)
        self.assertEqual(w.budget_ledger, p.budget_ledger())
        self.assertEqual(sum(e["allocated"] for e in w.budget_ledger.values()),
                         sum(e["allocated"] for e in p.budget_ledger().values()))

    def test_snapshot_contains_faz2_keys_after_planner_usage(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        f = _finding(url=f"{BASE}/item?id=1", param="id")
        p.observe_findings([f])
        p.plan(w)
        # findings_seen diisi orchestrator (orchestrator.py:177-181), bukan
        # planner — mirror append orchestrator agar snapshot realistis.
        w.findings_seen.append({"tool": f.tool, "title": f.title,
                                "severity": f.severity, "status": f.status,
                                "id": f.id, "target_url": f.target_url or "",
                                "param": f.param or ""})
        snap = w.snapshot()
        for key in ("findings_seen", "replan_events", "budget_ledger",
                    "hypotheses"):
            self.assertIn(key, snap)
        self.assertEqual(snap["findings_seen"], w.findings_seen)
        self.assertTrue(w.replan_events)
        self.assertTrue(w.budget_ledger)


class TestReportingAdversarial(unittest.TestCase):
    """Butir 6: section 03/03b dengan world sintetis ekstrem."""

    def test_03b_three_events_render_three_rows(self):
        w = WorldModel(target=BASE + "/", mode="read-only")
        w.replan_events = [
            {"trigger_finding": f"temuan {i}", "hypothesis_id": f"H-react-{i}",
             "claim": f"klaim {i}", "steps": [f"step-{i}-a", f"step-{i}-b"]}
            for i in range(3)
        ]
        rows = _section(_report_doc(w), "03b")["rows"]
        self.assertEqual(len(rows), 3)
        for i, row in enumerate(rows):
            self.assertIn(f"H-react-{i}", row[1])
            self.assertIn(f"step-{i}-a", row[2])

    def test_03_legacy_hypothesis_falls_back_to_dash(self):
        """Hipotesis format lama 5-key (tanpa confidence/budget_requests):
        kolom fallback '-' dan TIDAK crash (kompatibilitas backward)."""
        w = WorldModel(target=BASE + "/", mode="read-only")
        w.hypotheses = [{"id": "H-old", "claim": "klaim lama",
                         "evidence": "bukti lama", "decision": "keputusan lama",
                         "status": "PENDING"}]
        doc = _report_doc(w)
        rows = _section(doc, "03")["rows"]
        row = next(r for r in rows if r[0] == "H-old")
        self.assertEqual(row[4], "-", "kolom confidence harus fallback '-'")
        self.assertEqual(row[5], "-", "kolom budget harus fallback '-'")

    def test_03b_events_with_missing_keys_do_not_crash(self):
        w = WorldModel(target=BASE + "/", mode="read-only")
        w.replan_events = [
            {"trigger_finding": "t1", "hypothesis_id": "H-react-a",
             "claim": "c1"},  # tanpa "steps"
            {},  # event kosong total
        ]
        doc = _report_doc(w)
        rows = _section(doc, "03b")["rows"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][2], "-", "langkah kosong harus fallback '-'")
        self.assertEqual(rows[1][0], "-")

    def test_03b_event_with_steps_none_crashes(self):
        """SUDAH DIPERBAIKI (reporting.py:226): baris replan_events dengan
        "steps": None (mis. JSON lama/hasil edit manual) kini dirender dengan
        fallback '-' tanpa TypeError — fix: "; ".join(ev.get("steps") or [])."""
        w = WorldModel(target=BASE + "/", mode="read-only")
        w.replan_events = [{"trigger_finding": "t", "hypothesis_id": "H-react-x",
                            "claim": "c", "steps": None}]
        rows = _section(_report_doc(w), "03b")["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], "-")


class TestOrchestratorRealReplan(_OrchestratorMixin, unittest.TestCase):
    """Butir 7: bukti urutan eksekusi — follow-up H-react-* SETELAH finding."""

    def test_reactive_followup_executes_after_triggering_finding(self):
        # endpoint /item punya 6 param; plan awal hanya memrobe params[:4]
        # sehingga rule-2 (deep) punya 2 pasangan follow-up: invoice_id, account_id
        class _RichSeed(_SeedingProbe):
            def run(self, args, ctx):
                super().run(args, ctx)
                ctx.world.observe_endpoint(
                    DEAD_TARGET + "item",
                    ["id", "uid", "user_id", "order_id", "invoice_id",
                     "account_id"], discovered_by="http_probe")
                return ToolResult(tool=self.name, ok=True, data={"status": 200})

        seed_run = _RichSeed()
        run = self._run([seed_run, _SqliHit()], max_steps=60, max_time_s=30.0)
        self.assertEqual(run.summary.mode, "offensive")
        entries = run.audit.entries
        kinds = [e["kind"] for e in entries]

        # (a) finding pemicu tercatat sebelum hypothesis-opened
        fc = kinds.index("finding-candidate")
        opened_at = [i for i, e in enumerate(entries)
                     if e["kind"] == "hypothesis-opened"]
        self.assertTrue(opened_at and all(i > fc for i in opened_at),
                        "hypothesis-opened harus tercatat SETELAH finding")
        opened_ids = {entries[i].get("id") for i in opened_at}
        self.assertTrue(any(i.startswith("H-react-") for i in opened_ids),
                        f"harus membuka H-react-*; dapat {opened_ids}")

        # (b) urutan: tool-run pertama SETELAH finding adalah langkah follow-up
        # reaktif (param yang TIDAK termasuk params[:4] rencana statis)
        reactive_params = {"invoice_id", "account_id"}
        post = [e for e in entries[fc + 1:] if e["kind"] == "tool-run"]
        self.assertTrue(post, "harus ada eksekusi tool setelah finding")
        first_post = post[0]
        self.assertEqual(first_post["tool"], "sqli_probe")
        self.assertIn(first_post["args"]["param"], reactive_params,
                      f"langkah pertama pasca-finding harus follow-up reaktif; "
                      f"dapat {first_post['args']}")
        # kedua follow-up reaktif juga dieksekusi
        executed_reactive = {e["args"]["param"] for e in post
                             if e["tool"] == "sqli_probe"
                             and e["args"]["param"] in reactive_params}
        self.assertEqual(executed_reactive, reactive_params)

        # (c) summary melebihi langkah statis minimum: ada eksekusi tambahan
        # akibat re-plan (>= 2 follow-up reaktif + langkah statis)
        self.assertGreater(run.summary.steps_executed, 10)

        # (d) event + ledger + audit
        hids = [e["hypothesis_id"] for e in run.world.replan_events]
        self.assertEqual(len(hids), len(set(hids)))
        total = sum(v["allocated"] for v in run.world.budget_ledger.values())
        self.assertLessEqual(total, BUDGET)
        ok, note = run.audit.verify()
        self.assertTrue(ok, note)

    def test_reactive_steps_lead_next_planner_plan(self):
        """Level planner: langkah H-react-* harus memimpin plan() berikutnya.
        EV H-react-exploit 3.4 = tertinggi tunggal; H-react-deep 3.2 > probe
        H-params statis 2.85. (Catatan: temuan pada param 'id' akan menaikkan
        H-idor menjadi 3.8 sehingga id_seq memimpin — perilaku desain yang
        benar; test ini memakai param 'q' agar tidak menaikkan H-idor.)"""
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        p.observe_findings([_finding(url=f"{BASE}/item?q=1", param="q")])
        steps = p.plan(w)
        self.assertEqual(steps[0].tool, "exploitability")
        self.assertEqual(steps[0].hypothesis_id, "H-react-exploit")
        deep = [s for s in steps if s.hypothesis_id == "H-react-deep-sqli_probe"]
        self.assertEqual([s.args["param"] for s in deep],
                         ["account_id", "invoice_id"])
        i_deep = steps.index(deep[0])
        i_xss = next(i for i, s in enumerate(steps) if s.tool == "xss_probe")
        self.assertLess(i_deep, i_xss,
                        "follow-up reaktif harus melompati probe statis "
                        "ber-EV lebih rendah")


class TestEvOrderRegression(unittest.TestCase):
    """Butir 8: determinisme EV-order di bawah tekanan state & urutan insert."""

    def test_plan_three_times_identical_on_same_planner(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        s1 = [_step_key(s) for s in p.plan(w)]
        s2 = [_step_key(s) for s in p.plan(w)]
        s3 = [_step_key(s) for s in p.plan(w)]
        self.assertEqual(s1, s2)
        self.assertEqual(s2, s3)

    def test_plan_stays_identical_after_observe_state_grows(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _world(six_params=True)
        p.plan(w)
        p.observe_findings([_finding(url=f"{BASE}/item?id=1", param="id")])
        base = [_step_key(s) for s in p.plan(w)]
        for _ in range(2):
            self.assertEqual([_step_key(s) for s in p.plan(w)], base)
        # EV-desc tetap terjaga setelah state tumbuh
        evs = [_ev_of(s, p.budget_ledger()) for s in p.plan(w)]
        self.assertEqual(evs, sorted(evs, reverse=True))

    def test_insertion_order_variants_keep_ev_desc_and_step_set(self):
        """Dua world secara logis identik (hanya beda urutan insert dict
        endpoints): EV-desc WAJIB tetap terjaga dan HIMPUAN langkah sama."""
        PHW = _PHASE_WEIGHT

        def build(order: str):
            w = WorldModel(target=BASE + "/", mode="offensive")
            eps = [(BASE + "/a", ["sort", "filter"]),
                   (BASE + "/b", ["page", "limit"]),
                   (BASE + "/c", ["id", "uid"])]
            if order == "reversed":
                eps.reverse()
            for url, params in eps:
                w.observe_endpoint(url, params, discovered_by="crawler")
            return w

        plans = []
        for order in ("normal", "reversed"):
            p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
            steps = p.plan(build(order))
            ledger = p.budget_ledger()
            evs = [_ev_of(s, ledger) for s in steps]
            self.assertEqual(evs, sorted(evs, reverse=True),
                             f"EV-desc rusak pada varian insert {order}")
            plans.append({_step_key(s) for s in steps})
        self.assertEqual(plans[0], plans[1],
                         "himpunan langkah harus sama untuk world logis sama")

    def test_step_sequence_independent_of_endpoint_insertion_order(self):
        """SUDAH DIPERBAIKI: tie-break EV kini deterministik pada
        (tool, url, param) di planner._ev_key sehingga dua world logis
        identik menghasilkan SEKUENS plan() identik, tak peduli urutan
        insert dict world.endpoints."""
        def build(order: str):
            w = WorldModel(target=BASE + "/", mode="offensive")
            eps = [(BASE + "/a", ["sort", "filter"]),
                   (BASE + "/b", ["page", "limit"]),
                   (BASE + "/c", ["id", "uid"])]
            if order == "reversed":
                eps.reverse()
            for url, params in eps:
                w.observe_endpoint(url, params, discovered_by="crawler")
            return w

        seqs = []
        for order in ("normal", "reversed"):
            p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
            seqs.append([_step_key(s) for s in p.plan(build(order))])
        self.assertEqual(seqs[0], seqs[1],
                         "sekuens plan harus independen dari urutan insert dict")


if __name__ == "__main__":
    unittest.main()
