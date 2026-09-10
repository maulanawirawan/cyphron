"""Acceptance test FAZ 2 — Adaptive Planner v2.

Kontrak yang diuji (re-plan setelah temuan + budget allocation + EV ordering):
- DeterministicPlanner menerima ``request_budget`` dan punya ``observe_findings()``
  serta ``budget_ledger()``.
- Step bertambah field ``cost`` (default 1) dan ``hypothesis_id`` (default "").
- Re-plan dalam satu run: Finding (mis. sqli critical/high) membuka hipotesis
  reaktif ber-id "H-react-*", plan() berikutnya menjadwalkan langkah untuk
  hipotesis tersebut, dan world.replan_events terisi.
- Budget: jumlah allocated <= request_budget; hipotesis yang masih punya
  langkah dapat allocated >= 1; temuan CONFIRMED menaikkan confidence dan
  membesarkan alokasi hipotesis terkait pada plan() berikutnya.
- plan() diurutkan expected-value descending (impact*confidence/cost) dan
  deterministik.
- World kaya param vs world polos menghasilkan himpunan langkah berbeda; tiap
  langkah punya rationale dan hypothesis_id tidak semuanya kosong.
- Orchestrator memanggil planner.observe_findings saat step menghasilkan
  findings dan mencatat kind="hypothesis-opened" pada audit log.
- Reporting menampilkan kolom confidence/budget pada baris hipotesis dan tabel
  re-plan tetap punya baris placeholder saat kosong.

Semua test offline dan deterministik: WorldModel sintetis, tool palsu (tanpa
jaringan), target port mati bila perlu URL nyata.
"""

from __future__ import annotations

import json
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
BUDGET = 400
_SEV_CONFIDENCE = {"critical": 0.95, "high": 0.8, "medium": 0.5, "low": 0.3}


# ---------------------------------------------------------------- helpers ---

def _param_world() -> WorldModel:
    """World kaya param: endpoint ?id=&limit=&sort= + form login (POST)."""
    w = WorldModel(target=BASE + "/", mode="offensive")
    w.endpoints = {
        BASE + "/": Endpoint(url=BASE + "/", status=200, method="GET",
                             params=["id", "limit", "sort"]),
        BASE + "/login": Endpoint(url=BASE + "/login", status=200, method="POST",
                                  form_fields=["username", "password"]),
    }
    return w


def _plain_world() -> WorldModel:
    """World polos: hanya endpoint statis tanpa parameter."""
    w = WorldModel(target=BASE + "/", mode="offensive")
    w.endpoints = {
        BASE + "/about": Endpoint(url=BASE + "/about", status=200, method="GET"),
    }
    return w


def _sqli_finding(severity: str, url: str, param: str,
                  title: str = "SQL injection (error-based)") -> Finding:
    """Finding sqli sintetis; confidence mengikuti severity (bukti CONFIRMED)."""
    return Finding(
        tool="sqli_probe", title=title, severity=severity,
        description="database error terpicu payload injeksi (fixture uji)",
        target_url=url, param=param,
        confidence=_SEV_CONFIDENCE[severity], status="confirmed",
        evidence_kind="request-response",
        request=f"GET {url}?{param}=1' HTTP/1.1",
        response="HTTP/1.1 500 SQLiteException: incomplete input",
    )


def _key(step: Step) -> tuple:
    return (step.tool, json.dumps(step.args, sort_keys=True))


def _ev(step: Step, ledger: dict) -> float:
    """Expected value langkah = impact * confidence / cost (dari ledger)."""
    row = ledger.get(getattr(step, "hypothesis_id", ""))
    if not row:
        return 0.0
    cost = max(1, int(getattr(step, "cost", 1) or 1))
    return (float(row.get("impact", 0)) * float(row.get("confidence", 0))) / cost


def _cells(section: dict) -> str:
    return " | ".join(" | ".join(str(c) for c in row)
                      for row in (section.get("rows") or []))


def _report_world(with_events: bool) -> WorldModel:
    """World sintetis untuk reporting: hipotesis + ledger FAZ 2 terisi."""
    w = WorldModel(target=BASE + "/", mode="read-only")
    w.endpoints = {
        BASE + "/item": Endpoint(url=BASE + "/item", status=200, method="GET",
                                 params=["id"]),
    }
    w.hypotheses = [{
        "id": "H-params",
        "claim": "Parameter query membuka surface uji",
        "evidence": "endpoint berparameter teramati",
        "decision": "jadwalkan uji parameter",
        "status": "CONFIRMED",
        "confidence": 0.8,
        "impact": 3,
        "budget_requests": 200,
    }]
    w.budget_ledger = {"H-params": {
        "claim": "Parameter query membuka surface uji",
        "confidence": 0.8, "impact": 3, "allocated": 150, "spent": 40,
        "status": "CONFIRMED",
    }}
    w.findings_seen = []
    w.replan_events = ([{
        "step": 2, "trigger": "finding-candidate",
        "hypothesis_id": "H-react-sqli-1", "hypothesis": "H-react-sqli-1",
        "tool": "sqli_probe", "detail": "sqli terkonfirmasi pada parameter id",
    }] if with_events else [])
    return w


def _report_summary() -> ScanSummary:
    return ScanSummary(target=BASE + "/", mode="read-only", steps_executed=3,
                       elapsed_s=1.0)


def _report_doc(w: WorldModel) -> dict:
    opts = ScanOptions(target=BASE + "/")
    s = _report_summary()
    audit = AuditLog()
    blocks = reporting._build_blocks(opts, s, w, audit)
    return reporting._build_doc(opts, s, w, audit, blocks)


# ------------------------------------------------------------------ tests ---

class TestApiContract(unittest.TestCase):
    """Kontrak 1: signature baru planner, Step, ledger, world, hipotesis."""

    def test_planner_accepts_request_budget(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        self.assertIsNotNone(p)
        # pemanggil lama tanpa request_budget tetap harus jalan
        self.assertIsNotNone(DeterministicPlanner(offensive_allowed=False))

    def test_step_has_cost_and_hypothesis_id(self):
        s = Step(tool="sqli_probe", args={"url": BASE + "/"},
                 rationale="uji param", phase="active-testing")
        self.assertEqual(s.cost, 1, "default cost harus 1")
        self.assertEqual(s.hypothesis_id, "", "default hypothesis_id kosong")
        s2 = Step(tool="x", args={}, rationale="r", phase="recon",
                  cost=3, hypothesis_id="H-params")
        self.assertEqual((s2.cost, s2.hypothesis_id), (3, "H-params"))

    def test_budget_ledger_exists_and_shape(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _param_world()
        p.plan(w)
        ledger = p.budget_ledger()
        self.assertIsInstance(ledger, dict)
        self.assertTrue(ledger, "ledger harus berisi hipotesis setelah plan()")
        for hid, row in ledger.items():
            self.assertTrue(str(hid), "key ledger harus berupa id hipotesis")
            for key in ("claim", "confidence", "impact", "allocated", "spent",
                        "status"):
                self.assertIn(key, row, f"ledger[{hid}] kurang key '{key}'")
            self.assertGreaterEqual(float(row["confidence"]), 0.0)
            self.assertLessEqual(float(row["confidence"]), 1.0)
            self.assertGreaterEqual(int(row["allocated"]), 0)
            self.assertGreaterEqual(int(row["spent"]), 0)

    def test_world_model_has_faz2_fields(self):
        w = WorldModel()
        for f in ("findings_seen", "replan_events", "budget_ledger"):
            self.assertTrue(hasattr(w, f), f"WorldModel harus punya field '{f}'")

    def test_hypotheses_carry_confidence_impact_budget(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _param_world()
        p.plan(w)
        self.assertTrue(w.hypotheses)
        for h in w.hypotheses:
            for key in ("id", "claim", "evidence", "decision", "status"):
                self.assertIn(key, h, f"hipotesis {h.get('id')} kehilangan '{key}'")
            self.assertIn("confidence", h)
            self.assertIn("impact", h)
            self.assertIn("budget_requests", h)
            self.assertGreaterEqual(float(h["confidence"]), 0.0)
            self.assertLessEqual(float(h["confidence"]), 1.0)
            if h.get("status") == "REJECTED":
                self.assertGreaterEqual(int(h["impact"]), 0)
            else:
                self.assertGreaterEqual(int(h["impact"]), 1)
                self.assertLessEqual(int(h["impact"]), 4)
            self.assertGreaterEqual(int(h["budget_requests"]), 0)


class TestReplanInRun(unittest.TestCase):
    """Kontrak 2: temuan -> hipotesis reaktif H-react-* -> langkah + event."""

    def test_confirmed_finding_opens_reactive_hypothesis(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _param_world()
        p.plan(w)
        f = _sqli_finding("critical", BASE + "/?id=1", "id")
        opened = p.observe_findings([f])
        self.assertIsInstance(opened, list)
        self.assertGreaterEqual(len(opened), 1,
                                "temuan sqli critical harus membuka hipotesis reaktif")
        for h in opened:
            self.assertIsInstance(h, dict)
            self.assertTrue(str(h.get("id", "")).startswith("H-react-"),
                            f"id hipotesis reaktif harus H-react-*, dapat: {h.get('id')!r}")
            self.assertTrue(str(h.get("claim", "")).strip(),
                            "hipotesis reaktif harus punya claim")
        # temuan yang sama dipanggil ulang tidak boleh membuka hipotesis baru
        again = p.observe_findings([f])
        self.assertEqual(again, [],
                         f"temuan duplikat tidak boleh membuka hipotesis baru; dapat {again}")
        # input kosong tetap kosong
        self.assertEqual(p.observe_findings([]), [])

    def test_next_plan_schedules_reactive_step_and_records_event(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _param_world()
        p.plan(w)
        opened = p.observe_findings(
            [_sqli_finding("high", BASE + "/?id=1", "id")])
        self.assertTrue(opened)
        ids = {h["id"] for h in opened}
        steps = p.plan(w)
        served = [s for s in steps if getattr(s, "hypothesis_id", "") in ids]
        self.assertTrue(
            served,
            f"plan() berikutnya harus menjadwalkan langkah untuk {ids}; dapat "
            f"{[(s.tool, getattr(s, 'hypothesis_id', '')) for s in steps]}")
        self.assertTrue(getattr(w, "replan_events", None),
                        "world.replan_events harus terisi setelah re-plan")


class TestBudgetAllocation(unittest.TestCase):
    """Kontrak 3: alokasi anggaran per hipotesis dari request_budget."""

    def test_allocation_within_budget_and_served_get_at_least_one(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _param_world()
        steps = p.plan(w)
        ledger = p.budget_ledger()
        total = sum(int(r["allocated"]) for r in ledger.values())
        self.assertLessEqual(total, BUDGET,
                             f"jumlah allocated ({total}) melebihi request_budget ({BUDGET})")
        served = {getattr(s, "hypothesis_id", "") for s in steps
                  if getattr(s, "hypothesis_id", "")}
        self.assertTrue(served, "plan() harus melayani minimal satu hipotesis ber-id")
        for hid in served:
            self.assertIn(hid, ledger,
                          f"hipotesis terlayani '{hid}' harus ada di ledger")
            self.assertGreaterEqual(
                int(ledger[hid]["allocated"]), 1,
                f"hipotesis '{hid}' masih punya langkah -> allocated >= 1")

    def test_confirmed_findings_raise_confidence_then_allocation(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _param_world()
        p.plan(w)
        base = p.budget_ledger()
        p.observe_findings([_sqli_finding("critical", BASE + "/?id=1", "id")])
        p.plan(w)
        l1 = p.budget_ledger()
        self.assertLessEqual(
            sum(int(r["allocated"]) for r in l1.values()), BUDGET)
        rose = [h for h in l1
                if (h not in base and float(l1[h]["confidence"]) > 0)
                or (h in base and float(l1[h]["confidence"]) > float(base[h]["confidence"]))]
        self.assertTrue(
            rose,
            "confidence minimal satu hipotesis harus naik setelah temuan "
            f"CONFIRMED; base={base} after={l1}")
        # temuan kedua (bukti lebih kuat) -> confidence naik lagi -> alokasi membesar
        p.observe_findings([_sqli_finding(
            "critical", BASE + "/?uid=2", "uid",
            title="SQL injection (union-based)")])
        p.plan(w)
        l2 = p.budget_ledger()
        self.assertLessEqual(
            sum(int(r["allocated"]) for r in l2.values()), BUDGET)
        grew = [h for h in l2 if h in l1
                and int(l2[h]["allocated"]) > int(l1[h]["allocated"])]
        self.assertTrue(
            grew,
            "allocated hipotesis yang confidence-nya naik harus membesar pada "
            f"plan() berikutnya; l1={l1} l2={l2}")


class TestEvOrdering(unittest.TestCase):
    """Kontrak 4: plan() urut EV descending dan deterministik."""

    def test_served_steps_ordered_by_expected_value(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=BUDGET)
        w = _param_world()
        p.plan(w)
        opened = p.observe_findings([
            _sqli_finding("critical", BASE + "/?id=1", "id"),
            _sqli_finding("medium", BASE + "/?sort=x", "sort"),
        ])
        self.assertGreaterEqual(len(opened), 1)
        steps = p.plan(w)
        ledger = p.budget_ledger()
        served = [s for s in steps if getattr(s, "hypothesis_id", "") in ledger]
        hyps = {s.hypothesis_id for s in served}
        self.assertGreaterEqual(
            len(hyps), 2,
            f"butuh >= 2 hipotesis terlayani untuk menguji urutan EV; dapat {hyps}")
        active = [s for s in served if s.phase == "active-testing"]
        pool = active if len({s.hypothesis_id for s in active}) >= 2 else served
        evs = [_ev(s, ledger) for s in pool]
        self.assertEqual(
            evs, sorted(evs, reverse=True),
            "langkah terlayani harus urut EV descending; dapat: "
            + str([(s.tool, s.hypothesis_id, round(e, 3))
                   for s, e in zip(pool, evs)]))

    def test_plan_deterministic_across_calls(self):
        steps1 = DeterministicPlanner(
            offensive_allowed=True, request_budget=BUDGET).plan(_param_world())
        steps2 = DeterministicPlanner(
            offensive_allowed=True, request_budget=BUDGET).plan(_param_world())
        self.assertEqual([_key(s) for s in steps1], [_key(s) for s in steps2])
        self.assertEqual([s.hypothesis_id for s in steps1],
                         [s.hypothesis_id for s in steps2])
        self.assertEqual([s.cost for s in steps1], [s.cost for s in steps2])
        self.assertEqual(steps1, steps2, "plan() harus deterministik penuh")


class TestAdaptivePlans(unittest.TestCase):
    """Kontrak 5: world berbeda -> rencana berbeda & dapat dijelaskan."""

    def test_param_rich_vs_plain_world_plan_differently(self):
        plan_a = DeterministicPlanner(
            offensive_allowed=True, request_budget=BUDGET).plan(_param_world())
        plan_b = DeterministicPlanner(
            offensive_allowed=True, request_budget=BUDGET).plan(_plain_world())
        keys_a = {_key(s) for s in plan_a}
        keys_b = {_key(s) for s in plan_b}
        self.assertNotEqual(keys_a, keys_b,
                            "world kaya param vs polos harus menghasilkan rencana berbeda")
        tools_a = {s.tool for s in plan_a}
        tools_b = {s.tool for s in plan_b}
        self.assertIn("sqli_probe", tools_a)
        self.assertNotIn("sqli_probe", tools_b,
                         "world tanpa parameter tidak boleh menjadwalkan sqli_probe")
        self.assertTrue(tools_a - tools_b,
                        "world kaya param harus menambah langkah yang tidak ada di world polos")

    def test_every_step_has_rationale_and_hypothesis_not_all_empty(self):
        for world_fn in (_param_world, _plain_world):
            with self.subTest(world=world_fn.__name__):
                steps = DeterministicPlanner(
                    offensive_allowed=True,
                    request_budget=BUDGET).plan(world_fn())
                self.assertTrue(steps)
                for s in steps:
                    self.assertTrue(str(s.rationale).strip(),
                                    f"step '{s.tool}' tanpa rationale")
                self.assertTrue(
                    any(getattr(s, "hypothesis_id", "") for s in steps),
                    "minimal satu langkah harus punya hypothesis_id terisi")


# ------------------------------------------------- orchestrator integration --

AUTH_DOC = {
    "id": "AUTH-FAZ2-1",
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2030-01-01T00:00:00Z",
    "target": {"name": "fixture-faz2"},
    "scope": {
        "targets": ["localhost", "127.0.0.1"],
        "excluded": [],
        "cidr": ["127.0.0.0/8"],
        "ports": [],
    },
    "authorized_by": {"name": "tester"},
    "restrictions": ["no_dos", "no_data_exfiltration", "no_persistence"],
    "signature": "test-sig",
}

DEAD_TARGET = "http://127.0.0.1:1/"  # port mati; tidak ada koneksi nyata dibuat


class _SeedingHttpProbe(Tool):
    """Fake http_probe: menanam endpoint berparam ke world (tanpa jaringan)."""

    name = "http_probe"
    description = "fake probe yang men-seed world model"
    risk_tags = {"passive"}

    def run(self, args, ctx):
        ctx.world.observe_response(ctx.world.target or DEAD_TARGET, 200, {},
                                   "<html>fixture</html>", "http_probe")
        ctx.world.observe_endpoint(DEAD_TARGET + "?id=1", ["id"],
                                   discovered_by="http_probe")
        return ToolResult(tool=self.name, ok=True, data={"status": 200})


class _FakeSqliProbe(Tool):
    """Fake sqli_probe: selalu mengembalikan satu temuan critical."""

    name = "sqli_probe"
    description = "fake sqli probe untuk uji re-plan"
    risk_tags = {"active"}

    def run(self, args, ctx):
        f = Finding(
            tool="sqli_probe", title="SQL injection (error-based)",
            severity="critical",
            description="injeksi terkonfirmasi pada fixture palsu",
            target_url=args.get("url"), param=args.get("param"),
            confidence=0.95, status="confirmed",
            evidence_kind="request-response",
            request=f"GET {args.get('url')}?{args.get('param')}=1' HTTP/1.1",
            response="HTTP/1.1 500 SQLiteException: incomplete input",
        )
        return ToolResult(tool=self.name, ok=True, findings=[f], data={"hits": 1})


class TestOrchestratorIntegration(unittest.TestCase):
    """Kontrak orchestrator: run_scan membuka hipotesis reaktif via audit."""

    def test_run_scan_with_fake_registry_records_hypothesis_opened(self):
        def fake_registry(ctx):
            reg = ToolRegistry(ctx)
            reg.register(_SeedingHttpProbe())
            reg.register(_FakeSqliProbe())
            return reg

        with tempfile.TemporaryDirectory() as td:
            auth_path = Path(td) / "auth.json"
            auth_path.write_text(json.dumps(AUTH_DOC), encoding="utf-8")
            opts = ScanOptions(
                target=DEAD_TARGET, auth_path=auth_path, rate_limit_s=0.0,
                max_steps=60, max_requests=400, max_time_s=30, timeout_s=0.2,
                crawl_pages=3)
            # login tidak pernah dipanggil (tanpa account/accounts), patch saja
            # demi keamanan bila implementasi berubah.
            with mock.patch("cyphron.orchestrator.build_default_registry",
                            fake_registry), \
                 mock.patch("cyphron.tools.auth_login.login", return_value=None):
                run = run_scan(opts, verbose=False)

        self.assertGreater(run.summary.steps_executed, 0,
                           "run harus mengeksekusi minimal satu langkah")
        self.assertEqual(run.summary.mode, "offensive",
                         "dokumen otorisasi sah untuk 127.0.0.1 harus membuka mode offensive")
        kinds = [e["kind"] for e in run.audit.entries]
        self.assertIn("hypothesis-opened", kinds,
                      "run_scan harus mencatat kind='hypothesis-opened' saat step "
                      "menghasilkan findings")
        self.assertTrue(
            any(e["kind"] == "tool-run" and e.get("tool") == "sqli_probe"
                for e in run.audit.entries),
            "fake sqli_probe harus benar-benar dieksekusi lewat registry")
        self.assertGreaterEqual(len(run.summary.confirmed), 1,
                                "temuan confirmed dari fake tool harus lolos verifier")
        self.assertTrue(getattr(run.world, "replan_events", None),
                        "world.replan_events harus terisi saat run menghasilkan temuan")
        ok, note = run.audit.verify()
        self.assertTrue(ok, note)


class TestReportingFaz2(unittest.TestCase):
    """Kontrak 7: blok reporting menampilkan confidence/budget & re-plan."""

    def test_hypothesis_rows_show_confidence_and_budget(self):
        doc = _report_doc(_report_world(with_events=True))
        tables = [s for s in doc.get("sections", []) if s.get("kind") == "table"]
        hyp = [t for t in tables
               if "HIPOTESIS" in str(t.get("title", "")).upper()]
        self.assertTrue(hyp, "harus ada section tabel hipotesis planner")
        rows = hyp[0].get("rows") or []
        row = next((r for r in rows if r and str(r[0]) == "H-params"), None)
        self.assertIsNotNone(row, f"baris H-params harus ada pada tabel; rows={rows}")
        joined = " | ".join(str(c) for c in row)
        self.assertTrue("80%" in joined or "0.8" in joined,
                        f"baris hipotesis harus menampilkan confidence; dapat: {row}")
        self.assertTrue("200" in joined or "150" in joined,
                        f"baris hipotesis harus menampilkan budget/alokasi; dapat: {row}")

    def test_replan_table_placeholder_when_empty(self):
        doc = _report_doc(_report_world(with_events=False))
        tables = [s for s in doc.get("sections", []) if s.get("kind") == "table"]
        self.assertTrue(tables)
        for t in tables:
            self.assertTrue(t.get("rows"),
                            f"tabel '{t.get('title')}' tidak boleh kosong tanpa "
                            "baris placeholder saat re-plan kosong")

    def test_replan_events_rendered_when_present(self):
        doc = _report_doc(_report_world(with_events=True))
        tables = [s for s in doc.get("sections", []) if s.get("kind") == "table"]
        hit = [t for t in tables if "H-react-sqli-1" in _cells(t)]
        self.assertTrue(hit,
                        "event re-plan harus dirender: ada tabel yang barisnya "
                        "memuat id hipotesis reaktif H-react-sqli-1")

    def test_blocks_and_md_render_without_crash(self):
        w = _report_world(with_events=True)
        blocks = reporting._build_blocks(ScanOptions(target=BASE + "/"),
                                         _report_summary(), w, AuditLog())
        md = reporting._render_md(blocks)
        self.assertIsInstance(md, str)
        self.assertTrue(md.strip(), "render markdown tidak boleh kosong")


if __name__ == "__main__":
    unittest.main()
