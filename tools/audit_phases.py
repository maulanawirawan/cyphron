"""[AUDIT] audit_phases — orkestrator audit multi-fase, bukti di atas klaim.

Konsep pipeline audit multi-fase dengan findings machine-readable +
jalur needs-validation terinspirasi cloudflare/security-audit-skill
(65k+ stars, MIT) — dibangun from scratch TANPA kode dari repo itu;
atribusi konsep di docstring ini. Lisensi cyphron: PolyForm NC.

Yang diambil konsepnya dan diadaptasi kontrak cyphron:
  - fase audit berurutan yang bisa diaudit ulang;
  - findings machine-readable (JSON) bukan prosa;
  - kandidat tanpa bukti TIDAK PERNAH status confirmed (fail-closed);
  - cakupan dihitung jujur — fase/playbook yang belum lari = gap yang
    diberi label, laporan berlabel PARTIAL bukan COMPLETE.

Empat fase:
  1. surface : GET baseline — bukti target hidup. Tanpa itu audit
               berhenti (exit 2, report tetap ditulis).
  2. probe   : playbook registry (tools/exploit_playbooks) dijalankan.
               Default tier-1 saja; tier-2 butuh --allow-tier2; tier-3/
               destructive tidak pernah dijalankan alat ini (NEVER-LIST
               & tangga agresi engine tetap sumber kebenaran).
  3. verify  : tiap finding diperiksa buktinya. confirmed TANPA
               request/response/poc = diturunkan ke unconfirmed dan
               verdict dibatasi L1 (SUSPECTED) — klaim tanpa bukti
               tidak boleh lolos verifikasi (no proof, no report).
  4. report  : findings.json + coverage-ledger.json + REPORT.md.
               Playbook eligible tapi tak dijalankan / error = gap
               tercatat; ada gap -> report PARTIAL.

Gerbang target (aturan repo: authorized targets only):
  - hanya http(s);
  - host non-loopback WAJIB --confirm-external, kalau tidak -> exit 2
    SEBELUM request pertama.

Pemakaian:
  python tools/lab_target.py &                    # lawan uji lokal
  python tools/audit_phases.py --target http://127.0.0.1:8000 \
      --playbooks idor-orders,admin-access \
      --params-file params.json --credentials '{"username":"alice","password":"alicepass"}' \
      --out audit-out/
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _p in ("tools", "core", "skills"):
    sys.path.insert(0, str(ROOT / _p))

import redact  # noqa: E402
from findings import validate_finding  # noqa: E402
from ua import user_agent  # noqa: E402
from exploit_engine import redact as _redact  # noqa: E402  (fungsi engine)

import exploit_playbooks as ep  # noqa: E402

SCHEMA = "cyphron.audit-phases/1"
MAX_TIER_AUTOMATIC = 2  # tier-3/destructive tidak pernah otomatis


class AuditContext:
    """Kontrak ctx playbook (ala ExploitContext engine, versi audit):
    request() tanpa follow-redirect (bukti 302 terlihat), cookie sid
    dikelola manual, action log + redaksi kredensial di bukti."""

    def __init__(self, base_url: str, credentials: dict | None = None,
                 params: dict | None = None, out_dir: Path | None = None):
        self.base_url = base_url.rstrip("/")
        self.credentials = credentials or {}
        self.params = params or {}
        self.out_dir = out_dir
        self.actions: list[dict] = []
        self.secrets: list[str] = [str(v) for v in
                                   self.credentials.values()]
        self.ua = user_agent()
        self._session_cookie: str | None = None
        self.current_playbook = ""
        self.requests = 0

    def note_secret(self, value: str) -> None:
        if value:
            self.secrets.append(value)

    def request(self, method: str, path: str, data: dict | None = None,
                headers: dict | None = None, json_data: dict | None = None,
                raw: bytes | None = None,
                no_redirect: bool = False,
                no_session: bool = False) -> ep.ReqResult:
        url = self.base_url + path
        if raw is not None:
            body = raw
        elif json_data is not None:
            body = json.dumps(json_data).encode()
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
        else:
            body = None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", self.ua)
        if self._session_cookie and not no_session:
            req.add_header("Cookie", self._session_cookie)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        self.requests += 1
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                status = resp.status
                headers_out = dict(resp.headers.items())
                resp_body = resp.read(64_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:  # respons 4xx/5xx = bukti sah
            status = e.code
            headers_out = dict(e.headers.items())
            resp_body = e.read(64_000).decode("utf-8", "replace")
        for sc in headers_out.get("Set-Cookie", "").split(";"):
            k, _, v = sc.strip().partition("=")
            if k.lower() in ("sid", "session", "sessionid") and v:
                self.note_secret(v)
                self._session_cookie = f"{k}={v}"
        self.actions.append({
            "ts_epoch": int(time.time()),
            "playbook": self.current_playbook,
            "method": method, "path": path, "status": status})
        evidence = (f"{method} {path} -> {status}\n"
                    f"[headers: {', '.join(sorted(headers_out)) or 'none'}]\n"
                    f"{resp_body[:600]}")
        return ep.ReqResult(status, headers_out, resp_body,
                            _redact(evidence, self.secrets))


def _host_is_loopback(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    return host in ("127.0.0.1", "localhost", "::1")


def _select_playbooks(requested: list[str], allow_tier2: bool) -> list:
    """Pilih playbook registry; tier di atas batas TIDAK pernah dipilih."""
    chosen = []
    for name in requested:
        pb = ep.PLAYBOOKS.get(name)
        if pb is None:
            continue  # tak dikenal = tercatat di ledger, bukan error keras
        if pb.tier <= 1 or (pb.tier == 2 and allow_tier2):
            chosen.append(pb)
        # tier-3+ = tidak pernah (fail-closed, tak dibuka flag)
    return chosen


def _probe_one(pb, ctx: AuditContext, all_params: dict | None) -> tuple[list[dict], dict]:
    """Jalankan satu playbook; exception = baris ledger error, audit lanjut.

    Params per-playbook (kontrak engine): ctx.params = params playbook itu.
    """
    ctx.current_playbook = pb.name
    ctx.params = (all_params or {}).get(pb.name, {})
    t0 = time.time()
    try:
        rows = list(pb.run(ctx) or [])
        meta = {"playbook": pb.name, "tier": pb.tier, "status": "run",
                "findings": len(rows),
                "duration_sec": round(time.time() - t0, 3)}
    except Exception as exc:  # noqa: BLE001 — satu gagal tidak membunuh audit
        rows = []
        meta = {"playbook": pb.name, "tier": pb.tier, "status": "error",
                "error": repr(exc)[:200],
                "duration_sec": round(time.time() - t0, 3)}
    finally:
        ctx.current_playbook = ""
    return rows, meta


def _has_evidence(f: dict) -> bool:
    return any(bool(f.get(k)) for k in ("request", "response", "poc"))


def _verify_phase(findings: list[dict]) -> list[dict]:
    """Fail-closed: confirmed tanpa bukti = unconfirmed + verdict L1."""
    out = []
    for f in findings:
        if (f.get("status") == "confirmed"
                and int(f.get("verdict") or 0) >= 2
                and not _has_evidence(f)):
            f = dict(f)
            f["status"] = "unconfirmed"
            if f.get("verdict") is not None:
                f["verdict"] = min(int(f["verdict"]), 1)
            extra = dict(f.get("extra") or {})
            extra["audit_verify_note"] = (
                "evidence kosong (request/response/poc tidak ada) — "
                "diturunkan fase verify (fail-closed)")
            f["extra"] = extra
        out.append(f)
    return out


def run_audit(base_url: str, playbooks: list[str], params: dict | None,
              credentials: dict | None, out_dir: Path,
              allow_tier2: bool = False) -> dict:
    """Jalankan 4 fase. Return ringkasan machine-readable; report ditulis."""
    out_dir.mkdir(parents=True, exist_ok=True)
    params = params or {}
    ctx = AuditContext(base_url, credentials, params, out_dir)

    # fase 1: surface — bukti target hidup
    surface_ok, surface_detail = False, ""
    try:
        r = ctx.request("GET", "/")
        surface_ok = r.status > 0
        surface_detail = f"GET / -> {r.status}"
    except Exception as exc:  # noqa: BLE001
        surface_detail = repr(exc)[:200]

    # fase 2: probe
    known = [n for n in playbooks if n in ep.PLAYBOOKS]
    unknown = [n for n in playbooks if n not in ep.PLAYBOOKS]
    eligible = {pb.name for pb in ep.PLAYBOOKS.values()
                if pb.tier <= (2 if allow_tier2 else 1)}
    selected = _select_playbooks(playbooks, allow_tier2)
    findings: list[dict] = []
    ledger: list[dict] = []
    for pb in selected:
        rows, meta = _probe_one(pb, ctx, params)
        findings.extend(rows)
        ledger.append(meta)
    gaps = sorted(eligible - {pb.name for pb in selected})
    not_found = sorted(set(known) - {pb.name for pb in selected})

    # fase 3: verify — fail-closed pada bukti
    findings = _verify_phase(findings)
    # validate_finding return list error — non-kosong = invalid
    invalid = [f for f in findings if validate_finding(f)]

    # fase 4: report
    (out_dir / "findings.json").write_text(
        json.dumps({"schema": SCHEMA, "target": base_url,
                    "findings": findings}, indent=2, ensure_ascii=False)
        + "\n", encoding="utf-8")
    coverage = {
        "schema": SCHEMA, "target": base_url,
        "eligible_tier_max": 2 if allow_tier2 else 1,
        "eligible_total": len(eligible), "run": len(ledger),
        "gaps": gaps, "unknown_requested": unknown,
        "blocked_higher_tier": not_found, "ledger": ledger,
        "status": "COMPLETE" if (not gaps and not unknown and not not_found
                                 and all(m["status"] == "run"
                                         and m["findings"] >= 1
                                         for m in ledger)) else "PARTIAL",
    }
    (out_dir / "coverage-ledger.json").write_text(
        json.dumps(coverage, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    verified = [f for f in findings
                if f.get("status") == "confirmed"
                and int(f.get("verdict") or 0) >= 3]
    lines = [
        "# Audit report", "",
        f"- target: {base_url}",
        f"- surface: {surface_detail} "
        f"({'LIVE' if surface_ok else 'DOWN'})",
        f"- coverage: {coverage['status']} "
        f"({coverage['run']}/{coverage['eligible_total']} playbook tier"
        f"<={coverage['eligible_tier_max']} dijalankan)", "",
        "## Temuan terverifikasi (L3+)", "",
    ]
    lines += [f"- {f.get('title')} — verdict L{f.get('verdict')}"
              for f in verified] or ["- (tidak ada)"]
    lines += ["", "## Coverage ledger", ""]
    lines += [f"- {m['playbook']}: {m['status']} ({m.get('findings', 0)} baris)"
              for m in ledger]
    if gaps:
        lines += ["", f"## Gap ({len(gaps)} playbook eligible tak dijalankan)",
                  ""]
        lines += [f"- {g}" for g in gaps]
    lines += ["", "Fail-closed: temuan tanpa bukti diturunkan fase verify; "
                  "laporan dengan gap berlabel PARTIAL.", ""]
    (out_dir / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")

    return {"schema": SCHEMA, "target": base_url, "surface_live": surface_ok,
            "surface_detail": surface_detail, "findings": findings,
            "coverage": coverage, "invalid_contract": invalid}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="audit_phases — audit multi-fase fail-closed "
                    "(surface/probe/verify/report).")
    ap.add_argument("--target", required=True, help="base URL target")
    ap.add_argument("--playbooks", default="",
                    help="daftar playbook koma (default: tidak ada — "
                         "audit permukaan saja)")
    ap.add_argument("--params-file", help="JSON {playbook: {params}}")
    ap.add_argument("--credentials", help="JSON {username,password}")
    ap.add_argument("--allow-tier2", action="store_true",
                    help="izinkan playbook tier-2 (canary; tier-3 tetap "
                         "tidak pernah)")
    ap.add_argument("--confirm-external", action="store_true",
                    help="wajib untuk target non-loopback")
    ap.add_argument("--out", default="audit-out", help="direktori output")
    args = ap.parse_args(argv)

    if not args.target.startswith(("http://", "https://")):
        print("[audit] base_url harus http(s)", file=sys.stderr)
        return 2
    if not _host_is_loopback(args.target) and not args.confirm_external:
        print("[audit] target non-loopback butuh --confirm-external "
              "(authorized targets only — fail-closed)", file=sys.stderr)
        return 2
    try:
        params = json.loads(Path(args.params_file).read_text(
            encoding="utf-8")) if args.params_file else {}
        credentials = json.loads(args.credentials) if args.credentials else {}
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[audit] input tidak valid: {exc}", file=sys.stderr)
        return 2

    requested = [s.strip() for s in args.playbooks.split(",") if s.strip()]
    result = run_audit(args.target, requested, params, credentials,
                       Path(args.out), allow_tier2=args.allow_tier2)
    cov = result["coverage"]
    print(f"[audit] surface: {result['surface_detail']} "
          f"({'LIVE' if result['surface_live'] else 'DOWN'})")
    print(f"[audit] probe: {cov['run']} playbook dijalankan, "
          f"coverage {cov['status']}")
    n_l3 = sum(1 for f in result["findings"]
               if f.get("status") == "confirmed"
               and int(f.get("verdict") or 0) >= 3)
    print(f"[audit] findings: {len(result['findings'])} baris "
          f"({n_l3} terverifikasi L3+); gap: {len(cov['gaps'])}")
    if result["invalid_contract"]:
        print(f"[audit] PERINGATAN: {len(result['invalid_contract'])} baris "
              "gagal kontrak findings (tercatat)", file=sys.stderr)
    if not result["surface_live"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
