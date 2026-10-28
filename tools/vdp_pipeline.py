"""[F27] VDP pipeline — pipa recon klasik (subfinder/httpx/katana/dalfox
gaya Kali) di dalam disiplin Cyphron: policy-gated, bounded, zero-FP.

Tahapan per program (programs/index.json):
  enum   — subdomain-enum-surface + ct-inventory (read-only, data
           publik via DoH/CT) -> kandidat host, dipisah nanti
  alive  — SATU GET per kandidat (maks --max-hosts, default 25):
           klasifikasi hidup/mati (padanan httpx) + postur banner
  surf   — SATU GET per host hidup (maks --max-surf, default 10):
           js-endpoints + form/param discovery (padanan katana-lite,
           BUKAN deep crawl)
  xss    — skills/xss_reflect_check.py (padanan dalfox versi marker
           benign, 1 request/param, L2 lead): GATED — wajib
           --scope-ack DAN program accepted=true DAN scope
           mengizinkan (fail-closed; scanner otomatis ke produksi
           umumnya dilarang VDP — cek rules dulu)
  report — paket laporan markdown per program (klasifikasi, bukti,
           kanal lapor dari security.txt / report_channel) + satu
           findings.json gabungan via tools/merge_findings.py

Semua output ke findings/vdp/<program>/<run-id>/. Tanpa --program
dan --domains, tool no-op dengan baris audit (fail-closed, pola
discovery-seeds kosong).
"""
from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT))

from ua import user_agent  # noqa: E402

INDEX = ROOT / "programs" / "index.json"
UA = user_agent()
MAX_HOSTS_DEFAULT = 25
MAX_SURF_DEFAULT = 10
MAX_XSS_PARAMS = 8


def _run_skill(script: str, args: list[str], out: Path,
               timeout: int = 180) -> dict | None:
    """Jalankan skill python (kontrak findings.json). Return doc/None."""
    p = out / f"{Path(script).stem}.findings.json"
    cmd = [sys.executable, str(ROOT / "skills" / script), *args,
           "--out", str(p)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       cwd=str(ROOT))
    if r.returncode != 0 or not p.exists():
        print(f"[vdp] skill {script} gagal rc={r.returncode}: "
              f"{(r.stderr or '')[-200:]}", file=sys.stderr)
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _extract_candidates(doc: dict, domain: str) -> list[str]:
    """Tarik kandidat host dari output skill enum: list JSON di
    response (bentuk skill SURFACE) atau list di meta (hostnames)."""
    cands: list[str] = []
    for f in doc.get("findings", []):
        val = (f.get("response") or "").strip()
        try:
            arr = json.loads(val)
            if isinstance(arr, list):
                cands.extend(str(x).strip().lower() for x in arr)
        except Exception:
            for tok in val.replace(",", " ").split():
                tok = tok.strip().strip("`").lower()
                cands.append(tok)
    data = doc.get("data", {})
    for key in ("hostnames", "subdomains", "candidates"):
        v = data.get(key)
        if isinstance(v, list):
            cands.extend(str(x).strip().lower() for x in v)
    out: list[str] = []
    for c in cands:
        if c.startswith("*.") or not c.endswith(domain):
            continue
        if c not in out:
            out.append(c)
    return out


def _load_program(pid: str) -> dict:
    if not INDEX.exists():
        raise SystemExit(f"programs/index.json tidak ada di {ROOT} — "
                         "daftarkan program dulu (fail-closed)")
    try:
        idx = json.loads(INDEX.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"programs/index.json cacat: {exc} "
                         "(fail-closed)")
    for pr in idx.get("programs", []):
        if pr.get("id") == pid:
            return pr
    raise SystemExit(f"program '{pid}' tidak ada di programs/index.json "
                     "(fail-closed)")


def alive_probe(url: str, timeout: float = 12.0) -> dict:
    """SATU GET per host — klasifikasi hidup/mati + postur minim."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"alive": True, "status": r.status,
                    "server": (r.headers.get("Server") or "")[:80],
                    "content_type": (r.headers.get("Content-Type") or "")[:80],
                    "hsts": bool(r.headers.get("Strict-Transport-Security")),
                    "xfo": bool(r.headers.get("X-Frame-Options")),
                    "csp": bool(r.headers.get("Content-Security-Policy"))}
    except urllib.error.HTTPError as e:
        # 4xx/5xx = server menjawab -> hidup
        return {"alive": True, "status": e.code, "server": "", 
                "content_type": "", "hsts": False, "xfo": False,
                "csp": False}
    except Exception as exc:
        return {"alive": False, "error": f"{type(exc).__name__}"}


def audit_inventory(base_domain: str, results: dict) \
        -> tuple[list[dict], dict]:
    """(rows, meta) dari hasil alive-check: hidup tanpa header proteksi
    kunci = L1 lead postur; semua host tercatat (inventaris)."""
    from findings import make_finding
    rows: list[dict] = []
    alive = {h: r for h, r in results.items() if r.get("alive")}
    for host, r in sorted(alive.items()):
        missing = [f for f, k in (("HSTS", "hsts"), ("XFO", "xfo"),
                                  ("CSP", "csp")) if not r.get(k)]
        if missing and r.get("status") == 200:
            rows.append(make_finding(
                tool="vdp-pipeline", title=f"Security headers missing on "
                                           f"{host}: {','.join(missing)}",
                severity="low",
                description=f"Host hidup ({r.get('status')}) tanpa "
                            f"{', '.join(missing)} — postur dasar (lead; "
                            "pasangan kelas lengkap dari tier0 skill).",
                target_url=host, response=json.dumps(r)[:250],
                evidence_kind="request-response", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "MISC", "safety_class":
                       "bounded-requests", "missing": missing}))
    return rows, {"domain": base_domain,
                  "alive": sorted(alive), 
                  "dead": sorted(h for h, r in results.items()
                                 if not r.get("alive")),
                  "requests": len(results)}


def discover_params(url: str, body: str) -> list[str]:
    """Kandidat param dari form input + query di URL (naif, bounded)."""
    import re
    params: list[str] = []
    for m in re.finditer(r"<input[^>]+name=[\"']([a-zA-Z0-9_-]{1,40})",
                         body):
        if m.group(1).lower() not in ("csrf", "csrfmiddlewaretoken",
                                      "_token", "password"):
            params.append(m.group(1))
    for m in re.finditer(r"[?&]([a-zA-Z][a-zA-Z0-9_]{1,20})=", body):
        params.append(m.group(1))
    seen, out = set(), []
    for p in params:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out[:MAX_XSS_PARAMS]


def build_report(program: dict, domain: str, run_dir: Path) -> Path:
    """Paket laporan markdown siap submit ke kanal resmi program."""
    findings_p = run_dir / "findings.json"
    rows: list[dict] = []
    if findings_p.exists():
        try:
            rows = json.loads(findings_p.read_text(encoding="utf-8")) \
                .get("findings", [])
        except Exception:
            pass
    # lead substantif saja: terkonfirmasi, bukan inventaris AMAN,
    # bukan baris error transport (unconfirmed)
    leads = [f for f in rows if f.get("verdict", 0) >= 1
             and f.get("status") == "confirmed"
             and f.get("category") != "AMAN"]
    lines = [
        f"# Laporan VDP — {program.get('name', domain)}", "",
        f"- Domain: `{domain}`",
        f"- Run: `{run_dir.name}` "
        f"({datetime.now(timezone.utc).isoformat(timespec='seconds')})",
        f"- Kanal lapor: {program.get('report_channel', '(cek halaman program)')}",
        f"- Policy: {program.get('policy_url', '-')}",
        f"- Ringkasan: {len(leads)} lead (L1/L2, belum PoC) dari "
        f"{len(rows)} baris audit — no exploit, no report.", "",
        "## Temuan (lead)", "",
    ]
    inv_p = run_dir / "inventory.json"
    if inv_p.exists():
        try:
            inv = json.loads(inv_p.read_text(encoding="utf-8"))
            lines += ["## Inventaris host (padanan alive/dead)", "",
                      f"- Hidup: {len(inv.get('alive', []))} — "
                      + ", ".join(f"`{h}`" for h in inv.get("alive", [])),
                      f"- Mati: {len(inv.get('dead', []))} (tercatat, "
                      "tidak dilaporkan)", ""]
        except Exception:
            pass
    if leads:
        for f in leads[:30]:
            lines += [f"### {f.get('title')}",
                      f"- Kelas: {f.get('category')} | "
                      f"severity: {f.get('severity')} | verdict: "
                      f"L{f.get('verdict')} | CWE: {f.get('cwe', '-')}",
                      f"- Target: {f.get('target_url')}",
                      f"- Bukti: `{(f.get('response') or '')[:200]}`",
                      f"- Rekomendasi: {(f.get('recommendation') or '')[:300]}",
                      ""]
    else:
        lines += ["Tidak ada lead pada run ini (semua AMAN/inventaris).", ""]
    lines += ["## Aturan submit", "",
              "1. Verifikasi scope + rules program SEBELUM mengirim "
              "(otomatisasi dilarang di banyak VDP).",
              "2. Lead L1/L2 = observasi postur/refleksi; sertakan "
              "langkah reproduksi manual, bukan scanner.",
              "3. Jangan submit klaim eksekusi (L3+) tanpa PoC dari "
              "jalur playbook yang diizinkan program.",
              "4. Satu laporan per temuan; temuan duplikat/di luar "
              "scope = risiko banned.", ""]
    p = run_dir / "laporan.md"
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--program", required=True,
                    help="id program di programs/index.json")
    ap.add_argument("--domains", default="",
                    help="koma-berisi domain scope (kosong = domain "
                         "utama program saja; jangan masukkan di luar "
                         "scope resmi)")
    ap.add_argument("--stage", default="all",
                    choices=["enum", "alive", "surf", "xss", "report",
                             "all"])
    ap.add_argument("--max-hosts", type=int, default=MAX_HOSTS_DEFAULT)
    ap.add_argument("--max-surf", type=int, default=MAX_SURF_DEFAULT)
    ap.add_argument("--max-params", type=int, default=MAX_XSS_PARAMS)
    ap.add_argument("--scope-ack", action="store_true",
                    help="wajib untuk stage xss (rules program sudah "
                         "dibaca & mengizinkan)")
    ap.add_argument("--out-root", default="findings/vdp")
    args = ap.parse_args(argv)

    program = _load_program(args.program)
    domain = program.get("domain")
    if not domain:
        print("program tanpa field domain — fail-closed", file=sys.stderr)
        return 2
    domains = [d.strip() for d in args.domains.split(",") if d.strip()] \
        or [domain]
    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_dir = Path(args.out_root) / program["id"] / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[vdp] program={program['id']} run={run_id} "
          f"domains={domains} stage={args.stage}")

    # ---- enum: kandidat subdomain (read-only, data publik)
    candidates: list[str] = []
    if args.stage in ("enum", "all"):
        for d in domains:
            for script, flag in (("subdomain_enum_surface.py", "--domain"),
                                 ("ct_inventory.py", "--domain")):
                doc = _run_skill(script, [flag, d], run_dir)
                if not doc:
                    continue
                for cand in _extract_candidates(doc, d):
                    if cand not in candidates:
                        candidates.append(cand)
        (run_dir / "enum.json").write_text(json.dumps(
            {"domain": domain, "candidates": candidates}, indent=1),
            encoding="utf-8")
        print(f"[vdp] enum: {len(candidates)} kandidat")

    # ---- alive: klasifikasi hidup/mati (1 GET/kandidat, bounded)
    inventory = {}
    if args.stage in ("alive", "all"):
        probe = candidates[:args.max_hosts] \
            if candidates else [f"www.{d}" for d in domains]
        results = {}
        for host in probe:
            url = host if host.startswith("http") else f"https://{host}"
            results[host] = alive_probe(url)
            time.sleep(0.4)  # low-and-slow
        from findings import write_findings
        rows, meta = audit_inventory(domain, results)
        write_findings(str(run_dir / "alive"), rows,
                       {**meta, "safety_class": "bounded-requests"})
        inventory = meta
        (run_dir / "inventory.json").write_text(json.dumps(
            meta, indent=1), encoding="utf-8")
        print(f"[vdp] alive: {len(meta['alive'])} hidup / "
              f"{len(meta['dead'])} mati")

    # ---- surf: js-endpoints + kandidat param (1 GET/host, bounded)
    surf_hosts: list[str] = []
    if args.stage in ("surf", "all"):
        from findings import write_findings
        hosts = (inventory.get("alive") or [])[:args.max_surf] or \
            [f"www.{d}" for d in domains]
        for host in hosts:
            url = host if host.startswith("http") else f"https://{host}"
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            try:
                with urllib.request.urlopen(req, timeout=12) as r:
                    body = r.read(120_000).decode("utf-8", "replace")
            except Exception as exc:
                print(f"[vdp] surf skip {host}: {type(exc).__name__}",
                      file=sys.stderr)
                continue
            ev = run_dir / (
                f"surf-{host.replace('://','_').replace('/','_')}.raw.html")
            ev.write_text(body, encoding="utf-8")
            doc = _run_skill("js_endpoints.py",
                             ["--url", url, "--from-raw", str(ev)],
                             run_dir)
            params = discover_params(url, body)
            surf_hosts.append(url)
            (run_dir / f"surf-{host.replace('://','_').replace('/','_')}"
             f".json").write_text(json.dumps(
                {"url": url, "params": params,
                 "js_endpoints": bool(doc)}, indent=1), encoding="utf-8")
            time.sleep(0.4)
        print(f"[vdp] surf: {len(surf_hosts)} host, param kandidat "
              f"tersimpan")

    # ---- xss: GATED (scope-ack + program accepted)
    if args.stage in ("xss", "all"):
        if not args.scope_ack:
            print("[vdp] stage xss DILEWATI — butuh --scope-ack "
                  "(rules program mengizinkan pengujian aktif)",
                  file=sys.stderr)
        elif not program.get("accepted"):
            print("[vdp] stage xss DITOLAK — program belum accepted=true "
                  "(fail-closed)", file=sys.stderr)
        else:
            marker = f"xss-canary-{secrets.token_hex(6)}"
            for url in surf_hosts[:args.max_surf]:
                params_path = run_dir / (
                    f"surf-{url.replace('://','_').replace('/','_')}.json")
                if not params_path.exists():
                    continue
                params = json.loads(
                    params_path.read_text(encoding="utf-8"))["params"]
                if not params:
                    continue
                doc = _run_skill("xss_reflect_check.py",
                                 ["--url", url, "--scope-ack",
                                  *sum((["--param", p] for p in
                                        params[:args.max_params]), [])],
                                 run_dir)
                print(f"[vdp] xss {url}: "
                      f"{len(doc['findings']) if doc else 0} baris")

    # ---- report: merge + paket laporan
    if args.stage in ("report", "all"):
        parts = sorted(run_dir.glob("*.findings.json"))
        if parts:
            r = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "merge_findings.py"),
                 *[str(p) for p in parts],
                 "--out", str(run_dir / "findings.json"),
                 "--run", f"vdp-{program['id']}", "--dedup-id"],
                capture_output=True, text=True, timeout=300, cwd=str(ROOT))
            if r.returncode != 0:
                print(f"[vdp] merge rc={r.returncode}: "
                      f"{(r.stderr or '')[-200:]}", file=sys.stderr)
        rp = build_report(program, domain, run_dir)
        print(f"[vdp] laporan: {rp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
