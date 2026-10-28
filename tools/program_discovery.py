"""[F22] Program discovery — temukan kandidat program bounty/VDP BARU.

Sumber publik tanpa kredensial (opt-in per sumber, >=1 wajib diisi —
tanpa sumber tool no-op fail-closed dengan 0 request):
  a. security.txt crawl dari seed list domain (reuse skills/security_txt:
     maks 2 GET per domain /.well-known/ + /security.txt);
  b. daftar program publik yang di-host di GitHub (fetch raw, read-only,
     JSON array / JSONL — URL diisi operator);
  c. halaman program publik aggregator (read-only, tanpa login — pasangan
     (nama, domain) diekstrak regex yang diisi operator).

Kriteria kandidat (dari profil target operator): perusahaan didirikan
<=5 th, pendanaan <=2 th, punya website + domain email. Usia perusahaan/
pendanaan TIDAK ditebak dari data publik — hanya diisi via --meta CSV
(domain,founded_year,funded_year); tanpa itu kedua kriteria dicatat
"unverified" (zero-FP: tidak ada klaim lolos tanpa bukti).

Verdict ladder: L0 OBSERVED (kandidat teramati di sumber) / L1 SUSPECTED
LEAD (website + email domain terverifikasi). Tool ini TIDAK pernah
menghasilkan verdict > 1 — kandidat bukan kerentanan.

Output:
  - findings.json (kontrak satu pintu, 1 baris per kandidat domain);
  - kandidat BARU lintas-run disimpan per-file ke findings/discovery/
    untuk dibedah manual (state dedup: known-candidates.json, diff:
    discovery-diff.json — pola diff-since-last by ID dari program_sweep).

Pemakaian:
  python tools/program_discovery.py --seeds seeds.txt \
      [--github-lists URL1,URL2] [--aggregators URL --aggregator-regex RE] \
      [--meta company-meta.csv] [--candidates-dir findings/discovery] \
      --out findings.json
"""
from __future__ import annotations

import argparse
import csv
import datetime
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "tools"))
from findings import make_finding, validate_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402
import security_txt  # noqa: E402  (skills/ — reuse pola 1-request per domain)

UA = user_agent()
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
MAX_BODY = 64_000
DEFAULT_MAX_DOMAINS = 50
FOUNDING_MAX_YEARS = 5.0
FUNDING_MAX_YEARS = 2.0

TOOL = "program-discovery"


class ConfigError(ValueError):
    """Config/sumber tidak valid — error keras (fail-closed)."""


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.rstrip(".")
    if ":" in d:  # buang port
        d = d.rsplit(":", 1)[0]
    return d


def parse_seeds(path: Path) -> list[str]:
    """Baca seed list (satu domain per baris; # komentar). Domain tidak
    valid setelah normalisasi = ConfigError (error keras, fail-closed)."""
    if not path.exists():
        raise ConfigError(f"seeds file tidak ada: {path}")
    out: list[str] = []
    for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = normalize_domain(line)
        if not s or line.strip().startswith("#"):
            continue
        if not DOMAIN_RE.match(s):
            raise ConfigError(f"{path}:{ln}: bukan domain valid: {line.strip()!r}")
        if s not in out:
            out.append(s)
    return out


def parse_meta_csv(path: Path) -> dict[str, dict]:
    """CSV opsional (header wajib: domain,founded_year,funded_year) —
    satusatunya sumber kriteria usia perusahaan/pendanaan. Kolom kosong
    boleh. Baris domain duplikat = ConfigError."""
    out: dict[str, dict] = {}
    if not path.exists():
        raise ConfigError(f"meta csv tidak ada: {path}")
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "domain" not in reader.fieldnames:
            raise ConfigError("meta csv wajib punya kolom 'domain'")
        for row in reader:
            d = normalize_domain(row.get("domain") or "")
            if not d:
                continue
            if d in out:
                raise ConfigError(f"meta csv: domain duplikat: {d}")
            out[d] = {
                "founded_year": (row.get("founded_year") or "").strip(),
                "funded_year": (row.get("funded_year") or "").strip(),
            }
    return out


def fetch(url: str, timeout: float = 15.0) -> str | None:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status == 200:
                return r.read(MAX_BODY).decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------
# Sumber
# --------------------------------------------------------------------------

def source_seeds(seeds: list[str], max_domains: int) -> tuple[list[dict], dict]:
    """security.txt crawl per seed domain (reuse skills/security_txt.audit —
    (rows, meta) kontrak; maks 2 GET per domain). Return (candidates, meta)."""
    candidates: list[dict] = []
    gets = 0
    truncated = max(0, len(seeds) - max_domains)
    for d in seeds[:max_domains]:
        try:
            rows, meta = security_txt.audit(d)
        except Exception as exc:  # fetch() sudah swallow; guard terakhir
            candidates.append({"domain": d, "name": d, "source": "seeds",
                               "error": repr(exc)[:120]})
            continue
        gets += int(meta.get("requests", 0))
        fields = meta.get("fields") or {}
        contacts = [c for c in fields.get("contact", []) if isinstance(c, str)]
        emails = sorted({m.group(0) for c in contacts
                         for m in EMAIL_RE.finditer(c)})
        email_domain = any(
            e.lower().endswith("@" + d) or e.lower().split("@")[-1].endswith("." + d)
            for e in emails)
        candidates.append({
            "domain": d, "name": d, "source": "seeds",
            "website": True,
            "email_domain": email_domain,
            "contact_emails": emails[:10],
            "policy": [p for p in fields.get("policy", []) if isinstance(p, str)],
            "sectxt_path": meta.get("path"),
        })
    return candidates, {"requests": gets, "domains": min(len(seeds), max_domains),
                        "truncated": truncated}


def source_github_lists(urls: list[str], max_items: int) -> tuple[list[dict], dict]:
    """Fetch raw URL daftar program publik (JSON array / JSONL, read-only).
    Item tanpa domain dilewati + dihitung (bukan error — daftar pihak
    lain bisa longgar; yang penting TIDAK ada tebakan)."""
    candidates: list[dict] = []
    gets = 0
    skipped = 0
    for u in urls:
        body = fetch(u)
        gets += 1
        if body is None:
            candidates.append({"source": "github-list", "error": f"fetch gagal: {u}"})
            continue
        items = _parse_jsonish(body)
        for it in items[:max_items]:
            if not isinstance(it, dict):
                skipped += 1
                continue
            d = normalize_domain(str(it.get("domain") or it.get("host") or
                                     it.get("site") or ""))
            name = str(it.get("name") or it.get("program") or d).strip()
            if not d or not DOMAIN_RE.match(d):
                skipped += 1
                continue
            candidates.append({"domain": d, "name": name or d,
                               "source": "github-list", "source_url": u,
                               "website": True, "email_domain": False})
    return candidates, {"requests": gets, "skipped_items": skipped}


def _parse_jsonish(body: str) -> list:
    body = body.strip()
    try:
        doc = json.loads(body)
        if isinstance(doc, list):
            return doc
        if isinstance(doc, dict):
            for k in ("programs", "items", "data"):
                if isinstance(doc.get(k), list):
                    return doc[k]
            return []
    except Exception:
        pass
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            out.append(line)
    return out


def source_aggregators(urls: list[str], regex: str | None,
                       max_items: int) -> tuple[list[dict], dict]:
    """Halaman aggregator publik (read-only, tanpa login). Tanpa
    --aggregator-regex sumber ini DILEWATI dengan baris audit (fail-closed:
    tidak menebak struktur HTML)."""
    candidates: list[dict] = []
    gets = 0
    if not regex:
        for _ in urls:
            candidates.append({"source": "aggregator",
                               "error": "tanpa --aggregator-regex — sumber dilewati"})
        return candidates, {"requests": 0, "skipped_items": len(urls)}
    rx = re.compile(regex)
    for u in urls:
        body = fetch(u)
        gets += 1
        if body is None:
            candidates.append({"source": "aggregator", "error": f"fetch gagal: {u}"})
            continue
        n = 0
        for m in rx.finditer(body):
            if n >= max_items:
                break
            gd = m.groupdict()
            d = normalize_domain(gd.get("domain") or "")
            name = (gd.get("name") or d).strip()
            if not d or not DOMAIN_RE.match(d):
                continue
            n += 1
            candidates.append({"domain": d, "name": name or d,
                               "source": "aggregator", "source_url": u,
                               "website": True, "email_domain": False})
    return candidates, {"requests": gets}


# --------------------------------------------------------------------------
# Kriteria + dedup + diff
# --------------------------------------------------------------------------

def evaluate_criteria(candidate: dict, meta: dict | None,
                      now: datetime.datetime | None = None) -> dict:
    """Kriteria profil target. founded/funding HANYA dari meta CSV —
    tanpa meta dicatat 'unverified' (tidak pernah dianggap lolos)."""
    now = now or datetime.datetime.now()
    crit = {
        "website": bool(candidate.get("website")),
        "email_domain": bool(candidate.get("email_domain")),
        "founded_years": None,
        "funding_age_years": None,
    }
    if meta:
        fy = (meta.get("founded_year") or "").strip()
        if fy.isdigit():
            crit["founded_years"] = round(now.year - int(fy), 1)
        fd = (meta.get("funded_year") or "").strip()
        if fd.isdigit():
            crit["funding_age_years"] = round(now.year - int(fd), 1)
    crit["founded_ok"] = (crit["founded_years"] is None or
                          crit["founded_years"] <= FOUNDING_MAX_YEARS)
    crit["funding_ok"] = (crit["funding_age_years"] is None or
                          crit["funding_age_years"] <= FUNDING_MAX_YEARS)
    # verified = kriteria yang benar-benar terbukti dari data publik/meta
    crit["verified"] = [k for k in ("website", "email_domain")
                        if crit[k]] + \
                       ([f"founded<={FOUNDING_MAX_YEARS:.0f}th"] if crit["founded_years"] is not None and crit["founded_ok"] else []) + \
                       ([f"funding<={FUNDING_MAX_YEARS:.0f}th"] if crit["funding_age_years"] is not None and crit["funding_ok"] else [])
    crit["unverified"] = [k for k in ("founded_years", "funding_age_years")
                          if crit[k] is None]
    return crit


def merge_candidates(all_raw: list[dict]) -> tuple[list[dict], int]:
    """Dedup lintas-sumber by domain; sumber digabung; nama deterministik
    (lexicographic min) supaya id finding stabil lintas-run."""
    by_domain: dict[str, dict] = {}
    dropped_non_domain = 0
    for c in all_raw:
        d = c.get("domain")
        if not d:
            dropped_non_domain += 1  # baris error/audit dari sumber
            continue
        cur = by_domain.setdefault(d, {"domain": d, "names": [], "sources": []})
        if c.get("name"):
            cur["names"].append(c["name"])
        if c.get("source") and c["source"] not in cur["sources"]:
            cur["sources"].append(c["source"])
        for k in ("website", "email_domain", "policy", "source_url"):
            v = c.get(k)
            if v and not cur.get(k):
                cur[k] = v
            elif k in ("policy",) and v and isinstance(v, list):
                cur.setdefault(k, [])
                for item in v:
                    if item not in cur[k]:
                        cur[k].append(item)
    out = []
    for d, c in by_domain.items():
        c["name"] = min(c.pop("names", []) or [d])
        out.append(c)
    out.sort(key=lambda c: c["domain"])
    return out, dropped_non_domain


def load_state(candidates_dir: Path) -> dict:
    p = candidates_dir / "known-candidates.json"
    if not p.exists():
        return {"version": 1, "candidates": {}}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or not isinstance(doc.get("candidates"), dict):
            return {"version": 1, "candidates": {}}
        return doc
    except Exception:
        return {"version": 1, "candidates": {}}


def diff_state(state: dict, domains: list[str]) -> dict:
    known = state.get("candidates", {})
    new = [d for d in domains if d not in known]
    return {"new_domains": new, "known_count": len(known),
            "not_seen_this_run": sorted(set(known) - set(domains))}


def candidate_finding(c: dict, crit: dict, is_new: bool,
                      first_seen: int | None) -> dict:
    lead = bool(crit["website"] and crit["email_domain"])
    title = f"Program candidate: {c['name']} <{c['domain']}>"
    srcs = ", ".join(c.get("sources", [])) or "unknown"
    desc = (
        "Kandidat program bounty/VDP dari sumber publik: "
        f"{srcs}. Kriteria terverifikasi: "
        f"{', '.join(crit['verified']) or 'tidak ada'}. "
        + ("Kriteria usia perusahaan/pendanaan belum terverifikasi — "
           "isi via --meta CSV bila tersedia (zero-FP: tidak ditebak). "
           if crit["unverified"] else "")
        + "Bukan klaim kerentanan — kandidat untuk dibedah manual "
          "(cek policy sebelum sentuh).")
    return make_finding(
        tool=TOOL, title=title, severity="info", description=desc,
        recommendation="Verifikasi manual: policy program, umur perusahaan, "
                       "pendanaan, kanal lapor. Baru masukkan ke programs/index.json.",
        target_url=f"https://{c['domain']}/",
        evidence_kind="request-response" if crit["website"] else "file-manifest",
        finding_class="posture", confidence=0.9 if lead else 0.6,
        status="confirmed", verdict=1 if lead else 0,
        extra={"category": "DISCOVERY", "safety_class": "bounded-requests",
               "sources": c.get("sources", []),
               "criteria": {k: v for k, v in crit.items() if k != "verified"},
               "criteria_verified": crit["verified"],
               "is_new": is_new, "first_seen_epoch": first_seen,
               "contact_emails": c.get("contact_emails", []),
               "policy": c.get("policy", [])})


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main_with_args(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seeds", default=None,
                    help="file seed domain (1 per baris, # komentar)")
    ap.add_argument("--github-lists", default=None,
                    help="URL raw daftar program publik (JSON/JSONL, koma)")
    ap.add_argument("--aggregators", default=None,
                    help="URL halaman aggregator publik (koma)")
    ap.add_argument("--aggregator-regex", default=None,
                    help="regex dengan named group (?P<name>...) (?P<domain>...)")
    ap.add_argument("--meta", default=None,
                    help="CSV (domain,founded_year,funded_year) kriteria usia")
    ap.add_argument("--out", required=True)
    ap.add_argument("--candidates-dir", default="findings/discovery")
    ap.add_argument("--max-domains", type=int, default=DEFAULT_MAX_DOMAINS)
    ap.add_argument("--max-items", type=int, default=100)
    args = ap.parse_args(argv)

    raw: list[dict] = []
    meta_sources: dict = {}
    requests = 0

    if args.seeds:
        seeds = parse_seeds(Path(args.seeds))
        c, m = source_seeds(seeds, max(1, args.max_domains))
        raw.extend(c)
        meta_sources["seeds"] = m
        requests += m["requests"]
    if args.github_lists:
        urls = [u.strip() for u in args.github_lists.split(",") if u.strip()]
        c, m = source_github_lists(urls, max(1, args.max_items))
        raw.extend(c)
        meta_sources["github_lists"] = m
        requests += m["requests"]
    if args.aggregators:
        urls = [u.strip() for u in args.aggregators.split(",") if u.strip()]
        c, m = source_aggregators(urls, args.aggregator_regex, max(1, args.max_items))
        raw.extend(c)
        meta_sources["aggregators"] = m
        requests += m["requests"]

    meta_rows = parse_meta_csv(Path(args.meta)) if args.meta else {}
    merged, dropped = merge_candidates(raw)

    candidates_dir = ROOT / args.candidates_dir
    candidates_dir.mkdir(parents=True, exist_ok=True)
    state = load_state(candidates_dir)
    diff = diff_state(state, [c["domain"] for c in merged])

    rows: list[dict] = []
    now_epoch = int(time.time())
    for c in merged:
        crit = evaluate_criteria(c, meta_rows.get(c["domain"]))
        is_new = c["domain"] in diff["new_domains"]
        known = state["candidates"].get(c["domain"], {})
        first_seen = known.get("first_seen_epoch") or now_epoch
        f = candidate_finding(c, crit, is_new, first_seen)
        errs = validate_finding(f)
        if errs:  # fail-closed: baris kontrak-invalid tidak pernah keluar
            raise SystemExit(f"discovery: finding tidak valid: {errs}")
        rows.append(f)
        if is_new:
            (candidates_dir / f"{f['id']}.json").write_text(
                json.dumps({"candidate": c, "criteria": crit,
                            "id": f["id"], "discovered_at_epoch": now_epoch},
                           indent=2, ensure_ascii=False), encoding="utf-8")
        # state update: first_seen dipertahankan, last_seen diperbarui
        state["candidates"][c["domain"]] = {
            **known, "name": c["name"], "first_seen_epoch": first_seen,
            "last_seen_epoch": now_epoch, "id": f["id"]}

    from atomic import atomic_write_text  # noqa: E402  (tools/)
    atomic_write_text(candidates_dir / "known-candidates.json",
                      json.dumps(state, indent=2, ensure_ascii=False))
    (candidates_dir / "discovery-diff.json").write_text(
        json.dumps({"method": "domain-id-deterministik (pola program_sweep)",
                    "run_at_epoch": now_epoch, "new": diff["new_domains"],
                    "new_count": len(diff["new_domains"]),
                    "known_total": len(state["candidates"]),
                    "not_seen_this_run": diff["not_seen_this_run"],
                    "non_domain_rows_dropped": dropped},
                   indent=2, ensure_ascii=False), encoding="utf-8")

    new_count = sum(1 for r in rows if r.get("is_new"))
    meta_doc = {
        "run": "program-discovery",
        "safety_class": "bounded-requests",
        "requests": requests,
        "sources": meta_sources,
        "candidates_total": len(rows),
        "candidates_new": new_count,
        "leads": sum(1 for r in rows if r["verdict"] == 1),
        "candidates_dir": str(candidates_dir),
    }
    write_findings(args.out, rows, meta_doc)
    print(json.dumps({"ok": True, "out": args.out, **meta_doc},
                     ensure_ascii=False))
    return 0


def main() -> int:
    return main_with_args(None)


if __name__ == "__main__":
    raise SystemExit(main())
