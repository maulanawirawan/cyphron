"""[F7] Intel sync dari nol — template & feed intelijen SELALU segar.

Jawaban atas "bagaimana template tetap up to date": pipeline sinkronisasi
milik sendiri dengan manifest versi + delta + TTL. Sumber:
  - nuclei-templates (repo komunitas projectdiscovery) — corpus ribuan
    template; kita INGEST sebagai amunisi, bukan menulis ulang.
  - CISA KEV (known exploited vulnerabilities) — feed eksplloitasi nyata.
  - [F61a] watchlist — seed kurasi operator + NVD critical dalam
    jendela waktu: CVE kritis yang BELUM masuk KEV (celah konfirmasi
    KEV = masa paling berbahaya; lihat assets/intel/watchlist-seeds.json).

Manifest (assets/intel/manifest.json) mencatat per komponen: versi (sha
commit / tanggal rilis), jumlah template/entri, waktu sync, dan DELTA
dibanding sync sebelumnya — jadi kebaruannya terukur, bukan siluman.

Pemakaian:
  python tools/intel_sync.py --check            # cek segar tanpa unduh
  python tools/intel_sync.py --components nuclei-templates,kev
Semua artefak lokal (assets/intel/). Fail-closed: unduhan/ekstraksi
sebagian tidak pernah menimpa versi yang sudah baik.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEL = ROOT / "assets" / "intel"
MANIFEST = INTEL / "manifest.json"
UA = "cyphron-intel-sync/0.1"

NUCLEI_TPL_REPO = "projectdiscovery/nuclei-templates"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

# [F61a] Watchlist breaking-CVE: CVE kritis yang BELUM (atau belum
# terkonfirmasi) masuk KEV. KEV butuh konfirmasi eksploitasi — celah
# itu persis masa paling berbahaya (php2shell: percobaan eksploitasi
# 17 Okt, masuk KEV: belum per 25 Okt). Dua sumber:
#   - seed kurasi operator (assets/intel/watchlist-seeds.json) — CVE
#     pilihan dengan token produk eksplisit utk cve-matcher;
#   - feed NVD critical dalam jendela waktu (API 2.0, tanpa API key,
#     1 request per sync — dalam batas rate limit publik).
# Output assets/intel/watchlist.json — matcher HANYA memakai seed
# (kurasi, ada token); baris NVD = inventaris awareness, tanpa klaim.
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WATCHLIST_SEEDS = INTEL / "watchlist-seeds.json"
WATCHLIST_OUT = INTEL / "watchlist.json"
WATCHLIST_WINDOW_DAYS = 14

# [F67] Indeks rentang versi NVD (CPE cpeMatch) — basis audit
# dependensi yang TERIKAT VERSI tanpa fabrikasi: rentang datang dari
# data NVD, bukan tebakan. Sync harian = delta 3 hari (merge dengan
# indeks lama); bootstrap = 120 hari (batas maksimum API NVD). 2
# request per sync (CRITICAL + HIGH), pagination dibatasi.
NVD_RANGES_OUT = INTEL / "nvd-ranges.json"
NVD_RANGES_WINDOW_DAYS = 120
NVD_RANGES_DELTA_DAYS = 3
NVD_RANGES_RETAIN_DAYS = int(os.environ.get("CYPHRON_NVD_RETAIN_DAYS",
                                            "1460"))
NVD_BACKFILL_STATE = INTEL / "nvd-backfill-state.json"
NVD_MAX_PAGES = 3
NVD_POLITE_DELAY = 6.5
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()

# [F67] Feed cepat 6 jam (jadwal auto-update 6-jam); nuclei 12 jam
# (unduhan besar), CWE 168 jam (katalog lambat). Rate limit tetap aman:
# NVD 2 request/sync, KEV 1, watchlist 1.
TTL_HOURS = {"nuclei-templates": 12, "kev": 6, "cwe": 168,
             "watchlist": 6, "nvd-ranges": 6}


def fetch(url: str, timeout: float = 60.0,
          headers: dict | None = None, retries: int = 2) -> bytes:
    """GET dengan retry terbatas: timeout/5xx/429 dicoba ulang,
    4xx lain langsung gagal (fail-loud, bukan retry sia-sia)."""
    last: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url, headers={"User-Agent": UA, **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in (429, 500, 502, 503, 504):
                raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
        if attempt < retries:
            time.sleep(5 * (attempt + 1))
    raise last if last else RuntimeError("fetch gagal tanpa exception")


def load_manifest() -> dict:
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {"components": {}, "history": []}


def save_manifest(m: dict) -> None:
    INTEL.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(m, indent=2, ensure_ascii=False),
                        encoding="utf-8")


def should_sync(entry: dict | None, ttl_hours: int) -> bool:
    """Keputusan segar: belum pernah sync / TTL lewat. Fail-closed."""
    if not entry:
        return True
    age_h = (time.time() - entry.get("synced_at", 0)) / 3600.0
    return age_h >= ttl_hours


def verify_counts(wanted: set[str] | None = None) -> int:
    """Verifikasi fail-closed: hitung aktual vs manifest.

    - Hitung *.yaml/*.yml rekursif di assets/intel/nuclei-templates
    - Hitung entri vulnerabilities di assets/intel/kev.json
    - Hitung baris data di assets/intel/cwe-1000.csv (tanpa header)
    - Bandingkan dengan template_count / entry_count di manifest
    - Laporkan delta & AV deletions (actual < manifest) -> exit 2
    Tetap mempertahankan atomic staging & TTL di jalur sync normal.
    """
    m = load_manifest()
    if wanted is None:
        wanted = {"nuclei-templates", "kev", "cwe", "watchlist",
                  "nvd-ranges"}
    results: dict = {}
    ok = True
    av_suspected = False

    if "nuclei-templates" in wanted:
        comp = m["components"].get("nuclei-templates")
        manifest_count = comp.get("template_count") if comp else None
        dst = INTEL / "nuclei-templates"
        if dst.is_dir():
            actual = sum(1 for _ in dst.rglob("*.yaml"))
            actual += sum(1 for _ in dst.rglob("*.yml"))
        else:
            actual = 0
        if manifest_count is None:
            ok = False
            status = "no_manifest"
        else:
            mismatch = actual != manifest_count
            if mismatch:
                ok = False
                if actual < manifest_count:
                    av_suspected = True
            status = "mismatch" if mismatch else "ok"
        delta = (actual - manifest_count) if manifest_count is not None else None
        results["nuclei-templates"] = {
            "manifest_count": manifest_count,
            "actual_count": actual,
            "delta": delta,
            "status": status,
            "av_deletion_suspected": bool(
                manifest_count is not None and actual < manifest_count
            ),
            "manifest_version": comp.get("version") if comp else None,
            "path": str(dst),
        }

    if "kev" in wanted:
        comp = m["components"].get("kev")
        manifest_count = comp.get("entry_count") if comp else None
        kev_path = INTEL / "kev.json"
        actual = None
        parse_error = None
        if kev_path.is_file():
            try:
                doc = json.loads(kev_path.read_text(encoding="utf-8"))
                actual = len(doc.get("vulnerabilities", []))
            except Exception as e:  # noqa: BLE001
                parse_error = str(e)
                ok = False
        else:
            actual = 0
        if parse_error is not None:
            results["kev"] = {
                "manifest_count": manifest_count,
                "actual_count": None,
                "delta": None,
                "status": "error",
                "error": f"gagal baca kev.json: {parse_error}",
                "av_deletion_suspected": False,
                "path": str(kev_path),
            }
        else:
            if manifest_count is None:
                ok = False
                status = "no_manifest"
            else:
                mismatch = actual != manifest_count
                if mismatch:
                    ok = False
                    if actual is not None and actual < manifest_count:
                        av_suspected = True
                status = "mismatch" if mismatch else "ok"
            delta = (
                (actual - manifest_count)
                if (manifest_count is not None and actual is not None)
                else None
            )
            results["kev"] = {
                "manifest_count": manifest_count,
                "actual_count": actual,
                "delta": delta,
                "status": status,
                "av_deletion_suspected": bool(
                    manifest_count is not None
                    and actual is not None
                    and actual < manifest_count
                ),
                "manifest_version": comp.get("version") if comp else None,
                "path": str(kev_path),
            }

    if "cwe" in wanted:
        comp = m["components"].get("cwe")
        manifest_count = comp.get("entry_count") if comp else None
        cwe_path = INTEL / "cwe-1000.csv"
        actual = None
        parse_error = None
        if cwe_path.is_file():
            try:
                with cwe_path.open(encoding="utf-8", errors="replace",
                                   newline="") as f:
                    actual = max(0, sum(1 for _ in f) - 1)
            except OSError as e:  # noqa: BLE001
                parse_error = str(e)
                ok = False
        else:
            actual = 0
        if parse_error is not None:
            results["cwe"] = {
                "manifest_count": manifest_count, "actual_count": None,
                "delta": None, "status": "error",
                "error": f"gagal baca cwe-1000.csv: {parse_error}",
                "av_deletion_suspected": False, "path": str(cwe_path),
            }
        elif manifest_count is None:
            ok = False
            results["cwe"] = {
                "manifest_count": None, "actual_count": actual,
                "delta": None, "status": "no_manifest",
                "av_deletion_suspected": False, "path": str(cwe_path),
            }
        else:
            mismatch = actual != manifest_count
            if mismatch:
                ok = False
                if actual < manifest_count:
                    av_suspected = True
            results["cwe"] = {
                "manifest_count": manifest_count, "actual_count": actual,
                "delta": actual - manifest_count,
                "status": "mismatch" if mismatch else "ok",
                "av_deletion_suspected": actual < manifest_count,
                "manifest_version": comp.get("version") if comp else None,
                "path": str(cwe_path),
            }

    if "watchlist" in wanted:
        comp = m["components"].get("watchlist")
        manifest_count = comp.get("entry_count") if comp else None
        wl_path = WATCHLIST_OUT
        actual = None
        parse_error = None
        if wl_path.is_file():
            try:
                wdoc = json.loads(wl_path.read_text(encoding="utf-8"))
                actual = len(wdoc.get("seeds", [])) + \
                    len(wdoc.get("nvd_critical", []))
            except Exception as e:  # noqa: BLE001
                parse_error = str(e)
                ok = False
        else:
            actual = 0
        if parse_error is not None:
            results["watchlist"] = {
                "manifest_count": manifest_count, "actual_count": None,
                "delta": None, "status": "error",
                "error": f"gagal baca watchlist.json: {parse_error}",
                "av_deletion_suspected": False, "path": str(wl_path),
            }
        elif manifest_count is None:
            ok = False
            results["watchlist"] = {
                "manifest_count": None, "actual_count": actual,
                "delta": None, "status": "no_manifest",
                "av_deletion_suspected": False, "path": str(wl_path),
            }
        else:
            mismatch = actual != manifest_count
            if mismatch:
                ok = False
                if actual < manifest_count:
                    av_suspected = True
            results["watchlist"] = {
                "manifest_count": manifest_count, "actual_count": actual,
                "delta": actual - manifest_count,
                "status": "mismatch" if mismatch else "ok",
                "av_deletion_suspected": actual < manifest_count,
                "manifest_version": comp.get("version") if comp else None,
                "path": str(wl_path),
            }

    if "nvd-ranges" in wanted:
        comp = m["components"].get("nvd-ranges")
        manifest_count = comp.get("entry_count") if comp else None
        nvd_path = NVD_RANGES_OUT
        actual = None
        parse_error = None
        if nvd_path.is_file():
            try:
                ndoc = json.loads(nvd_path.read_text(encoding="utf-8"))
                actual = len(ndoc.get("entries", []))
            except Exception as e:  # noqa: BLE001
                parse_error = str(e)
                ok = False
        else:
            actual = 0
        if parse_error is not None:
            results["nvd-ranges"] = {
                "manifest_count": manifest_count, "actual_count": None,
                "delta": None, "status": "error",
                "error": f"gagal baca nvd-ranges.json: {parse_error}",
                "av_deletion_suspected": False, "path": str(nvd_path),
            }
        elif manifest_count is None:
            ok = False
            results["nvd-ranges"] = {
                "manifest_count": None, "actual_count": actual,
                "delta": None, "status": "no_manifest",
                "av_deletion_suspected": False, "path": str(nvd_path),
            }
        else:
            mismatch = actual != manifest_count
            if mismatch:
                ok = False
                if actual < manifest_count:
                    av_suspected = True
            results["nvd-ranges"] = {
                "manifest_count": manifest_count, "actual_count": actual,
                "delta": actual - manifest_count,
                "status": "mismatch" if mismatch else "ok",
                "av_deletion_suspected": actual < manifest_count,
                "manifest_version": comp.get("version") if comp else None,
                "path": str(nvd_path),
            }

    report = {
        "ok": ok,
        "av_deletions_suspected": av_suspected,
        "exit_code": 0 if ok else 2,
        "components": results,
        "manifest_path": str(MANIFEST),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if av_suspected:
        print(
            "ALERT: AV/pembersih mungkin menghapus file — actual < manifest",
            file=sys.stderr,
        )
    return 0 if ok else 2


def sync_nuclei_templates(force: bool = False) -> dict:
    """Sinkronkan corpus nuclei-templates. Versi = sha commit HEAD.
    Unduh hanya kalau versi berubah (atau --force)."""
    m = load_manifest()
    prev = m["components"].get("nuclei-templates")
    ttl = TTL_HOURS["nuclei-templates"]
    if not force and not should_sync(prev, ttl):
        return {"skipped": True, "reason": "TTL segar", "prev": prev}

    api = json.loads(fetch(
        f"https://api.github.com/repos/{NUCLEI_TPL_REPO}/commits/main"
    ).decode())
    sha = api.get("sha", "")[:12]
    commit_date = api.get("commit", {}).get("committer", {}).get("date", "")
    if prev and prev.get("version") == sha and not force:
        entry = {**prev, "synced_at": time.time()}
        m["components"]["nuclei-templates"] = entry
        save_manifest(m)
        return {"skipped": True, "reason": "versi sama", "version": sha}

    # Unduh tarball HEAD lalu ekstraksi ke folder sementara — baru
    # ditukar setelah lengkap (fail-closed: sebagian tidak menimpa yang baik)
    tgz = fetch(
        f"https://codeload.github.com/{NUCLEI_TPL_REPO}/tar.gz/refs/heads/main",
        timeout=600.0,
    )
    staging = INTEL / ".staging-nuclei-templates"
    if staging.exists():
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tf:
        tf.extractall(staging)
    root = next((p for p in staging.iterdir() if p.is_dir()), None)
    if root is None:
        raise RuntimeError("arsip template tidak berisi folder — dibatalkan")

    # Staging -> folder aktif (atomic-ish: rename tua, pindahkan baru)
    dst = INTEL / "nuclei-templates"
    import shutil
    if dst.exists():
        old = INTEL / ".old-nuclei-templates"
        shutil.rmtree(old, ignore_errors=True)
        dst.rename(old)
    root.rename(dst)
    import shutil as sh
    sh.rmtree(staging, ignore_errors=True)
    sh.rmtree(INTEL / ".old-nuclei-templates", ignore_errors=True)

    count = sum(1 for _ in dst.rglob("*.yaml"))
    count += sum(1 for _ in dst.rglob("*.yml"))
    entry = {
        "version": sha, "commit_date": commit_date, "template_count": count,
        "synced_at": time.time(),
        "delta_from_prev": (count - prev["template_count"])
        if prev and prev.get("template_count") else None,
    }
    m["components"]["nuclei-templates"] = entry
    m["history"].append({"component": "nuclei-templates",
                         "at": time.time(), **{k: v for k, v in entry.items()
                                               if k != "synced_at"}})
    m["history"] = m["history"][-50:]
    save_manifest(m)
    return {"synced": True, **entry}


def sync_kev(force: bool = False) -> dict:
    """Sinkronkan CISA KEV. Versi = dateReleased + jumlah entri."""
    m = load_manifest()
    prev = m["components"].get("kev")
    ttl = TTL_HOURS["kev"]
    if not force and not should_sync(prev, ttl):
        return {"skipped": True, "reason": "TTL segar", "prev": prev}

    doc = json.loads(fetch(KEV_URL).decode())
    count = len(doc.get("vulnerabilities", []))
    version = doc.get("dateReleased", "") or doc.get("catalogVersion", "")
    entry = {
        "version": version, "entry_count": count, "synced_at": time.time(),
        "delta_from_prev": (count - prev["entry_count"]) if prev else None,
    }
    (INTEL / "kev.json").write_text(json.dumps(doc), encoding="utf-8")
    m["components"]["kev"] = entry
    m["history"].append({"component": "kev", "at": time.time(),
                         **{k: v for k, v in entry.items() if k != "synced_at"}})
    m["history"] = m["history"][-50:]
    save_manifest(m)
    return {"synced": True, **entry}


def load_watchlist_seeds(path: Path | None = None) -> list[dict]:
    """Seed kurasi operator -> daftar entri valid (cve+product+tokens+
    source_url wajib). Fail-closed: file tidak ada / entri cacat =
    dilewati dengan catatan, bukan dipakai sebagian senyap."""
    path = path or WATCHLIST_SEEDS
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    out: list[dict] = []
    for s in doc.get("seeds", []) or []:
        if not (s.get("cve") and s.get("product") and s.get("tokens")
                and s.get("source_url")):
            continue
        out.append({k: s[k] for k in
                    ("cve", "vendor", "product", "tokens", "note",
                     "source_url", "added") if s.get(k)})
    return out


def _parse_nvd_critical(doc: dict) -> list[dict]:
    """Respons NVD API 2.0 -> baris minimal {cve, cvss, published,
    summary}. Parse defensif: baris tanpa id dilewati."""
    rows: list[dict] = []
    for item in doc.get("vulnerabilities", []) or []:
        cve = (item.get("cve") or {}).get("id")
        if not cve:
            continue
        c = item["cve"]
        score = None
        metrics = c.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            lst = metrics.get(key) or []
            if lst:
                score = ((lst[0].get("cvssData") or {}).get("baseScore"))
                if score is not None:
                    break
        summary = ""
        for d in c.get("descriptions", []) or []:
            if d.get("lang") == "en":
                summary = (d.get("value") or "")[:200]
                break
        rows.append({"cve": cve, "cvss": score,
                     "published": (c.get("published") or "")[:10],
                     "summary": summary})
    return rows


def sync_watchlist(force: bool = False,
                   window_days: int = WATCHLIST_WINDOW_DAYS) -> dict:
    """Sinkronkan watchlist breaking-CVE: seed kurasi + NVD critical
    dalam jendela waktu. Versi = tanggal jendela + jumlah entri.
    Fail-closed: file aktif ditulis atomic (tmp + replace) HANYA setelah
    dokumen lengkap terbentuk; kegagalan fetch menjaga versi lama."""
    m = load_manifest()
    prev = m["components"].get("watchlist")
    ttl = TTL_HOURS["watchlist"]
    if not force and not should_sync(prev, ttl):
        return {"skipped": True, "reason": "TTL segar", "prev": prev}

    seeds = load_watchlist_seeds()
    # NVD API 2.0: jendela pubStartDate/pubEndDate ISO-8601 (maks 120
    # hari); 1 request per sync — dalam batas rate limit publik.
    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=window_days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    url = (f"{NVD_URL}?cvssV3Severity=CRITICAL"
           f"&pubStartDate={start.strftime(fmt)}"
           f"&pubEndDate={end.strftime(fmt)}&resultsPerPage=500")
    doc = json.loads(fetch(url, timeout=120.0).decode())
    nvd_rows = _parse_nvd_critical(doc)
    seen = {s["cve"] for s in seeds}
    nvd_rows = [r for r in nvd_rows if r["cve"] not in seen]

    out_doc = {
        "synced_at": time.time(),
        "window_days": window_days,
        "window": {"start": start.strftime("%Y-%m-%d"),
                   "end": end.strftime("%Y-%m-%d")},
        "seeds": seeds,
        "nvd_critical": nvd_rows,
    }
    INTEL.mkdir(parents=True, exist_ok=True)
    tmp = WATCHLIST_OUT.with_suffix(".tmp")
    tmp.write_text(json.dumps(out_doc), encoding="utf-8")
    tmp.replace(WATCHLIST_OUT)

    count = len(seeds) + len(nvd_rows)
    version = f"window-{end.strftime('%Y%m%d')}"
    entry = {
        "version": version, "entry_count": count,
        "seed_count": len(seeds), "nvd_count": len(nvd_rows),
        "window_days": window_days, "synced_at": time.time(),
        "delta_from_prev": (count - prev["entry_count"])
        if prev and prev.get("entry_count") is not None else None,
    }
    m["components"]["watchlist"] = entry
    m["history"].append({"component": "watchlist", "at": time.time(),
                         **{k: v for k, v in entry.items()
                            if k != "synced_at"}})
    m["history"] = m["history"][-50:]
    save_manifest(m)
    return {"synced": True, **entry}


def _nvd_score(c: dict) -> float | None:
    """Skor CVSS pertama yang tersedia (v4/v3/v2) — None = tidak ada."""
    metrics = c.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                "cvssMetricV2"):
        lst = metrics.get(key) or []
        if not lst:
            continue
        score = ((lst[0].get("cvssData") or {}).get("baseScore"))
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                return None
    return None


def _norm_cpe_token(s: str) -> str:
    return " ".join(
        re.sub(r"[^a-z0-9.]+", " ", str(s).lower()).split())


def _cpe_parts(criteria: str) -> tuple[str, str, str] | None:
    """cpe:2.3:a:vendor:product:version:... -> (vendor, product, version).
    Bukan part 'a' (aplikasi) = None — OS/hardware tidak dipakai di sini."""
    parts = (criteria or "").split(":")
    if len(parts) < 6 or parts[2] != "a":
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    if not vendor or not product:
        return None
    return vendor, product, version


def _nvd_range_key(e: dict) -> tuple:
    return (e.get("cve"), e.get("vendor"), e.get("product"),
            e.get("exact"), e.get("start_incl"), e.get("start_excl"),
            e.get("end_incl"), e.get("end_excl"))


def _parse_nvd_ranges(doc: dict) -> list[dict]:
    """Response NVD API 2.0 -> entri rentang versi. Hanya cpeMatch
    vulnerable dengan constraint eksplisit; wildcard murni = dilewati."""
    out: dict[tuple, dict] = {}
    for item in doc.get("vulnerabilities", []) or []:
        c = item.get("cve") or {}
        cid = c.get("id")
        if not cid:
            continue
        score = _nvd_score(c)
        published = (c.get("published") or "")[:10]
        for conf in c.get("configurations", []) or []:
            for node in conf.get("nodes", []) or []:
                for m in node.get("cpeMatch", []) or []:
                    if not m.get("vulnerable"):
                        continue
                    parts = _cpe_parts(m.get("criteria") or "")
                    if parts is None:
                        continue
                    vendor, product, version = parts
                    exact = (version if version not in ("", "*", "-")
                             else None)
                    entry = {
                        "cve": cid,
                        "vendor": vendor,
                        "product": product,
                        "vendor_norm": _norm_cpe_token(vendor),
                        "product_norm": _norm_cpe_token(product),
                        "cvss": score,
                        "published": published,
                        "exact": exact,
                        "start_incl": m.get("versionStartIncluding"),
                        "start_excl": m.get("versionStartExcluding"),
                        "end_incl": m.get("versionEndIncluding"),
                        "end_excl": m.get("versionEndExcluding"),
                        "source_url": NVD_DETAIL_URL + cid,
                        "cpe": m.get("criteria"),
                    }
                    if not any(entry[k] for k in
                               ("exact", "start_incl", "start_excl",
                                "end_incl", "end_excl")):
                        continue  # wildcard murni = bukan rentang
                    out[_nvd_range_key(entry)] = entry
    return list(out.values())


def _nvd_params(severity: str, start_iso: str, end_iso: str,
                page: int) -> dict:
    return {"lastModStartDate": start_iso,
            "lastModEndDate": end_iso,
            "cvssV3Severity": severity,
            "resultsPerPage": 2000,
            "startIndex": page * 2000}


def _iso_utc(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _fetch_nvd_window(start_iso: str, end_iso: str) -> list[dict]:
    """2 severity x maks NVD_MAX_PAGES halaman; sleep sopan tanpa key."""
    out: dict[tuple, dict] = {}
    n_req = 0
    for severity in ("CRITICAL", "HIGH"):
        for page in range(NVD_MAX_PAGES):
            if n_req and NVD_POLITE_DELAY:
                time.sleep(NVD_POLITE_DELAY)
            params = _nvd_params(severity, start_iso, end_iso, page)
            url = f"{NVD_URL}?{urllib.parse.urlencode(params)}"
            headers = ({"apiKey": NVD_API_KEY} if NVD_API_KEY else None)
            doc = json.loads(fetch(url, timeout=120.0, headers=headers))
            n_req += 1
            for e in _parse_nvd_ranges(doc):
                out[_nvd_range_key(e)] = e
            total = int(doc.get("totalResults") or 0)
            if (page + 1) * 2000 >= total:
                break
    return list(out.values())


def _fetch_nvd_ranges(days: int) -> list[dict]:
    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=days)
    return _fetch_nvd_window(_iso_utc(start), _iso_utc(end))


def sync_nvd_ranges(force: bool = False) -> dict:
    """Sinkronkan indeks rentang versi NVD. Delta harian (3 hari) bila
    indeks sudah ada; bootstrap 120 hari bila belum. Merge by key +
    retensi 400 hari. Fail-closed: fetch gagal = indeks lama utuh."""
    m = load_manifest()
    prev = m["components"].get("nvd-ranges")
    ttl = TTL_HOURS["nvd-ranges"]
    if not force and not should_sync(prev, ttl):
        return {"skipped": True, "reason": "TTL segar", "prev": prev}

    existing: dict[tuple, dict] = {}
    if NVD_RANGES_OUT.is_file():
        try:
            doc = json.loads(NVD_RANGES_OUT.read_text(encoding="utf-8"))
            for e in doc.get("entries", []) or []:
                if e.get("cve") and e.get("product"):
                    existing[_nvd_range_key(e)] = e
        except Exception:  # noqa: BLE001
            existing = {}

    window = (NVD_RANGES_DELTA_DAYS if existing
              else NVD_RANGES_WINDOW_DAYS)
    fresh = _fetch_nvd_ranges(window)
    for e in fresh:
        existing[_nvd_range_key(e)] = e

    cutoff = time.strftime(
        "%Y-%m-%d",
        time.gmtime(time.time() - NVD_RANGES_RETAIN_DAYS * 86400))
    entries = [e for e in existing.values()
               if (e.get("published") or "9999-12-31") >= cutoff]
    entries.sort(
        key=lambda e: (e.get("published") or "", e.get("cve") or ""),
        reverse=True)

    out_doc = {"synced_at": time.time(), "window_days": window,
               "entries": entries}
    INTEL.mkdir(parents=True, exist_ok=True)
    tmp = NVD_RANGES_OUT.with_suffix(".tmp")
    tmp.write_text(json.dumps(out_doc), encoding="utf-8")
    tmp.replace(NVD_RANGES_OUT)

    count = len(entries)
    entry = {
        "version": f"nvd-{time.strftime('%Y%m%d', time.gmtime())}",
        "entry_count": count, "synced_at": time.time(),
        "delta_from_prev": (count - prev["entry_count"])
        if prev and prev.get("entry_count") is not None else None,
        "window_days": window, "api_key": bool(NVD_API_KEY),
    }
    m["components"]["nvd-ranges"] = entry
    m["history"].append({"component": "nvd-ranges", "at": time.time(),
                         **{k: v for k, v in entry.items()
                            if k != "synced_at"}})
    m["history"] = m["history"][-50:]
    save_manifest(m)
    return {"synced": True, **entry}


def _load_nvd_store() -> dict[tuple, dict]:
    entries: dict[tuple, dict] = {}
    if NVD_RANGES_OUT.is_file():
        try:
            doc = json.loads(NVD_RANGES_OUT.read_text(encoding="utf-8"))
            for e in doc.get("entries", []) or []:
                if e.get("cve") and e.get("product"):
                    entries[_nvd_range_key(e)] = e
        except Exception:  # noqa: BLE001
            entries = {}
    return entries


def _write_nvd_store(entries: list[dict],
                     window_days: int | None) -> None:
    out_doc = {"synced_at": time.time(), "window_days": window_days,
               "entries": entries}
    INTEL.mkdir(parents=True, exist_ok=True)
    tmp = NVD_RANGES_OUT.with_suffix(".tmp")
    tmp.write_text(json.dumps(out_doc), encoding="utf-8")
    tmp.replace(NVD_RANGES_OUT)


def _prune_nvd_entries(entries: dict[tuple, dict]) -> list[dict]:
    cutoff = time.strftime(
        "%Y-%m-%d",
        time.gmtime(time.time() - NVD_RANGES_RETAIN_DAYS * 86400))
    kept = [e for e in entries.values()
            if (e.get("published") or "9999-12-31") >= cutoff]
    kept.sort(
        key=lambda e: (e.get("published") or "", e.get("cve") or ""),
        reverse=True)
    return kept


def _nvd_backfill_entry(count: int, prev: dict | None, total_days: int,
                        state: dict) -> dict:
    return {
        "version": f"nvd-{time.strftime('%Y%m%d', time.gmtime())}-bf",
        "entry_count": count, "synced_at": time.time(),
        "delta_from_prev": (count - prev["entry_count"])
        if prev and prev.get("entry_count") is not None else None,
        "window_days": None, "backfill_days": total_days,
        "oldest_covered": state.get("oldest_covered"),
        "api_key": bool(NVD_API_KEY),
    }


def backfill_nvd_ranges(total_days: int = 730,
                        chunk_days: int = 120,
                        force: bool = False) -> dict:
    """Backfill rentang versi historis (chunk <= 120 hari, resumable).

    State `assets/intel/nvd-backfill-state.json` menyimpan tanggal
    tertua yang sudah tercakup. Interupsi = jalan lagi melanjutkan dari
    titik itu (tanpa --force). Semua chunk di-merge ke indeks yang sama
    dan ditulis atomic per chunk — data lama tidak pernah hilang.
    """
    from datetime import datetime, timedelta, timezone
    if total_days <= 0:
        return {"skipped": True, "reason": "total_days <= 0"}
    now = datetime.now(timezone.utc).replace(microsecond=0)
    target = now - timedelta(days=total_days)
    state: dict = {}
    if NVD_BACKFILL_STATE.is_file():
        try:
            state = json.loads(
                NVD_BACKFILL_STATE.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            state = {}
    cursor = now
    if state.get("oldest_covered") and not force:
        try:
            cur = datetime.fromisoformat(state["oldest_covered"])
            if cur.tzinfo is None:
                cur = cur.replace(tzinfo=timezone.utc)
            if cur < cursor:
                cursor = cur
        except ValueError:
            pass
    if cursor <= target:
        return {"skipped": True, "reason": "rentang sudah tercakup",
                "oldest_covered": _iso_utc(cursor)}

    m = load_manifest()
    prev = m["components"].get("nvd-ranges")
    entries = _load_nvd_store()
    n_chunks = 0
    entry: dict = {}
    while cursor > target:
        start = max(cursor - timedelta(days=min(chunk_days, 120)),
                    target)
        try:
            fresh = _fetch_nvd_window(_iso_utc(start), _iso_utc(cursor))
        except Exception as exc:  # noqa: BLE001
            # Fail-closed: chunk yang sudah selesai tetap tersimpan
            # (store + state + manifest konsisten); jalan lagi = lanjut.
            return {"synced": False, "chunks_done": n_chunks,
                    "error": f"{type(exc).__name__}: {exc}"[:200],
                    "oldest_covered": state.get("oldest_covered")}
        for e in fresh:
            entries[_nvd_range_key(e)] = e
        kept = _prune_nvd_entries(entries)
        _write_nvd_store(kept, window_days=None)
        state = {"oldest_covered": _iso_utc(start),
                 "target_days": total_days,
                 "updated_at": time.time()}
        INTEL.mkdir(parents=True, exist_ok=True)
        tmp = NVD_BACKFILL_STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        tmp.replace(NVD_BACKFILL_STATE)
        entries = {_nvd_range_key(e): e for e in kept}
        cursor = start
        n_chunks += 1
        entry = _nvd_backfill_entry(len(entries), prev, total_days,
                                    state)
        m["components"]["nvd-ranges"] = entry
        m["history"].append({"component": "nvd-ranges",
                             "at": time.time(),
                             **{k: v for k, v in entry.items()
                                if k != "synced_at"}})
        m["history"] = m["history"][-50:]
        save_manifest(m)

    return {"synced": True, "chunks": n_chunks, **entry}


def load_cwe_catalog(path: Path | None = None) -> dict:
    """Katalog CWE lokal -> {cwe_id: {name, status, abstraction}}.
    Fail-closed: file tidak ada = {} (pemanggil melewati audit)."""
    path = path or (INTEL / "cwe-1000.csv")
    if not path.exists():
        return {}
    import csv
    import io
    out: dict = {}
    with path.open(encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            cid = (row.get("CWE-ID") or "").strip()
            if not cid.isdigit():
                continue
            out[f"CWE-{int(cid)}"] = {
                "name": (row.get("Name") or "").strip(),
                "status": (row.get("Status") or "").strip(),
                "abstraction": (row.get("Weakness Abstraction")
                                or "").strip(),
            }
    return out


def sync_cwe(force: bool = False) -> dict:
    """Sinkronkan katalog CWE MITRE (csv view 1000, zip). Versi = header
    HTTP Last-Modified zip (deterministik + drift-terdeteksi)."""
    m = load_manifest()
    prev = m["components"].get("cwe")
    ttl = TTL_HOURS["cwe"]
    if not force and not should_sync(prev, ttl):
        return {"skipped": True, "reason": "TTL segar", "prev": prev}

    req = urllib.request.Request(CWE_CSV_URL, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120.0) as r:
        blob = r.read()
        last_modified = (r.headers.get("Last-Modified") or "").strip()
    import io
    import zipfile
    zf = zipfile.ZipFile(io.BytesIO(blob))
    names = [n for n in zf.namelist() if n.endswith(".csv")]
    if not names:
        raise RuntimeError("arsip CWE tidak berisi CSV — dibatalkan")
    text = zf.read(names[0]).decode("utf-8", "replace")
    rows = text.splitlines()
    count = max(0, len(rows) - 1)  # tanpa header
    version = last_modified or f"rows:{count}"
    (INTEL / "cwe-1000.csv").write_text(text, encoding="utf-8")
    entry = {
        "version": version, "entry_count": count, "synced_at": time.time(),
        "delta_from_prev": (count - prev["entry_count"]) if prev else None,
    }
    m["components"]["cwe"] = entry
    m["history"].append({"component": "cwe", "at": time.time(),
                         **{k: v for k, v in entry.items()
                            if k != "synced_at"}})
    m["history"] = m["history"][-50:]
    save_manifest(m)
    return {"synced": True, **entry}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--components", default="nuclei-templates,kev,cwe,"
                    "watchlist,nvd-ranges",
                    help="komponen dipisah koma (default: semua)")
    ap.add_argument("--check", action="store_true",
                    help="cek status segar saja, tanpa unduh")
    ap.add_argument("--verify", action="store_true",
                    help="verifikasi fail-closed: hitung aktual vs manifest, "
                         "laporkan AV deletions & delta, exit 2 bila mismatch")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--backfill-days", type=int, default=0,
                    help="backfill rentang versi historis N hari "
                         "(chunk <=120 hari, resumable); 0 = mati")
    ap.add_argument("--out", default=None,
                    help="tulis hasil sebagai findings.json kontrak "
                         "(memungkinkan dijadwalkan lewat worker)")
    args = ap.parse_args()

    if getattr(args, "backfill_days", 0) > 0:
        res = backfill_nvd_ranges(args.backfill_days, force=args.force)
        print(json.dumps({"nvd-ranges-backfill": res}, indent=2,
                         ensure_ascii=False))
        return 0

    wanted = {c.strip() for c in args.components.split(",") if c.strip()}
    if args.verify:
        return verify_counts(wanted)
    m = load_manifest()
    results = {}
    if "nuclei-templates" in wanted:
        prev = m["components"].get("nuclei-templates")
        if args.check:
            results["nuclei-templates"] = {
                "fresh": not should_sync(prev, TTL_HOURS["nuclei-templates"]),
                "current": prev,
            }
        else:
            results["nuclei-templates"] = sync_nuclei_templates(args.force)
    if "kev" in wanted:
        prev = m["components"].get("kev")
        if args.check:
            results["kev"] = {
                "fresh": not should_sync(prev, TTL_HOURS["kev"]),
                "current": prev,
            }
        else:
            results["kev"] = sync_kev(args.force)
    if "cwe" in wanted:
        prev = m["components"].get("cwe")
        if args.check:
            results["cwe"] = {
                "fresh": not should_sync(prev, TTL_HOURS["cwe"]),
                "current": prev,
            }
        else:
            results["cwe"] = sync_cwe(args.force)
    if "watchlist" in wanted:
        prev = m["components"].get("watchlist")
        if args.check:
            results["watchlist"] = {
                "fresh": not should_sync(prev, TTL_HOURS["watchlist"]),
                "current": prev,
            }
        else:
            results["watchlist"] = sync_watchlist(args.force)
    if "nvd-ranges" in wanted:
        prev = m["components"].get("nvd-ranges")
        if args.check:
            results["nvd-ranges"] = {
                "fresh": not should_sync(prev, TTL_HOURS["nvd-ranges"]),
                "current": prev,
            }
        else:
            results["nvd-ranges"] = sync_nvd_ranges(args.force)

    print(json.dumps(results, indent=2, ensure_ascii=False))

    # Kontrak findings.json: hasil sync jadi temuan inventaris teraudit
    # (L0 OBSERVED) — bisa dijadwalkan lewat worker dan masuk satu pintu.
    if args.out:
        sys.path.insert(0, str(ROOT / "core"))
        from findings import make_finding, write_findings
        rows = []
        for comp, r in results.items():
            skipped = bool(r.get("skipped"))
            detail = r.get("prev", r) if skipped else r
            if comp == "nuclei-templates":
                title = (f"Intel corpus fresh: nuclei-templates "
                         f"{detail.get('template_count', '?')} template "
                         f"(versi {detail.get('version', '?')}, delta "
                         f"{detail.get('delta_from_prev')})")
            elif comp == "kev":
                title = (f"Intel feed fresh: CISA KEV {detail.get('entry_count', '?')} "
                         f"entri (versi {detail.get('version', '?')}, delta "
                         f"{detail.get('delta_from_prev')})")
            elif comp == "watchlist":
                title = (f"Intel watchlist: {detail.get('seed_count', '?')} "
                         f"seed kurasi + {detail.get('nvd_count', '?')} "
                         f"NVD-critical (jendela "
                         f"{detail.get('window_days', '?')} hari, delta "
                         f"{detail.get('delta_from_prev')})")
            elif comp == "nvd-ranges":
                title = (f"Intel NVD ranges: {detail.get('entry_count', '?')} "
                         f"entri rentang versi (versi "
                         f"{detail.get('version', '?')}, delta "
                         f"{detail.get('delta_from_prev')})")
            else:
                title = f"Intel sync {comp}: {json.dumps(r)[:100]}"
            rows.append(make_finding(
                tool="intel-sync",
                title=title + (" [TTL segar, dilewati]" if skipped else ""),
                severity="info",
                description="Inventaris intelijen pindai ter-update otomatis. "
                            "Hasil sync terekam di manifest (versi + delta) — "
                            "dapat diaudit, tidak ada unduhan senyap.",
                target_url=None,
                evidence_kind="file-manifest",
                finding_class="posture",
                confidence=1.0,
                status="confirmed",
                verdict=0,
                extra={"category": "INTEL", "safety_class": "read-only",
                       "detail": r},
            ))
        write_findings(args.out, rows, {
            "run": "intel-sync", "method": "manifest",
            "safety_class": "read-only", "requests": 0,
            "components": sorted(results.keys()),
        })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
