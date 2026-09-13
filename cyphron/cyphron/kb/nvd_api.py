"""Sinkron NVD via API 2.0 — jalur resmi saat feed JSON 1.1 tidak lagi
terlayani (HTTP 403 di kb_sync nyata, Sep 2026).

Cara kerja: per tahun, potong jadi jendela <=120 hari (batas API), paginasi
resultsPerPage=2000, throttle bawaan 6.0 dtk (≤5 req/30 dtk tanpa API key;
dengan key set --throttle 0.7). Hasil dikonversi ke bentuk feed-1.1
("CVE_Items") supaya kb/nvd_sqlite.py tidak berubah.

Simpan: kb/data/nvd/nvd-api-<tahun>.json.gz (format sama dengan feed).
"""

from __future__ import annotations

import datetime as _dt
import gzip
import json
import time
from pathlib import Path

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
DEFAULT_THROTTLE_S = 6.0  # tanpa API key: maks 5 req / 30 dtk


def _year_windows(year: int) -> list[tuple[str, str]]:
    start = _dt.date(year, 1, 1)
    end_of_year = _dt.date(year, 12, 31)
    windows = []
    while start <= end_of_year:
        end = min(start + _dt.timedelta(days=119), end_of_year)
        windows.append((start.isoformat() + "T00:00:00.000",
                        end.isoformat() + "T23:59:59.999"))
        start = end + _dt.timedelta(days=1)
    return windows


def api_to_feed_item(vuln: dict) -> dict | None:
    """Entri API 2.0 {"cve": {...}} -> bentuk item feed 1.1 (subset yang
    dipakai nvd_sqlite). None bila struktur tidak dikenal."""
    cve = (vuln or {}).get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en" and d.get("value"):
            desc = d["value"][:500]
            break
    cwe = ""
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = d.get("value") or ""
            if val.startswith("CWE-"):
                cwe = val
                break
        if cwe:
            break
    score = None
    vector = ""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            data = (arr[0] or {}).get("cvssData") or {}
            try:
                score = float(data.get("baseScore"))
            except (TypeError, ValueError):
                score = None
            vector = data.get("vectorString") or ""
            if score is not None:
                break
    pairs = []
    for conf in cve.get("configurations") or []:
        for node in (conf or {}).get("nodes") or []:
            for m in (node or {}).get("cpeMatch") or []:
                if not m.get("criteria"):
                    continue
                pairs.append({
                    "cpe23Uri": m["criteria"], "vulnerable": True,
                    "versionStartIncluding": m.get("versionStartIncluding"),
                    "versionEndIncluding": m.get("versionEndIncluding"),
                    "versionStartExcluding": m.get("versionStartExcluding"),
                    "versionEndExcluding": m.get("versionEndExcluding"),
                })
    item: dict = {
        "cve": {
            "CVE_data_meta": {"ID": cve_id},
            "description": {"description_data": [{"lang": "en",
                                                  "value": desc}]},
            "problemtype": {"problemtype_data": [{"description": [
                {"value": cwe or "NVD-CWE-noinfo"}]}]},
        },
        "config": {"nodes": [{"operator": "OR", "cpe_match": pairs}]},
        "publishedDate": cve.get("published") or "",
        "lastModifiedDate": cve.get("lastModified") or "",
    }
    if score is not None:
        item["impact"] = {"baseMetricV3": {"cvssV3": {
            "baseScore": score, "vectorString": vector}}}
    return item


def sync_nvd_api(kb_dir: Path, years=None, fetch=None,
                 throttle_s: float = DEFAULT_THROTTLE_S,
                 api_key: str | None = None) -> dict:
    """Unduh CVE per tahun via API 2.0; tulis nvd-api-<tahun>.json.gz.
    fetch None = unduhan nyata (User-Agent + header apiKey bila diisi);
    test menyuntikkan fetch sendiri (tanpa jaringan)."""
    import urllib.request

    if fetch is None:
        def fetch(url: str, timeout: float = 180.0) -> bytes:
            headers = {"User-Agent": "cyphron-kb/1.0"}
            if api_key:
                headers["apiKey"] = api_key
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()

    years = list(years) if years is not None else list(range(2018, 2027))
    out_dir = kb_dir / "nvd"
    out_dir.mkdir(parents=True, exist_ok=True)
    total = 0
    done_years = []
    for year in years:
        items: list[dict] = []
        for start, end in _year_windows(year):
            idx = 0
            total_results = None
            while total_results is None or idx < total_results:
                url = (f"{API_URL}?pubStartDate={start}&pubEndDate={end}"
                       f"&resultsPerPage={RESULTS_PER_PAGE}&startIndex={idx}")
                blob = fetch(url)
                data = json.loads(blob.decode("utf-8", errors="replace"))
                total_results = data.get("totalResults", 0)
                for vuln in data.get("vulnerabilities") or []:
                    item = api_to_feed_item(vuln)
                    if item is not None:
                        items.append(item)
                idx += RESULTS_PER_PAGE
                if idx < total_results:
                    time.sleep(throttle_s)
        blob_out = gzip.compress(
            json.dumps({"CVE_Items": items},
                       ensure_ascii=False).encode("utf-8"))
        (out_dir / f"nvd-api-{year}.json.gz").write_bytes(blob_out)
        total += len(items)
        done_years.append(year)
    return {"origin": API_URL, "years": done_years, "cves": total,
            "summary": (f"API 2.0 {len(done_years)} tahun "
                        f"({done_years[0]}-{done_years[-1]}), {total} CVE")}
