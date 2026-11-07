"""[CONTRIB] CVE sweep — intake pipeline kontribusi dari NVD 2.0 API.

Satu perintah yang menyapu CVE baru dalam jendela waktu dan men-triage
kandidat yang LAYAK DIKONTRIBUSIKAN (template deteksi / koreksi advisory):
network-reachable (AV:N), skor >= ambang, punya deskripsi EN, dan
ber-flag sinyal yang sudah terbukti di lapangan:
  - has_patch   : ada referensi commit/release/advisory upstream
  - auth_free   : vektor CVSS PR:N (tanpa privilese) dan deskripsi tidak
                  menyebut autentikasi
  - denied      : kategori yang berulang kali ditolak maintainer
                  (DoS, XSS library, RCE, dsb.) — di-skip, bukan dikerjakan

Flag adalah HEURISTIK dari data publik (vektor CVSS + deskripsi + refs) —
kandidat tetap wajib riset manual + anti-dup sebelum dikerjakan
(`tools/antidup_check.py`). Bukan pengganti intel_sync: ini intake untuk
pipeline kontribusi operator, bukan sync cakupan deteksi.

Pemakaian:
  python tools/cve_sweep.py                          # 24 jam terakhir
  python tools/cve_sweep.py --since 2026-11-06T17:10:00
  python tools/cve_sweep.py --keyword wordpress      # keywordSearch NVD
  python tools/cve_sweep.py --state sweep-state.txt --out kandidat.json

State (`--state`, satu CVE ID per baris) membuat sweep berulang menjadi
inkremental: ID yang sudah tercatat dilewati, ID baru di-append SEBELUM
analisa (jangan hilangkan ID baru saat sesi putus).

Gotcha NVD yang sudah dibungkus di sini:
  - tanggal WAJIB offset zona (`+00:00`) dan di-URL-encode — tanggal
    polos menghasilkan 404 yang misleading;
  - tanpa API key, NVD membatasi laju permintaan — pagination di-sleep,
    429/403 di-retry dengan backoff, bukan dianggap gagal.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 200
MAX_PAGES_DEFAULT = 40
RETRY_DELAYS = (10.0, 20.0, 40.0)

# Pola kategori yang berulang kali ditolak maintainer template/advisory
# (dialihkan ke "skip dan catat", bukan dikerjakan).
DENIED_PATTERNS: tuple[tuple[str, str], ...] = tuple(
    (re.compile(pat, re.IGNORECASE), label)
    for pat, label in (
        (r"\bcross[- ]site scripting\b|\bxss\b", "xss"),
        (r"\bsql(?:i| injection)\b", "sqli"),
        (r"\bremote code execution\b|\brce\b", "rce"),
        (r"\barbitrary file (?:upload|write)\b|\bfile upload\b", "upload"),
        (r"\bdeserializ", "deserialization"),
        (r"\bdenial of service\b|\bdo?s\b|\bresource consumption\b"
         r"|\bhang(?:s|ing)?\b",
         "dos"),
        (r"\bcommand injection\b", "command-injection"),
        (r"\bsandbox escape\b|\bprototype pollution\b", "client-lib"),
    )
)

# Sinyal deskripsi bahwa eksploitasi butuh privilese/session.
AUTH_REQUIRED_PATTERNS = (
    re.compile(r"\bauthenticat", re.IGNORECASE),
    re.compile(r"\blogged[- ]?in\b|\bprivileged user\b|\badmin(?:istrator)?\b",
               re.IGNORECASE),
    re.compile(r"\bwith a valid (?:session|token|csrf)\b", re.IGNORECASE),
)

# Referensi yang menandakan ada patch/riwayat perbaikan yang bisa
# diverifikasi (syarat minimal: jangan kerjakan tanpa release patched).
PATCH_REF_PATTERNS = (
    re.compile(r"/commit/", re.IGNORECASE),
    re.compile(r"/releases/tag/", re.IGNORECASE),
    re.compile(r"security/advisories", re.IGNORECASE),
    re.compile(r"/pull/\d+", re.IGNORECASE),
)

_USER_AGENT = "cyphron-cve-sweep/1.0"


def iso_utc(dt: datetime) -> str:
    """ISO-8601 UTC dengan offset eksplisit — syarat API NVD."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def parse_since(value: str) -> datetime:
    """Parse argumen --since (ISO, boleh tanpa offset -> dianggap UTC)."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def build_params(start: datetime, end: datetime,
                 keyword: str | None = None) -> dict[str, str]:
    """Parameter query NVD dengan tanggal ter-offset dan ter-encode.

    Pure: return dict; encoding URL dilakukan fetch_nvd (urllib.parse
    urlencode di sisi pemanggil tetap aman karena nilai sudah membawa
    offset eksplisit).
    """
    params = {
        "pubStartDate": iso_utc(start),
        "pubEndDate": iso_utc(end),
        "resultsPerPage": str(RESULTS_PER_PAGE),
    }
    if keyword:
        params["keywordSearch"] = keyword
    return params


def extract_cvss(cve: dict) -> tuple[float | None, str]:
    """Ambil (skor, vektor) dari metrik CVSS dengan prioritas v4.0 → v2.0."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            vector = data.get("vectorString") or ""
            if score is not None:
                return float(score), vector
    return None, ""


def classify(cve: dict, score: float, vector: str) -> dict:
    """Flag heuristik kelayakan kontribusi dari data publik.

    Return dict flag: has_patch, auth_free, denied, denied_reason.
    Pure — tidak memanggil jaringan.
    """
    desc = next((d["value"] for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    refs = [r.get("url", "") for r in cve.get("references", [])]
    has_patch = any(p.search(u) for u in refs for p in PATCH_REF_PATTERNS)

    privileged_vector = "PR:L" in vector or "PR:H" in vector
    auth_by_desc = any(p.search(desc) for p in AUTH_REQUIRED_PATTERNS)
    auth_free = ("AV:N" in vector and not privileged_vector
                 and not auth_by_desc)

    denied, denied_reason = False, ""
    for pat, label in DENIED_PATTERNS:
        if pat.search(desc):
            denied, denied_reason = True, label
            break

    return {
        "has_patch": has_patch,
        "auth_free": auth_free,
        "denied": denied,
        "denied_reason": denied_reason,
    }


def filter_candidates(cves: list[dict], min_score: float,
                      seen: set[str]) -> tuple[list[dict], int]:
    """Triage daftar CVE mentah -> kandidat terurut skor menurun.

    Return (kandidat, jumlah_baru). Kandidat = skor >= min_score, AV:N,
    punya deskripsi EN, belum ada di `seen`, dan tidak ber-flag denied.
    `auth_free` TIDAK menyaring (hanya flag) — beberapa pola yang
    diterima maintainer tetap melibatkan sesi/CSRF; sinyal itu dilaporkan,
    keputusan di operator.
    """
    candidates: list[dict] = []
    new_count = 0
    for cve in cves:
        cid = cve.get("id", "")
        if not cid or cid in seen:
            continue
        new_count += 1
        score, vector = extract_cvss(cve)
        if score is None or score < min_score:
            continue
        if "AV:N" not in vector:
            continue
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        if not desc:
            continue
        flags = classify(cve, score, vector)
        if flags["denied"]:
            continue
        candidates.append({
            "id": cid,
            "score": score,
            "vector": vector,
            "description": desc,
            "references": [r.get("url", "") for r in
                           cve.get("references", [])],
            "flags": flags,
        })
    candidates.sort(key=lambda c: (-c["score"], c["id"]))
    return candidates, new_count


def load_state(path: Path) -> set[str]:
    """Baca state seen (satu CVE ID per baris); file hilang = kosong."""
    if not path.exists():
        return set()
    return {line.strip() for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()}


def update_state(path: Path, ids: list[str]) -> None:
    """Append ID baru ke state — dipanggil SEBELUM analisa detail."""
    if not ids:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for cid in sorted(ids):
            fh.write(cid + "\n")


def fetch_nvd(params: dict[str, str],
              max_pages: int = MAX_PAGES_DEFAULT) -> list[dict]:
    """Fetch penuh satu window NVD dengan pagination + retry backoff.

    Fail-closed: kalau satu halaman gagal permanen, exception naik —
    JANGAN melanjutkan dengan data setengah jendela (bisa mengira
    'tidak ada CVE baru' padahal cuma jaringan yang putus).
    """
    fetched: list[dict] = []
    start_index = 0
    for _ in range(max_pages):
        page_params = dict(params)
        page_params["startIndex"] = str(start_index)
        url = NVD_URL + "?" + urllib.parse.urlencode(page_params)
        data = _fetch_json(url)
        # tiap item = {"cve": {...}} — ambil objek CVE-nya, bukan wrapper
        fetched.extend(item["cve"] for item in data.get("vulnerabilities", [])
                       if isinstance(item, dict) and item.get("cve"))
        total = int(data.get("totalResults", 0))
        start_index += int(data.get("resultsPerPage", 0))
        if total == 0 or start_index >= total:
            break
        time.sleep(7.0)
    return fetched


def _fetch_json(url: str) -> dict:
    """GET JSON dengan retry backoff untuk 403/429 (rate limit NVD)."""
    last_err: Exception | None = None
    for delay in (0.0,) + RETRY_DELAYS:
        if delay:
            time.sleep(delay)
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": _USER_AGENT,
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            last_err = exc
            if exc.code not in (403, 429, 503):
                raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
    raise RuntimeError(f"NVD fetch gagal permanen setelah retry: {last_err}")


def run(start: datetime, keyword: str | None, min_score: float,
        state_path: Path, out_path: Path | None,
        max_pages: int) -> dict:
    """Alur utama: sweep -> state append -> triage -> laporan."""
    end = datetime.now(timezone.utc)
    params = build_params(start, end, keyword)
    raw = fetch_nvd(params, max_pages=max_pages)

    # Append SEMUA ID baru ke state sebelum analisa — sesi putus tidak
    # boleh membuat window ini disapu ulang dari nol besok. Tapi triage
    # memakai snapshot seen SEBELUM append (ID baru hari ini harus tetap
    # lolos triage, bukan terbuang karena barusan saja dicatat).
    seen_before = load_state(state_path)
    new_ids = [c["id"] for c in raw if c.get("id") and c["id"] not in seen_before]
    update_state(state_path, new_ids)

    candidates, new_count = filter_candidates(raw, min_score, seen_before)

    report = {
        "generated_at": iso_utc(end),
        "window": {"start": params["pubStartDate"],
                   "end": params["pubEndDate"],
                   "keyword": keyword},
        "total_fetched": len(raw),
        "new_ids": new_count,
        "candidates": candidates,
        "notes": [
            "flags adalah heuristik publik — riset manual + "
            "tools/antidup_check.py wajib sebelum mengerjakan kandidat",
        ],
    }
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sweep + triage CVE baru dari NVD 2.0 untuk pipeline "
                    "kontribusi (template/advisory).")
    parser.add_argument(
        "--since", default=None,
        help="mulai window ISO-8601 (default: state terakhir, atau 24 jam)")
    parser.add_argument("--keyword", default=None,
                        help="keywordSearch NVD, mis. wordpress")
    parser.add_argument("--min-score", type=float, default=5.0,
                        help="ambang CVSS (default 5.0)")
    parser.add_argument("--state", default="cve-sweep-state.txt",
                        help="file state seen (default cve-sweep-state.txt)")
    parser.add_argument("--out", default=None,
                        help="tulis laporan JSON ke file ini")
    parser.add_argument("--max-pages", type=int,
                        default=MAX_PAGES_DEFAULT,
                        help="pagi maksimum (safety, default 40)")
    args = parser.parse_args(argv)

    state_path = Path(args.state)
    if args.since:
        start = parse_since(args.since)
    elif state_path.exists() and state_path.stat().st_size:
        # Lanjutkan dari ujung state: 30 menit sebelum file state terakhir
        # diubah (aman terhadap sweep yang kepotong di tengah window).
        start = (datetime.fromtimestamp(state_path.stat().st_mtime,
                                        tz=timezone.utc)
                 - timedelta(minutes=30))
    else:
        start = datetime.now(timezone.utc) - timedelta(hours=24)

    report = run(start, args.keyword, args.min_score, state_path,
                 Path(args.out) if args.out else None, args.max_pages)

    print(f"window  : {report['window']['start']} -> "
          f"{report['window']['end']}")
    print(f"fetched : {report['total_fetched']} "
          f"({report['new_ids']} ID baru ke state)")
    print(f"kandidat: {len(report['candidates'])} (skor >= "
          f"{args.min_score}, AV:N, tanpa kategori denied)")
    for c in report["candidates"]:
        flags = c["flags"]
        marks = []
        if flags["has_patch"]:
            marks.append("patch")
        if not flags["auth_free"]:
            marks.append("auth?")
        print(f"  {c['id']:<18} {c['score']:<4} "
              f"{'[' + ','.join(marks) + ']' if marks else '[?]'} "
              f"{c['description'][:90]}")
    if args.out:
        print(f"laporan : {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
