"""[SAFETY: bounded-requests] file-exposure-checker — backup/SCM file
terbuka di path umum (CWE-538/200) — port dari dir_probe legacy.

5 GET (satu per path kandidat, sesuai estimasi budget bounded-requests).
ZERO-FP: path dianggap TERBUKA hanya bila status 200 DAN isi respons
cocok dengan bentuk khas file-nya (magic/signature), bukan halaman
error/log-in generik:

  /.git/config    -> baris "[core]" / "[branch" / "[remote"
  /.env           -> baris KEY=value (≥1, kunci huruf/underscore)
  /.svn/wc.db     -> magic SQLite "SQLite format 3"
  /.DS_Store      -> magic Bud1
  /backup.zip     -> magic PK\x03\x04

Fail-closed: 404/403/redirect = bukan temuan (AMAN).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
MAX_PATHS = 5  # = estimasi bounded-requests orchestrator; jangan dilebihi

# (path, nama, verifikasi bentuk isi) — verifikasi bentuk = zero-FP
CANDIDATES = [
    ("/.git/config", "git-config",
     lambda b: any(f"[{s}" in b for s in ("core", "branch", "remote"))),
    ("/.env", "dotenv",
     lambda b: any(__import__("re").match(r"[A-Za-z_][A-Za-z0-9_]*\s*=",
                                          line) for line in b.splitlines())),
    ("/.svn/wc.db", "svn-wcdb",
     lambda b: b.startswith("SQLite format 3")),
    ("/.DS_Store", "ds-store",
     lambda b: b.startswith(b"\x00\x00\x00\x01Bud1".decode("latin-1"))),
    ("/backup.zip", "backup-archive",
     lambda b: b.startswith("PK\x03\x04")),
]


def probe(base_url: str, timeout: float = 15.0) -> dict:
    """SATU GET per path kandidat (maks 5). Return {path: hasil}."""
    out: dict = {}
    for path, name, _check in CANDIDATES[:MAX_PATHS]:
        req = urllib.request.Request(base_url.rstrip("/") + path,
                                     headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(4096).decode("utf-8", "replace")
                out[path] = {"status": r.status, "body": body}
        except urllib.error.HTTPError as e:
            out[path] = {"status": e.code, "body": ""}
        except Exception as exc:
            out[path] = {"status": None, "error": f"{type(exc).__name__}"}
    return out


def audit(base_url: str, results: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    shape_by_path = {p: n for p, n, _ in CANDIDATES}
    exposed = []
    for path, res in results.items():
        check = next((c for p, _n, c in CANDIDATES if p == path), None)
        if res.get("status") == 200 and check and check(res.get("body", "")):
            name = shape_by_path[path]
            exposed.append(path)
            rows.append(make_finding(
                tool="file-exposure-checker",
                title=f"Sensitive file exposed on {base_url}{path} ({name})",
                severity="medium",
                description=f"File '{name}' terbuka tanpa otentikasi di "
                            f"{path} — isi cocok dengan bentuk khas file "
                            "(verifikasi signature, bukan halaman generik). "
                            "Repo metadata/.env/backup = peta serangan + "
                            "kredensial potensial (lead).",
                recommendation="Blokir akses publik ke path SCM/backup "
                               "(web server rule), pindahkan di luar "
                               "webroot, hapus dari deploy.",
                cwe="CWE-538",
                target_url=base_url.rstrip("/") + path,
                response=str(res.get("body", ""))[:300],
                evidence_kind="request-response", finding_class="weakness",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "EXPOSURE", "safety_class":
                       "bounded-requests", "file_kind": name,
                       "path": path}))
    rows.append(make_finding(
        tool="file-exposure-checker",
        title=f"File exposure posture on {base_url}",
        severity="info",
        description=(f"{len(exposed)} dari {len(results)} path kandidat "
                     f"terbuka: {exposed}" if exposed else
                     "Tidak ada file backup/SCM terbuka pada 5 path "
                     "kandidat (AMAN, inventaris)."),
        target_url=base_url,
        response=json.dumps({p: r.get("status") for p, r in
                             results.items()})[:300],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed",
        verdict=1 if exposed else 0,
        extra={"category": "EXPOSURE" if exposed else "AMAN",
               "safety_class": "bounded-requests",
               "exposed": exposed, "checked": len(results)}))
    return rows, {"url": base_url, "requests": len(results),
                  "exposed": exposed}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="file_exposure_findings.json")
    args = ap.parse_args()
    results = probe(args.url)
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"file-exposure-checker: {len(rows)} temuan "
          f"({len(meta.get('exposed', []))} terbuka, {meta.get('requests', 0)} request) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
