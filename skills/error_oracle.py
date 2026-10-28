"""[SAFETY: 1-request] error-oracle — error page sebagai oracle bocoran
(CWE-209): SATU GET ke path canary acak (dijamin bukan halaman nyata),
body diklasifikasi dengan signature KETAT:
  - error database (SQL syntax, exception driver) -> L2;
  - stack trace aplikasi (Python/Java/Go/.NET)     -> L2;
  - halaman debug framework (Werkzeug, DEBUG=True, Xdebug,
    ASP.NET source error)                          -> L1.
Halaman 404 generik = AMAN. Status 403/429 (WAF/challenge) = tanpa
klaim (pelajaran FP: refleksi halaman challenge bukan sinyal aplikasi).
Signature berbasis multi-kata spesifik — kata generik ("error",
"exception" sendirian) tidak pernah dihitung.
"""
from __future__ import annotations

import argparse
import re
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()

# error database — multi-kata spesifik, lowercase
DB_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "unterminated quoted string",
    "sqlite3.operationalerror",
    "sqlite3.syntaxerror",
    "sqlite error",
    "pdoexception",
    "sqlstate[",
    "pg::syntaxerror",
    "pg::error",
    "syntax error at or near",
    "syntax error in query expression",
    "mysqlsyntaxerrorexception",
    "sql syntax error",
)
# stack trace aplikasi — multi-kata/posisi spesifik
STACK_SIGNATURES = (
    "traceback (most recent call last)",
    "file \"",                 # python traceback frame
    ".py\", line",
    "at java.",                # java stack frame
    "at org.",
    "at sun.reflect",
    "at com.",
    "javax.servlet.servletexception",
    "org.apache.catalina",
    "exception in thread",
    "panic: runtime error",    # go
    "goroutine ",
    "system.nullreferenceexception",  # .NET
    "at microsoft.",
    "stack trace:",
)

# halaman debug framework — banner spesifik
DEBUG_SIGNATURES = (
    "werkzeug debugger",
    "you're seeing this error because debug",
    "django.views.debug",
    "xdebug",
    "app_debug",
    "server error in '/' application",
    "source error:",
    "an unhandled exception occurred",
)

_ORA_RE = re.compile(r"ora-\d{5}")


def _match(body: str) -> str | None:
    low = body.lower()
    for sig in DB_SIGNATURES:
        if sig in low:
            return f"db:{sig}"
    if _ORA_RE.search(low):
        return f"db:{_ORA_RE.search(low).group(0)}"
    for sig in STACK_SIGNATURES:
        if sig in low:
            return f"stack:{sig}"
    for sig in DEBUG_SIGNATURES:
        if sig in low:
            return f"debug:{sig}"
    return None


def probe(base_url: str, timeout: float = 15.0) -> dict:
    """SATU GET ke path canary acak (per-run, tak masuk cache)."""
    path = f"/cyphron-err-{secrets.token_hex(8)}"
    req = urllib.request.Request(base_url.rstrip("/") + path,
                                 headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "body": r.read(64_000).decode("utf-8", "replace"),
                    "path": path}
    except urllib.error.HTTPError as e:
        try:
            body = (e.read(64_000) or b"").decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body, "path": path}
    except Exception as exc:
        return {"status": None, "body": "", "path": path,
                "error": type(exc).__name__}


def audit(base_url: str, result: dict) -> tuple[list[dict], dict]:
    status = result.get("status")
    body = result.get("body", "")
    hit = _match(body) if body else None

    if result.get("error") or status is None:
        rows = [make_finding(
            tool="error-oracle",
            title=f"Error oracle on {base_url} — tidak dapat dinilai",
            severity="info",
            description=(f"Request gagal ({result.get('error')}) — error "
                         "page tidak dinilai (tanpa klaim, fail-closed)."),
            target_url=base_url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "1-request"})]
        return rows, {"url": base_url, "hit": None, "error": True}
    if status in (403, 429):
        # pelajaran FP: halaman challenge/WAF bukan sinyal aplikasi
        rows = [make_finding(
            tool="error-oracle",
            title=f"Error oracle on {base_url} — interferensi WAF/challenge",
            severity="info",
            description=f"Status {status} pada path canary — respons "
                        "kemungkinan halaman challenge/WAF, bukan error "
                        "aplikasi; tidak dinilai (tanpa klaim).",
            target_url=base_url,
            response=body[:200],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "1-request",
                   "status": status})]
        return rows, {"url": base_url, "hit": None, "waf": True}

    kind = hit.split(":", 1)[0] if hit else None
    if hit:
        verdict = 2 if kind in ("db", "stack") else 1
        sev = "medium" if verdict == 2 else "low"
        cwe = "CWE-209"
        cat = {"db": "ERROR-DISCLOSURE", "stack": "ERROR-DISCLOSURE",
               "debug": "DEBUG-EXPOSURE"}[kind]
        rows = [make_finding(
            tool="error-oracle",
            title=f"Verbose error disclosure on {base_url} ({kind})",
            severity=sev,
            description=f"Error page pada path canary memuat signature "
                        f"'{hit}' — detail internal ({'exception database'
                        if kind == 'db' else 'stack trace aplikasi'
                        if kind == 'stack' else 'halaman debug framework'}) "
                        "terbuka untuk pengunjung biasa; bisa jadi oracle "
                        "untuk menyusun serangan lanjutan.",
            recommendation="Halaman error generik untuk end-user; catat "
                           "detail ke log server saja.",
            cwe=cwe,
            target_url=base_url,
            response=body[:300],
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=verdict,
            extra={"category": cat, "safety_class": "1-request",
                   "signature": hit})]
        return rows, {"url": base_url, "hit": hit}

    rows = [make_finding(
        tool="error-oracle",
        title=f"Error oracle posture on {base_url}",
        severity="info",
        description="Halaman error path canary TIDAK memuat signature "
                    "database/stack-trace/debug — error generik "
                    "(AMAN/inventaris).",
        target_url=base_url,
        response=body[:200],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=0,
        extra={"category": "AMAN", "safety_class": "1-request"})]
    return rows, {"url": base_url, "hit": None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="error_oracle_findings.json")
    args = ap.parse_args()
    result = probe(args.url)
    rows, meta = audit(args.url, result)
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    print(f"error-oracle: {len(rows)} baris (hit={meta.get('hit', 0)}) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
