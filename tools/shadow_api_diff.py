r"""[SAFETY: read-only] shadow_api_diff — diff OFFLINE endpoint API yang
TERAMATI di access log vs yang TERDOKUMENTASI di spesifikasi OpenAPI —
shadow/zombie API (endpoint di luar dokumentasi, atau didokumentasi tapi
tak pernah dipakai). TANPA jaringan.

Input -> mekanisme -> output:
  - Input : --spec openapi.json (dokumen OpenAPI 2/3 versi JSON) ATAU
            --paths file teks (satu "METHOD /path" atau "/path" per
            baris), plus --log access log (Combined/Common Log Format
            atau JSONL per baris dgn field method/path/status/ip).
  - Mekanisme: setiap request teramati dicocokkan ke template path
            terdokumentasi ({param} -> [^/]+); tak cocok = shadow.
            Volume/keunikan IP/status menentukan skor risiko.
  - Output: temuan {check, severity, method, path, ...} + stats.

Cek:
  shadow-endpoint       (score) : endpoint teramati TIDAK cocok ke
                                  dokumentasi (kandidat shadow API).
  unobserved-documented (low)   : endpoint terdokumentasi yang tak
                                  pernah teramati di log — kandidat
                                  zombie API (inventaris, bukan
                                  temuan serangan).

Skor risiko shadow (dari ditulis eksplisit):
  +3 tanpa header Authorization teramati (JSON log saja; CLF tidak
     merekam header -> +1 "tidak diketahui", dicatat di meta)
  +2 volume > 1000 request; +1 volume > 100
  +2 IP sumber unik > 10
  +1 pernah mendapat respons 2xx (endpoint berfungsi)
  severity: >=5 high; >=3 medium; sisanya low.

Fail-closed:
  - spec tidak ada / bukan JSON / nol path  -> exit 2.
  - log tidak ada / NOL baris ter-parse     -> exit 2.
  - baris log rusak dicatat di meta (maks 20), tidak dibuang diam.
  - presence header auth hanya dinilai utk JSON log; CLF = "tidak
    diketahui" (tidak pernah pura-pura memeriksa).

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error.

Pemakaian:
  python tools/shadow_api_diff.py --spec openapi.json --log access.log
  python tools/shadow_api_diff.py --spec api.json --log lb.jsonl \\
      --prefix /api --fail-on high
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

SCHEMA = "secai.shadow-api-diff/1"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_UNPARSED_SAMPLES = 20

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                "OPTIONS")

_CLF_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)')
_REQ_RE = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<uri>\S+)')

_DYNAMIC_SEGS = (
    re.compile(r"^\d+$"),                                # 123
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
               r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),      # uuid
    re.compile(r"^[0-9a-f]{16,}$", re.I),                # hex id
    re.compile(r"^[A-Za-z0-9_-]{20,}$"),                 # token-ish
)


def normalize_observed(path: str) -> str:
    """Path teramati -> template: segmen dinamis -> {var}."""
    segs = path.split("/")
    out = []
    for s in segs:
        if any(rx.match(s) for rx in _DYNAMIC_SEGS):
            out.append("{var}")
        else:
            out.append(s)
    return "/".join(out)


def spec_template_re(spec_path: str) -> re.Pattern[str]:
    """OpenAPI path {param} -> regex [^/]+ (fullmatch)."""
    rx = re.sub(r"\{[^/}]+\}", r"[^/]+", re.escape(spec_path)
                .replace(r"\{", "{").replace(r"\}", "}"))
    return re.compile(f"^{rx}$")


def load_documented(spec_path: "Path | None",
                    paths_file: "Path | None",
                    ) -> dict[str, set[str]]:
    """-> {METHOD: {template_path}} (template = {var} normal form)."""
    documented: dict[str, set[str]] = {m: set() for m in HTTP_METHODS}
    templates: list[str] = []
    if spec_path:
        try:
            doc = json.loads(spec_path.read_text(encoding="utf-8",
                                                 errors="replace"))
        except ValueError as exc:
            raise ValueError(f"{spec_path}: JSON tidak valid ({exc})"
                             ) from None
        paths = doc.get("paths", {}) if isinstance(doc, dict) else {}
        if not isinstance(paths, dict) or not paths:
            raise ValueError(f"{spec_path}: tidak ada objek 'paths'")
        for p, ops in paths.items():
            templates.append(normalize_spec_path(p))
            if isinstance(ops, dict):
                for m in ops:
                    mu = str(m).upper()
                    if mu in HTTP_METHODS:
                        documented[mu].add(normalize_spec_path(p))
    else:
        for idx, line in enumerate(
                paths_file.read_text(encoding="utf-8",
                                     errors="replace").splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split(None, 1)
            if len(parts) == 2 and parts[0].upper() in HTTP_METHODS:
                m, p = parts[0].upper(), parts[1]
            else:
                m, p = "GET", parts[0]
            if not p.startswith("/"):
                raise ValueError(f"{paths_file}:L{idx}: path tidak "
                                 f"valid '{p}'")
            documented[m].add(normalize_spec_path(p))
            templates.append(normalize_spec_path(p))
    if not any(documented[m] for m in HTTP_METHODS):
        raise ValueError("nol endpoint terdokumentasi ter-parse")
    return documented


def normalize_spec_path(p: str) -> str:
    return re.sub(r"\{[^/}]+\}", "{var}", p)


def parse_log(text: str, src: str) -> tuple[list[dict], list[str]]:
    """Access log CLF/JSONL -> daftar request (method, path, status,
    ip, has_auth). Format tak dikenal pada baris -> unparsed."""
    reqs: list[dict] = []
    unparsed: list[str] = []
    for idx, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                item = json.loads(line)
            except ValueError:
                unparsed.append(f"L{idx}:{line[:120]}")
                continue
            method = str(item.get("method") or
                         item.get("http_method") or "").upper()
            raw_path = str(item.get("path") or item.get("uri") or
                           item.get("url") or "")
            status = item.get("status") or item.get("status_code") or 0
            ip = str(item.get("ip") or item.get("remote_addr") or
                     item.get("client_ip") or "")
            has_auth = bool(item.get("authorization") or
                            item.get("auth_header") or
                            item.get("has_auth"))
            if not raw_path:
                unparsed.append(f"L{idx}: tanpa path")
                continue
            if not status:
                status = 0
            reqs.append({"method": method or "GET", "path": raw_path,
                         "status": int(status), "ip": ip,
                         "auth": "yes" if has_auth else "no",
                         "auth_known": True})
            continue
        m = _CLF_RE.match(line)
        if not m:
            unparsed.append(f"L{idx}:{line[:120]}")
            continue
        rm = _REQ_RE.match(m.group("request").strip())
        if not rm:
            unparsed.append(f"L{idx}:{m.group('request')[:120]}")
            continue
        raw = m.group("request")
        reqs.append({
            "method": rm.group("method"),
            "path": rm.group("uri"),
            "status": int(m.group("status")),
            "ip": m.group("ip"),
            "auth": "yes" if "Authorization" in raw or "authorization" \
                in raw.lower() else "no",
            "auth_known": False,  # CLF tak merekam header
        })
    if not reqs:
        raise ValueError(f"{src}: nol baris access log ter-parse")
    return reqs, unparsed


def triage(reqs: list[dict], documented: dict[str, set[str]],
           prefix: str) -> tuple[list[dict], dict]:
    """Request teramati vs dokumentasi -> (temuan, stats)."""
    spec_regexes = [(tmpl, spec_template_re(tmpl))
                    for m in HTTP_METHODS for tmpl in documented[m]]
    spec_norm = {t for m in HTTP_METHODS for t in documented[m]}

    observed: dict[tuple[str, str], dict] = {}
    for r in reqs:
        raw_path = r["path"].split("?", 1)[0]
        if prefix and not raw_path.startswith(prefix):
            continue
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path
        norm = normalize_observed(unquote(raw_path))
        hit = norm in spec_norm or any(
            rx.match(norm) for _t, rx in spec_regexes) or any(
            rx.match(raw_path) for _t, rx in spec_regexes)
        key = (r["method"], norm)
        if key not in observed:
            observed[key] = {"count": 0, "ips": set(),
                             "status": set(), "auth": set(),
                             "auth_known": set(), "raw": raw_path,
                             "documented": hit}
        o = observed[key]
        o["count"] += 1
        if r["ip"]:
            o["ips"].add(r["ip"])
        o["status"].add(r["status"])
        o["auth"].add(r["auth"])
        o["auth_known"].add(r["auth_known"])

    findings: list[dict] = []
    for (method, norm), o in sorted(observed.items()):
        if o["documented"]:
            continue
        score = 0
        auth_unknown = False in o["auth_known"]
        if auth_unknown:
            score += 1
        elif "yes" not in o["auth"]:
            score += 3
        if o["count"] > 1000:
            score += 2
        elif o["count"] > 100:
            score += 1
        if len(o["ips"]) > 10:
            score += 2
        if any(200 <= s < 300 for s in o["status"]):
            score += 1
        severity = "high" if score >= 5 else \
            "medium" if score >= 3 else "low"
        findings.append({
            "check": "shadow-endpoint", "severity": severity,
            "method": method, "path": o["raw"][:200],
            "normalized": norm, "risk_score": score,
            "requests": o["count"], "unique_ips": len(o["ips"]),
            "statuses": sorted(s for s in o["status"] if s),
            "message": f"endpoint teramati {o['count']}x tak cocok "
                       "dokumentasi OpenAPI (skor risiko "
                       f"{score})",
        })
    seen_documented = {norm for (m, norm), o in observed.items()
                       if o["documented"]}
    zombie = sorted(t for t in spec_norm if t not in seen_documented)
    findings.append({
        "check": "unobserved-documented", "severity": "low",
        "message": f"{len(zombie)} endpoint terdokumentasi tak "
                   "teramati di log (kandidat zombie API — inventaris)",
        "paths": zombie[:100],
    })
    stats = {
        "requests_total": len(reqs),
        "observed_endpoints": len(observed),
        "documented_endpoints": sum(len(documented[m])
                                    for m in HTTP_METHODS),
        "shadow_endpoints": sum(1 for f in findings
                                if f["check"] == "shadow-endpoint"),
    }
    return findings, stats


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Diff OFFLINE endpoint teramati (access log) vs "
                    "terdokumentasi (OpenAPI JSON) — shadow API, nol "
                    "jaringan")
    ap.add_argument("--spec", help="OpenAPI spec versi JSON")
    ap.add_argument("--paths", help="file teks daftar 'METHOD /path' "
                                    "(alternatif --spec)")
    ap.add_argument("--log", required=True, help="access log CLF/JSONL")
    ap.add_argument("--prefix", default="",
                    help="hanya path berawalan ini (mis. /api)")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"],
                    default="medium")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)
    if not args.spec and not args.paths:
        print("ERROR: wajib --spec atau --paths", file=sys.stderr)
        return 2

    try:
        documented = load_documented(
            Path(args.spec) if args.spec else None,
            Path(args.paths) if args.paths else None)
        log_path = Path(args.log)
        if not log_path.exists():
            raise FileNotFoundError(f"{args.log}: file tidak ada")
        if log_path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"{args.log} > {MAX_FILE_BYTES} byte")
        reqs, unparsed = parse_log(
            log_path.read_text(encoding="utf-8", errors="replace"),
            args.log)
    except (OSError, ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    findings, stats = triage(reqs, documented, args.prefix)
    order = {"high": 0, "medium": 1, "low": 2}
    result = {
        "schema": SCHEMA,
        "findings": findings,
        "stats": stats,
        "notes": [
            "CLF tidak merekam header Authorization — kehadiran auth "
            "hanya dinilai utk JSON log; skor risiko memakai nilai "
            "'tidak diketahui' (+1) bila format tak merekam",
            "kecocokan template: {param} spec dicocokkan ke segmen "
            "dinamis teramati; pola path tak lazim (regex manual di "
            "spec) bisa salah cocok — lead perlu verifikasi manusia",
        ],
        "meta": {"unparsed": unparsed, "prefix": args.prefix,
                 "fail_on": args.fail_on,
                 "source": "internal design"},
    }
    out = json.dumps(result, ensure_ascii=False, sort_keys=True,
                     indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    gate = order[args.fail_on]
    hit = any(order[f["severity"]] <= gate for f in findings
              if f["check"] == "shadow-endpoint")
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
