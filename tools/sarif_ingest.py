"""[INGEST] sarif_ingest — ingest hasil scanner eksternal SARIF 2.1.0 -> findings.json.

Mengisi antrean port dari trailofbits/skills plugin 'static-analysis' skill
'sarif-parsing' (antrean SKILL-PORT-QUEUE; atribusi konsep). Konsep yang
diport: resolusi severity per SARIF 2.1.0 §3.27.10 (result.level itu OPSIONAL —
CodeQL menaruh severity di rule, bukan di result, sehingga pembacaan
`result.level` saja membuat run penuh error terbaca bersih), normalisasi path
lintas tool, fingerprint stabil untuk dedup, agregasi multi-file. Ditulis dari
nol dengan stdlib saja (tanpa jaringan); bukan salinan kode pihak lain.
Lisensi secai: PolyForm NC.

Kenapa secai butuh ini: exploit_ci_gate.py bisa MENG-EXPORT SARIF, tetapi
temuan scanner eksternal (CodeQL/Semgrep/semacamnya) tidak punya jalur masuk —
tidak ada ingest. Tool ini satu pintu: SARIF -> findings.json (verdict L0
OBSERVED — hasil analisis statis = lead, bukan bukti runtime), sehingga bisa
di-merge (merge_findings) dan diaudit bersama temuan lain.

Aturan resolusi level (SARIF 2.1.0 §3.27.10, urutan wajib):
  1. kind != "fail" (pass/notApplicable) -> "none" (bukan temuan)
  2. result.level bila ada
  3. rule defaultConfiguration.level (join ruleIndex -> rules[], fallback
     ruleId match bila tool tidak menulis ruleIndex)
  4. "warning" (default spesifikasi)
Level di luar {none,note,warning,error} -> result DITOLAK (dihitung di meta),
bukan didiam-diamkan.

Fingerprint: pakai fingerprints/partialFingerprints dari tool bila ada;
fallback sha256(ruleId|path_norm|line|pesan) — path utuh dipertahankan dalam
kunci (rule sama di auth/login.py dan admin/login.py = dua temuan, kunci
basename-only membuang salah satu).

Fail-closed:
  - file bukan JSON / version bukan 2.x / runs bukan list -> error exit 2
  - SEMUA file gagal divalidasi                           -> error exit 2
  - level eksplisit tidak sah                             -> result ditolak + dicatat
Exit: 0 findings.json tertulis (meta menunjukkan hitungan lengkap); 2 input
tidak valid.

Pemakaian:
  python tools/sarif_ingest.py --sarif codeql.sarif semgrep.sarif --out findings/sarif/findings.json
  python tools/sarif_ingest.py --sarif codeql.sarif --min-level warning --base /src --out out.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SARIF_LEVELS = ("none", "note", "warning", "error")
# urutan untuk filter/dedupe (index besar = lebih tinggi)
_LEVEL_RANK = {lv: i for i, lv in enumerate(SARIF_LEVELS)}
SEVERITY_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
MIN_REPORT_LEVEL = 3  # sinkron kontrak: verdict >= 3 = reportable


def resolve_level(result: dict, run: dict) -> str:
    """Severity satu result sesuai SARIF 2.1.0 §3.27.10 (lihat docstring)."""
    kind = result.get("kind", "fail")
    if kind != "fail":
        return "none"
    explicit = result.get("level")
    if explicit:
        return str(explicit)
    rules = (run.get("tool", {}).get("driver", {}) or {}).get("rules", []) or []
    rule: dict = {}
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        rule = rules[idx] or {}
    if not rule:
        rid = result.get("ruleId")
        rule = next((r for r in rules if r.get("id") == rid), {})
    level = (rule.get("defaultConfiguration", {}) or {}).get("level")
    return str(level) if level else "warning"


def normalize_path(uri: str, base: str | None = None) -> str:
    """Path lintas-tool -> bentuk pembanding: file:// dilepas, percent-decode,
    backslash jadi slash; bila --base, relatifkan bila di bawahnya."""
    p = (uri or "").strip()
    if p.startswith("file://"):
        p = p[len("file://"):]
        if p.startswith("/") and len(p) > 2 and p[2] == ":":
            p = p[1:]  # file:///C:/x -> C:/x (Windows)
    p = urllib.parse.unquote(p)
    p = p.replace("\\", "/")
    if base:
        nb = base.replace("\\", "/").rstrip("/") + "/"
        if p.startswith(nb):
            p = p[len(nb):]
    return p


def _fp_from_tool(result: dict) -> str | None:
    """Fingerprint yang tool laporkan sendiri (utamakan; stabil lintas mesin)."""
    for key in ("fingerprints", "partialFingerprints"):
        fps = result.get(key)
        if isinstance(fps, dict) and fps:
            joined = "|".join(f"{k}={fps[k]}" for k in sorted(fps))
            if joined.strip("|"):
                return f"{key}:{joined}"
    return None


def compute_fingerprint(result: dict, norm_path: str, start_line: int) -> str:
    """Fingerprint stabil: milik tool bila ada, fallback hash deterministik."""
    tool_fp = _fp_from_tool(result)
    if tool_fp:
        return tool_fp
    msg = (result.get("message", {}) or {}).get("text", "") or ""
    basis = "|".join([
        str(result.get("ruleId") or ""),
        norm_path,
        str(start_line),
        msg[:200],
    ])
    return "hash:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def validate_doc(doc: object, source: Path) -> dict:
    """Validasi wadah SARIF (fail-closed) -> dict yang punya runs list."""
    if not isinstance(doc, dict):
        raise ValueError(f"{source}: bukan objek JSON")
    version = doc.get("version")
    if not isinstance(version, str) or not version.startswith("2."):
        raise ValueError(f"{source}: SARIF version tidak didukung: {version!r} "
                         "(butuh 2.x)")
    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise ValueError(f"{source}: field 'runs' bukan list")
    return doc


def _driver_name(run: dict) -> str:
    name = (run.get("tool", {}).get("driver", {}) or {}).get("name")
    return str(name) if name else "sarif-unknown"


def _start_line(result: dict) -> int | None:
    try:
        region = result["locations"][0]["physicalLocation"]["region"]
        line = region.get("startLine")
        return int(line) if line else None
    except (IndexError, KeyError, TypeError, ValueError):
        return None


def _file_uri(result: dict) -> str:
    try:
        return str(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
    except (IndexError, KeyError, TypeError):
        return ""


def ingest(paths: "list[str | Path]", min_level: str = "note",
           base: str | None = None) -> tuple[list[dict], dict]:
    """Baca satu/lebih SARIF -> (findings kontrak, meta hitungan).

    Fail-closed: minimal SATU file harus tervalidasi; bila semuanya gagal,
    raise ValueError. Dedup lintas-run pakai fingerprint (tie -> severity
    tertinggi, lalu kemunculan pertama).
    """
    if min_level not in _LEVEL_RANK:
        raise ValueError(f"--min-level tidak sah: {min_level!r} "
                         f"(allowed: {'|'.join(SARIF_LEVELS)})")
    parsed_runs: list[tuple[Path, dict, dict]] = []
    errors: list[str] = []
    for p in map(Path, paths):
        try:
            doc = validate_doc(json.loads(p.read_text(encoding="utf-8")), p)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(str(exc))
            continue
        for run in doc["runs"]:
            if isinstance(run, dict):
                parsed_runs.append((p, doc, run))
    if not parsed_runs:
        raise ValueError("tidak ada SARIF yang tervalidasi:\n  "
                         + "\n  ".join(errors or ["(tidak ada input)"]))

    meta: dict = {
        "requests": 0,
        "sarif_files": len(paths),
        "file_errors": errors,
        "runs": len(parsed_runs),
        "results_total": 0,
        "rejected_level": 0,
        "skipped_not_fail": 0,
        "dedup_dropped": 0,
        "min_level": min_level,
        "level_histogram": {},
    }
    candidates: list[dict] = []
    for _, _, run in parsed_runs:
        results = run.get("results")
        if not isinstance(results, list):
            continue
        driver = _driver_name(run)
        for result in results:
            if not isinstance(result, dict):
                continue
            meta["results_total"] += 1
            level = resolve_level(result, run)
            if level not in SARIF_LEVELS:
                meta["rejected_level"] += 1
                continue
            if level == "none":
                meta["skipped_not_fail"] += 1
                continue
            if _LEVEL_RANK[level] < _LEVEL_RANK[min_level]:
                continue
            meta["level_histogram"][level] = \
                meta["level_histogram"].get(level, 0) + 1
            uri = _file_uri(result)
            npath = normalize_path(uri, base)
            line = _start_line(result)
            msg = (result.get("message", {}) or {}).get("text", "") or ""
            candidates.append({
                "level": level,
                "driver": driver,
                "rule_id": str(result.get("ruleId") or "unknown-rule"),
                "message": msg,
                "file_path": npath,
                "line": line,
                "fingerprint": compute_fingerprint(result, npath, line or 0),
            })

    # dedup: kunci fingerprint; tie-break severity tertinggi lalu urutan input
    by_fp: dict[str, dict] = {}
    for cand in candidates:
        fp = cand["fingerprint"]
        cur = by_fp.get(fp)
        if cur is None:
            by_fp[fp] = cand
            continue
        meta["dedup_dropped"] += 1
        if _LEVEL_RANK[cand["level"]] > _LEVEL_RANK[cur["level"]]:
            by_fp[fp] = cand

    findings: list[dict] = []
    for cand in by_fp.values():
        title = f"{cand['rule_id']}: {cand['message']}".strip()
        findings.append(make_finding(
            tool=f"sarif:{cand['driver']}",
            title=title[:300],
            severity=SEVERITY_MAP[cand["level"]],
            description=cand["message"],
            recommendation="Verifikasi manual sebelum dinaikkan verdict — "
                           "temuan statis bukan bukti runtime.",
            target_url=None,
            file_path=cand["file_path"] or None,
            line_start=cand["line"],
            line_end=cand["line"],
            evidence_kind="static-analysis",
            finding_class="weakness",
            confidence=0.5,
            status="unconfirmed",
            verdict=0,
            extra={"sarif_fingerprint": cand["fingerprint"],
                   "sarif_rule": cand["rule_id"]},
        ))
    meta["emitted"] = len(findings)
    return findings, meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="sarif_ingest — ingest SARIF 2.1.0 scanner eksternal "
                    "-> findings.json secai (fail-closed; resolusi "
                    "severity per §3.27.10).")
    ap.add_argument("--sarif", required=True, nargs="+",
                    help="satu/lebih file SARIF 2.1.0")
    ap.add_argument("--out", required=True, help="path findings.json output")
    ap.add_argument("--min-level", default="note",
                    choices=list(SARIF_LEVELS),
                    help="level SARIF minimum yang diemisikan (default: note)")
    ap.add_argument("--base", default=None,
                    help="path dasar untuk relatifkan artifactLocation.uri")
    args = ap.parse_args(argv)
    try:
        findings, meta = ingest(args.sarif, min_level=args.min_level,
                                base=args.base)
    except ValueError as exc:
        print(f"[sarif-ingest] ditolak: {exc}", file=sys.stderr)
        return 2
    write_findings(args.out, findings, meta=meta)
    print(f"[sarif-ingest] files={meta['sarif_files']} "
          f"runs={meta['runs']} results={meta['results_total']} -> "
          f"emitted={meta['emitted']} "
          f"(dedup -{meta['dedup_dropped']}, level-reject "
          f"{meta['rejected_level']}, non-fail {meta['skipped_not_fail']})")
    if meta["file_errors"]:
        for err in meta["file_errors"]:
            print(f"[sarif-ingest] SKIP file: {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
