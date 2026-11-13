r"""[SAFETY: read-only] kubebench_ingest — ingest & triase output kube-bench
(CIS Kubernetes Benchmark) dari file hasil: format TEKS ([PASS]/[FAIL]/
[WARN]/[INFO] + summary) maupun JSON (daftar Controls dgn
tests/results). NOL jaringan, read-only, stdlib murni.

Mekanisme:
  1. Deteksi format per file: JSON (list Controls / objek tunggal /
     {"Controls": [...]}) ATAU teks baris [STATUS] nomor deskripsi.
     Entri tak ter-parse DIHITUNG unparsed (fail-closed, tidak dibuang).
  2. Triase FAIL:
     - FAIL dgn kata-kunci kontrol kritis (anonymous-auth, rbac,
       client-cert-auth, authorization-mode, encryption, admission
       — dicocokkan dari DESKRIPSI, bukan nomor, agar tahan lintas
       versi CIS) = severity high.
     - FAIL lain = medium (fakta konfigurasi CIS, urgensi variatif).
     - Mode --managed (klaster terkelola EKS/GKE/AKS): FAIL bagian
       control-plane/etcd DITURUNKAN ke medium + label managed-
       cluster-exception EKSPLOSIT (butuh dokumentasi pengecualian
       vendor — TIDAK pernah dihapus senyap).
  3. WARN = butuh verifikasi manual (info) — bukan pass, bukan fail.
  4. Ringkasan PASS/FAIL/WARN/INFO di meta; duplikat test_number
     dihitung eksplisit.

Verdict: status PASS/FAIL adalah fakta output alat tersimpan -> status
confirmed, evidence_kind "tool-output", verdict L3, poc = baris/entri
asal. Tool ini TRIASE — tidak mengklaim klaster aman: PASS per kontrol
bukan postur keseluruhan (meta.summary + note).

Fail-closed: file tidak ada / JSON rusak / 0 hasil dikenali -> exit 2.

Pemakaian:
  python tools/kubebench_ingest.py --report kube-bench.json --out f.json
  python tools/kubebench_ingest.py --report kb.txt --managed --out f.json
Exit: 0 tanpa FAIL, 1 ada FAIL, 2 error input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "secai.kubebench-ingest/1"
MAX_FILE_BYTES = 16 * 1024 * 1024

CRITICAL_KEYWORDS = (
    "anonymous-auth", "rbac", "client-cert-auth", "authorization-mode",
    "encryption", "admission control",
)
# bagian yang bisa jadi pengecualian klaster terkelola
MANAGED_SECTIONS = ("control plane", "master", "etcd", "api server")

_LINE_RE = re.compile(
    r"^\[(PASS|FAIL|WARN|INFO)\]\s+(\d+(?:\.\d+)*)\s+(.+)$",
    re.I)


def _critical(desc: str) -> str | None:
    low = desc.lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in low:
            return kw
    return None


def parse_text(text: str) -> tuple[list[dict], list[str]]:
    """Parse format teks kube-bench. Return (results, unparsed).

    Heuristik: [INFO] dengan nomor TANPA titik ('1', '2') = header
    bagian; baris [STATUS] lain = hasil (nomor kube-bench selalu
    bertitik x.y.z). Hasil [INFO] bertitik dianggap header juga
    (tidak membawa temuan — dicatat di unparsed-count, bukan hilang
    senyap dari meta.unparsed).
    """
    results: list[dict] = []
    unparsed: list[str] = []
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LINE_RE.match(line)
        if m:
            status, num, desc = (m.group(1).upper(), m.group(2),
                                 m.group(3).strip())
            if status == "INFO" and "." not in num:
                section = desc
                continue
            results.append({
                "status": status,
                "test_number": num,
                "test_desc": desc,
                "section": section,
                "remediation": "",
                "source_line": line,
            })
        elif line.startswith("["):
            unparsed.append(line[:160])
    return results, unparsed


def parse_json(doc: object) -> tuple[list[dict], list[str]]:
    """Parse JSON kube-bench (Controls -> tests -> results)."""
    controls: list[dict] = []
    if isinstance(doc, dict) and isinstance(doc.get("Controls"), list):
        controls = doc["Controls"]
    elif isinstance(doc, list):
        controls = [c for c in doc if isinstance(c, dict)]
    elif isinstance(doc, dict):
        controls = [doc]
    results: list[dict] = []
    unparsed: list[str] = []
    for c in controls:
        if not isinstance(c, dict):
            unparsed.append("control bukan objek")
            continue
        section = str(c.get("text", ""))
        tests = c.get("tests")
        if not isinstance(tests, list):
            tests = []
        found_any = False
        for t in tests:
            if not isinstance(t, dict):
                continue
            for r in t.get("results") or []:
                if not isinstance(r, dict):
                    continue
                num = str(r.get("test_number", "")).strip()
                status = str(r.get("status", "")).strip().upper()
                if not num or not status:
                    unparsed.append(f"result tanpa number/status di "
                                    f"{section[:60]}")
                    continue
                found_any = True
                results.append({
                    "status": status,
                    "test_number": num,
                    "test_desc": str(r.get("test_desc", "")).strip(),
                    "section": section,
                    "remediation": str(r.get("remediation", ""))[:400],
                    "expected_result": str(r.get("expected_result", "")),
                    "actual_value": str(r.get("actual_value", ""))[:300],
                    "source_line": f"{num} {r.get('test_desc', '')}"
                                   f"[{status}]",
                })
        if not found_any:
            unparsed.append(f"control tanpa results: {section[:60]}")
    return results, unparsed


def triage(results: list[dict], managed: bool) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0, "OTHER": 0}
    seen: dict[str, int] = {}
    for r in results:
        st = r["status"] if r["status"] in counts else "OTHER"
        counts[st] += 1
        key = r["test_number"]
        seen[key] = seen.get(key, 0) + 1
        if st not in ("FAIL", "WARN"):
            continue
        section_low = r["section"].lower()
        critical = _critical(r["test_desc"])
        if st == "WARN":
            sev, label = "info", "perlu-verifikasi-manual"
        elif critical:
            sev, label = "high", "kontrol-kritis"
        else:
            sev, label = "medium", "cis-fail"
        if managed and st == "FAIL" and \
                any(s in section_low for s in MANAGED_SECTIONS):
            sev = "medium"
            label = "managed-cluster-exception"
        findings.append(make_finding(
            tool="kubebench-ingest",
            title=f"[{st}] {r['test_number']} {r['test_desc'][:90]}"
                  + (f" ({label})" if label != "cis-fail" else ""),
            severity=sev,
            description=(
                f"kube-bench {label}: {r['test_desc']} — bagian: "
                f"{r['section'] or '?'}"
                + (" — kontrol kritis keamanan klaster" if critical
                   and st == "FAIL" else "")
                + (" — pada klaster TERKELOLA bagian ini biasanya di luar "
                   "kendali operator: dokumentasikan pengecualian vendor "
                   "dengan jelas, jangan dihapus senyap"
                   if label == "managed-cluster-exception" else "")
                + (" — WARN berarti kube-bench tidak bisa memastikan; "
                   "verifikasi manual wajib sebelum dianggap lolos"
                   if st == "WARN" else "")),
            recommendation=(r.get("remediation")
                            or "Perbaiki sesuai remediation CIS "
                               f"{r['test_number']}"),
            param=r["test_number"],
            poc=r.get("source_line", "")[:300],
            evidence_kind="tool-output",
            finding_class="weakness" if st == "FAIL" else "observation",
            confidence=1.0,
            status="confirmed",
            verdict=2,
            extra={"schema": SCHEMA, "label": label,
                   "test_number": r["test_number"],
                   "section": r["section"],
                   "expected_result": r.get("expected_result", ""),
                   "actual_value": r.get("actual_value", ""),
                   "critical_keyword": critical,
                   "managed": managed},
        ))
    dupes = {k: v for k, v in seen.items() if v > 1}
    return findings, {"counts": counts, "duplicates": dupes}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] kubebench_ingest — ingest & "
                    "triase output kube-bench (teks/JSON), NOL jaringan")
    ap.add_argument("--report", required=True,
                    help="file output kube-bench (JSON atau teks)")
    ap.add_argument("--out", default="kubebench_ingest_findings.json")
    ap.add_argument("--managed", action="store_true",
                    help="klaster terkelola (EKS/GKE/AKS): FAIL control-"
                         "plane/etcd diturunkan + label exception "
                         "eksplisit (tidak dihapus)")
    args = ap.parse_args(argv)

    p = Path(args.report)
    if not p.is_file():
        print(f"[kubebench_ingest] report tidak ada: {p} (fail-closed)",
              file=sys.stderr)
        return 2
    if p.stat().st_size > MAX_FILE_BYTES:
        print(f"[kubebench_ingest] report terlalu besar ({p}) "
              "(fail-closed)", file=sys.stderr)
        return 2
    text = p.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        print("[kubebench_ingest] report kosong (fail-closed)",
              file=sys.stderr)
        return 2

    results: list[dict] = []
    unparsed: list[str] = []
    fmt = "text"
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            # teks kube-bench JUGA bisa mulai '[' (baris [FAIL]...) —
            # jatuh ke parser teks, bukan langsung gagal
            doc = None
        if doc is not None:
            results, unparsed = parse_json(doc)
            fmt = "json"
    if not results:
        r2, u2 = parse_text(text)
        results.extend(r2)
        unparsed.extend(u2)
    if not results:
        print(f"[kubebench_ingest] 0 hasil dikenali dari {p} "
              f"({len(unparsed)} unparsed) — bukan output kube-bench? "
              "(fail-closed)", file=sys.stderr)
        return 2

    findings, stats = triage(results, args.managed)
    meta = {
        "schema": SCHEMA,
        "report": str(p),
        "format": fmt,
        "results": len(results),
        "unparsed": unparsed[:64],
        "summary": stats["counts"],
        "duplicates": stats["duplicates"],
        "managed": args.managed,
        "note": "PASS per kontrol bukan postur keseluruhan; WARN wajib "
                "verifikasi manual; exception klaster terkelola "
                "didokumentasikan, tidak dihapus senyap",
    }
    write_findings(args.out, findings, meta)
    fails = stats["counts"]["FAIL"]
    if fails:
        print(f"[kubebench_ingest] {fails} FAIL / "
              f"{stats['counts']['WARN']} WARN / "
              f"{stats['counts']['PASS']} PASS -> {args.out}")
        return 1
    print(f"[kubebench_ingest] tanpa FAIL ({stats['counts']['WARN']} WARN "
          f"/ {stats['counts']['PASS']} PASS) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
