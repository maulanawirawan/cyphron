"""[F3] Generator laporan PDF kategorial via Typst.

Konsumen findings.json (satu pintu) -> PDF kategorial + metrik presisi
per tool + pemetaan compliance indikatif + retest delta (--compare).
Target: render <2 s, footprint pipeline <50 MB (typst binary ~20 MB,
tanpa headless-browser).

Cara kerja: generator menulis data.json + template typst ke folder build
sementara, lalu `typst compile` — teks temuan TIDAK pernah masuk sebagai
markup typst (bebas injeksi/escaping).

Pemakaian:
  python tools/report_pdf.py --findings findings/tier0-contoh/findings.json \
      --out findings/tier0-contoh/report.pdf \
      [--compare findings/run-lama/findings.json] \
      [--title "..." --subtitle "..."]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "tools"))
from findings import MIN_REPORT_LEVEL  # noqa: E402
import triage_advisor  # noqa: E402  (F24 learning loop)
import threat_model  # noqa: E402  (F74 konteks per program)

def _resolve_typst() -> str | None:
    """Cari executable typst: env CYPHRON_TYPST -> binary vendored
    (tools/bin, Windows) -> PATH. None = tidak tersedia (main() gagal
    dengan pesan jelas — fail-closed)."""
    env = os.environ.get("CYPHRON_TYPST")
    if env and Path(env).exists():
        return env
    # vendored hanya untuk Windows — di linux, typst.exe yang ter-COPY ke
    # image tak bisa jalan (subprocess gagal sunyi exit 1); pakai PATH.
    if sys.platform == "win32":
        vendored = (ROOT / "tools" / "bin"
                    / "typst-x86_64-pc-windows-msvc" / "typst.exe")
        if vendored.exists():
            return str(vendored)
    return shutil.which("typst")


TYPST = _resolve_typst()
TEMPLATE = ROOT / "tools" / "report_template.typ"

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Strict contract untuk pre-render validation (fail-closed)
STRICT_SEVERITIES = {"critical", "high", "medium", "low", "info"}
STRICT_VERDICTS = {-1, 0, 1, 2, 3, 4, 5}

LADDER = [
    {"level": "L0", "name": "OBSERVED", "desc": "Fakta teramati (inventaris/posture), bukan klaim kerentanan."},
    {"level": "L1", "name": "SUSPECTED (LEAD)", "desc": "Petunjuk patut dugaan — belum terbukti; diverifikasi lanjut berotorisasi."},
    {"level": "L2", "name": "REPRODUCED", "desc": "Berhasil direproduksi sekali di lingkungan terkendali."},
    {"level": "L3", "name": "DETERMINISTICALLY VERIFIED", "desc": "Bukti request-response deterministik; reportable."},
    {"level": "L4", "name": "IMPACT VERIFIED", "desc": "Dampak nyata terbukti (mis. data terekspos terbaca)."},
    {"level": "L5", "name": "BLIND VALIDATED", "desc": "Divalidasi pihak ketiga/recipient tanpa perlu detail internal."},
    {"level": "L-x", "name": "REJECTED", "desc": "Tertolak (false positive terbukti) — dicatat sebagai disiplin."},
]

# [F42] Lapisan bahasa awam: bucket sederhana yang DIPETAKAN
# deterministik dari verdict ladder (tanpa penilaian tambahan di luar
# bukti). Pembaca awam cukup paham: mana yang boleh dipercaya penuh,
# mana yang masih perlu manusia mengecek, mana yang bersih, dan mana
# yang tidak bisa dinilai karena alatnya gagal.
PLAIN_GUIDE = [
    {"key": "proven", "label": "TERBUKTI", "color": "166534",
     "meaning": "Bukti kuat dan bisa diulang (PoC). Boleh dilaporkan "
                "sebagai temuan resmi."},
    {"key": "check", "label": "PERLU DICEK", "color": "b45309",
     "meaning": "Indikasi awal yang layak diperiksa manusia. BELUM boleh "
                "disebut kerentanan."},
    {"key": "clean", "label": "BERSIH", "color": "1f2937",
     "meaning": "Sudah diperiksa; tidak ada masalah teramati (atau "
                "catatan inventaris netral)."},
    {"key": "unassessed", "label": "TIDAK BISA DINILAI", "color": "6b7280",
     "meaning": "Alat gagal mengumpulkan data (jaringan/timeout/opt-in). "
                "Bukan temuan — ulangi saat kondisi sehat."},
    {"key": "filtered", "label": "TERSARING", "color": "6b7280",
     "meaning": "Dugaan yang terbukti SALAH (false positive) — disaring "
                "keluar sebagai disiplin."},
]

PLAIN_WHY = {
    "proven": "Artinya: kelemahan terbukti dengan bukti yang bisa "
              "diulang — layak dilaporkan.",
    "check": "Artinya: petunjuk awal saja — wajib pemeriksaan manual "
             "sebelum disebut kerentanan.",
    "clean": "Artinya: pemeriksaan selesai tanpa masalah teramati.",
    "unassessed": "Artinya: tidak dinilai karena pengumpulan data gagal "
                  "— bukan temuan.",
    "filtered": "Artinya: sudah terbukti salah (false positive) — tidak "
                "masuk klaim.",
}


def plain_status(r: dict) -> str:
    """Pemetaan deterministik baris findings -> bucket bahasa awam.
    Urutan keputusan: L-x duluan (tersaring), lalu status, lalu ladder."""
    if r.get("verdict", 0) == -1:
        return "filtered"
    if r.get("status") != "confirmed":
        return "unassessed"
    v = r.get("verdict", 0)
    if v >= MIN_REPORT_LEVEL:
        return "proven"
    if v >= 1:
        return "check"
    return "clean"


def plain_fields(r: dict) -> dict:
    key = plain_status(r)
    g = next(b for b in PLAIN_GUIDE if b["key"] == key)
    return {"plain_label": g["label"], "plain_color": g["color"],
            "plain_why": PLAIN_WHY[key]}


def plain_bottom_line(counts: dict) -> str:
    parts = [f"dari {sum(counts.values())} temuan",
             f"{counts['proven']} TERBUKTI",
             f"{counts['check']} masih PERLU DICEK manusia",
             f"{counts['clean']} BERSIH"]
    if counts["unassessed"]:
        parts.append(f"{counts['unassessed']} TIDAK BISA DINILAI "
                     "(alat gagal)")
    if counts["filtered"]:
        parts.append(f"{counts['filtered']} TERSARING (false positive)")
    return ("Bacanya sederhana — " + ", ".join(parts)
            + ". Hanya status TERBUKTI yang boleh menjadi laporan resmi; "
              "sisanya petunjuk kerja, bukan kesimpulan.")


# Pemetaan indikatif CWE -> kerangka kepatuhan (bukan audit)
COMPLIANCE_MAP = {
    "CWE-290": ("PCI DSS 6.4.3/8.3", "CC6.1", "A.8.4/A.5.14"),
    "CWE-319": ("PCI DSS 4.2.1", "CC6.7", "A.8.24"),
    "CWE-693": ("PCI DSS 1.2/2.2", "CC6.1", "A.8.9"),
    "CWE-200": ("PCI DSS 1.3.2", "CC6.5", "A.8.9"),
    "CWE-79": ("PCI DSS 6.2.4", "CC8.1", "A.8.28"),
    "CWE-89": ("PCI DSS 6.2.4", "CC8.1", "A.8.28"),
    "CWE-798": ("PCI DSS 8.3.2", "CC6.1", "A.8.5"),
    "CWE-522": ("PCI DSS 8.3.2", "CC6.1", "A.8.5"),
    "CWE-614": ("PCI DSS 4.2.1/6.4.3", "CC6.7", "A.8.12"),
    "CWE-1004": ("PCI DSS 6.4.3", "CC6.7", "A.8.12"),
    "CWE-770": ("PCI DSS 1.2", "CC6.6", "A.8.20"),
}

TARGET_KEYS = ("target_url", "target")


def load_doc(path: Path) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if not doc.get("ok"):
        raise SystemExit(f"{path}: ok=false — tidak dirender")
    for i, f in enumerate(doc.get("findings", [])):
        for k in ("tool", "title", "severity", "verdict", "verdict_tag", "id"):
            if k not in f:
                raise SystemExit(f"{path}: findings[{i}] tanpa field '{k}' — bukan findings.json kontrak")
    return doc


def validate_findings_strict(docs: list[dict]) -> None:
    """Pre-render strict validation fail-closed — severity/verdict/confidence."""
    for doc_idx, doc in enumerate(docs):
        for i, f in enumerate(doc.get("findings", [])):
            for k in ("tool", "title", "severity", "verdict", "verdict_tag", "id"):
                if k not in f:
                    raise SystemExit(
                        f"pre-render validation: docs[{doc_idx}] findings[{i}] tanpa field '{k}' — fail-closed"
                    )
            sev = f.get("severity")
            if sev not in STRICT_SEVERITIES:
                raise SystemExit(
                    f"pre-render validation: docs[{doc_idx}] findings[{i}] severity invalid '{sev}' — fail-closed"
                )
            verdict = f.get("verdict")
            if verdict not in STRICT_VERDICTS:
                raise SystemExit(
                    f"pre-render validation: docs[{doc_idx}] findings[{i}] verdict invalid '{verdict}' — fail-closed"
                )
            if "confidence" in f:
                try:
                    c = float(f["confidence"])
                    if not (0.0 <= c <= 1.0):
                        raise SystemExit(
                            f"pre-render validation: docs[{doc_idx}] findings[{i}] confidence out of range {c} — fail-closed"
                        )
                except (TypeError, ValueError):
                    raise SystemExit(
                        f"pre-render validation: docs[{doc_idx}] findings[{i}] confidence not numeric '{f.get('confidence')}' — fail-closed"
                    )


def severity_counts(rows: list[dict]) -> list[int]:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for r in rows:
        counts[r.get("severity", "info")] = counts.get(r.get("severity", "info"), 0) + 1
    return [counts[s] for s in ("critical", "high", "medium", "low", "info")]


def precision_per_tool(rows: list[dict], tool_requests: dict | None = None
                       ) -> list[dict]:
    tool_requests = tool_requests or {}
    per: dict[str, dict] = {}
    for r in rows:
        t = per.setdefault(r.get("tool", "?"), {"total": 0, "reportable": 0,
                                               "leads": 0, "rejected": 0})
        t["total"] += 1
        v = r.get("verdict", 0)
        if v == -1:
            t["rejected"] += 1
        elif v >= MIN_REPORT_LEVEL:
            t["reportable"] += 1
        else:
            t["leads"] += 1
    out = []
    for tool, t in sorted(per.items()):
        denom = t["total"] - t["rejected"]
        ratio = f"{100 * t['reportable'] / denom:.0f}%" if denom else "—"
        req = tool_requests.get(tool)
        density = (f"{t['total'] / req:.2f}" if req else "—")
        out.append({"tool": tool, **t, "ratio": ratio,
                    "requests": req if req is not None else "—",
                    "findings_per_request": density})
    return out


def density_metrics(rows: list[dict], requests: int, elapsed_s: float) -> dict:
    """Metrik kepadatan run (F18): temuan per unit biaya — request jaringan
    ke target dan detik waktu run. Angka None dirender sebagai em-dash."""
    total = len(rows)
    reportable = sum(1 for r in rows if r.get("verdict", 0) >= MIN_REPORT_LEVEL)
    return {
        "total_findings": total,
        "requests": requests,
        "elapsed_s": round(elapsed_s, 2) if elapsed_s else None,
        "findings_per_request": round(total / requests, 2) if requests else None,
        "findings_per_second": round(total / elapsed_s, 2) if elapsed_s else None,
        "reportable_per_request": round(reportable / requests, 3) if requests else None,
        "elapsed_s_display": f"{elapsed_s:.1f}" if elapsed_s else "—",
        "fpr_display": f"{total / requests:.2f}" if requests else "—",
        "fps_display": f"{total / elapsed_s:.2f}" if elapsed_s else "—",
        "rpr_display": f"{reportable / requests:.3f}" if requests else "—",
    }


def retest_delta(old_ids: dict[str, dict], new_ids: dict[str, dict]) -> dict:
    old_set, new_set = set(old_ids), set(new_ids)
    persist = old_set & new_set
    fixed = old_set - new_set
    new = new_set - old_set
    def titles(ids, src):
        return sorted(src[i].get("title", i) for i in ids)
    return {
        "persist": len(persist), "fixed": len(fixed), "new": len(new),
        "fixed_items": titles(fixed, old_ids)[:20],
        "new_items": titles(new, new_ids)[:20],
    }


def row_ids(rows: list[dict]) -> dict[str, dict]:
    out = {}
    for r in rows:
        rid = r.get("id")
        if rid:
            out[rid] = r
    return out


def build_data(docs: list[dict], compare: Path | None, title: str, subtitle: str, date_str: str | None = None, class_history: list[dict] | None = None, egress: dict | None = None, threat_model: dict | None = None) -> dict:
    rows: list[dict] = []
    sources: list[str] = []
    sources_acc: list[dict] = []
    requests = 0
    elapsed_s = 0.0
    tool_requests: dict[str, int] = {}
    for d in docs:
        rows.extend(d.get("findings", []))
        meta = d.get("data", {}) or {}
        sources_acc.extend(meta.get("sources", []) or [])
        src = meta.get("run") or ", ".join(str(s.get("file", "?")) for s in meta.get("sources", [])) or "?"
        sources.append(str(src))
        requests += int(meta.get("requests", 0) or d.get("requests", 0))
        elapsed_s += float(meta.get("elapsed_s", 0) or 0)
        for s in meta.get("sources", []) or []:
            if isinstance(s, dict) and s.get("skill"):
                tool_requests[str(s["skill"])] = (
                    tool_requests.get(str(s["skill"]), 0)
                    + int(s.get("requests", 0) or 0))

    # Kategori: dari field category; temuan dikelompokkan, urut severity
    def sort_key(r):
        # runtut: baris confirmed (lead kuat dulu) -> unconfirmed/gagal paling akhir
        conf = 0 if r.get("status") == "confirmed" else 1
        return (conf, -r.get("verdict", 0),
                SEV_ORDER.get(r.get("severity", "info"), 9), r.get("title", ""))
    rows_sorted = sorted(rows, key=sort_key)
    # badan laporan = baris confirmed saja; baris unconfirmed (gagal
    # jaringan / dilewati opt-in) masuk section tersendiri di akhir —
    # pembaca tidak mencampur lead dengan kegagalan lingkungan
    rows_confirmed = [r for r in rows_sorted
                      if r.get("status") == "confirmed"]
    rows_unconfirmed = [r for r in rows_sorted
                        if r.get("status") != "confirmed"]
    cats: dict[str, list[dict]] = {}
    for r in rows_confirmed:
        cat = r.get("category") or "LAINNYA"
        cats.setdefault(cat, []).append(r)
    categories = [{
        "name": c,
        "count": len(fs),
        "findings": [{
            "title": r.get("title", ""),
            "severity": r.get("severity", "info"),
            "verdict_tag": r.get("verdict_tag", ""),
            "verdict": r.get("verdict", 0),
            "description": r.get("description", ""),
            "recommendation": r.get("recommendation", ""),
            "target": (r.get("target_url") or r.get("target") or "—"),
            "evidence_kind": r.get("evidence_kind", "—"),
            "cwe": r.get("cwe"),
            "safety_class": r.get("safety_class", "—"),
            "confidence": r.get("confidence", 0.5),
            "id": r.get("id", ""),
            "family_quorum": r.get("family_quorum"),
            "family_sources": r.get("family_sources") or [],
            **plain_fields(r),
        } for r in fs],
    } for c, fs in cats.items()]
    unconfirmed = [{
        "title": r.get("title", ""),
        "description": r.get("description", ""),
        "tool": r.get("tool", "—"),
        "verdict_tag": r.get("verdict_tag", ""),
        **plain_fields(r),
    } for r in rows_unconfirmed]

    # [F42] hitungan bucket bahasa awam + panduan + baris bawah
    plain_counts = {b["key"]: 0 for b in PLAIN_GUIDE}
    for r in rows:
        plain_counts[plain_status(r)] += 1
    plain_guide = [{**b, "count": plain_counts[b["key"]]}
                   for b in PLAIN_GUIDE]

    reportable_count = sum(1 for r in rows if r.get("verdict", 0) >= MIN_REPORT_LEVEL)
    rejected_count = sum(1 for r in rows if r.get("verdict", 0) == -1)
    lead_count = len(rows) - reportable_count - rejected_count

    # cakupan efektif: skill yang dijalankan (meta.sources) vs skill yang
    # SELURUH barisnya unconfirmed (gagal jaringan/opt-in) — pembaca
    # langsung tahu seberapa luas cakupan run ini
    attempted = {str(s.get("skill")) for s in sources_acc
                 if s.get("skill")}
    tools_seen: dict[str, bool] = {}
    for r in rows:
        tool = str(r.get("tool"))
        tools_seen[tool] = (tools_seen.get(tool, False)
                            or r.get("status") == "confirmed")
    failed_tools = sorted(t for t, has_ok in tools_seen.items()
                          if not has_ok)
    coverage = {
        "attempted": len(attempted),
        "clean": len(attempted - set(failed_tools)),
        "failed_tools": failed_tools,
        "note": (f"{len(attempted - set(failed_tools))}/{len(attempted)} "
                 "skill selesai bersih" if attempted else ""),
    }

    # tabel verdict + top-3 lead untuk ringkasan eksekutif
    verdict_counts = {
        "l2plus": sum(1 for r in rows if r.get("verdict", 0) >= 2),
        "l1": sum(1 for r in rows if r.get("verdict", 0) == 1),
        "l0": sum(1 for r in rows if r.get("verdict", 0) == 0),
        "rejected": rejected_count,
    }
    lead_candidates = sorted(
        (r for r in rows if r.get("status") == "confirmed"
         and r.get("verdict", 0) >= 1),
        key=lambda r: (-r.get("verdict", 0),
                       SEV_ORDER.get(r.get("severity", "info"), 9),
                       r.get("title", "")))
    top_leads = [{
        "title": r.get("title", ""),
        "why": (r.get("description") or "")[:200],
        "verdict_tag": r.get("verdict_tag", ""),
    } for r in lead_candidates[:3]]

    targets = sorted({str(r.get("target_url") or r.get("target")
                    or f"self-check ({r.get('tool', '?')})") for r in rows})[:8]

    compliance = sorted({r["cwe"]: True for r in rows if r.get("cwe")})
    compliance_rows = [
        {"cwe": cwe, "pci": v[0], "soc2": v[1], "iso": v[2]}
        for cwe, v in COMPLIANCE_MAP.items() if cwe in compliance
    ]

    delta = None
    if compare is not None:
        old_doc = load_doc(compare)
        delta = retest_delta(row_ids(old_doc.get("findings", [])), row_ids(rows))

    n_l3plus = reportable_count
    fq_count = sum(1 for r in rows if r.get("family_quorum"))
    fq_note = ""
    if fq_count:
        fq_note = (f" Sebanyak {fq_count} temuan terkonfirmasi lintas "
                   "3 tool keluarga header (FAO family quorum).")
    summary = (
        f"Dokumen ini merangkum {len(rows)} temuan dari data kontrak "
        f"findings.json. {n_l3plus} temuan berada di level reportable "
        f"(L3+), {lead_count} berstatus lead (belum terbukti), dan "
        f"{rejected_count} tertolak. Sesuai disiplin verdict ladder, "
        "hanya temuan L3+ yang disajikan sebagai klaim; lead dilaporkan "
        "sebagai petunjuk dengan bukti mentahnya, bukan sebagai "
        "kerentanan terbukti." + fq_note
    )
    return {
        "title": title,
        "subtitle": subtitle,
        "date": date_str if date_str is not None else time.strftime("%d %B %Y"),
        "targets": targets or ["—"],
        "sources": sources or ["?"],
        "total_findings": len(rows),
        "reportable_count": reportable_count,
        "lead_count": lead_count,
        "rejected_count": rejected_count,
        "requests": requests,
        "density": density_metrics(rows, requests, elapsed_s),
        "by_severity": severity_counts(rows),
        "verdict_counts": verdict_counts,
        "plain_counts": plain_counts,
        "plain_guide": plain_guide,
        "bottom_line": plain_bottom_line(plain_counts),
        "top_leads": top_leads,
        "coverage": coverage,
        "egress": egress,
        "threat_model": (
            {"title": threat_model.get("title", ""),
             "sections": threat_model.get("sections", []),
             "path": threat_model.get("path", ""),
             "sha256": threat_model.get("sha256", "")}
            if threat_model and not threat_model.get("rejected") else None),
        "executive_summary": summary,
        "ladder": LADDER,
        "categories": categories,
        "unconfirmed": unconfirmed,
        "precision": precision_per_tool(rows, tool_requests),
        "compliance": compliance_rows or [{"cwe": "—", "pci": "—", "soc2": "—", "iso": "—"}],
        "delta": delta,
        "class_history": class_history or [],
        "watermark": "LOCAL-ONLY",
    }


def sha256_file(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--findings", action="append", required=True,
                    help="file findings.json; boleh diulang")
    ap.add_argument("--egress", default=None,
                    help="state JSON dari tools/egress_preflight.py — "
                         "kesehatan jalur keluar ditampilkan di ringkasan")
    ap.add_argument("--compare", default=None,
                    help="findings.json run sebelumnya (retest delta)")
    ap.add_argument("--threat-model", default=None,
                    help="threat_model.md program (opsional) — konteks "
                         "triage operator dirender di laporan")
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", default="Laporan Security Assessment")
    ap.add_argument("--subtitle", default="Ringkasan kategorial berbasis bukti (verdict ladder)")
    ap.add_argument("--date", default=None, help="tanggal untuk determinisme (default: hari ini; pakai YYYY-MM-DD atau string bebas)")
    ap.add_argument("--learning", action="append", default=None,
                    help="file outcomes untuk tabel riwayat kelas (default: "
                         f"{triage_advisor.DEFAULT_LEARNING} bila ada)")
    ap.add_argument("--no-learning", action="store_true",
                    help="matikan integrasi learning loop")
    args = ap.parse_args()

    if not TYPST:
        raise SystemExit("typst tidak ditemukan — set CYPHRON_TYPST, "
                         "letakkan binary di tools/bin/, atau PATH")

    docs = [load_doc(Path(p)) for p in args.findings]
    for doc in docs:
        for i,f in enumerate(doc.get("findings",[])):
            if f.get("severity") not in ("critical","high","medium","low","info"):
                raise SystemExit(f"report fail-closed: invalid severity at findings[{i}]")
            if f.get("verdict") not in (-1,0,1,2,3,4,5):
                raise SystemExit(f"report fail-closed: invalid verdict at findings[{i}]")
            if not (0.0 <= float(f.get("confidence",0.5)) <= 1.0):
                raise SystemExit(f"report fail-closed: confidence out of range at {i}")
    validate_findings_strict(docs)
    compare = Path(args.compare) if args.compare else None
    # F24 learning loop: tabel riwayat kelas dari outcomes (read-only).
    class_history: list[dict] = []
    if not args.no_learning:
        if args.learning:
            lpaths = [Path(p) for p in args.learning]
        else:
            default = triage_advisor.DEFAULT_LEARNING
            lpaths = [default] if default.exists() else []
        outcomes, _ = triage_advisor.load_outcomes(lpaths)
        class_history = triage_advisor.class_history_rows(outcomes)
    egress_state = None
    if args.egress:
        _ep = Path(args.egress)
        if _ep.exists():
            egress_state = json.loads(_ep.read_text(encoding="utf-8"))
        else:
            print(f"peringatan: egress state tidak ada: {_ep}",
                  file=sys.stderr)
    # [F74] threat model program (opsional — riset oss-scanner): konteks
    # triage operator di laporan; verdict ladder TIDAK berubah.
    tm_meta = None
    if args.threat_model:
        tm_meta = threat_model.load_path(args.threat_model)
        if tm_meta is None:
            print(f"peringatan: threat model tidak ada: {args.threat_model}",
                  file=sys.stderr)
        elif tm_meta.get("rejected"):
            print(f"peringatan: threat model ditolak: {tm_meta['rejected']}",
                  file=sys.stderr)
            tm_meta = None
    data = build_data(docs, compare, args.title, args.subtitle,
                      date_str=args.date, egress=egress_state, class_history=class_history,
                      threat_model=tm_meta)

    build_dir = Path(tempfile.mkdtemp(prefix="cyphron-report_"))
    try:
        (build_dir / "report.typ").write_text(
            TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
        (build_dir / "data.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        t0 = time.perf_counter()
        r = subprocess.run(
            [str(TYPST), "compile", "report.typ", "report.pdf"],
            cwd=build_dir, capture_output=True, text=True, timeout=120)
        render_s = time.perf_counter() - t0
        if r.returncode != 0:
            sys.stderr.write(r.stdout[-3000:] + r.stderr[-3000:])
            raise SystemExit(f"typst compile gagal (exit {r.returncode})")
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(build_dir / "report.pdf", out)
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)

    # Deterministik: normalisasi CreationDate/ModDate + XMP stream agar hash stabil
    # Typst selalu tulis waktu compile -> hash berubah tiap detik. Kita pin ke fixed.
    try:
        import fitz as _fitz2
        import re as _re2
        d2 = _fitz2.open(str(out))
        fixed = "D:20200101000000+07'00'"
        meta = d2.metadata
        meta["creationDate"] = fixed
        meta["modDate"] = fixed
        d2.set_metadata(meta)
        tmp_pdf = str(out) + ".tmp"
        d2.save(tmp_pdf, garbage=4, deflate=True)
        d2.close()
        Path(tmp_pdf).replace(out)
        # Lapisan 2: normalisasi XMP + trailer ID via bytes agar hash deterministik
        raw = Path(out).read_bytes()
        raw = _re2.sub(rb"<xmp:CreateDate>.*?</xmp:CreateDate>", b"<xmp:CreateDate>2020-01-01T00:00:00+07:00</xmp:CreateDate>", raw)
        raw = _re2.sub(rb"<xmp:ModifyDate>.*?</xmp:ModifyDate>", b"<xmp:ModifyDate>2020-01-01T00:00:00+07:00</xmp:ModifyDate>", raw)
        raw = _re2.sub(rb"<xmpMM:InstanceID>.*?</xmpMM:InstanceID>", b"<xmpMM:InstanceID>fixed-instance-id</xmpMM:InstanceID>", raw)
        raw = _re2.sub(rb"<xmpMM:DocumentID>.*?</xmpMM:DocumentID>", b"<xmpMM:DocumentID>fixed-document-id</xmpMM:DocumentID>", raw)
        # Trailer ID: /ID[(base64)<hex>] -> deterministic
        raw = _re2.sub(rb"/ID\[\(.*?\)<.*?>\]", b"/ID[(fixed-trailer-id)<00000000000000000000000000000000>]", raw)
        Path(out).write_bytes(raw)
    except Exception:
        pass

    # Validasi hasil dengan pymupdf: konten wajib ada di halaman mana pun
    import fitz
    doc = fitz.open(str(out))
    pages = doc.page_count
    all_text = "\n".join(doc[i].get_text() for i in range(pages))
    title_probe = data["title"]
    doc.close()
    ok_text = ("Metodologi" in all_text and "Verdict" in all_text
               and "Cara membaca" in all_text and "TERBUKTI" in all_text
               and title_probe in all_text)
    if not ok_text or pages < 1:
        raise SystemExit("PDF dihasilkan tetapi konten tidak sesuai — fail-closed")

    print(json.dumps({
        "ok": True, "out": str(out), "pages": pages,
        "render_s": round(render_s, 3),
        "pdf_bytes": out.stat().st_size,
        "sha256": sha256_file(out)[:16],
        "total_findings": data["total_findings"],
        "reportable": data["reportable_count"],
        "delta": bool(data["delta"]),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
