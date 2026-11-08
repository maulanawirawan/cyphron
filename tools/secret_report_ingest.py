r"""[INGEST] secret_report_ingest — ingest laporan pemindai secret
eksternal (gitleaks JSON / trufflehog JSON-JSONL) -> findings.json
secai + DIFF BASELINE: hanya temuan BARU (tidak ada di baseline)
yang dihitung gate.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/implementing-secret-scanning-with-gitleaks' (#0699) +
'skills/implementing-secrets-scanning-in-ci-cd' (#0701) — atribusi
konsep; lisensi sumber Apache-2.0. Dibangun FROM SCRATCH TANPA
menyalin kode sumber/tool sumber (gitleaks/trufflehog sendiri adalah
alat pihak ketiga — di sini laporan HASILNYA yang diingest, scanner
eksternal tetap dijalankan CI terpisah).

Premis sumber yang diekstrak (manajemen baseline): repo legacy sudah
memuat ribuan temuan lama — memblokir SEMUA temuan menumpukan
development; gitleaks memakai --baseline-path agar hanya temuan BARU
yang gagal CI. Konsep yang diport: (1) satu pintu ingest lintas
scanner, (2) id stabil per temuan, (3) diff baseline -> gate "new
only", (4) triase baseline wajib di-review & dikurangi saat rotasi —
baseline BUKAN allowlist abadi.

Ranah dibagi eksplisit:
  - sarif_ingest      : SARIF 2.1.0 generik (gitleaks bisa emit
    SARIF — masuk situ); tool ini melayani format JSON NATIF
    gitleaks + trufflehog dan logika baseline-diff.
  - secret_history_scan / repo-secret-scan : PEMINDAI git/file
    sendiri (menghasilkan temuan); tool ini INGEST laporan scanner
    eksternal — arah input berbeda.
  - exploit_ci_gate   : gerbang CI repo sendiri.

Input -> mekanisme -> output:
  - Input : --report FILE[,FILE...] — JSON natif gitleaks (array
            entri dgn RuleID/File/StartLine/Secret/Fingerprint) ATAU
            trufflehog (array atau JSONL dgn SourceMetadata/Detector/
            Raw/Verified). Deteksi format PER ENTRI, bukan per file.
            --baseline FILE — output findings.json tool ini dari run
            sebelumnya (id temuan = known).
  - Mekanisme: normalisasi -> id kontrak secai (make_finding,
            sha256(tool|title|target|file|param)) -> redaksi nilai
            (prefix 4 + panjang, TIDAK PERNAH nilai penuh) -> diff
            vs baseline (id) -> gate.
  - Output: findings.json; meta: total/new/known/dedup/rejected +
            jumlah per scanner. Temuan = status confirmed, verdict
            L2 REPRODUCED (string terbukti ada di laporan), severity:
            gitleaks = high (rule-based); trufflehog = critical bila
            Verified (verifikasi live scanner sumber) selain itu high.

Fail-closed: file tak ter-parse / tidak ada entri ter-recognize sama
sekali -> exit 2; entri bentuk asing ditolak + dihitung (tidak
diam-diam); nilai rahasia tak pernah masuk output penuh.

Pemakaian:
  python tools/secret_report_ingest.py --report gl.json,th.jsonl \
      --baseline baseline.json --out findings.json
Exit: 0 tidak ada temuan BARU; 1 ada temuan baru (gate gagal);
      2 error input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "secai.secret-report-ingest/1"
MAX_FILE_BYTES = 64 * 1024 * 1024

SEVERITY_GITLEAKS = "high"
SEVERITY_TRUFFLEHOG = "high"
SEVERITY_TRUFFLEHOG_VERIFIED = "critical"


def _redact(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return "(kosong)"
    if len(v) <= 8:
        return f"{v[:2]}***({len(v)} char)"
    return f"{v[:4]}***({len(v)} char)"


def _norm_path(p: str) -> str:
    return (p or "").replace("\\", "/").strip()


def is_gitleaks_entry(e: dict) -> bool:
    return isinstance(e, dict) and "RuleID" in e and (
        "File" in e or "Secret" in e)


def is_trufflehog_entry(e: dict) -> bool:
    if not isinstance(e, dict):
        return False
    if "DetectorName" in e or "DetectorType" in e:
        return True
    return "SourceMetadata" in e and ("Raw" in e or "RawV3" in e
                                      or "Data" in e)


def norm_gitleaks(e: dict, source_file: str) -> dict | None:
    rule = str(e.get("RuleID") or "gitleaks-rule")
    path = _norm_path(str(e.get("File") or ""))
    line = e.get("StartLine")
    secret = str(e.get("Secret") or "")
    title = f"gitleaks:{rule}"
    desc = (
        f"Pemindai gitleaks menandai {rule} di {path}"
        f"{':' + str(line) if line else ''} — nilai diredaksi "
        f"({_redact(secret)})."
        + (f" Commit: {e.get('Commit')}" if e.get("Commit") else ""))
    if not path:
        return None
    # param = identitas NON-rahasia utk stabilitas id baseline:
    # fingerprint gitleaks (commit:file:line:rule-hash, tanpa nilai)
    fp = e.get("Fingerprint")
    return {
        "title": title,
        "severity": SEVERITY_GITLEAKS,
        "description": desc,
        "file_path": path,
        "line_start": int(line) if isinstance(line, int) else None,
        "param": str(fp) if fp else None,
        "poc": f"{path}:{line} rule={rule} secret={_redact(secret)}",
        "scanner": "gitleaks",
        "verified": None,
    }


def norm_trufflehog(e: dict, source_file: str) -> dict | None:
    det = str(e.get("DetectorName") or e.get("DetectorType")
              or "trufflehog-detector")
    meta = e.get("SourceMetadata") or {}
    data = (meta.get("Data") or {}) if isinstance(meta, dict) else {}
    path = _norm_path(str(data.get("FilesystemPath")
                          or data.get("file") or ""))
    if not path and e.get("SourceName") == "git":
        repo = str(data.get("repo") or "")
        path = f"git:{repo}" if repo else ""
    if not path:
        path = source_file  # scanner output tanpa path file sumber
    raw = str(e.get("Raw") or e.get("RawV3") or e.get("Data") or "")
    verified = bool(e.get("Verified"))
    title = f"trufflehog:{det}" + (" (verified)" if verified else "")
    desc = (
        f"Pemindai trufflehog menandai {det} di {path} — nilai "
        f"diredaksi ({_redact(raw)}); Verified={verified} "
        f"(verifikasi live milik scanner sumber).")
    # param = identitas NON-rahasia: SourceID bila ada, selain itu
    # konteks top-level non-terkait-rahasia (Raw/RawV3/ExtraData
    # dikecualikan) — jangan pernah menaruh nilai secret di param
    sid = e.get("SourceID")
    if sid:
        param = str(sid)
    else:
        ctx = {k: v for k, v in e.items()
               if k not in ("Raw", "RawV3", "ExtraData",
                            "SourceMetadata")
               and isinstance(v, (str, int, float, bool))}
        param = json.dumps(ctx, sort_keys=True, default=str)[:120]
    return {
        "title": title,
        "severity": (SEVERITY_TRUFFLEHOG_VERIFIED if verified
                     else SEVERITY_TRUFFLEHOG),
        "description": desc,
        "file_path": path,
        "line_start": None,
        "param": param or None,
        "poc": f"{path} detector={det} secret={_redact(raw)} "
               f"verified={verified}",
        "scanner": "trufflehog",
        "verified": verified,
    }


def load_reports(paths: list[str]) -> tuple[list[dict], dict]:
    """Baca semua laporan -> entri ternormalisasi + meta."""
    entries: list[dict] = []
    meta = {"files": 0, "json_lines": 0, "recognized": 0,
            "rejected": 0, "by_scanner": {}}
    for path in paths:
        raw = Path(path).read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise SystemExit(2)
        text = raw.decode("utf-8", "replace")
        meta["files"] += 1
        candidates: list[dict] = []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                candidates = [c for c in data if isinstance(c, dict)]
            elif isinstance(data, dict):
                # beberapa tool membungkus: {"findings": [...]}
                inner = data.get("findings") or data.get("results")
                if isinstance(inner, list):
                    candidates = [c for c in inner if isinstance(c, dict)]
                else:
                    candidates = [data]
        except ValueError:
            # JSONL: satu objek per baris
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                meta["json_lines"] += 1
                try:
                    c = json.loads(line)
                except ValueError:
                    meta["rejected"] += 1
                    continue
                if isinstance(c, dict):
                    candidates.append(c)
        for c in candidates:
            norm = None
            if is_gitleaks_entry(c):
                norm = norm_gitleaks(c, path)
            elif is_trufflehog_entry(c):
                norm = norm_trufflehog(c, path)
            if norm is None:
                meta["rejected"] += 1
                continue
            meta["recognized"] += 1
            meta["by_scanner"][norm["scanner"]] = \
                meta["by_scanner"].get(norm["scanner"], 0) + 1
            entries.append(norm)
    if meta["recognized"] == 0:
        # tidak ada satu pun entri dikenali dari semua laporan = input
        # salah format (fail-closed), bukan "bersih"
        raise SystemExit(2)
    return entries, meta


def load_baseline_ids(path: str | None) -> set[str]:
    ids: set[str] = set()
    if not path:
        return ids
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = doc.get("findings") if isinstance(doc, dict) else doc
    if isinstance(findings, dict):
        findings = findings.get("findings")
    if not isinstance(findings, list):
        raise SystemExit(2)
    for f in findings:
        if isinstance(f, dict) and isinstance(f.get("id"), str):
            ids.add(f["id"])
    return ids


def build_findings(entries: list[dict],
                   baseline: set[str]) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    seen: set[str] = set()
    new_ids: set[str] = set()
    dedup = 0
    known = 0
    for e in entries:
        f = make_finding(
            tool="secret_report_ingest",
            title=e["title"],
            severity=e["severity"],
            description=e["description"],
            recommendation="Rotasi kredensial SEKARANG (cabut di "
                           "provider, buat baru, masukkan secrets "
                           "manager); riwayat git dibersihkan hanya "
                           "dengan koordinasi tim (git-filter-repo).",
            file_path=e["file_path"],
            line_start=e.get("line_start"),
            param=e.get("param"),
            status="confirmed",
            evidence_kind="artifact-parse",
            poc=e["poc"],
            confidence=0.85,
            finding_class="exposure",
            extra={"scanner": e["scanner"],
                   "verified": e["verified"]},
        )
        if f["id"] in seen:
            dedup += 1
            continue
        seen.add(f["id"])
        if f["id"] in baseline:
            known += 1
            continue
        new_ids.add(f["id"])
        findings.append(f)
    meta = {
        "schema": SCHEMA,
        "recognized": len(entries),
        "unique": len(seen),
        "dedup": dedup,
        "baseline_known": known,
        "new": len(findings),
        "by_scanner": None,  # diisi pemanggil
        "baseline_size": len(baseline),
        "redaction": "nilai selalu diredaksi (prefix+panjang) — "
                     "laporan asli tetap di simpan scanner",
        "gate": "exit 1 bila ada temuan BARU (baseline diff)",
    }
    return findings, meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ingest laporan gitleaks/trufflehog + diff baseline")
    ap.add_argument("--report", required=True,
                    help="koma-pisah file laporan (gitleaks/trufflehog)")
    ap.add_argument("--baseline",
                    help="findings.json run sebelumnya (id = known)")
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args(argv)

    paths = [p.strip() for p in args.report.split(",") if p.strip()]
    for p in paths:
        if not Path(p).is_file():
            print(f"[secret_report_ingest] file tidak ada: {p}",
                  file=sys.stderr)
            return 2
    if args.baseline and not Path(args.baseline).is_file():
        print(f"[secret_report_ingest] baseline tidak ada: "
              f"{args.baseline}", file=sys.stderr)
        return 2

    try:
        entries, meta = load_reports(paths)
    except SystemExit:
        print("[secret_report_ingest] laporan tidak ter-parse ATAU "
              "0 entri dikenali (fail-closed)", file=sys.stderr)
        return 2
    try:
        baseline = load_baseline_ids(args.baseline)
    except SystemExit:
        print("[secret_report_ingest] baseline bukan output tool ini "
              "(fail-closed)", file=sys.stderr)
        return 2

    findings, out_meta = build_findings(entries, baseline)
    out_meta["by_scanner"] = meta["by_scanner"]
    out_meta["rejected"] = meta["rejected"]
    out_meta["files"] = meta["files"]
    write_findings(args.out, findings, out_meta)
    if findings:
        print(f"[secret_report_ingest] {len(findings)} temuan BARU "
              f"({out_meta['baseline_known']} baseline, "
              f"{out_meta['dedup']} dedup) -> {args.out}")
        return 1
    print(f"[secret_report_ingest] tanpa temuan baru "
          f"({out_meta['baseline_known']} baseline, "
          f"{out_meta['unique']} unik dikenali) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
