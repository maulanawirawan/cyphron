"""[INGEST] cspm_finding_ingest — ingest temuan CSPM eksternal (Prowler
flat/OCSF + ScoutSuite) -> findings.json secai.

Kenapa secai butuh ini: pemindaian postur cloud (Prowler/ScoutSuite) pada
lab menghasilkan file JSON/JSONL yang belum punya jalur masuk findings.json
— sarif_ingest hanya menerima SARIF 2.1.0. Tool ini satu pintu untuk keduanya
(verdict L0 OBSERVED — temuan postur = lead, bukan bukti runtime), sehingga
bisa di-merge (merge_findings) dan diaudit bersama temuan lain.

Format input yang dikenali (deteksi otomatis per file):
  1. Prowler flat JSON   : array objek (CheckId/Severity/Status/ResourceId/
                           Provider/AccountId/Region/ResourceType/
                           StatusExtended).
  2. Prowler OCSF JSONL  : satu objek per baris (severity_id 0-6, status_id,
                           resource.uid, finding_info.title, metadata
                           product.name/provider).
  3. ScoutSuite JSON     : laporan penuh; dikumpulkan rekursif dari node
                           yang punya kunci level+items (services.<svc>.
                           findings.*; danger->high, warning->medium,
                           sisanya bukan temuan).

Severity dinormalisasi ke secai: critical/high/medium/low/info. Nilai
severity di luar himpunan -> temuan DITOLAK (dihitung di meta), bukan
didiam-diamkan (fail-closed ala sarif_ingest).

Fail-closed:
  - bukan JSON/JSONL valid / tidak ada temuan ter-parse di SEMUA file
    -> error exit 2.
  - severity tak dikenali -> ditolak + dicatat meta.rejected_severity.
  - status tak dikenali (bukan FAIL/PASS atau padanannya) -> status
    "unknown" dihitung di meta dan temuan TETAP masuk dgn catatan
    (postur tidak bisa disimpulkan bersih).

Exit: 0 findings.json tertulis; 2 input tidak valid.

Pemakaian:
  python tools/cspm_finding_ingest.py --input prowler.json --out findings/cspm.json
  python tools/cspm_finding_ingest.py --input prowler-ocsf.jsonl \
      scout-results.json --out findings/cspm.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# mapping severity Prowler flat -> secai
FLAT_SEV = {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "informational": "info"}
# mapping OCSF severity_id -> secai (OCSF 3.0 event.severity_id)
OCSF_SEV = {0: "info", 1: "info", 2: "low", 3: "medium", 4: "high",
            5: "critical", 6: "critical"}
# ScoutSuite level -> secai (node findings)
SCOUT_SEV = {"danger": "high", "warning": "medium"}
FAIL_STATUSES = {"fail", "failing", "alarm", "non_compliant", "noncompliant",
                 "error", "alert"}
PASS_STATUSES = {"pass", "passed", "ok", "compliant", "secure", "resolved"}
MIN_REPORT_LEVEL = 3


def _norm_severity(raw: object) -> "str | None":
    if raw is None:
        return None
    return FLAT_SEV.get(str(raw).strip().lower())


def _norm_status(raw: object) -> str:
    s = str(raw or "").strip().lower()
    if s in FAIL_STATUSES:
        return "FAIL"
    if s in PASS_STATUSES:
        return "PASS"
    return "UNKNOWN"


def flat_id(f: dict) -> str:
    basis = f"{f.get('resource_id', '')}|{f.get('check_id', '')}"
    return "hash:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def parse_flat(items: list) -> "list[dict]":
    out: list[dict] = []
    for f in items:
        if not isinstance(f, dict):
            continue
        out.append({
            "check_id": str(f.get("CheckId") or f.get("check_id")
                            or f.get("CheckTitle") or "unknown-check"),
            "title": str(f.get("CheckTitle") or f.get("check_title")
                         or f.get("CheckId") or ""),
            "severity_raw": f.get("Severity") or f.get("severity"),
            "status_raw": f.get("Status") or f.get("status"),
            "provider": str(f.get("Provider") or f.get("provider")
                            or "unknown"),
            "account": str(f.get("AccountId") or f.get("account_id") or ""),
            "region": str(f.get("Region") or f.get("region") or ""),
            "resource_type": str(f.get("ResourceType")
                                 or f.get("resource_type") or ""),
            "resource_id": str(f.get("ResourceId") or f.get("resource_id")
                               or ""),
            "detail": str(f.get("StatusExtended")
                          or f.get("status_extended") or ""),
        })
    return out


def parse_ocsf_line(obj: dict) -> "dict | None":
    """Prowler json-ocsf: severity_id/status_id/resource.uid/finding_info."""
    if not isinstance(obj, dict):
        return None
    if "severity_id" not in obj and "finding_info" not in obj:
        return None
    info = obj.get("finding_info") or {}
    resource = obj.get("resource") or {}
    metadata = obj.get("metadata") or {}
    product = metadata.get("product") or {}
    cloud = (obj.get("cloud") or {}).get("provider") \
        if isinstance(obj.get("cloud"), dict) else None
    status_id = obj.get("status_id")
    # OCSF: 4=Resolved dianggap tidak aktif; lainnya dianggap aktif-FAIL
    # bila temuan dibawa (Prowler OCSF hanya menulis finding yang berstatus
    # failure utk checks yang gagal; status_id dibiarkan menyertai).
    status = "PASS" if status_id == 4 else "FAIL" if status_id is not None \
        else "UNKNOWN"
    sev = OCSF_SEV.get(obj.get("severity_id"))
    return {
        "check_id": str(info.get("title") or obj.get("check_id")
                        or "unknown-check"),
        "title": str(info.get("title") or ""),
        "severity_raw": sev,
        "status_raw": "FAIL" if status == "FAIL" else ("PASS" if status
                                                       == "PASS" else ""),
        "provider": str(cloud or product.get("vendor_name")
                        or product.get("name") or "unknown"),
        "account": str(resource.get("account_uid")
                       or obj.get("account_uid") or ""),
        "region": str(obj.get("region") or ""),
        "resource_type": str(resource.get("type") or ""),
        "resource_id": str(resource.get("uid") or ""),
        "detail": str(obj.get("message") or obj.get("desc") or ""),
    }


def collect_scout(node: object, out: "list[dict]",
                  path: str = "") -> None:
    """Rekursif: kumpulkan node findings ScoutSuite (punya level+items)."""
    if isinstance(node, dict):
        level = node.get("level")
        items = node.get("items")
        if isinstance(level, str) and level.lower() in SCOUT_SEV \
                and isinstance(items, list):
            out.append({
                "check_id": path.rsplit("/", 1)[-1] or "scout-finding",
                "title": str(node.get("description") or path),
                "severity_raw": SCOUT_SEV[level.lower()],
                "status_raw": "FAIL",
                "provider": "scoutsuite",
                "account": "",
                "region": "",
                "resource_type": path.split("/")[1] if "/" in path else "",
                "resource_id": "; ".join(str(x) for x in items[:5])[:300],
                "detail": str(node.get("rationale") or ""),
            })
        for key, val in node.items():
            collect_scout(val, out, f"{path}/{key}" if path else str(key))
    elif isinstance(node, list):
        for val in node:
            collect_scout(val, out, path)


def load_norms(path: Path) -> "tuple[list[dict], list[str]]":
    """Baca satu file -> (normalized list, errors). Deteksi format otomatis:
    JSON utuh dulu (array/objek), kalau gagal -> JSONL baris-per-baris."""
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    norms: list[dict] = []
    doc: object = None
    json_ok = False
    if stripped.startswith(("[", "{")):
        try:
            doc = json.loads(text)
            json_ok = True
        except json.JSONDecodeError:
            pass  # JSONL baris-ganda -> cabang fallback di bawah
    if json_ok and isinstance(doc, dict) \
            and isinstance(doc.get("configurationItems"), list):
        norms = parse_flat([x for x in doc["configurationItems"]
                            if isinstance(x, dict)])
    elif json_ok and isinstance(doc, list):
        norms = parse_flat([x for x in doc if isinstance(x, dict)])
    elif json_ok and isinstance(doc, dict):
        collect_scout(doc, norms)
    if not norms:
        # JSONL: satu objek per baris (OCSF/generik)
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"{path}:{line_no}: baris bukan JSON")
                continue
            norm = parse_ocsf_line(obj)
            if norm is None:
                norm = parse_flat([obj])[0] if isinstance(obj, dict) else None
            if norm:
                norms.append(norm)
    return norms, errors


def ingest(paths: "list[str | Path]",
           min_severity: str = "info") -> "tuple[list[dict], dict]":
    """Baca satu/lebih ekspor CSPM -> (findings kontrak, meta)."""
    if min_severity not in SEV_ORDER:
        raise ValueError(f"--min-severity tidak sah: {min_severity!r} "
                         f"(allowed: {'|'.join(SEV_ORDER)})")
    norms: list[dict] = []
    errors: list[str] = []
    for p in map(Path, paths):
        try:
            file_norms, file_errors = load_norms(p)
            norms.extend(file_norms)
            errors.extend(file_errors)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{p}: {exc}")
    if not norms:
        raise ValueError("tidak ada temuan CSPM yang ter-parse:\n  "
                         + "\n  ".join(errors or ["(tidak ada input)"]))

    meta: dict = {"inputs": len(paths), "file_errors": errors,
                  "parsed": len(norms), "pass_count": 0,
                  "unknown_status": 0, "rejected_severity": 0,
                  "dedup_dropped": 0, "severity_histogram": {}}
    by_id: dict[str, dict] = {}
    for norm in norms:
        status = _norm_status(norm["status_raw"])
        if status == "PASS":
            meta["pass_count"] += 1
            continue
        if status == "UNKNOWN":
            meta["unknown_status"] += 1
        sev = _norm_severity(norm["severity_raw"]) \
            if norm["severity_raw"] is not None else None
        # OCSF memetakan severity_id langsung ke label secai
        if sev is None and norm["severity_raw"] is not None:
            sev = str(norm["severity_raw"]).lower()
        if sev not in SEV_ORDER:
            meta["rejected_severity"] += 1
            continue
        if SEV_ORDER[sev] > SEV_ORDER[min_severity]:
            continue
        meta["severity_histogram"][sev] = \
            meta["severity_histogram"].get(sev, 0) + 1
        fid = flat_id(norm)
        if fid in by_id:
            meta["dedup_dropped"] += 1
            continue
        by_id[fid] = {**norm, "severity": sev, "fid": fid}

    ordered = sorted(by_id.values(),
                     key=lambda n: (SEV_ORDER[n["severity"]], n["check_id"]))
    findings: list[dict] = []
    for norm in ordered:
        title = f"{norm['check_id']}: {norm['title'] or norm['detail']}"
        findings.append(make_finding(
            tool=f"cspm:{norm['provider']}",
            title=title[:300],
            severity=norm["severity"],
            description=norm["detail"] or norm["title"],
            recommendation="Verifikasi manual + remediasi sesuai kontrol "
                           "postur cloud; temuan postur = lead statis.",
            target_url=None,
            file_path=None,
            line_start=None,
            line_end=None,
            evidence_kind="posture-analysis",
            finding_class="misconfiguration",
            confidence=0.6,
            status="unconfirmed",
            verdict=0,
            extra={
                "cspm_fingerprint": norm["fid"],
                "check_id": norm["check_id"],
                "resource_id": norm["resource_id"],
                "resource_type": norm["resource_type"],
                "account": norm["account"],
                "region": norm["region"],
            },
        ))
    meta["emitted"] = len(findings)
    return findings, meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="cspm_finding_ingest — ingest temuan CSPM eksternal "
                    "(Prowler flat/OCSF, ScoutSuite) -> findings.json "
                    "secai (fail-closed; L0 OBSERVED).")
    ap.add_argument("--input", required=True, nargs="+",
                    help="satu/lebih file JSON/JSONL hasil CSPM")
    ap.add_argument("--out", required=True, help="path findings.json output")
    ap.add_argument("--min-severity", default="info",
                    choices=sorted(SEV_ORDER),
                    help="severity minimum yang diemisikan (default: info)")
    args = ap.parse_args(argv)
    try:
        findings, meta = ingest(args.input, min_severity=args.min_severity)
    except ValueError as exc:
        print(f"[cspm-ingest] ditolak: {exc}", file=sys.stderr)
        return 2
    write_findings(args.out, findings, meta=meta)
    print(f"[cspm-ingest] inputs={meta['inputs']} parsed={meta['parsed']} "
          f"-> emitted={meta['emitted']} (pass={meta['pass_count']}, "
          f"dedup -{meta['dedup_dropped']}, severity-reject "
          f"{meta['rejected_severity']}, unknown-status "
          f"{meta['unknown_status']})")
    for err in meta["file_errors"]:
        print(f"[cspm-ingest] SKIP: {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
