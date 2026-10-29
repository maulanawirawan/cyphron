"""Shared findings helpers for the cyphron skill packs — SATU PINTU.

Every skill writes ONE output format: `findings.json`, compatible with the
Cyphron `Finding` schema + verdict ladder (verdicts.py) and mapped to
RawFinding/NormalizedFinding by packages/scanner adapters (plan F3).

Skill findings are deterministic probes: a skill that reproduces a response
differential or reads back a marker reports status="confirmed" with
evidence_kind="request-response" (verdict L3); a plausible-but-unproven hit
reports status="unconfirmed" (L1 LEAD). Skills NEVER guess — fail-closed.

Hardening F-BOW: validasi ketat severity/status/confidence/cwe/verdict
sinkron dengan core-rs/src/contract.rs (byte-identik). Tidak ada klaim
tanpa bukti — fail-closed di setiap hop.

Gerbang bukti (Evidence Gate — sync contract.rs):
  - status "unconfirmed" TIDAK BOLEH membawa verdict >= MIN_REPORT_LEVEL
    (L3+) — klaim belum terkonfirmasi maksimal LEAD (L1).
  - status "false-positive" wajib verdict -1.
  - verdict >= 3 (reportable) WAJIB membawa bukti nyata: minimal satu
    dari request/response/poc non-kosong. Metadata atau evidence_kind
    saja TIDAK menaikkan verdict — yang naik adalah bukti.
  - make_finding menolak kombinasi inkonsisten saat konstruksi, bukan
    hanya saat validasi (fail-closed di kedua sisi).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

__all__ = [
    "SEVERITIES", "VERDICT_NAMES", "MIN_REPORT_LEVEL", "VALID_STATUSES",
    "verdict_tag", "make_finding", "write_findings", "read_findings",
    "validate_finding",
]

SEVERITIES = ("critical", "high", "medium", "low", "info")
VALID_STATUSES = ("confirmed", "unconfirmed", "false-positive")

VERDICT_NAMES = {
    0: "OBSERVED", 1: "SUSPECTED", 2: "REPRODUCED",
    3: "DETERMINISTICALLY_VERIFIED", 4: "IMPACT_VERIFIED",
    5: "BLIND_VALIDATED", -1: "REJECTED",
}
MIN_REPORT_LEVEL = 3
VALID_VERDICTS = (-1, 0, 1, 2, 3, 4, 5)
_CWE_RE = re.compile(r"^CWE-\d{1,5}$")


def _is_valid_cwe(s: str) -> bool:
    return bool(_CWE_RE.match(s))


def verdict_tag(level: int) -> str:
    if level == -1:
        return "L-x REJECTED"
    name = VERDICT_NAMES.get(level, str(level)).replace("_", " ")
    lead = " - LEAD" if level < MIN_REPORT_LEVEL else ""
    return f"L{level} {name}{lead}"


def _has_core_evidence(f: dict) -> bool:
    """Bukti nyata di field inti: request/response/poc (sync contract.rs)."""
    return any(str(f.get(k) or "").strip() for k in ("request", "response", "poc"))


def validate_finding(f: dict) -> list[str]:
    """Validasi satu baris finding terhadap kontrak — return daftar error (kosong = valid)."""
    errs: list[str] = []
    if f.get("severity") not in SEVERITIES:
        errs.append(f"invalid severity: {f.get('severity')}")
    if f.get("status") not in VALID_STATUSES:
        errs.append(f"invalid status: {f.get('status')}")
    # confidence: HARUS angka (bool ditolak) — sinkron dengan serde f64 di
    # contract.rs yang menolak string "0.5" saat parse. Dulu Python menerima
    # string numerik = drift dua-bahasa (lolos Python, gagal di Rust).
    conf_raw = f.get("confidence", 0.5)
    if isinstance(conf_raw, bool) or not isinstance(conf_raw, (int, float)):
        errs.append(f"confidence not numeric: {conf_raw!r}")
    else:
        if not (0.0 <= float(conf_raw) <= 1.0):
            errs.append(f"confidence out of range 0.0..1.0: {conf_raw}")
    cwe = f.get("cwe")
    if cwe and not _is_valid_cwe(cwe):
        errs.append(f"invalid cwe format: {cwe}")
    v = f.get("verdict")
    if v not in VALID_VERDICTS:
        errs.append(f"verdict out of range L-x..L5: {v}")
    else:
        expect_tag = verdict_tag(int(v))
        if f.get("verdict_tag") != expect_tag:
            errs.append(f"verdict_tag mismatch: got '{f.get('verdict_tag')}', contract '{expect_tag}'")
        expect_rep = int(v) >= MIN_REPORT_LEVEL
        if bool(f.get("reportable")) != expect_rep:
            errs.append(f"reportable mismatch: verdict {v} => {expect_rep}")
        # Gerbang bukti (sync contract.rs Finding::validate):
        if f.get("status") == "unconfirmed" and int(v) >= MIN_REPORT_LEVEL:
            errs.append(
                f"unconfirmed finding cannot carry verdict {v} "
                f"(>= L{MIN_REPORT_LEVEL}) — klaim belum terkonfirmasi maksimal L1"
            )
        if f.get("status") == "false-positive" and int(v) != -1:
            errs.append(f"false-positive must carry verdict -1, got {v}")
        if f.get("status") == "confirmed" and expect_rep and not _has_core_evidence(f):
            errs.append(
                f"confirmed verdict {v} without evidence: request/response/poc "
                "semuanya kosong — L3 wajib bukti nyata"
            )
    # id deterministik sha256(tool|title|target_url|file_path|param)[:16] — strict single hash, no alt_id
    tool = f.get("tool", "")
    title = f.get("title", "")
    target = f.get("target_url")
    if not target and isinstance(f.get("extra"), dict):
        target = f["extra"].get("target_url") or ""
    target = target or ""
    fp = f.get("file_path")
    if fp is None and isinstance(f.get("extra"), dict):
        fp = f["extra"].get("file_path") or ""
    fp = fp or ""
    param = f.get("param")
    if param is None and isinstance(f.get("extra"), dict):
        param = f["extra"].get("param") or ""
    param = param or ""
    basis = "|".join([str(tool), str(title), str(target), str(fp), str(param)])
    expect_id = hashlib.sha256(basis.encode()).hexdigest()[:16]
    if tool and title and f.get("id") and f["id"] != expect_id:
        errs.append(f"id mismatch: got '{f.get('id')}', contract '{expect_id}'")
    return errs


def make_finding(
    *,
    tool: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str = "",
    cwe: str | None = None,
    target_url: str | None = None,
    file_path: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    param: str | None = None,
    request: str | None = None,
    response: str | None = None,
    poc: str | None = None,
    evidence_kind: str = "",
    finding_class: str = "weakness",
    confidence: float = 0.5,
    status: str = "unconfirmed",
    verdict: int | None = None,
    lab_only: bool = False,
    extra: dict | None = None,
    **more,
) -> dict:
    """Build one finding dict; verdict defaults from evidence shape. Fail-closed validation."""
    if severity not in SEVERITIES:
        raise ValueError(f"invalid severity: {severity}")
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status} (allowed: {VALID_STATUSES})")
    if not (0.0 <= float(confidence) <= 1.0):
        raise ValueError(f"confidence out of range 0.0..1.0: {confidence}")
    if cwe and not _is_valid_cwe(cwe):
        raise ValueError(f"invalid cwe format: {cwe} (expected CWE-NNN)")
    if verdict is not None and verdict not in VALID_VERDICTS:
        raise ValueError(f"verdict out of range L-x..L5: {verdict}")
    # Gerbang status-verdict saat konstruksi (fail-closed dua sisi, sync
    # contract.rs): kombinasi inkonsisten ditolak, bukan dibiarkan lolos
    # sampai validate_finding.
    if verdict is None:
        if status == "false-positive":
            verdict = -1
        elif status == "confirmed" and evidence_kind in (
            "request-response", "probe-pair", "oob", "arithmetic", "differential"
        ):
            verdict = 3
        elif evidence_kind:
            verdict = 1
        else:
            verdict = 0
    else:
        if status == "false-positive" and verdict != -1:
            raise ValueError(
                f"false-positive must carry verdict -1, got {verdict}"
            )
        if status == "unconfirmed" and verdict > 1:
            raise ValueError(
                f"unconfirmed finding cannot carry verdict {verdict} "
                "(>= L2) — klaim belum terkonfirmasi maksimal L1 "
                "(naikkan status ke 'confirmed' dengan bukti nyata, "
                "atau turunkan verdict; fail-closed)"
            )
        if status == "confirmed" and verdict == -1:
            raise ValueError("confirmed finding cannot carry verdict -1 (REJECTED)")
    if status == "confirmed" and verdict >= MIN_REPORT_LEVEL and not (
        str(request or "").strip()
        or str(response or "").strip()
        or str(poc or "").strip()
    ):
        raise ValueError(
            f"confirmed verdict {verdict} tanpa bukti: request/response/poc "
            "semuanya kosong — L3 wajib bukti nyata (fail-closed)"
        )
    basis = "|".join([tool, title, target_url or "", file_path or "", param or ""])
    out = {
        "tool": tool,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "cwe": cwe,
        "target_url": target_url,
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "param": param,
        "request": request,
        "response": response,
        "poc": poc,
        "confidence": float(confidence),
        "status": status,
        "evidence_kind": evidence_kind,
        "finding_class": finding_class,
        "id": hashlib.sha256(basis.encode()).hexdigest()[:16],
        "verdict": verdict,
        "verdict_tag": verdict_tag(verdict),
        "reportable": verdict >= MIN_REPORT_LEVEL,
        "lab_only": lab_only,
    }
    if extra:
        # jangan biarkan extra menimpa field inti tanpa sengaja
        for k, v in extra.items():
            if k in out and out[k] != v:
                # extra yang bentrok di-log sebagai extension terpisah
                out[f"extra_{k}"] = v
            else:
                out[k] = v
    if more:
        for k, v in more.items():
            if k in out and out[k] != v:
                out[f"extra_{k}"] = v
            else:
                out[k] = v
    return out


def write_findings(path: str | Path, findings: list[dict], meta: dict | None = None) -> None:
    """Write the single-pintu findings.json contract."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "ok": True,
        "data": meta or {},
        "findings": findings,
        "requests": int((meta or {}).get("requests", 0)),
    }
    Path(path).write_text(
        json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def read_findings(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
