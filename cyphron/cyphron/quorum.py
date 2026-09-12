"""quorum — Independent Validator Quorum (Cyphron Intelligence Fabric).

Satu mesin tidak boleh menentukan sendiri bahwa temuannya valid. Adjudicator
ini mengumpulkan suara TIGA validator independen yang rule-based (bukan
LLM-judged, jadi deterministik dan bisa diaudit):

  V1 runtime-evidence : status `confirmed` dari verifier + evidence_kind yang
     dapat direproduksi (request-response / probe-pair / header / file /
     code-line) + confidence >= 0.5.
  V2 skeptic          : bukti minimal ADA dan bisa dipakai ulang orang lain -
     (request DAN response) ATAU (code location DAN poc) ATAU poc eksplisit.
     Skeptic yang gagal keras menolak temuan apa pun statusnya.
  V3 consistency      : schema masuk akal (CWE format, severity valid,
     description cukup detail, title spesifik).

Kombinasi (deterministik):
  skeptic gagal                        -> REJECTED  (0.1)
  runtime evidence + >= 2 validator    -> CONFIRMED (0.9)
  >= 1 validator (tanpa runtime evid.) -> PROBABLE  (0.6)
  tanpa kegagalan keras, 0 vote        -> INCONCLUSIVE (0.3)

CONFIRMED selalu menuntut V1: bukti runtime yang dapat direproduksi adalah
tulang punggung; kesesuaian schema dan bukti tertulis saja tidak cukup.

Status quorum TIDAK pernah menaikkan severity dan TIDAK menghapus temuan -
hanya melabeli keyakinan. Laporan enterprise bisa menampilkan baris
"Independent Validators: 3/3" per temuan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .findings import Finding, VALID_SEVERITIES

__all__ = ["Verdict", "adjudicate"]

_CWE_RE = re.compile(r"^CWE-\d+$")
_REPRO_KINDS = {"request-response", "probe-pair", "header", "file", "code-line"}


@dataclass
class Verdict:
    finding_id: str
    status: str                    # CONFIRMED | PROBABLE | INCONCLUSIVE | REJECTED
    technical_confidence: float
    validators: dict[str, bool]
    notes: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "status": self.status,
            "technical_confidence": self.technical_confidence,
            "validators": self.validators, "notes": self.notes,
        }


def _v1_runtime_evidence(f: Finding) -> bool:
    return (f.status == "confirmed" and f.confidence >= 0.5
            and f.evidence_kind in _REPRO_KINDS)


def _v2_skeptic(f: Finding) -> bool:
    has_pair = bool(f.request) and bool(f.response)
    has_code = bool(f.file_path) and bool(f.poc)
    has_poc = bool(f.poc)
    return has_pair or has_code or has_poc


def _v3_consistency(f: Finding) -> bool:
    if f.severity not in VALID_SEVERITIES:
        return False
    if f.cwe and not _CWE_RE.match(f.cwe):
        return False
    if len(f.description or "") < 60:
        return False
    if len(f.title or "") < 15:
        return False
    # confidence 1.0 tanpa bukti pair/code = red flag konsistensi
    if f.confidence >= 0.99 and not (f.request and f.response) and not f.file_path:
        return False
    return True


def adjudicate(findings: list[Finding]) -> list[Verdict]:
    out: list[Verdict] = []
    for f in findings:
        v1 = _v1_runtime_evidence(f)
        v2 = _v2_skeptic(f)
        v3 = _v3_consistency(f)
        validators = {"runtime_evidence": v1, "skeptic": v2, "consistency": v3}
        votes = sum([v1, v2, v3])
        if not v2:
            status, conf = "REJECTED", 0.1
            note = "skeptic: tidak ada bukti yang dapat direproduksi"
        elif v1 and votes >= 2:
            status, conf = "CONFIRMED", 0.9
            note = f"validators agree: {votes}/3 (runtime evidence present)"
        elif votes >= 1:
            status, conf = "PROBABLE", 0.6
            note = f"{votes} validator agree tanpa runtime evidence - butuh repro"
        else:
            status, conf = "INCONCLUSIVE", 0.3
            note = "no hard failure but no positive vote"
        out.append(Verdict(finding_id=f.id, status=status,
                           technical_confidence=conf, validators=validators,
                           notes=note))
    return out


def summarize(verdicts: list[Verdict]) -> dict:
    counts = {"CONFIRMED": 0, "PROBABLE": 0, "INCONCLUSIVE": 0, "REJECTED": 0}
    for v in verdicts:
        counts[v.status] = counts.get(v.status, 0) + 1
    return counts
