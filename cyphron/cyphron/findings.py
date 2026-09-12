"""Normalized finding schema (interop) — tool, cwe, severity, title,
description, recommendation, filePath/lines, targetUrl, evidence/PoC,
confidence, sourceSkill. Includes fingerprint dedup."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
VALID_SEVERITIES = set(SEVERITY_ORDER)


@dataclass
class Finding:
    tool: str
    title: str
    severity: str
    description: str
    recommendation: str = ""
    cwe: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    target_url: str | None = None
    param: str | None = None
    request: str | None = None
    response: str | None = None
    poc: str | None = None
    confidence: float = 0.0
    source_skill: str = ""
    status: str = "unconfirmed"  # confirmed | unconfirmed | false-positive
    evidence_kind: str = ""  # request-response | code-line | probe-pair | header | file
    finding_class: str = "weakness"  # exploitable | weakness | posture | surface | info
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: str = ""
    evidence_chain: list = field(default_factory=list)  # Evidence Ledger provenance

    def __post_init__(self):
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        basis = "|".join([
            self.tool, self.title, self.target_url or "", self.file_path or "",
            self.param or "",
        ])
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def attach_evidence(self, kind: str, detail: dict) -> None:
        """Evidence Ledger: provenance berantai (validator, repro, artifact).

        Setiap entri diberi timestamp + hash sehingga auditor dapat menjawab
        "kenapa Cyphron yakin temuan ini benar" tanpa memercayai klaim."""
        entry = {
            "kind": kind,
            "at": datetime.now(timezone.utc).isoformat(),
            "sha256": hashlib.sha256(
                json.dumps(detail, sort_keys=True, default=str).encode()).hexdigest()[:16],
        }
        entry.update(detail)
        self.evidence_chain.append(entry)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.id in seen:
            existing = seen[f.id]
            if f.confidence > existing.confidence:
                seen[f.id] = f
        else:
            seen[f.id] = f
    return sorted(
        seen.values(),
        key=lambda f: (SEVERITY_ORDER[f.severity], -f.confidence, f.title),
    )
