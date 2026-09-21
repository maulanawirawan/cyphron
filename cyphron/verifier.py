"""Verifier — a candidate becomes a CONFIRMED finding only with concrete,
reproducible evidence. Rule-based (not LLM-judged): request/response pairs,
probe pairs, arithmetic/OOB/differential — atau code lines dengan pola yang
cocok. Everything else stays 'unconfirmed' (LEAD) and is reported separately
so it can never inflate results.

Verdict Ladder ditegakkan DI SINI (kontrak verdicts.py): status 'confirmed'
yang verdict-nya < MIN_REPORT_LEVEL (bukti non-deterministik: header/file
saja) DITURUNKAN ke lead — 'RISIKO TERKONFIRMASI' untuk klien wajib bukti
deterministik, bukan sekadar observasi konsisten."""

from __future__ import annotations

from . import verdicts as _verdicts
from .findings import Finding, dedupe

MIN_CONFIRMED_CONFIDENCE = 0.5


def finalize(candidates: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Returns (confirmed, unconfirmed), deduped and sorted.

    Enforce verdict ladder: confirmed tanpa bukti deterministik (verdict < 3)
    turun ke unconfirmed — mis. temuan ber-evidence "header" saja (CSP
    missing) adalah hardening LEAD, bukan kerentanan terkonfirmasi."""
    confirmed: list[Finding] = []
    unconfirmed: list[Finding] = []
    for f in candidates:
        if f.evidence_kind == "request-response" and not (f.request or f.response):
            f.status = "unconfirmed"
            f.confidence = min(f.confidence, 0.3)
        if f.status == "confirmed" and f.confidence < MIN_CONFIRMED_CONFIDENCE:
            f.status = "unconfirmed"
        if f.status == "confirmed" and not _verdicts.qualifies_for_report(f):
            # verdict ladder: REPRODUCED (2) atau di bawahnya = LEAD
            f.status = "unconfirmed"
            f.confidence = min(f.confidence, 0.49)
        (confirmed if f.status == "confirmed" else unconfirmed).append(f)
    return dedupe(confirmed), dedupe(unconfirmed)
