"""Verifier — a candidate becomes a CONFIRMED finding only with concrete,
reproducible evidence. Rule-based (not LLM-judged): request/response pairs,
code lines with matched patterns, or header facts. Everything else stays
'unconfirmed' and is reported separately so it can never inflate results."""

from __future__ import annotations

from .findings import Finding, dedupe

MIN_CONFIRMED_CONFIDENCE = 0.5


def finalize(candidates: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Returns (confirmed, unconfirmed), deduped and sorted."""
    confirmed: list[Finding] = []
    unconfirmed: list[Finding] = []
    for f in candidates:
        if f.evidence_kind == "request-response" and not (f.request or f.response):
            f.status = "unconfirmed"
            f.confidence = min(f.confidence, 0.3)
        if f.status == "confirmed" and f.confidence < MIN_CONFIRMED_CONFIDENCE:
            f.status = "unconfirmed"
        (confirmed if f.status == "confirmed" else unconfirmed).append(f)
    return dedupe(confirmed), dedupe(unconfirmed)
