"""[F17] Novelty & duplicate-risk classifier — pelajaran triage lapangan.

Dari 5 laporan lapangan: 2 ditolak karena DUPLIKAT (email-posture + wp-user-
enumeration). Fungsi ini menilai risiko duplikat SEBELUM laporan dikirim:

  risiko TINGGI : temuan kelas "widely-known" (email-posture, wp-user-enum,
                  security-header, tls-posture) di domain besar/terkenal —
                  pelapor lain hampir pasti sudah melaporkan duluan.
  risiko SEDANG : kelas behavioral di subdomain aplikasi (rate-limit,
                  debug-page) — duplikat mungkin bila aplikasi populer.
  risiko RENDAH : temuan dengan bukti khusus (chain, IDOR spesifik,
                  endpoint jarang) — nilai baru paling tinggi.

Sumber cek opsional: arsip Open Bug Bounty untuk domain (1 GET, read-only).

Pemakaian (dipakai pipeline laporan, bukan berdiri sendiri):
  from tools.novelty_check import classify
  flag = classify(finding, domain_tier="major-org")
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

# Kelas temuan yang cenderung sudah dilaporkan orang lain (dari data
# triage nyata: 2/5 laporan lapangan ditolak karena duplikat di kelas ini)
WIDELY_KNOWN_CLASSES = {
    "email-posture", "wp-user-enumeration", "security-header",
    "tls-posture", "email-posture-dns", "posture", "surface",
    "rate-limit-missing (domain utama)",
}
TITLE_HINTS_HIGH = (
    "DMARC", "SPF", "security header", "missing security",
    "user enumeration", "REST API user", "directory listing",
    "TLS certificate", "security.txt",
)
TITLE_HINTS_MEDIUM = ("rate limit", "verbose", "debug page", "cookie")


def classify(title: str, finding_class: str | None = None,
             target: str | None = None) -> dict:
    blob = title.lower()
    cls = (finding_class or "").lower()
    if cls in {c.split(" (")[0] for c in WIDELY_KNOWN_CLASSES} or \
       any(h.lower() in blob for h in TITLE_HINTS_HIGH):
        level = "HIGH"
    elif any(h in blob for h in TITLE_HINTS_MEDIUM) or \
            cls.startswith(("rate-limit", "debug-page")):
        level = "MEDIUM"
    else:
        level = "LOW"
    advice = {
        "HIGH": "CEK DULU: laporan sejenis hampir pasti sudah ada "
                "(data triage: 2/5 ditolak duplikat di kelas ini). "
                "Tanyakan known-list ke program / cek arsip OBB; "
                "jangan kirim sebagai laporan utama.",
        "MEDIUM": "Perkuat dengan bukti spesifik + dampak terukur "
                  "sebelum kirim.",
        "LOW": "Nilai baru tinggi — kirim dengan bukti lengkap.",
    }[level]
    return {"duplicate_risk": level, "advice": advice}


def check_obb_archive(domain: str, timeout: float = 15.0) -> dict:
    """Cek arsip Open Bug Bounty untuk domain (1 GET, read-only).
    Return jumlah indikasi laporan terbuka; error fail-closed."""
    url = f"https://www.openbugbounty.org/search/?search={domain}&type=host"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "cyphron-audit/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(64_000).decode("utf-8", errors="replace")
        # hitung indikasi entri laporan domain tsb di hasil pencarian
        count = body.lower().count(f"{domain.lower()}")
        return {"checked": True, "mentions": count,
                "note": "indikasi Mentions di arsip OBB — verifikasi manual"}
    except Exception as exc:
        return {"checked": False, "error": f"{type(exc).__name__}: {exc}"}


def stamp_report_findings(findings: list[dict],
                          domain_tier: str = "major-org") -> list[dict]:
    """Tandai tiap temuan laporan dengan risiko duplikat + urutan kirim
    (risiko rendah dulu). TIDAK mengubah verdict — hanya metadata."""
    ranked = []
    for f in findings:
        flag = classify(f.get("title", ""), f.get("finding_class"),
                        f.get("target_url"))
        f = dict(f)
        f["novelty"] = flag
        ranked.append(f)
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    ranked.sort(key=lambda f: order[f["novelty"]["duplicate_risk"]])
    return ranked
