"""Proof Verifier — verifikasi substantif bukti temuan L3+.

Audit 2026-10 (kritik reviewer A): gerbang bukti saat ini memeriksa
KEBERADAAN request/response/poc — keberadaan bukan pembuktian. Modul ini
memeriksa ISI bukti terhadap klaim kategori (aturan per kategori umum
di registry). Fail-closed: yang tidak lolos diturunkan ke L1 dengan
alasan eksplisit (extra.proof_verify) — bukan dibuang senyap.

Aturan (v1, konservatif — hanya yang bisa diputuskan dari bukti):
  RV-1 refleksi  : klaim refleksi/probe -> token probe di request HARUS
                   muncul juga di response (echo identik bukan bukti)
  RV-2 versi     : klaim disclosure versi -> bukti memuat pola versi
                   (x.y.z) yang dikutip di judul
  RV-3 secret    : klaim secret/credential -> bukti memuat format kuat
                   (prefix AKIA/glowarisghp_/BEGIN ... KEY) ATAU assignment
                   kredensial
  RV-4 generic   : response tidak boleh identik dengan request (echo
                   kosong), minimal 20 karakter konten di luar metadata
Yang tidak tercakup aturan -> lolos (tidak bisa diputuskan = jangan
asumsikan gagal; laporan menyebut cakupan verifier).

Pemakaian:
  from proof_verifier import verify, downgrade
  ok, reason = verify(finding)
  if not ok: finding = downgrade(finding, reason)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import verdict_tag  # noqa: E402

_VERSION_RE = re.compile(r"\b\d{1,3}\.\d{1,3}(\.\d{1,3}){1,2}\b")
_SECRET_FORMATS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_\-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
]
_REFLECT_HINT = re.compile(r"(?i)(refleksi|reflection|probe|echo)")


def _text(finding: dict, *fields: str) -> str:
    return " ".join(str(finding.get(f) or "") for f in fields)


def verify(finding: dict) -> tuple[bool, str]:
    """True = bukti substantif cukup utk verdict saat ini. False = turun."""
    verdict = int(finding.get("verdict", 0))
    if verdict < 3:
        return True, "di bawah L3 — verifier tidak berlaku"
    request = str(finding.get("request") or "")
    response = str(finding.get("response") or "")
    poc = str(finding.get("poc") or "")
    evidence = f"{response} {poc}"
    title_desc = _text(finding, "title", "description")

    # RV-1 refleksi: token probe di request harus terpantul di response
    if _REFLECT_HINT.search(title_desc) and request.strip():
        tokens = re.findall(r"[A-Za-z0-9_\-]{12,}", request)
        # token kandidat = bagian yang KEMUNGKINAN marker (bukan header HTTP)
        markers = [t for t in tokens if t.lower() not in
                   ("http", "https", "host", "content", "length", "charset",
                    "useragent", "accept", "cookie")]
        if markers and not any(m in evidence for m in markers):
            return False, "RV-1: token probe tidak terpantul di response"

    # RV-2 disclosure versi: pola versi di judul harus ada di bukti
    if "disclosure" in title_desc.lower() or "versi" in title_desc.lower():
        versions_in_title = [m.group(0) for m in
                             _VERSION_RE.finditer(title_desc)]
        if versions_in_title and not any(
                v in evidence for v in versions_in_title):
            return False, "RV-2: versi yang diklaim tidak ada di bukti"

    # RV-3 secret: format kredensial kuat harus hadir di bukti
    category = ""
    extra = finding.get("extra") or {}
    if isinstance(extra, dict):
        category = str(extra.get("category") or "")
    if "SECRET" in category.upper() or "secret" in title_desc.lower():
        if not any(p.search(evidence) for p in _SECRET_FORMATS):
            return False, "RV-3: format kredensial kuat tidak ada di bukti"

    # RV-4 generic: response identik dengan request = echo kosong
    if response.strip() and request.strip() and response.strip() == request.strip():
        return False, "RV-4: response identik request (echo tanpa bukti)"
    if not evidence.strip():
        return False, "RV-4: tidak ada konten bukti sama sekali"

    return True, "lolos aturan verifier v1"


def downgrade(finding: dict, reason: str) -> dict:
    """Turunkan temuan gagal-verifikasi ke L1 (LEAD) — fail-closed, bukan
    dibuang. verdict_tag/reportable ikut dihitung ulang."""
    out = dict(finding)
    out["verdict"] = 1
    out["verdict_tag"] = verdict_tag(1)
    out["reportable"] = False
    out["confidence"] = min(float(out.get("confidence", 0.5)), 0.5)
    extra = out.get("extra") if isinstance(out.get("extra"), dict) else {}
    extra = dict(extra or {})
    extra["proof_verify"] = f"failed:{reason}"
    out["extra"] = extra
    out["description"] = (
        str(out.get("description") or "")
        + f" [PROOF-VERIFY: {reason} — diturunkan ke L1]"
    )
    return out
