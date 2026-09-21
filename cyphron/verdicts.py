"""verdicts — Verdict Ladder: tangga keputusan deterministik Cyphron.

Tidak ada temuan "setengah jalan": setiap kandidat berada pada satu level
tangga, dan HANYA level >= 3 yang layak menjadi temuan klien. Level 0-2 =
LEAD (indikasi, dilabel jelas, bukan klaim). REJECTED = terbukti salah dan
menjadi bahan rule anti-FP baru.

Level:
  0 OBSERVED                    sinyal mentah (bukan klaim)
  1 SUSPECTED                   pola cocok + ada konteks (masih bukan klaim)
  2 REPRODUCED                  respons diferensial konsisten (A/B + kontrol)
  3 DETERMINISTICALLY_VERIFIED  bukti aritmetika/marker unik/OOB/bukti pair
  4 IMPACT_VERIFIED             dampak minimal terbukti dan tersaksi
  5 BLIND_VALIDATED             validator independen mereproduksi dari claim
                                saja (tanpa reasoning penemu)
 -1 REJECTED                    terbukti false-positive
"""

from __future__ import annotations

OBSERVED = 0
SUSPECTED = 1
REPRODUCED = 2
DETERMINISTICALLY_VERIFIED = 3
IMPACT_VERIFIED = 4
BLIND_VALIDATED = 5
REJECTED = -1

NAMES = {
    0: "OBSERVED", 1: "SUSPECTED", 2: "REPRODUCED",
    3: "DETERMINISTICALLY_VERIFIED", 4: "IMPACT_VERIFIED",
    5: "BLIND_VALIDATED", -1: "REJECTED",
}

# kinds evidence yang menghitung sebagai bukti deterministik
_DETERMINISTIC_KINDS = {
    "request-response", "probe-pair", "arithmetic", "oob", "differential",
}
# kinds yang menandai level lebih tinggi (di-attach engine/validator)
_IMPACT_KIND = "impact"
_BLIND_KIND = "blind"

MIN_REPORT_LEVEL = 3


def verdict_of(finding) -> int:
    """Tentukan level tangga dari status + bukti sebuah Finding.

    Sumber kind: evidence_chain (hasil attach_evidence) ATAU field
    evidence_kind di konstruktor — dulu hanya chain yang dibaca sehingga
    engine yang membuat Finding dengan evidence_kind="request-response"
    tanpa attach_evidence dinilai REPRODUCED padahal buktinya deterministik.
    """
    status = (getattr(finding, "status", "") or "").lower()
    if status == "false-positive":
        return REJECTED
    chain = list(getattr(finding, "evidence_chain", None) or [])
    kinds = {str(e.get("kind", "")).lower() for e in chain if isinstance(e, dict)}
    field_kind = str(getattr(finding, "evidence_kind", "") or "").lower()
    if field_kind:
        kinds.add(field_kind)
    if _BLIND_KIND in kinds:
        return BLIND_VALIDATED
    if _IMPACT_KIND in kinds:
        return IMPACT_VERIFIED
    if status == "confirmed":
        if kinds & _DETERMINISTIC_KINDS:
            return DETERMINISTICALLY_VERIFIED
        return REPRODUCED
    if chain or field_kind:
        return SUSPECTED
    return OBSERVED


def qualifies_for_report(finding) -> bool:
    """True bila level >= 3 (layak tampil sebagai temuan klien)."""
    return verdict_of(finding) >= MIN_REPORT_LEVEL


def label(level: int) -> str:
    return NAMES.get(level, f"L{level}")


def tag(level: int) -> str:
    """Label pendek SATU SUMBER untuk semua permukaan laporan
    (PDF/MD/DOCX/JSON): 'L1 SUSPECTED - LEAD',
    'L3 DETERMINISTICALLY VERIFIED', 'L-x REJECTED'.

    Verdict enforcement lanjutan (22-09): label level tidak lagi hanya di
    chip per-temuan PDF detail — reporting memusatkan tag ini di meta cover,
    callout, matriks verdict, tabel observasi, ringkasan, dan JSON."""
    if level == REJECTED:
        return "L-x REJECTED"
    name = NAMES.get(level, str(level)).replace("_", " ")
    lead = " - LEAD" if level < MIN_REPORT_LEVEL else ""
    return f"L{level} {name}{lead}"


def is_lead(finding) -> bool:
    """LEAD = level 0-2 (indikasi; WAJIB dilabel, bukan klaim)."""
    return 0 <= verdict_of(finding) < MIN_REPORT_LEVEL
