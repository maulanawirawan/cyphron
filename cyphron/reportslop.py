"""reportslop — gerbang kualitas laporan (anti-slop) tanpa LLM.

Linter deterministik untuk laporan buatan agent (report.md, GOD-REPORT,
RESILIENCE-REPORT): mendeteksi frasa generik/"AI-sounding" (ID+EN), klaim
absolut, statistik tanpa sumber, dan pengulangan template. Keluaran PASS /
FAIL per blok (dipisah heading `## `).

Filosofi: laporan kelas konsultan = bukti + bahasa yang bisa dipertanggung-
jawabkan. Kalimat yang "terdengar pintar" tapi kosong makna = temuan.

Pemakaian:
    from .reportslop import lint_report
    hasil = lint_report(text_md)          # dict verdict + daftar blok
    python -m cyphron report-lint laporan.md
"""

from __future__ import annotations

import re
from collections import Counter

# Kalimat/frasa yang hampir selalu pengisi, bukan informasi.
_SLOP_PHRASES = (
    # ID
    "sebagai model bahasa", "sebagai ai", "dalam era digital",
    "di era digital", "dunia yang serba", "seiring berkembangnya",
    "tak dapat dipungkiri", "tidak dapat dipungkiri", "perlu dicatat bahwa",
    "penting untuk dicatat bahwa", "dengan demikian dapat disimpulkan",
    "sangat penting untuk diingat", "selangkah lebih maju",
    "jangan ragu untuk menghubungi", "semoga membantu",
    "solusi terbaik untuk semua", "memaksimalkan potensi",
    "memberikan ketenangan pikiran", "pilihan tepat untuk kebutuhan anda",
    # EN
    "it is worth noting", "it's worth noting", "in today's fast-paced",
    "in the ever-evolving", "delve into", "delves into", "tapestry",
    "navigate the complexities", "unlock the power", "unleash the power",
    "seamlessly integrate", "cutting-edge", "state-of-the-art solution",
    "as an ai language model", "as an ai", "hope this helps",
    "feel free to reach out", "game-changer", "at the end of the day",
)

# Klaim absolut — dua arah (tuduhan atau jaminan) sama-sama terlarang.
_ABSOLUTE_CLAIMS = (
    "100% aman", "100% secure", "zero false positive", "zero false positives",
    "dijamin aman", "dijaman aman", "terjamin 100%", "temuan terjamin",
    "tidak pernah gagal", "mustahil gagal", "impossible to fail",
    "guaranteed", "tanpa risiko", "risk-free", "pasti berhasil",
)

# Statistik tanpa sumber: angka persen/jumlah yang tidak diberi konteks
# pengukuran pada kalimat yang sama.
_PCT_RE = re.compile(r"\b\d{1,3}(?:[.,]\d+)?\s?%")
_UNSOURCE_HINTS = ("diukur", "dari uji", "hasil uji", "sumber:", "sumbernya",
                   "dihitung dari", "basis data", "sample", "sampel",
                   "dari total", "terhadap", "benchmark", "measured",
                   "dataset", "gold", "dari log", "dari scan", "dari audit")
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")

_MIN_SENT_FOR_PCT = True


def _sentences(block_text: str) -> list[str]:
    """Gabungkan baris paragraf dulu (kalimat bisa wrap antar baris),
    baru pecah jadi kalimat. Heading/tabel dilewati; ISI code block (di
    antara ``` fence) juga dilewati — perintah/angka di kode bukan kalimat
    naratif yang bisa memicu temuan slop palsu."""
    out = []
    para: list[str] = []
    in_code = False
    for line in block_text.splitlines():
        s = line.strip()
        if s.startswith("```"):
            in_code = not in_code
            if para:
                out.extend(_split_sents(" ".join(para)))
                para = []
            continue
        if in_code:
            continue
        is_meta = (not s or s.startswith(("#", "|", "- [ ]", "- [x]")))
        if is_meta:
            if para:
                out.extend(_split_sents(" ".join(para)))
                para = []
            continue
        para.append(s)
    if para:
        out.extend(_split_sents(" ".join(para)))
    return out


def _split_sents(text: str) -> list[str]:
    return [s.strip() for s in _SENT_SPLIT.split(text) if s.strip()]


def _norm_sentence(s: str) -> str:
    return re.sub(r"[^a-z0-9 ]", "", s.lower()).strip()


def lint_report(text: str) -> dict:
    """Lint laporan markdown. Return:
    {
      "verdict": "PASS"|"FAIL",
      "score": 0-100,
      "blocks": [{"heading": str, "verdict": PASS|FAIL, "issues": [...]}],
    }
    """
    # blok = dipisah heading level-2; preamble sebelum heading pertama = blok 0
    parts = re.split(r"(?m)^##\s+", text)
    blocks: list[dict] = []
    for bi, part in enumerate(parts):
        heading = "preamble" if bi == 0 else part.splitlines()[0].strip()
        body = part if bi == 0 else "\n".join(part.splitlines()[1:])
        issues: list[dict] = []
        low = body.lower()

        for phrase in _SLOP_PHRASES:
            if phrase in low:
                issues.append({
                    "rule": "SL-FRASE-GENERIK",
                    "quote": phrase,
                    "note": "frasa pengisi tanpa informasi",
                })
        for claim in _ABSOLUTE_CLAIMS:
            if claim in low:
                issues.append({
                    "rule": "SL-KLAIM-ABSOLUT",
                    "quote": claim,
                    "note": "klaim absolut tidak boleh ada di laporan",
                })

        for sent in _sentences(body):
            if _PCT_RE.search(sent) and not any(h in sent.lower()
                                                for h in _UNSOURCE_HINTS):
                issues.append({
                    "rule": "SL-STAT-TANPA-SUMBER",
                    "quote": sent[:120],
                    "note": ("persentase tanpa konteks pengukuran/sumber "
                             "pada kalimat yang sama"),
                })

        # pengulangan template: kalimat sama (dinormalisasi) muncul > 2x
        counts = Counter(_norm_sentence(s) for s in _sentences(body)
                         if len(s.split()) >= 6)
        for norm, n in counts.items():
            if n > 2:
                issues.append({
                    "rule": "SL-PENGULANGAN",
                    "quote": norm[:100],
                    "note": f"kalimat yang sama muncul {n}x",
                })

        blocks.append({
            "heading": heading,
            "verdict": "FAIL" if issues else "PASS",
            "issues": issues,
        })

    failed = sum(1 for b in blocks if b["verdict"] == "FAIL")
    total = max(1, len(blocks))
    score = round(100 * (1 - failed / total))
    return {
        "verdict": "PASS" if failed == 0 else "FAIL",
        "score": score,
        "blocks": blocks,
    }


def lint_report_file(path) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return lint_report(fh.read())


def format_result(res: dict) -> str:
    rows = [f"Gerbang kualitas laporan: {res['verdict']} (skor {res['score']})"]
    for b in res["blocks"]:
        rows.append(f"- [{b['verdict']}] {b['heading']}")
        for i in b["issues"]:
            rows.append(f"    {i['rule']}: {i['quote']!r} — {i['note']}")
    return "\n".join(rows)
