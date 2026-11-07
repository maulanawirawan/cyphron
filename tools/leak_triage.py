"""[DEFEND] leak_triage — triase klaim kebocoran data sebelum panik/beraksi.

Konteks November 2026: klaim "N juta data instansi dijual di darkweb" beredar
cepat di media sosial, sering TANPA sampel yang bisa diverifikasi, sementara
instansi yang disebut sering membantah. Operator (SecOps/bank/instansi) butuh
proses DISIPLIN: klaim tanpa bukti = UNVERIFIED — tidak boleh jadi dasar
laporan, narasi publik, atau eskalasi (kontrak "No proof, no report").
Konsep kategori berasal dari praktik IR standar (verifiable sample, official
response, field fingerprint, corroboration); dibangun from scratch.

Fail-closed tegas:
  - klaim tanpa sampel bukti + tanpa sumber resmi  -> UNVERIFIED
  - klaim dengan bukti sampel       -> VERIFIED-CANDIDATE (bukan "confirmed"
    — konfirmasi akhir tetap milik pemilik data/responder)
  - sampel terbukti tidak cocok (fingerprint tak konsisten dengan skema
    yang dideklarasikan)             -> DEBUNKED-CANDIDATE
Empat gerbang bukti (semua dihitung, tidak ada yang menyembunyikan):
  1. sample        : sampel record tersedia + bisa direproduksi (file/hash)
  2. fingerprint   : field-set sampel konsisten dgn skema sistem yang dituduh
  3. corroboration : >= 2 sumber independen melaporkan sama (bukan re-post)
  4. official      : respon resmi pemilik data (denial ATAU konfirmasi)
Skor = jumlah gerbang lulus; verdict diturunkan dari skor + kombinasi
(KOMBI-WAJIB: tanpa gerbang 1 = Maksimal UNVERIFIED, apa pun skornya).

Runbook IR (dicetak di report, dari praktik IR publik — bukan data rahasia):
  UNVERIFIED   : pantau sumber resmi + telemetri; jangan amplifikasi klaim
  VERIFIED-CAND: rotate kredensial terdampak, audit log akses, siap notifikasi
                 regulator sesuai UU PDP, isolasi jalur eksfiltrasi
  DEBUNKED-CAND: dokumentasikan pemberantasan klaim; satu siaran, lalu diam

Pemakaian:
  python tools/leak_triage.py --claim "10M data Coretax dijual" \
      --records 10000000 --fields "nik,nama,npwp,email" \
      --corroborators 1 --official "denial-DJP-2026-11-07" \
      --sample-hash "" --out triage.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "cyphron.leak-triage/1"
VERDICTS = ("UNVERIFIED", "VERIFIED-CANDIDATE", "DEBUNKED-CANDIDATE")


def _norm_fields(raw: str) -> list[str]:
    """Normalisasi daftar field: spasi/;/| -> koma, lowercase, unik urut."""
    parts = re.split(r"[;|,\s]+", (raw or "").strip().lower())
    return sorted({p for p in parts if p})


def _fingerprint_overlap(claimed_fields: list[str],
                         sample_fields: list[str]) -> "tuple[float, list]":
    """Irisan field yang dituduh vs field yang ada di sampel.

    Return (rasio 0..1, daftar field yang cocok). Rasio >= 0.6 dianggap
    konsisten (klaim sering menyebut subset field).
    """
    if not claimed_fields:
        return 0.0, []
    cs, ss = set(claimed_fields), set(sample_fields)
    overlap = sorted(cs & ss)
    return round(len(overlap) / len(cs), 3), overlap


def triage(claim: str, records: int, fields: str,
           sample_available: bool = False,
           sample_hash: str = "",
           sample_fields: str = "",
           corroborators: int = 0,
           official: str = "") -> dict:
    """Hitung verdict klaim kebocoran. Fail-closed — lihat docstring modul."""
    if not claim or not claim.strip():
        raise ValueError("klaim tidak boleh kosong")
    if records < 0:
        raise ValueError("jumlah record tidak boleh negatif")
    claimed = _norm_fields(fields)
    sample = _norm_fields(sample_fields)
    official_norm = (official or "").strip().lower()

    gates = {
        "sample": {
            "pass": bool(sample_available),
            "detail": ("sampel tersedia" + (f" + hash {sample_hash[:12]}…"
                       if sample_hash else " (tanpa hash)") )
                      if sample_available
                      else "TIDAK ada sampel yang bisa diverifikasi",
        },
        "fingerprint": {
            "pass": False,
            "detail": "tanpa sampel, fingerprint tak bisa dihitung",
        },
        "corroboration": {
            "pass": corroborators >= 2,
            "detail": f"{corroborators} sumber independen "
                      f"({'>= 2 lulus' if corroborators >= 2 else '< 2'})",
        },
        "official": {
            "pass": bool(official_norm),
            "detail": (f"respon resmi: {official_norm[:80]}"
                       if official_norm else
                       "belum ada respon resmi pemilik data"),
        },
    }
    if sample_available and sample:
        ratio, overlap = _fingerprint_overlap(claimed, sample)
        gates["fingerprint"] = {
            "pass": ratio >= 0.6,
            "detail": f"irisan field {len(overlap)}/{len(claimed)} "
                      f"(rasio {ratio}): {','.join(overlap) or '-'}",
        }
        # sampel dengan fingerprint TIDAK konsisten = sinyal bantahan kuat
        if ratio == 0.0 and claimed:
            # field yang dituduh sama sekali tidak ada di sampel
            gates["fingerprint"]["detail"] += " — TIDAK ADA irisan"

    score = sum(1 for g in gates.values() if g["pass"])

    # verdict: fail-closed dengan kombinasi wajib
    fp_consistent = gates["fingerprint"]["pass"]
    fp_decided = "fingerprint" in gates and sample_available and bool(sample)
    if fp_decided and not fp_consistent and score >= 2:
        verdict = "DEBUNKED-CANDIDATE"
    elif gates["sample"]["pass"] and score >= 3:
        verdict = "VERIFIED-CANDIDATE"
    else:
        verdict = "UNVERIFIED"

    runbook = {
        "UNVERIFIED": [
            "pantau kanal resmi pemilik data + telemetri internal",
            "jangan amplifikasi klaim (repost menambah kepanikan tanpa bukti)",
            "siapkan query hunting utk indikator yang disebut klaim",
        ],
        "VERIFIED-CANDIDATE": [
            "rotate/reset kredensial & token terdampak",
            "audit log akses + cari anomali egress",
            "siapkan notifikasi regulator sesuai UU PDP + timeline",
            "konfirmasi akhir: pemilik data / responder resmi",
        ],
        "DEBUNKED-CANDIDATE": [
            "dokumentasikan bukti bantahan (fingerprint mismatch)",
            "satu klarifikasi; tidak perlu repetisi",
            "tetap log klaim utk korelasi klaim ulang berikutnya",
        ],
    }[verdict]

    return {
        "schema": SCHEMA,
        "claim": claim.strip(),
        "records_claimed": records,
        "fields_claimed": claimed,
        "gates": gates,
        "score": score,
        "verdict": verdict,
        "rule": ("tanpa sampel verifiable = maksimal UNVERIFIED, apa pun "
                 "skornya" if not gates["sample"]["pass"]
                 else "sample + skor >= 3 = VERIFIED-CANDIDATE"),
        "runbook": runbook,
        "disclaimer": "triage klaim = alat bantu keputusan, bukan penilaian "
                      "hukum/forensik akhir; konfirmasi akhir milik pemilik "
                      "data (no proof, no report).",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="leak_triage — triase klaim kebocoran data "
                    "(fail-closed, no proof no report).")
    ap.add_argument("--claim", required=True, help="teks klaim singkat")
    ap.add_argument("--records", type=int, default=0,
                    help="jumlah record yang diklaim")
    ap.add_argument("--fields", default="",
                    help="field yang diklaim bocor (koma/; dipisah)")
    ap.add_argument("--sample-available", action="store_true",
                    help="sampel record tersedia & bisa diverifikasi")
    ap.add_argument("--sample-hash", default="",
                    help="hash sampel (SHA-256) untuk reproducibility")
    ap.add_argument("--sample-fields", default="",
                    help="field yang terlihat di sampel")
    ap.add_argument("--corroborators", type=int, default=0,
                    help="jumlah sumber independen (bukan re-post)")
    ap.add_argument("--official", default="",
                    help="respon resmi pemilik data (mis. 'denial-2026-11-07')")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    try:
        result = triage(args.claim, args.records, args.fields,
                        sample_available=args.sample_available,
                        sample_hash=args.sample_hash,
                        sample_fields=args.sample_fields,
                        corroborators=args.corroborators,
                        official=args.official)
    except ValueError as exc:
        print(f"[leak-triage] input tidak valid: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    print(f"[leak-triage] verdict: {result['verdict']} "
          f"(score {result['score']}/4)")
    for name, g in result["gates"].items():
        mark = "PASS" if g["pass"] else "----"
        print(f"  [{mark}] {name}: {g['detail']}")
    for i, step in enumerate(result["runbook"], 1):
        print(f"  {i}. {step}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
