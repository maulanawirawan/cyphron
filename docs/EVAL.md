# EVAL — Hasil Evaluasi Cyphron

Dibuat: 2026-09-21 17:51 UTC · Gerbang regresi: **PASS**

## Suite

- Test: 683 (gagal 0, error 0, skipped 2)
- Status: HIJAU
- Jumlah engine terdaftar: 145

## Benchmark KB (fixture deterministik)

```

```

## Metode

- Suite = seluruh tests/ (unit + e2e fixture, tanpa jaringan nyata).
- Benchmark = fingerprint -> CPE -> KB NVD lokal pada dataset gold
  internal; kasus ambigu DITOLAK dan dilaporkan terpisah (zero-FP).
- Gerbang regresi: suite wajib hijau DAN jumlah test tidak boleh turun
  vs riwayat sebelumnya (eval-history.jsonl).
