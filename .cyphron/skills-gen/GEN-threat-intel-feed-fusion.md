---
name: threat-intel-feed-fusion
domain: intel
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Threat Intel Feed Fusion

> Domain: **intel**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Fusi feed threat intel: dedup, skor, mapping ke aset

## WORKFLOW (ringkas — load detail on-demand)
Feed -> normalisasi STIX -> dedup -> skor relevansi -> blokir/deteksi

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.