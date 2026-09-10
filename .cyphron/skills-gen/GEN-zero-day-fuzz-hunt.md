---
name: zero-day-fuzz-hunt
domain: offensive
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Zero Day Fuzz Hunt

> Domain: **offensive**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Zero-day hunting di sistem sendiri: differential fuzzing input

## WORKFLOW (ringkas — load detail on-demand)
Fuzz input -> bandingkan respons/crash -> reproduksi -> laporan internal

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.