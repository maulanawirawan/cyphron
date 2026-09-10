---
name: deception-canary-deploy
domain: deception
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Deception Canary Deploy

> Domain: **deception**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Pasang canary (dummy service/token) untuk deteksi dini intrusi

## WORKFLOW (ringkas — load detail on-demand)
Canary token/service -> alert saat disentuh -> dokumentasi penempatan

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.