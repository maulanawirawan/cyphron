---
name: cloud-trail-anomaly
domain: cloud
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Cloud Trail Anomaly

> Domain: **cloud**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Deteksi anomali CloudTrail/Azure Activity: akses aneh, privilege berubah

## WORKFLOW (ringkas — load detail on-demand)
Event -> baseline -> alerts pada iam:PassRole, key expose, unusual region

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.