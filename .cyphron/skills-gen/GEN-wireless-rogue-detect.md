---
name: wireless-rogue-detect
domain: wireless
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Wireless Rogue Detect

> Domain: **wireless**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Deteksi rogue AP / evil twin di lingkungan kantor (authorized survey)

## WORKFLOW (ringkas — load detail on-demand)
Scan beacon -> bandingkan BSSID whitelist -> alert SSID mirip

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.