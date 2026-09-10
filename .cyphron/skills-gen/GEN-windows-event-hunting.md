---
name: windows-event-hunting
domain: soc
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Windows Event Hunting

> Domain: **soc**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Berburu di Windows Event Log: logon anomaly, proses berbahaya

## WORKFLOW (ringkas — load detail on-demand)
4624/4625/4688/7045 -> korelasikan anomali waktu & host

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.