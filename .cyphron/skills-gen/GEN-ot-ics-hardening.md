---
name: ot-ics-hardening
domain: ot
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Ot Ics Hardening

> Domain: **ot**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Pengerasan jaringan OT/ICS (Purdue model, unidirectional gateway)

## WORKFLOW (ringkas — load detail on-demand)
Petakan zona Purdue -> konduits -> blok IT->OT langsung -> monitoring pasif

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.