---
name: vuln-management-sla
domain: vulnmgmt
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Vuln Management Sla

> Domain: **vulnmgmt**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Bangun SLA remediasi berbasis risiko + kebijakan pengecualian

## WORKFLOW (ringkas — load detail on-demand)
Skor risiko kontekstual -> SLA per band -> pengecualian berkedaluwarsa

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.