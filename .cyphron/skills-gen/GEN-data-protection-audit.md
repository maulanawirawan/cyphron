---
name: data-protection-audit
domain: governance
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Data Protection Audit

> Domain: **governance**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Audit klasifikasi & perlindungan data PII per sistem

## WORKFLOW (ringkas — load detail on-demand)
Inventaris data -> klasifikasi -> kontrol (enkripsi/akses/retensi) -> gap

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.