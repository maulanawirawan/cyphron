---
name: ransomware-readiness
domain: ir
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Ransomware Readiness

> Domain: **ir**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Kesiapan ransomware: backup imutabel, deteksi massal-encrypt, playbook

## WORKFLOW (ringkas — load detail on-demand)
Uji restore -> deteksi renam massal/entropi -> playbook isolasi

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.