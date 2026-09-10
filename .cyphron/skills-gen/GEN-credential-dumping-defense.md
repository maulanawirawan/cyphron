---
name: credential-dumping-defense
domain: endpoint
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Credential Dumping Defense

> Domain: **endpoint**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Deteksi & mitigasi dumping LSASS/SAM (mimikatz-class)

## WORKFLOW (ringkas — load detail on-demand)
Audit event 4656/4624 + perlindungan LSASS PPL + deteksi akses membaca lsass

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.