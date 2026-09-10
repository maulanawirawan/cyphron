---
name: memory-forensics-volatility
domain: forensics
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Memory Forensics Volatility

> Domain: **forensics**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Analisis memori (RAM dump) untuk mencari proses tersembunyi, injeksi kode, dan kredensial di memori

## WORKFLOW (ringkas — load detail on-demand)
Dump RAM (winpmem/AVML) -> profil OS -> proses anomali -> string yara -> laporan

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.