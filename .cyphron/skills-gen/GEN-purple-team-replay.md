---
name: purple-team-replay
domain: purple
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Purple Team Replay

> Domain: **purple**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Replay teknik ATT&CK dan ukur deteksi tiap teknik

## WORKFLOW (ringkas — load detail on-demand)
Pilih teknik ATT&CK -> jalur aman -> ukur apakah SIEM memicu -> gap

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.