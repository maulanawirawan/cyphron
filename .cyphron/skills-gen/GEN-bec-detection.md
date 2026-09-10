---
name: bec-detection
domain: phishing
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Bec Detection

> Domain: **phishing**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Deteksi Business Email Compromise: domain mirip, display-name spoof, thread hijack

## WORKFLOW (ringkas — load detail on-demand)
Bandingkan domain pengirim vs daftar resmi (levenshtein) + cek SPF/DKIM/DMARC + pola thread

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.