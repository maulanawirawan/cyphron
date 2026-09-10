---
name: linux-forensics-triage
domain: forensics
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Linux Forensics Triage

> Domain: **forensics**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Triage Linux: auth.log, cron, SUID, persistence mechanism

## WORKFLOW (ringkas — load detail on-demand)
auth.log -> crontab -> SUID -> systemd unit -> modul kernel

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.