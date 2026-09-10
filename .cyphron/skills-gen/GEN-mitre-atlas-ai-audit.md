---
name: mitre-atlas-ai-audit
domain: ai
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Mitre Atlas Ai Audit

> Domain: **ai**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Audit risiko AI (ATLAS): prompt injection, data poisoning, model theft

## WORKFLOW (ringkas — load detail on-demand)
Petakan permukaan AI -> uji injection/guardrail -> mitigasi

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.