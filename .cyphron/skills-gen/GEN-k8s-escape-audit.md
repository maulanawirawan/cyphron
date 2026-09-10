---
name: k8s-escape-audit
domain: container
version: 1.0
format: progressive-disclosure
---

# Skill GEN — K8S Escape Audit

> Domain: **container**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Audit jalur keluar container: privileged, hostMount, capabilities

## WORKFLOW (ringkas — load detail on-demand)
Review spec: privileged/hostPID/hostPath/cap-add; blok kombinasi berbahaya

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.