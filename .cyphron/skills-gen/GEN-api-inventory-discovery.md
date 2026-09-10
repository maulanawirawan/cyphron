---
name: api-inventory-discovery
domain: api
version: 1.0
format: progressive-disclosure
---

# Skill GEN — Api Inventory Discovery

> Domain: **api**. Ditambahkan lewat generator dedup (bukan duplikat
> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).

## WHEN TO USE
Inventaris API: REST/GraphQL/gRPC terdokumentasi vs nyata

## WORKFLOW (ringkas — load detail on-demand)
Spec vs traffic vs code -> gap endpoint tak terdokumentasi

## VERIFICATION
- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.
- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).

## ETHICS
- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.