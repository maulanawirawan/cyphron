# [MEDIUM-21] Sort Filter Injection

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **sort_inj** (ROADMAP)

## TEKNIK
Injeksi pada sort/filter ORM.

## FP-GUARD (syarat temuan TRUE)
hit = error/urutan berubah. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: sort_inj — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 4.0 - 6.9 (medium).