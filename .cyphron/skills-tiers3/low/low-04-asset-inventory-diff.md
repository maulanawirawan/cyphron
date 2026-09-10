# [LOW-04] Asset Inventory Diff

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **asset_diff** (ROADMAP)

## TEKNIK
Inventaris aset vs temuan scan.

## FP-GUARD (syarat temuan TRUE)
hit = aset tak terpetakan. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: asset_diff — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).