# [HIGH-06] Cache Key Normalization Bounty

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **cache_norm** (ROADMAP)

## TEKNIK
Normalisasi cache key (; / ../ %09) -> poison.

## FP-GUARD (syarat temuan TRUE)
hit = cache menyajikan payload. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: cache_norm — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 7.0 - 8.9 (high).