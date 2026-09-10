# [HIGH-10] Cache Poisoning Unkeyed

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **cache_poison** (ROADMAP)

## TEKNIK
Header unkeyed terpantul dan ter-cache.

## FP-GUARD (syarat temuan TRUE)
hit = cache menyimpan versi beracun. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: cache_poison — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 7.0 - 8.9 (high).