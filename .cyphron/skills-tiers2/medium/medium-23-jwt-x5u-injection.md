# [MEDIUM-23] Jwt X5U Injection

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **jwt_x5u** (ROADMAP)

## TEKNIK
Header x5u diambil dari URL penyerang.

## FP-GUARD (syarat temuan TRUE)
hit = token ditempa valid. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: jwt_x5u — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 4.0 - 6.9 (medium).