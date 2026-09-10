# [MEDIUM-01] Nosql Operator Injection

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **nosql** (ROADMAP)

## TEKNIK
Operator Mongo $ne/$gt di body JSON.

## FP-GUARD (syarat temuan TRUE)
hit = auth lolos / error Mongo. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: nosql — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 4.0 - 6.9 (medium).