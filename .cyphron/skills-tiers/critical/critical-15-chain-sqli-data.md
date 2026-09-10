# [CRITICAL-15] Chain Sqli Data

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **chain_sqli** (ROADMAP)

## TEKNIK
Rantai: SQLi -> data sensitif (tanpa eksfiltrasi).

## FP-GUARD (syarat temuan TRUE)
hit = schema terbaca, contoh 1 baris. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: chain_sqli — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).