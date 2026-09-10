# [CRITICAL-06] Payment Amount Tamper Race

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **pay_race** (ROADMAP)

## TEKNIK
Tamper amount + race pada checkout.

## FP-GUARD (syarat temuan TRUE)
hit = order sukses < nilai. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: pay_race — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).