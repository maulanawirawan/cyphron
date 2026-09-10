# [CRITICAL-30] Zero Day Hunt Fuzz

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **fuzzer** (ROADMAP)

## TEKNIK
Zero-day di sistem sendiri: fuzzing differential.

## FP-GUARD (syarat temuan TRUE)
hit = crash/anomali direproduksi. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: fuzzer — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).