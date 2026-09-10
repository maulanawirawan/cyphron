# [CRITICAL-11] Zero Day Hunt Fuzz

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **fuzz_engine** (LIVE)

## TEKNIK
Zero-day hunting: differential fuzzing di sistem sendiri.

## FP-GUARD (syarat temuan TRUE)
hit = crash/anomali direproduksi. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: fuzz_engine — siap pakai hari ini.

## CVSS
Band: 9.0 - 10.0 (critical).