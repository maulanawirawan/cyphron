# [CRITICAL-04] Jndi Rce Probe

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **jndi** (ROADMAP)

## TEKNIK
JNDI lookup (log4j-class) canary.

## FP-GUARD (syarat temuan TRUE)
hit = canary DNS terpicu. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: jndi — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).