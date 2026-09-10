# [LOW-08] Response Timing Oracle

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **timing_oracle** (ROADMAP)

## TEKNIK
Oracle timing untuk enum username (CWE-208).

## FP-GUARD (syarat temuan TRUE)
hit = delta latency konsisten. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: timing_oracle — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).