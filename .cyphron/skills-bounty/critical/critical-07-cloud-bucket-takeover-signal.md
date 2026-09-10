# [CRITICAL-07] Cloud Bucket Takeover Signal

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **bucket_sig** (ROADMAP)

## TEKNIK
Bucket/S3 endpoint dangling milik target.

## FP-GUARD (syarat temuan TRUE)
hit = NoSuchBucket di domain target. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: bucket_sig — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).