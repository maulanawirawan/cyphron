# [MEDIUM-09] Api Surface Drift

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **drift** (ROADMAP)

## TEKNIK
Endpoint live tidak ada di spec.

## FP-GUARD (syarat temuan TRUE)
hit = endpoint tanpa docs. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: drift — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 4.0 - 6.9 (medium).