# [LOW-01] Sbom Coverage Audit

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **sbom_cov** (ROADMAP)

## TEKNIK
Cakupan SBOM per artefak diukur.

## FP-GUARD (syarat temuan TRUE)
laporan cakupan persen. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: sbom_cov — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).