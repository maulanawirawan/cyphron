# [CRITICAL-20] Dns Takeover

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **dns_takeover** (ROADMAP)

## TEKNIK
Domain/subdomain takeover via DNS menggantung.

## FP-GUARD (syarat temuan TRUE)
hit = NXDOMAIN + fingerprint layanan. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: dns_takeover — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).