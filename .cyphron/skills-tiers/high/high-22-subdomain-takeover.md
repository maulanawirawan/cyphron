# [HIGH-22] Subdomain Takeover

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **ct_takeover** (ROADMAP)

## TEKNIK
Subdomain takeover terkonfirmasi.

## FP-GUARD (syarat temuan TRUE)
hit = CNAME ke layanan unclaimed + fingerprint. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: ct_takeover — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 7.0 - 8.9 (high).