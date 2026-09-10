# [MEDIUM-06] Jwt Audience Check

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **jwt_aud** (ROADMAP)

## TEKNIK
aud/iss tidak divalidasi lintas service.

## FP-GUARD (syarat temuan TRUE)
hit = token lintas aud diterima. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: jwt_aud — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 4.0 - 6.9 (medium).