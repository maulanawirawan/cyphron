# [HIGH-20] Csp Bypass Trusted

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **csp_bypass** (ROADMAP)

## TEKNIK
Bypass CSP via domain trusted (cdn abuse).

## FP-GUARD (syarat temuan TRUE)
hit = payload lewat domain allowlist. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: csp_bypass — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 7.0 - 8.9 (high).