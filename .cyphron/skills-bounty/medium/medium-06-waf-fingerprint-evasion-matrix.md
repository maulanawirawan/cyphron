# [MEDIUM-06] Waf Fingerprint Evasion Matrix

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **waf_matrix** (ROADMAP)

## TEKNIK
Peta WAF + matriks bypass aman (Cloudflare/AWS).

## FP-GUARD (syarat temuan TRUE)
hit = payload lolos terukur. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: waf_matrix — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 4.0 - 6.9 (medium).