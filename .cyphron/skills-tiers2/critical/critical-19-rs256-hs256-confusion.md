# [CRITICAL-19] Rs256 Hs256 Confusion

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **alg_conf** (ROADMAP)

## TEKNIK
Confusion RS256->HS256 (kunci publik sbg HMAC).

## FP-GUARD (syarat temuan TRUE)
hit = token ditempa valid. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: alg_conf — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).