# [MEDIUM-01] Csp Missing

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **security_headers** (LIVE)

## TEKNIK
CSP tidak ada sama sekali.

## FP-GUARD (syarat temuan TRUE)
definitif: header absen. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: security_headers — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).