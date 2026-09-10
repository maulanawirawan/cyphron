# [MEDIUM-11] Cookie Samesite Session

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **security_headers** (LIVE)

## TEKNIK
Cookie sesi tanpa SameSite.

## FP-GUARD (syarat temuan TRUE)
definitif: atribut absen. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: security_headers — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).