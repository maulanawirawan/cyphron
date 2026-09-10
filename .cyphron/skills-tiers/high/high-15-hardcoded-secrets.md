# [HIGH-15] Hardcoded Secrets

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **secret_scan** (LIVE)

## TEKNIK
Kredensial ter-hardcode di repositori.

## FP-GUARD (syarat temuan TRUE)
SAST file:line + redaksi. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: secret_scan — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).