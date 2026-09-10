# [HIGH-14] Sast Tls Verify Off

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **code_audit** (LIVE)

## TEKNIK
Verifikasi TLS dimatikan.

## FP-GUARD (syarat temuan TRUE)
SAST file:line. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: code_audit — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).