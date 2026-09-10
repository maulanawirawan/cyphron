# [CRITICAL-05] Unauth Admin Access

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **session_probe** (LIVE)

## TEKNIK
Akses panel admin tanpa autentikasi.

## FP-GUARD (syarat temuan TRUE)
hit = 200 + marker admin tanpa kredensial. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: session_probe — siap pakai hari ini.

## CVSS
Band: 9.0 - 10.0 (critical).