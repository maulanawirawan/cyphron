# [CRITICAL-04] Authbypass Algnone

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **session_probe** (LIVE)

## TEKNIK
Bypass autentikasi via alg:none.

## FP-GUARD (syarat temuan TRUE)
hit = tampered 200 vs baseline denied. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: session_probe — siap pakai hari ini.

## CVSS
Band: 9.0 - 10.0 (critical).