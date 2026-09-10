# [LOW-21] Session Cookie Name

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **session_probe** (LIVE)

## TEKNIK
Nama cookie sesi terungkap.

## FP-GUARD (syarat temuan TRUE)
definitif: Set-Cookie. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: session_probe — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).