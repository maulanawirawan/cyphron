# [LOW-30] Mx Provider Map

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **email_probe** (LIVE)

## TEKNIK
Provider email terpetakan dari MX.

## FP-GUARD (syarat temuan TRUE)
definitif: MX record. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: email_probe — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).