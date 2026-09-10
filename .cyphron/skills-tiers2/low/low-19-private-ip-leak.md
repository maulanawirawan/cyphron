# [LOW-19] Private Ip Leak

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **deep_probe** (LIVE)

## TEKNIK
IP privat bocor di header/body.

## FP-GUARD (syarat temuan TRUE)
definitif: regex RFC1918. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: deep_probe — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).