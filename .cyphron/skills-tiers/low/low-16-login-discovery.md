# [LOW-16] Login Discovery

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **auth_probe** (LIVE)

## TEKNIK
Endpoint login teridentifikasi.

## FP-GUARD (syarat temuan TRUE)
hit = form password di HTML. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: auth_probe — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).