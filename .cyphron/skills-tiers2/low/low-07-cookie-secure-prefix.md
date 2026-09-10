# [LOW-07] Cookie Secure Prefix

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **security_headers** (LIVE)

## TEKNIK
Cookie __Secure- tanpa flag Secure.

## FP-GUARD (syarat temuan TRUE)
definitif: nama vs atribut. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: security_headers — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).