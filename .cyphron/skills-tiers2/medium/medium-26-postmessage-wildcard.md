# [MEDIUM-26] Postmessage Wildcard

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **crawler** (LIVE)

## TEKNIK
postMessage target '*' dengan data sensitif.

## FP-GUARD (syarat temuan TRUE)
definitif: di source JS. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: crawler — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).