# [MEDIUM-22] Graphiql Exposed

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **deep_probe** (LIVE)

## TEKNIK
GraphiQL IDE terbuka.

## FP-GUARD (syarat temuan TRUE)
hit = 200 + HTML IDE. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: deep_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).