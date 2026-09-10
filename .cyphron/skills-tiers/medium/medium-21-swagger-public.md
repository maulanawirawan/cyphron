# [MEDIUM-21] Swagger Public

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **dir_probe** (LIVE)

## TEKNIK
Swagger/OpenAPI publik tanpa auth.

## FP-GUARD (syarat temuan TRUE)
hit = 200 + JSON spec. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: dir_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).