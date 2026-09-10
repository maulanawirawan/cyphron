# [MEDIUM-16] Open Redirect Reflected

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **redirect_probe** (LIVE)

## TEKNIK
Open redirect terpantul via parameter.

## FP-GUARD (syarat temuan TRUE)
hit = Location ke canary host. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: redirect_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).