# [HIGH-02] Open Redirect Confirmed

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **redirect_probe** (LIVE)

## TEKNIK
Open redirect ke canary host.

## FP-GUARD (syarat temuan TRUE)
hit = 3xx Location canary. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: redirect_probe — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).