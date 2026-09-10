# [HIGH-19] Route No Authz

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **session_probe** (LIVE)

## TEKNIK
Rute sensitif identik tanpa sesi.

## FP-GUARD (syarat temuan TRUE)
hit = 200+len identik unauth vs auth. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: session_probe — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).