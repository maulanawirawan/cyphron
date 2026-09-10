# [CRITICAL-01] Ssti Verified

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **deep_probe** (LIVE)

## TEKNIK
SSTI dual-payload terverifikasi (potensi RCE).

## FP-GUARD (syarat temuan TRUE)
hit = 49 DAN 998001 muncul, absen di baseline, payload tak ter-echo. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: deep_probe — siap pakai hari ini.

## CVSS
Band: 9.0 - 10.0 (critical).