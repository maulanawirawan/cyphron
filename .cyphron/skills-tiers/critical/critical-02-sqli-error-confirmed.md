# [CRITICAL-02] Sqli Error Confirmed

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **sqli_probe** (LIVE)

## TEKNIK
SQLi error-based terkonfirmasi.

## FP-GUARD (syarat temuan TRUE)
hit = signature DB error muncul hanya dengan payload. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: sqli_probe — siap pakai hari ini.

## CVSS
Band: 9.0 - 10.0 (critical).