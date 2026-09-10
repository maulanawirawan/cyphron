# [HIGH-04] Hostheader Reflect

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **deep_probe** (LIVE)

## TEKNIK
X-Forwarded-Host terpantul di respons.

## FP-GUARD (syarat temuan TRUE)
definitif: nilai canary di body. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: deep_probe — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).