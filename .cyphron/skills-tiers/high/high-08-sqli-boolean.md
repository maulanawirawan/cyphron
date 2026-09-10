# [HIGH-08] Sqli Boolean

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **sqli_probe** (LIVE)

## TEKNIK
Boolean-based blind SQLi (pasangan diverifikasi).

## FP-GUARD (syarat temuan TRUE)
hit = divergensi terukur pasangan TRUE/FALSE. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: sqli_probe — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).