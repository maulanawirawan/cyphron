# [HIGH-01] Xss Reflected

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **xss_probe** (LIVE)

## TEKNIK
Reflected XSS terkonfirmasi (marker markup mentah).

## FP-GUARD (syarat temuan TRUE)
hit = tag script payload terpantul utuh. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: xss_probe — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).