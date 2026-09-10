# [CRITICAL-19] Db Dump Exposed

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **dir_probe** (LIVE)

## TEKNIK
Dump database dengan tabel pengguna terekspos.

## FP-GUARD (syarat temuan TRUE)
hit = header tabel user terbaca. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: dir_probe — siap pakai hari ini.

## CVSS
Band: 9.0 - 10.0 (critical).