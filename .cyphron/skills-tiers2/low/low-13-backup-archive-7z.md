# [LOW-13] Backup Archive 7Z

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **dir_probe** (LIVE)

## TEKNIK
Arsip .7z/.rar terekspos.

## FP-GUARD (syarat temuan TRUE)
definitif: 200 + magic byte. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: dir_probe — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).