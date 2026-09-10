# [LOW-26] Git Branch Names

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **dir_probe** (LIVE)

## TEKNIK
Nama branch bocor via .git/HEAD.

## FP-GUARD (syarat temuan TRUE)
definitif: isi ref. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: dir_probe — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).