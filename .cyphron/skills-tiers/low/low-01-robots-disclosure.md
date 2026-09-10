# [LOW-01] Robots Disclosure

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **crawler** (LIVE)

## TEKNIK
robots.txt membocorkan path privat.

## FP-GUARD (syarat temuan TRUE)
hit = 200 + konten, bandingkan baseline 404. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: crawler — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).