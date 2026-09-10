# [MEDIUM-10] Http Desc Leak

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **crawler** (LIVE)

## TEKNIK
Deskripsi endpoint bocorkan perilaku internal.

## FP-GUARD (syarat temuan TRUE)
hit = teks sensitif. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: crawler — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).