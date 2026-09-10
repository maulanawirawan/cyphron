# [MEDIUM-09] Login Error Diff

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **auth_probe** (LIVE)

## TEKNIK
Pesan error login berbeda per kasus.

## FP-GUARD (syarat temuan TRUE)
hit = marker error berbeda. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: auth_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).