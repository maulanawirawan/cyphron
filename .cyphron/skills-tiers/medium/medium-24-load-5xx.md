# [MEDIUM-24] Load 5Xx

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **load_probe** (LIVE)

## TEKNIK
5xx muncul di bawah beban terukur.

## FP-GUARD (syarat temuan TRUE)
hit = 5xx > 0 dalam ladder. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: load_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).