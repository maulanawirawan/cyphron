# [CRITICAL-07] Arbitrary File Read

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **deep_probe** (LIVE)

## TEKNIK
Pembacaan file arbitrer terkonfirmasi.

## FP-GUARD (syarat temuan TRUE)
hit = isi /etc/passwd terverifikasi vs baseline. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: deep_probe — siap pakai hari ini.

## CVSS
Band: 9.0 - 10.0 (critical).