# [LOW-18] Response Time Fingerprint

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **load_probe** (LIVE)

## TEKNIK
Fingerprint stack dari pola waktu respons.

## FP-GUARD (syarat temuan TRUE)
statistik multi-request. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: load_probe — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).