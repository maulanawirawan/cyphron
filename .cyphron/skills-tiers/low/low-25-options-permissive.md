# [LOW-25] Options Permissive

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **method_audit** (LIVE)

## TEKNIK
OPTIONS mengizinkan metode berisiko rendah.

## FP-GUARD (syarat temuan TRUE)
definitif: header Allow. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: method_audit — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).