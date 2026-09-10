# [MEDIUM-12] Dns Caa Missing

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **email_probe** (LIVE)

## TEKNIK
CAA tidak dipublikasikan.

## FP-GUARD (syarat temuan TRUE)
fakta DNS. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: email_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).