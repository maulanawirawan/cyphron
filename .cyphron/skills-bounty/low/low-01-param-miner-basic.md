# [LOW-01] Param Miner Basic

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **param_miner** (LIVE)

## TEKNIK
Param tersembunyi ditambang via diff respons (arjun-style).

## FP-GUARD (syarat temuan TRUE)
hit = param mengubah respons vs baseline. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: param_miner — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).