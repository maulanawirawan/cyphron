# [MEDIUM-25] Load Latency

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **load_probe** (LIVE)

## TEKNIK
p95 melonjak > 2x baseline stage.

## FP-GUARD (syarat temuan TRUE)
hit = rasio p95 antar stage. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: load_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).