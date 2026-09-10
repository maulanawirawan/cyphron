# [MEDIUM-13] Session Entropy Low

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **session_probe** (LIVE)

## TEKNIK
Entropi token sesi < 100 bit.

## FP-GUARD (syarat temuan TRUE)
hit = perhitungan entropi. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: session_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).