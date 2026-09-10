# [LOW-24] Cors No Cred

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **deep_probe** (LIVE)

## TEKNIK
CORS refleksi Origin tanpa kredensial.

## FP-GUARD (syarat temuan TRUE)
hit = ACAO == Origin, ACAC != true. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: deep_probe — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).