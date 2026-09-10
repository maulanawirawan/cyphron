# [MEDIUM-07] Lockout Absent

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **auth_probe** (LIVE)

## TEKNIK
Tidak ada lockout/rate-limit di login.

## FP-GUARD (syarat temuan TRUE)
6 gagal beruntun tanpa 429. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: auth_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).