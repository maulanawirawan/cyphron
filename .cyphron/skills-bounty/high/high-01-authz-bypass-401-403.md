# [HIGH-01] Authz Bypass 401 403

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **authz_bypass** (LIVE)

## TEKNIK
Matriks bypass 401/403: path tricks, X-Original-URL, verb.

## FP-GUARD (syarat temuan TRUE)
hit = 200 konten nyata via bypass. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: authz_bypass — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).