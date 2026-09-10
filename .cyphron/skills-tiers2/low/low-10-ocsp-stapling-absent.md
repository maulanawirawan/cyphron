# [LOW-10] Ocsp Stapling Absent

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **tls_audit** (LIVE)

## TEKNIK
OCSP stapling tidak aktif.

## FP-GUARD (syarat temuan TRUE)
hit = stapled None. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: tls_audit — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).