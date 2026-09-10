# [LOW-08] Cert San Audit

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **tls_audit** (LIVE)

## TEKNIK
SAN sertifikat memuat nama internal.

## FP-GUARD (syarat temuan TRUE)
definitif: decode SAN. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: tls_audit — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).