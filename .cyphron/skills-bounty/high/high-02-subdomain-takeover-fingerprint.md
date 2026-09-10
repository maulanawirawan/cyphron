# [HIGH-02] Subdomain Takeover Fingerprint

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **takeover** (LIVE)

## TEKNIK
CNAME dangling + fingerprint provider (S3/GH/Azure).

## FP-GUARD (syarat temuan TRUE)
hit = fingerprint brand definitif. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: takeover — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).