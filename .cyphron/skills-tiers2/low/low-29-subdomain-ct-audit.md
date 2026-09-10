# [LOW-29] Subdomain Ct Audit

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **ct_log** (ROADMAP)

## TEKNIK
Sertifikat CT membocorkan nama subdomain.

## FP-GUARD (syarat temuan TRUE)
hit = CT log entry. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: ct_log — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).