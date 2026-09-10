# [LOW-06] Cookie Attrs Audit

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **cookie_audit** (ROADMAP)

## TEKNIK
SameSite/Domain/Expires cookie di-audit.

## FP-GUARD (syarat temuan TRUE)
definitif: atribut Set-Cookie. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: cookie_audit — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).