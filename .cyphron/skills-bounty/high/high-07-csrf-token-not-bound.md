# [HIGH-07] Csrf Token Not Bound

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **csrf_bind** (ROADMAP)

## TEKNIK
CSRF token tidak terikat sesi.

## FP-GUARD (syarat temuan TRUE)
hit = token A dipakai sesi B sukses. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: csrf_bind — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 7.0 - 8.9 (high).