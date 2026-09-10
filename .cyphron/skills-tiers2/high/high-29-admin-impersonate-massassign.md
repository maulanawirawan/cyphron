# [HIGH-29] Admin Impersonate Massassign

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **massassign2** (ROADMAP)

## TEKNIK
Impersonasi admin via mass-assignment.

## FP-GUARD (syarat temuan TRUE)
hit = role berubah via PATCH. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: massassign2 — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 7.0 - 8.9 (high).