# [LOW-05] Sri Missing Cdn

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **sri** (ROADMAP)

## TEKNIK
Script cross-origin tanpa integrity SRI.

## FP-GUARD (syarat temuan TRUE)
definitif: atribut integrity. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: sri — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).