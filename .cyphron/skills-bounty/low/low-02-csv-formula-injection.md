# [LOW-02] Csv Formula Injection

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **csv_inj** (ROADMAP)

## TEKNIK
Payload =cmd/@SUM di field CSV export.

## FP-GUARD (syarat temuan TRUE)
hit = formula terpantul di output CSV. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: csv_inj — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).