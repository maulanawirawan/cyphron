# [LOW-03] Dangling Markup Injection

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **dangle** (ROADMAP)

## TEKNIK
<img src=//canary terpantul di respons.

## FP-GUARD (syarat temuan TRUE)
hit = canary url dalam markup. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: dangle — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).