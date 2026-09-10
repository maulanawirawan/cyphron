# [LOW-03] Cert Transparency Watch

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **ct_watch** (ROADMAP)

## TEKNIK
Pemantauan CT log berkala.

## FP-GUARD (syarat temuan TRUE)
alert subdomain tak dikenal. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: ct_watch — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).