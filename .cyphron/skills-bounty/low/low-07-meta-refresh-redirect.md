# [LOW-07] Meta Refresh Redirect

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **meta_redir** (ROADMAP)

## TEKNIK
Redirect tersembunyi via meta refresh.

## FP-GUARD (syarat temuan TRUE)
hit = navigasi ke canary. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: meta_redir — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).