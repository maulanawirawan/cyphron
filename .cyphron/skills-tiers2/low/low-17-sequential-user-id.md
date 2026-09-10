# [LOW-17] Sequential User Id

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **id_seq** (ROADMAP)

## TEKNIK
ID pengguna terlihat sekuensial.

## FP-GUARD (syarat temuan TRUE)
hit = dua id beda 1. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: id_seq — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).