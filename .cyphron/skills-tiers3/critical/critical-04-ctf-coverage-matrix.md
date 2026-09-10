# [CRITICAL-04] Ctf Coverage Matrix

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **ctf_cov** (ROADMAP)

## TEKNIK
Matriks kategori CTF jeopardy teruji.

## FP-GUARD (syarat temuan TRUE)
matriks kategori. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: ctf_cov — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).