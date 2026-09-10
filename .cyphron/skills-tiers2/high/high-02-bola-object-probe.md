# [HIGH-02] Bola Object Probe

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **bola** (ROADMAP)

## TEKNIK
BOLA pada endpoint terautentikasi.

## FP-GUARD (syarat temuan TRUE)
hit = objek tenant lain terbaca. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: bola — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 7.0 - 8.9 (high).