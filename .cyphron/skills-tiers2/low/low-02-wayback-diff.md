# [LOW-02] Wayback Diff

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **wayback** (ROADMAP)

## TEKNIK
Bandingkan rute historis vs sekarang (rute hilang = lead).

## FP-GUARD (syarat temuan TRUE)
hit = rute lama 404 kini. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: wayback — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).