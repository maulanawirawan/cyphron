# [LOW-02] Sec101 Fundamentals

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **sec101** (ROADMAP)

## TEKNIK
Baseline 8 pilar Security-101 diuji ke sistem sendiri.

## FP-GUARD (syarat temuan TRUE)
checklist lulus. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: sec101 — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).