# [HIGH-05] Js Analysis Endpoint Harvest

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **js_harvest** (ROADMAP)

## TEKNIK
Harvest endpoint/API dari bundle JS (LinkFinder-style).

## FP-GUARD (syarat temuan TRUE)
hit = endpoint baru dari JS. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: js_harvest — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 7.0 - 8.9 (high).