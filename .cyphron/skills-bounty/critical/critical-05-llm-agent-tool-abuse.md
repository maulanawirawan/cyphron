# [CRITICAL-05] Llm Agent Tool Abuse

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **llm_tool** (ROADMAP)

## TEKNIK
Prompt injection memicu tool agen AI (browser/db).

## FP-GUARD (syarat temuan TRUE)
hit = tool dipanggil dgn canary. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: llm_tool — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).