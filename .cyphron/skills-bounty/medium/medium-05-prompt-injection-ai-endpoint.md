# [MEDIUM-05] Prompt Injection Ai Endpoint

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **llm_probe** (LIVE)

## TEKNIK
Payload jailbreak ke endpoint AI/LLM (OwlShield angles).

## FP-GUARD (syarat temuan TRUE)
hit = output melewati policy. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: llm_probe — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).