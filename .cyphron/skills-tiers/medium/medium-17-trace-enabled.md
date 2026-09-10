# [MEDIUM-17] Trace Enabled

> Tingkat: **MEDIUM** (estimasi CVSS v3.1: 4.0 - 6.9) | Engine: **method_audit** (LIVE)

## TEKNIK
Metode TRACE aktif (XST).

## FP-GUARD (syarat temuan TRUE)
hit = body echo probe. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: method_audit — siap pakai hari ini.

## CVSS
Band: 4.0 - 6.9 (medium).