# [CRITICAL-16] Prod Admin Default Creds

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **auth_probe** (LIVE)

## TEKNIK
Kredensial default panel admin produksi.

## FP-GUARD (syarat temuan TRUE)
hit = login sukses + marker panel. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: auth_probe — siap pakai hari ini.

## CVSS
Band: 9.0 - 10.0 (critical).