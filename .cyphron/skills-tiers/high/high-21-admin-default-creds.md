# [HIGH-21] Admin Default Creds

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **auth_probe** (LIVE)

## TEKNIK
Kredensial default panel admin.

## FP-GUARD (syarat temuan TRUE)
hit = diferensial + marker panel. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: auth_probe — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).