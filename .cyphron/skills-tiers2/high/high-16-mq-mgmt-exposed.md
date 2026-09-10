# [HIGH-16] Mq Mgmt Exposed

> Tingkat: **HIGH** (estimasi CVSS v3.1: 7.0 - 8.9) | Engine: **dir_probe** (LIVE)

## TEKNIK
Konsol RabbitMQ/Kafka mgmt terbuka.

## FP-GUARD (syarat temuan TRUE)
hit = 200 + marker panel. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: dir_probe — siap pakai hari ini.

## CVSS
Band: 7.0 - 8.9 (high).