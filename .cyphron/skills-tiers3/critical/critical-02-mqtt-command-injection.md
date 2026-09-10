# [CRITICAL-02] Mqtt Command Injection

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **mqtt_cmd** (ROADMAP)

## TEKNIK
Injeksi perintah via pesan MQTT (kasus Grafana CAI).

## FP-GUARD (syarat temuan TRUE)
hit = perangkat bereaksi canary. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: mqtt_cmd — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).