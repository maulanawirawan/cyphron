# [LOW-05] Backup Restore Drill

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **backup_drill** (ROADMAP)

## TEKNIK
Latihan restore backup terjadwal.

## FP-GUARD (syarat temuan TRUE)
hit = restore sukses terukur. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: backup_drill — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 0.1 - 3.9 (low).