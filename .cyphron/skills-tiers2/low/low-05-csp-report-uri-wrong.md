# [LOW-05] Csp Report Uri Wrong

> Tingkat: **LOW** (estimasi CVSS v3.1: 0.1 - 3.9) | Engine: **security_headers** (LIVE)

## TEKNIK
Report-uri CSP mengarah keluar/mati.

## FP-GUARD (syarat temuan TRUE)
hit = domain report tak dikenal. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: security_headers — siap pakai hari ini.

## CVSS
Band: 0.1 - 3.9 (low).