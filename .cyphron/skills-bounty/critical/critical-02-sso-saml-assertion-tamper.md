# [CRITICAL-02] Sso Saml Assertion Tamper

> Tingkat: **CRITICAL** (estimasi CVSS v3.1: 9.0 - 10.0) | Engine: **saml** (ROADMAP)

## TEKNIK
Tamper assertion SAML (unsigned).

## FP-GUARD (syarat temuan TRUE)
hit = login sebagai korban. Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.

## VERIFIKASI
Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,
dengan request/response tercatat dan early-stop-on-hit aktif.

## SCRIPT/ENGINE
`cyphron` engine: saml — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE.

## CVSS
Band: 9.0 - 10.0 (critical).