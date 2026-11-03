# Contributing to Cyphron / Kontribusi ke Cyphron

PRs are welcome! The engine grows because people poke at it. / PR selalu
diterima — engine ini tumbuh karena ada yang ngoprek.

## How / Cara

1. Fork -> branch baru (`feat/nama-fitur` atau `fix/nama-bug`)
2. Satu PR = satu tujuan. Small & focused beats big & vague.
3. Kalau mengubah perilaku: sertakan bukti (output, error sebelum/sesudah,
   log) — cyphron didasari *proof, not claims*.
4. Test: `python -m pytest tests/ -x`
5. Style: ikuti gaya kode di sekitarnya; bahasa santai (EN/ID) boleh.

## Aturan main / Ground rules

- Hanya untuk security assessment **berotorisasi** — aset milik sendiri
  atau ada izin eksplisit. Sama seperti README.
- PR yang di-merge = kamu otomatis tercatat sebagai contributor repo ini 🎉
- Kontribusi ikut lisensi [LICENSE](LICENSE) (PolyForm NC): gratis untuk
  non-komersial. Kalau suatu saat Cyphron dipakai komersial, itu dibahas
  terbuka bareng semua kontributor (standar proyek source-available).
